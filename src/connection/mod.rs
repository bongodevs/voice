//! A live Discord voice connection: gateway v8 WebSocket, UDP transport, DAVE end-to-end
//! encryption, and the 20 ms send loop.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::dave::davey::ProposalsOperationType;
use crate::dave::DaveEncryptor;
use crate::event::{EventDispatcher, VoiceEvent, VoiceEventListener};
use crate::pacer::{FrameClock, FramePacer};
use crate::provider::OpusFrameProvider;
use crate::transport::{choose_mode, cipher_for_mode};
use crate::udp::{DiscoveredAddress, VoiceUdp};

mod builders;
mod dave;
mod send_loop;
mod supervisor;

use builders::*;
use dave::*;
use send_loop::*;
use supervisor::*;

/// Close codes the voice gateway can be resumed on (op 7); anything else is fatal. 4009 is a
/// routine heartbeat lapse, and 4900 is raised by this crate to force a reconnect.
const RESUMABLE_CLOSE_CODES: &[u16] = &[
    1001, 1006, 4000, 4001, 4002, 4003, 4005, 4009, 4012, 4015, 4016, 4020, 4900,
];

/// Upper bound on the whole `IDENTIFY` to `SESSION_DESCRIPTION` exchange, awaited inline by the
/// caller. Wide enough for a full IP-discovery retry cycle plus a slow voice region.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Heartbeat intervals without an op-6 ACK before the gateway is declared dead and resumed. Only
/// fires on a zombie socket: it reads fine, but the gateway behind it is gone.
const MISSED_ACKS_BEFORE_DEAD: u32 = 3;

/// Resume attempts before the close is reported to the client; a confirmed session restores the
/// budget.
const MAX_RECONNECT_ATTEMPTS: u32 = 3;

/// How long the gateway supervisor is left alive after [`VoiceConnection::disconnect`] queues the
/// close frame, so it actually reaches Discord before the task is aborted.
const CLOSE_FLUSH_GRACE: Duration = Duration::from_millis(250);

/// Lifecycle state of a [`VoiceConnection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionState {
    /// The initial handshake is in progress.
    Connecting = 0,
    /// Fully connected: gateway live and audio flowing.
    Connected = 1,
    /// The gateway dropped and a resume is being attempted.
    Reconnecting = 2,
    /// Permanently closed (disconnected or a fatal close).
    Closed = 3,
}

impl ConnectionState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => ConnectionState::Connecting,
            1 => ConnectionState::Connected,
            2 => ConnectionState::Reconnecting,
            _ => ConnectionState::Closed,
        }
    }
}

/// Error type for connection establishment.
pub type ConnectError = Box<dyn std::error::Error + Send + Sync>;

// DAVE binary op-codes.
const OP_DAVE_MLS_EXTERNAL_SENDER: u8 = 25;
const OP_DAVE_MLS_KEY_PACKAGE: u8 = 26;
const OP_DAVE_MLS_PROPOSALS: u8 = 27;
const OP_DAVE_MLS_COMMIT_WELCOME: u8 = 28;
const OP_DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION: u8 = 29;
const OP_DAVE_MLS_WELCOME: u8 = 30;
const OP_DAVE_MLS_INVALID_COMMIT_WELCOME: u8 = 31;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = SplitSink<WsStream, Message>;
type WsSource = SplitStream<WsStream>;

/// A DAVE event forwarded from the gateway supervisor to the send task (which owns the session).
#[derive(Debug)]
enum DaveEvent {
    /// A binary MLS op (25/27/29/30) with its payload.
    Binary { op: u8, payload: Vec<u8> },
    /// Op 21 `DAVE_PREPARE_TRANSITION`.
    PrepareTransition {
        protocol_version: u16,
        transition_id: u64,
    },
    /// Op 22 `DAVE_EXECUTE_TRANSITION`.
    ExecuteTransition { transition_id: u64 },
    /// Op 24 `DAVE_PREPARE_EPOCH`.
    PrepareEpoch { protocol_version: u16, epoch: u64 },
    /// Op 11 `CLIENT_CONNECT`: users the gateway announced.
    UsersConnected { user_ids: Vec<u64> },
    /// Op 13 `CLIENT_DISCONNECT`: a user left.
    UserDisconnected { user_id: u64 },
    /// Op 4 `SESSION_DESCRIPTION`: the transport key/mode and DAVE version to apply.
    SessionDescription {
        /// The 32-byte transport secret key.
        secret_key: Vec<u8>,
        /// The negotiated transport mode wire name (`d.mode`).
        mode: String,
        /// The negotiated DAVE protocol version (`0` disables DAVE).
        dave_protocol_version: u16,
    },
}

/// Everything needed to join a voice channel, sourced from the main gateway's `VOICE_STATE_UPDATE`
/// and `VOICE_SERVER_UPDATE` events.
#[derive(Debug, Clone)]
pub struct VoiceServerInfo {
    /// Guild (server) id.
    pub guild_id: u64,
    /// Bot user id.
    pub user_id: u64,
    /// Voice channel id (used for the DAVE session).
    pub channel_id: u64,
    /// Voice session id from the main gateway.
    pub session_id: String,
    /// Voice token.
    pub token: String,
    /// Voice server endpoint host (e.g. `"region.discord.media"`), without scheme.
    pub endpoint: String,
}

impl VoiceServerInfo {
    fn ws_url(&self) -> String {
        let host = self
            .endpoint
            .trim_start_matches("wss://")
            .trim_start_matches("ws://");
        format!("wss://{host}/?v=8")
    }
}

/// Re-announces our speaking state on op 11/12 so clients that join after playback began get our
/// SSRC-to-user mapping; without it late joiners hear nothing.
#[derive(Clone)]
struct SpeakingReannounce {
    ws_tx: mpsc::UnboundedSender<Message>,
    speaking: Arc<AtomicBool>,
    ssrc: u32,
}

impl SpeakingReannounce {
    fn announce_if_speaking(&self) {
        if self.speaking.load(Ordering::Relaxed) {
            let _ = self.ws_tx.send(speaking_message(true, self.ssrc));
        }
    }
}

/// Parameters needed to resume a dropped voice session (op 7).
struct ResumeInfo {
    url: String,
    server_id: u64,
    session_id: String,
    token: String,
}

/// A live voice connection. Dropping it (or calling [`disconnect`](Self::disconnect)) stops all
/// tasks.
pub struct VoiceConnection {
    ws_tx: mpsc::UnboundedSender<Message>,
    ssrc: u32,
    state: Arc<AtomicU8>,
    /// Last heartbeat round-trip in milliseconds (`u64::MAX` until the first ACK).
    ping: Arc<AtomicU64>,
    /// Shared with the send task's pacer and the op-11/12 re-announce, so an explicit
    /// [`set_speaking`](Self::set_speaking) stays consistent with what gets re-announced.
    speaking: Arc<AtomicBool>,
    dispatcher: EventDispatcher,
    /// The 20 ms send task. Aborted first on disconnect so frames stop immediately.
    sender: Option<JoinHandle<()>>,
    /// The gateway supervisor. Given a short grace period on disconnect so the close frame flushes.
    supervisor: Option<JoinHandle<()>>,
}

impl VoiceConnection {
    /// Connect to a Discord voice server and start streaming frames from `provider`.
    pub async fn connect<P>(info: VoiceServerInfo, provider: P) -> Result<Self, ConnectError>
    where
        P: OpusFrameProvider + 'static,
    {
        Self::connect_with_dispatcher(info, provider, EventDispatcher::new()).await
    }

    /// Connect, dispatching lifecycle [`VoiceEvent`]s to the listeners already on `dispatcher`.
    /// Register them first: the handshake events fire before this returns.
    pub async fn connect_with_dispatcher<P>(
        info: VoiceServerInfo,
        provider: P,
        dispatcher: EventDispatcher,
    ) -> Result<Self, ConnectError>
    where
        P: OpusFrameProvider + 'static,
    {
        let state = Arc::new(AtomicU8::new(ConnectionState::Connecting as u8));
        let url = info.ws_url();
        let (ws, _response) = match timeout(HANDSHAKE_TIMEOUT, connect_async(url.as_str())).await {
            Ok(result) => result?,
            Err(_) => return Err("voice gateway connect timed out".into()),
        };
        let (mut sink, mut stream) = ws.split();

        sink.send(Message::text(identify_message(&info))).await?;

        let mut ssrc = 0u32;
        let mut udp: Option<VoiceUdp> = None;
        let mut chosen_mode: Option<&'static str> = None;
        let mut heartbeat_interval = 41_250.0f64;
        let mut last_seq = 0u64;

        // Created before the handshake so DAVE ops arriving during it queue instead of being lost:
        // op 25 can precede `SESSION_DESCRIPTION`, and losing it is unrecoverable.
        let (dave_tx, dave_rx) = mpsc::unbounded_channel::<DaveEvent>();

        // Drive the handshake until SESSION_DESCRIPTION, yielding the secret key + dave version.
        let handshake = async {
            loop {
                let Some(message) = stream.next().await else {
                    // Report the failure as an error: no session was established, so a close
                    // event here would be spurious.
                    return Err::<(Vec<u8>, u16), ConnectError>(handshake_error(
                        &dispatcher,
                        "gateway closed during handshake".into(),
                    ));
                };
                let text = match message? {
                    Message::Text(t) => t,
                    Message::Binary(b) => {
                        if b.len() >= 2 {
                            last_seq = last_seq.max(u16::from_be_bytes([b[0], b[1]]) as u64);
                        }
                        forward_dave_binary(&b, &dave_tx);
                        continue;
                    }
                    // A close here carries the diagnosis the caller needs (4006 stale session, 4009
                    // timeout, 4014 disconnected, 4004 auth failed), so keep it in the error.
                    Message::Close(frame) => {
                        let (code, reason) = frame
                            .map(|f| (u16::from(f.code), f.reason.to_string()))
                            .unwrap_or((1006, String::new()));
                        tracing::warn!(code, reason = %reason, "voice: gateway closed during handshake");
                        return Err(handshake_error(
                            &dispatcher,
                            format!("gateway closed during handshake: {code} {reason}"),
                        ));
                    }
                    _ => continue,
                };
                let value: Value = serde_json::from_str(text.as_str())?;
                if let Some(s) = value["seq"].as_u64() {
                    last_seq = last_seq.max(s);
                }
                let Some(op) = value["op"].as_u64() else {
                    continue;
                };
                // Same routing the supervisor does once it takes over: the 11/13 roster and the
                // 21/22/24 transition ops can land before `SESSION_DESCRIPTION`.
                forward_dave_json(op, &value["d"], &dave_tx);
                match op {
                    8 => {
                        heartbeat_interval = value["d"]["heartbeat_interval"]
                            .as_f64()
                            .unwrap_or(41_250.0);
                    }
                    2 => {
                        let d = &value["d"];
                        ssrc = d["ssrc"].as_u64().ok_or("READY missing ssrc")? as u32;
                        let ip = d["ip"].as_str().ok_or("READY missing ip")?.to_string();
                        let port = d["port"].as_u64().ok_or("READY missing port")? as u16;
                        let offered: Vec<String> = d["modes"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|m| m.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let mode = choose_mode(&offered).ok_or_else(|| {
                            format!("server offered no supported mode: {offered:?}")
                        })?;

                        tracing::info!(ssrc, ip = %ip, port, mode, "voice: gateway READY");
                        dispatcher.dispatch(VoiceEvent::GatewayReady {
                            ssrc,
                            ip: ip.clone(),
                            port,
                        });

                        let remote: SocketAddr = format!("{ip}:{port}").parse()?;
                        let socket = VoiceUdp::connect(remote).await?;
                        let discovered = socket.discover_ip(ssrc).await?;
                        tracing::info!(
                            ip = %discovered.ip,
                            port = discovered.port,
                            "voice: external address discovered"
                        );
                        dispatcher.dispatch(VoiceEvent::ExternalIpDiscovered {
                            ip: discovered.ip.clone(),
                            port: discovered.port,
                        });
                        sink.send(Message::text(select_protocol_message(&discovered, mode)))
                            .await?;
                        chosen_mode = Some(mode);
                        udp = Some(socket);
                    }
                    4 => {
                        let key: Vec<u8> = value["d"]["secret_key"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|n| n.as_u64().map(|x| x as u8))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let version =
                            value["d"]["dave_protocol_version"].as_u64().unwrap_or(0) as u16;
                        return Ok((key, version));
                    }
                    _ => {}
                }
            }
        };
        let (secret_key, dave_version): (Vec<u8>, u16) =
            match timeout(HANDSHAKE_TIMEOUT, handshake).await {
                Ok(result) => result?,
                Err(_) => return Err("voice handshake timed out".into()),
            };

        let udp = udp.ok_or("never received READY")?;
        let mode = chosen_mode.ok_or("never received READY")?;
        if dave_version == 0 {
            tracing::info!(
                mode,
                "voice: session established (DAVE disabled, transport-only)"
            );
        } else {
            tracing::info!(
                mode,
                dave_protocol_version = dave_version,
                "voice: session established, negotiating DAVE end-to-end encryption"
            );
        }
        dispatcher.dispatch(VoiceEvent::SessionDescription {
            mode: mode.to_string(),
            dave_protocol_version: dave_version,
        });
        let transport = cipher_for_mode(mode, &secret_key).map_err(ConnectError::from)?;
        // MLS keygen (Ed25519 + HPKE) is CPU-bound; keep it off the async worker.
        let user_id = info.user_id;
        let channel_id = info.channel_id;
        let mut dave =
            tokio::task::spawn_blocking(move || DaveEncryptor::new(user_id, channel_id)).await??;

        let (ws_tx, ws_rx) = mpsc::unbounded_channel::<Message>();

        // Queue our MLS key package up front, so the gateway has it before it issues the add
        // proposals that put us in the group.
        if dave_version > 0 {
            let ws_tx_kp = ws_tx.clone();
            dave = tokio::task::spawn_blocking(move || {
                send_key_package(&mut dave, &ws_tx_kp);
                dave
            })
            .await?;
        }
        // Send-only connection: ask the SFU for no inbound media at all.
        let _ = ws_tx.send(media_sink_wants_message());
        // Shared speaking flag: the send task keeps it in sync, the gateway task reads it to
        // re-announce speaking when a client connects.
        let speaking = Arc::new(AtomicBool::new(false));

        // Store `Connected` before the tasks exist: an immediate close stores `Closed` from the
        // supervisor, and storing `Connected` after that would overwrite it and never exit.
        state.store(ConnectionState::Connected as u8, Ordering::SeqCst);
        tracing::info!(ssrc, "voice: connected, audio send loop running");

        let sender = tokio::spawn(send_loop(
            provider,
            udp,
            dave,
            transport,
            ssrc,
            dave_version > 0,
            ws_tx.clone(),
            dave_rx,
            dispatcher.clone(),
            speaking.clone(),
            state.clone(),
        ));

        let resume = ResumeInfo {
            url,
            server_id: info.guild_id,
            session_id: info.session_id,
            token: info.token,
        };
        let ping = Arc::new(AtomicU64::new(u64::MAX));
        let reannounce = SpeakingReannounce {
            ws_tx: ws_tx.clone(),
            speaking: speaking.clone(),
            ssrc,
        };
        let supervisor = tokio::spawn(gateway_loop(
            resume,
            sink,
            stream,
            ws_rx,
            dave_tx,
            heartbeat_interval,
            last_seq,
            state.clone(),
            ping.clone(),
            dispatcher.clone(),
            reannounce,
        ));

        Ok(Self {
            ws_tx,
            ssrc,
            state,
            ping,
            speaking,
            dispatcher,
            sender: Some(sender),
            supervisor: Some(supervisor),
        })
    }

    /// The connection SSRC.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The last voice-gateway heartbeat round-trip latency in milliseconds, or `None` if no
    /// heartbeat has been acknowledged yet.
    pub fn ping(&self) -> Option<u64> {
        match self.ping.load(Ordering::Relaxed) {
            u64::MAX => None,
            value => Some(value),
        }
    }

    /// The current lifecycle [`ConnectionState`].
    pub fn state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.state.load(Ordering::SeqCst))
    }

    /// The event dispatcher driving this connection's [`VoiceEvent`]s.
    pub fn dispatcher(&self) -> &EventDispatcher {
        &self.dispatcher
    }

    /// Register a listener for ongoing [`VoiceEvent`]s. Handshake events already emitted before
    /// [`connect`](Self::connect) returned are not replayed.
    pub fn add_listener(&self, listener: Arc<dyn VoiceEventListener>) {
        self.dispatcher.register(listener);
    }

    /// Announce speaking state to the gateway.
    pub fn set_speaking(&self, speaking: bool) {
        // Keep the shared flag in step with the announcement: the op-11/12 re-announce reads it, so
        // a stale `true` here would tell every late joiner we are speaking after we stopped.
        self.speaking.store(speaking, Ordering::Relaxed);
        let _ = self.ws_tx.send(speaking_message(speaking, self.ssrc));
    }

    /// Disconnect: close the gateway and stop all tasks.
    pub fn disconnect(mut self) {
        self.state
            .store(ConnectionState::Closed as u8, Ordering::SeqCst);
        let _ = self.ws_tx.send(close_message());
        // Stop the audio immediately: the caller may already be feeding this guild's frames to a
        // replacement connection, and two send tasks on one SSRC interleave RTP sequence numbers.
        if let Some(sender) = self.sender.take() {
            sender.abort();
        }
        // The supervisor still has to pump the queued close frame out of `ws_tx`, so give it a
        // moment before pulling the rug out. Off-runtime callers just abort now.
        let Some(supervisor) = self.supervisor.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    sleep(CLOSE_FLUSH_GRACE).await;
                    supervisor.abort();
                });
            }
            Err(_) => supervisor.abort(),
        }
    }
}

impl Drop for VoiceConnection {
    fn drop(&mut self) {
        for task in [self.sender.take(), self.supervisor.take()]
            .into_iter()
            .flatten()
        {
            task.abort();
        }
    }
}

/// Report a handshake-phase failure to the listeners and build the matching error. No
/// `GatewayClosed` is emitted before a session is established; the caller drives the failure.
fn handshake_error(dispatcher: &EventDispatcher, message: String) -> ConnectError {
    dispatcher.dispatch(VoiceEvent::GatewayError {
        message: message.clone(),
    });
    message.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct CapturedEvents(Mutex<Vec<VoiceEvent>>);

    impl VoiceEventListener for CapturedEvents {
        fn on_event(&self, event: &VoiceEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    fn info(endpoint: &str) -> VoiceServerInfo {
        VoiceServerInfo {
            guild_id: 1,
            user_id: 2,
            channel_id: 3,
            session_id: "s".into(),
            token: "t".into(),
            endpoint: endpoint.into(),
        }
    }

    #[test]
    fn builds_v8_ws_url_and_strips_scheme() {
        assert_eq!(
            info("region.discord.media").ws_url(),
            "wss://region.discord.media/?v=8"
        );
        assert_eq!(
            info("wss://region.discord.media").ws_url(),
            "wss://region.discord.media/?v=8"
        );
    }

    #[test]
    fn dave_binary_framing_is_op_then_payload() {
        let msg = dave_binary(OP_DAVE_MLS_KEY_PACKAGE, b"kp");
        let data = msg.into_data();
        assert_eq!(data[0], OP_DAVE_MLS_KEY_PACKAGE); // op first, no seq prefix
        assert_eq!(&data[1..], b"kp");
    }

    #[test]
    fn proposals_payload_splits_optype_from_mls_bytes() {
        // op-27 payload (after seq+op) is `[operation_type][proposals…]`; the optype byte must be
        // stripped before the MLS bytes reach davey, or TLS deserialization fails.
        let (op, mls) = split_proposals(&[0x00, 0xDE, 0xAD]).unwrap();
        assert_eq!(op, ProposalsOperationType::APPEND);
        assert_eq!(mls, &[0xDE, 0xAD]);

        let (op, mls) = split_proposals(&[0x01, 0xBE, 0xEF]).unwrap();
        assert_eq!(op, ProposalsOperationType::REVOKE);
        assert_eq!(mls, &[0xBE, 0xEF]);

        assert!(split_proposals(&[]).is_none()); // empty
        assert!(split_proposals(&[0x07]).is_none()); // unknown operation type
    }

    #[test]
    fn transition_id_is_stripped_from_commit_and_welcome() {
        // op-29/op-30 payloads (after seq+op) are `[transition_id: u16 BE][mls…]`.
        let (id, mls) = strip_transition_id(&[0x00, 0x05, 0xAA, 0xBB]).unwrap();
        assert_eq!(id, 5);
        assert_eq!(mls, &[0xAA, 0xBB]);

        // A bare transition id with no MLS bytes is still valid framing.
        let (id, mls) = strip_transition_id(&[0x01, 0x00]).unwrap();
        assert_eq!(id, 256);
        assert!(mls.is_empty());

        assert!(strip_transition_id(&[0x00]).is_none()); // too short for a u16 id
    }

    #[test]
    fn invalid_commit_welcome_is_op31_json_with_transition_id() {
        let value: Value = serde_json::from_str(
            invalid_commit_welcome_message(42)
                .into_text()
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(value["op"], 31);
        assert_eq!(value["d"]["transition_id"], 42);
    }

    #[test]
    fn heartbeat_is_v8_shape_with_seq_ack() {
        let msg = heartbeat_message(7, 42);
        let text = msg.into_text().unwrap();
        let value: Value = serde_json::from_str(text.as_str()).unwrap();
        assert_eq!(value["op"], 3);
        assert_eq!(value["d"]["t"], 7);
        assert_eq!(value["d"]["seq_ack"], 42);
    }

    #[test]
    fn resume_uses_op7_with_seq_ack() {
        let resume = ResumeInfo {
            url: "wss://x/?v=8".into(),
            server_id: 99,
            session_id: "sid".into(),
            token: "tok".into(),
        };
        let value: Value =
            serde_json::from_str(resume_message(&resume, 12).into_text().unwrap().as_str())
                .unwrap();
        assert_eq!(value["op"], 7);
        assert_eq!(value["d"]["server_id"], "99");
        assert_eq!(value["d"]["session_id"], "sid");
        assert_eq!(value["d"]["seq_ack"], 12);
    }

    #[test]
    fn transition_ready_is_op23() {
        let value: Value =
            serde_json::from_str(transition_ready_message(5).into_text().unwrap().as_str())
                .unwrap();
        assert_eq!(value["op"], 23);
        assert_eq!(value["d"]["transition_id"], 5);
    }

    #[test]
    fn resumable_close_codes_only() {
        // Codes in the resumable set, plus an abnormal drop with no frame, are resumable.
        for &code in RESUMABLE_CLOSE_CODES {
            assert!(is_resumable(Some(code)), "{code} should resume");
        }
        assert!(is_resumable(None), "abnormal drop should resume");
        // A heartbeat lapse (4009) must resume, not be treated as fatal.
        assert!(is_resumable(Some(4009)));
        // Fatal: 4004 auth failed, 4006 session no longer valid, 4011 server not found,
        // 4014 disconnected, 4021 rate limited, 4022 all clients disconnected.
        for code in [1000u16, 4004, 4006, 4011, 4014, 4021, 4022] {
            assert!(!is_resumable(Some(code)), "{code} should be fatal");
        }
    }

    #[test]
    fn connection_state_round_trips() {
        for state in [
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Reconnecting,
            ConnectionState::Closed,
        ] {
            assert_eq!(ConnectionState::from_u8(state as u8), state);
        }
    }

    #[test]
    fn dave_ops_are_routed_to_the_send_task() {
        let (tx, mut rx) = mpsc::unbounded_channel::<DaveEvent>();

        // `[seq: u16 BE][op][mls…]`: the seq and op bytes are stripped, the MLS bytes are not.
        forward_dave_binary(&[0x00, 0x07, OP_DAVE_MLS_EXTERNAL_SENDER, 0xAB], &tx);
        forward_dave_binary(&[0x00, 0x08, 99, 0xCD], &tx); // not a DAVE op
        forward_dave_binary(&[0x00], &tx); // too short to carry an op
        forward_dave_json(11, &json!({ "user_ids": ["4", "5"] }), &tx);
        forward_dave_json(13, &json!({ "user_id": "4" }), &tx);
        forward_dave_json(
            21,
            &json!({ "protocol_version": 1, "transition_id": 3 }),
            &tx,
        );
        forward_dave_json(22, &json!({ "transition_id": 3 }), &tx);
        forward_dave_json(24, &json!({ "protocol_version": 1, "epoch": 1 }), &tx);
        forward_dave_json(6, &json!({}), &tx); // heartbeat ack is not a DAVE op
        drop(tx);

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        assert_eq!(events.len(), 6, "one event per DAVE op, nothing else");
        assert!(matches!(
            &events[0],
            DaveEvent::Binary { op: OP_DAVE_MLS_EXTERNAL_SENDER, payload } if payload == &[0xAB]
        ));
        assert!(
            matches!(&events[1], DaveEvent::UsersConnected { user_ids } if user_ids == &[4, 5])
        );
        assert!(matches!(
            events[2],
            DaveEvent::UserDisconnected { user_id: 4 }
        ));
        assert!(matches!(
            events[3],
            DaveEvent::PrepareTransition {
                protocol_version: 1,
                transition_id: 3
            }
        ));
        assert!(matches!(
            events[4],
            DaveEvent::ExecuteTransition { transition_id: 3 }
        ));
        assert!(matches!(
            events[5],
            DaveEvent::PrepareEpoch {
                protocol_version: 1,
                epoch: 1
            }
        ));
    }

    #[test]
    fn resume_backoff_grows_and_stays_bounded() {
        // Voice servers cycle whole hosts at once, so the delay must grow and carry jitter while
        // staying inside the gateway's session-resume window.
        let delays: Vec<Duration> = (0..5).map(backoff_delay).collect();
        for pair in delays.windows(2) {
            assert!(pair[1] > pair[0], "{:?} must grow", delays);
        }
        assert!(delays[0] >= Duration::from_millis(500));
        assert!(*delays.last().unwrap() <= Duration::from_millis(8_500));
    }

    #[test]
    fn local_close_is_normal_closure_and_sink_wants_nothing() {
        let Message::Close(Some(frame)) = close_message() else {
            panic!("expected a close frame");
        };
        assert_eq!(u16::from(frame.code), 1000);

        let value: Value =
            serde_json::from_str(media_sink_wants_message().into_text().unwrap().as_str()).unwrap();
        assert_eq!(value["op"], 15);
        assert_eq!(value["d"]["any"], 0);
    }

    #[test]
    fn handshake_failures_report_as_gateway_error_only() {
        let dispatcher = EventDispatcher::new();
        let captured = Arc::new(CapturedEvents::default());
        dispatcher.register(captured.clone());

        let error = handshake_error(&dispatcher, "gateway closed during handshake: 4006".into());
        assert!(error.to_string().contains("4006"));

        let events = captured.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], VoiceEvent::GatewayError { .. }),
            "no close may be reported before a session exists, got {:?}",
            events[0]
        );
    }

    #[test]
    fn identify_includes_channel_id() {
        let value: Value =
            serde_json::from_str(identify_message(&info("region.discord.media")).as_str()).unwrap();
        assert_eq!(value["d"]["channel_id"].as_str(), Some("3"));
    }

    #[test]
    fn disconnect_emits_no_gateway_close() {
        let dispatcher = EventDispatcher::new();
        let captured = Arc::new(CapturedEvents::default());
        dispatcher.register(captured.clone());
        let (ws_tx, _ws_rx) = mpsc::unbounded_channel();
        let connection = VoiceConnection {
            ws_tx,
            ssrc: 1,
            state: Arc::new(AtomicU8::new(ConnectionState::Connected as u8)),
            ping: Arc::new(AtomicU64::new(u64::MAX)),
            speaking: Arc::new(AtomicBool::new(false)),
            dispatcher,
            sender: None,
            supervisor: None,
        };

        connection.disconnect();

        let events = captured.0.lock().unwrap();
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, VoiceEvent::GatewayClosed { .. })),
            "a disconnect initiated by the caller must stay silent, got {events:?}"
        );
    }
}
