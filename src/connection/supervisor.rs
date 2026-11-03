use super::builders::{heartbeat_message, resume_message};
use super::*;

/// Resume budget across closes: a confirmed session (op 4 or op 9) restores it.
struct ReconnectBudget {
    attempts: u32,
}

impl ReconnectBudget {
    fn new() -> Self {
        Self { attempts: 0 }
    }

    /// The session description arrived or a resume was acknowledged: the budget is whole again.
    fn confirm(&mut self) {
        self.attempts = 0;
    }

    fn can_attempt(&self) -> bool {
        self.attempts < MAX_RECONNECT_ATTEMPTS
    }

    fn record_attempt(&mut self) {
        self.attempts += 1;
    }

    fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// A heartbeat interval whose first tick waits a full period, as the reference's
/// `scheduleAtFixedRate` does. A zero period would panic, so keep at least one millisecond.
fn heartbeat_interval(period: Duration) -> tokio::time::Interval {
    let period = period.max(Duration::from_millis(1));
    let mut interval = interval_at(tokio::time::Instant::now() + period, period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

/// Gateway supervisor: owns the WebSocket, heartbeats, dispatches inbound ops, and resumes on a
/// dropped connection while the send task (UDP/DAVE) keeps running.
#[allow(clippy::too_many_arguments)]
pub(super) async fn gateway_loop(
    resume: ResumeInfo,
    mut sink: WsSink,
    mut stream: WsSource,
    mut ws_rx: mpsc::UnboundedReceiver<Message>,
    dave_tx: mpsc::UnboundedSender<DaveEvent>,
    heartbeat_interval_ms: f64,
    mut last_seq: u64,
    state: Arc<AtomicU8>,
    ping: Arc<AtomicU64>,
    dispatcher: EventDispatcher,
    reannounce: SpeakingReannounce,
) {
    let mut hb = heartbeat_interval(Duration::from_millis(heartbeat_interval_ms as u64));
    let mut budget = ReconnectBudget::new();
    // The handshake's session description starts the budget at zero; this covers op 4/op 9 mid-loop.
    let mut session_confirmed = false;

    loop {
        let outcome = pump(
            sink,
            stream,
            &mut ws_rx,
            &dave_tx,
            &dispatcher,
            &reannounce,
            &mut hb,
            &mut last_seq,
            &ping,
            &state,
            &mut session_confirmed,
        )
        .await;
        if session_confirmed {
            session_confirmed = false;
            budget.confirm();
        }

        match outcome {
            // We initiated the close (the connection was disconnected/dropped).
            PumpOutcome::Stop => {
                state.store(ConnectionState::Closed as u8, Ordering::SeqCst);
                break;
            }
            // The gateway dropped: resume on a resumable close code, otherwise treat it as fatal.
            PumpOutcome::Closed {
                code,
                reason,
                by_remote,
            } => {
                // `disconnect` and the send loop giving up both store `Closed` before the close
                // frame goes out, so a local stop is neither resumed nor reported.
                if ConnectionState::from_u8(state.load(Ordering::SeqCst)) == ConnectionState::Closed
                {
                    tracing::debug!(code = code.unwrap_or(0), "voice: gateway closed locally");
                    break;
                }
                let mut recovered = None;
                if is_resumable(code) && budget.can_attempt() {
                    // Only resume if still Connected; a concurrent `disconnect` sets Closed, and
                    // resuming would revive a connection the caller asked to drop.
                    let claimed = state
                        .compare_exchange(
                            ConnectionState::Connected as u8,
                            ConnectionState::Reconnecting as u8,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok();
                    if !claimed {
                        // `disconnect` raced in after the drop; the writer has already flushed its
                        // close.
                        return;
                    }
                    tracing::warn!(
                        code = code.unwrap_or(0),
                        attempt = budget.attempts() + 1,
                        budget = MAX_RECONNECT_ATTEMPTS,
                        "voice: gateway dropped, attempting resume"
                    );
                    // Backoff is jittered because Discord cycling a voice server drops every
                    // connection on the host at once, and a fixed schedule reconnects them in step.
                    while budget.can_attempt() {
                        // Nothing pumps `ws_rx` during this loop, so a `disconnect` queued there is
                        // invisible; watch the state instead of leaking the session until Discord
                        // times it out.
                        if ConnectionState::from_u8(state.load(Ordering::SeqCst))
                            == ConnectionState::Closed
                        {
                            return;
                        }
                        sleep(backoff_delay(budget.attempts())).await;
                        budget.record_attempt();
                        if let Ok((mut new_sink, new_stream)) = reconnect(&resume.url).await {
                            // The resume has to finish before the new writer starts; a stalled
                            // handshake must not pin the supervisor forever.
                            let resumed = timeout(
                                WRITE_TIMEOUT,
                                new_sink.send(resume_message(&resume, last_seq)),
                            )
                            .await
                            .map(|result| result.is_ok())
                            .unwrap_or(false);
                            if resumed {
                                recovered = Some((new_sink, new_stream));
                                break;
                            }
                        }
                    }
                } else if is_resumable(code) {
                    tracing::warn!(
                        attempts = budget.attempts(),
                        "voice: reconnect budget exhausted, reporting the close to the client"
                    );
                }
                match recovered {
                    Some((new_sink, new_stream)) => {
                        sink = new_sink;
                        stream = new_stream;
                        tracing::info!("voice: gateway session resumed");
                        state.store(ConnectionState::Connected as u8, Ordering::SeqCst);
                    }
                    None => {
                        tracing::warn!(
                            code = code.unwrap_or(1006),
                            reason = %reason,
                            by_remote,
                            "voice: gateway closed"
                        );
                        state.store(ConnectionState::Closed as u8, Ordering::SeqCst);
                        dispatcher.dispatch(closed_event(code, reason, by_remote));
                        break;
                    }
                }
            }
        }
    }
}

/// Whether a WebSocket close should trigger a resume. A missing code (an abnormal drop with no
/// close frame, e.g. 1006-style) is treated as resumable.
pub(super) fn is_resumable(code: Option<u16>) -> bool {
    match code {
        Some(code) => RESUMABLE_CLOSE_CODES.contains(&code),
        None => true,
    }
}

/// The close event for a dropped connection. A close without a code of its own is an abnormal
/// drop: report 1006 `Abnormal closure` rather than a zero-code close.
fn closed_event(code: Option<u16>, reason: String, by_remote: bool) -> VoiceEvent {
    match code {
        Some(code) => VoiceEvent::GatewayClosed {
            code,
            reason,
            by_remote,
        },
        None => VoiceEvent::GatewayClosed {
            code: 1006,
            reason: if reason.is_empty() {
                "Abnormal closure".into()
            } else {
                reason
            },
            by_remote,
        },
    }
}

/// Resume backoff: `500 ms * 2^attempt` capped at 8 s, plus up to 500 ms of clock-derived jitter.
pub(super) fn backoff_delay(attempt: u32) -> Duration {
    let base = Duration::from_millis(500 << attempt.min(4));
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| (since.subsec_nanos() % 500_000) as u64)
        .unwrap_or(0);
    base + Duration::from_micros(jitter)
}

/// Outcome of one [`pump`] over a single WebSocket lifetime.
#[derive(Debug)]
enum PumpOutcome {
    /// The outbound channel closed (the connection was disconnected or dropped), so stop entirely.
    Stop,
    /// The WebSocket closed or errored. [`is_resumable`] decides resume-vs-fatal from `code`.
    Closed {
        /// The close code, if a close frame was received.
        code: Option<u16>,
        /// The close reason text (empty if none).
        reason: String,
        /// Whether the remote (Discord) initiated the close.
        by_remote: bool,
    },
}

/// Queue one message for the writer task without waiting. A full queue means the gateway has
/// stopped reading, so the caller closes the session instead of buffering without bound.
fn queue_outbound(tx: &mpsc::Sender<Message>, message: Message) -> Result<(), &'static str> {
    match tx.try_send(message) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => Err("outbound queue full"),
        Err(mpsc::error::TrySendError::Closed(_)) => Err("outbound writer stopped"),
    }
}

/// The only task that awaits a socket write. Keeping writes here means a stalled gateway cannot
/// delay heartbeats or inbound reads, and every write has a deadline of its own.
async fn writer_task<S>(
    mut sink: S,
    mut rx: mpsc::Receiver<Message>,
    failed: mpsc::UnboundedSender<String>,
) where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    while let Some(message) = rx.recv().await {
        match timeout(WRITE_TIMEOUT, sink.send(message)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = failed.send(format!("outbound send failed: {error}"));
                return;
            }
            Err(_) => {
                let _ = failed.send("outbound send timed out".into());
                return;
            }
        }
    }
    // The supervisor is stopping; give the close frame the same short grace as `disconnect`.
    let _ = timeout(CLOSE_FLUSH_GRACE, sink.send(Message::Close(None))).await;
}

/// Drive one WebSocket until it drops or the outbound channel closes.
#[allow(clippy::too_many_arguments)]
async fn pump<S, R, E>(
    sink: S,
    mut stream: R,
    ws_rx: &mut mpsc::UnboundedReceiver<Message>,
    dave_tx: &mpsc::UnboundedSender<DaveEvent>,
    dispatcher: &EventDispatcher,
    reannounce: &SpeakingReannounce,
    hb: &mut tokio::time::Interval,
    last_seq: &mut u64,
    ping: &Arc<AtomicU64>,
    state: &Arc<AtomicU8>,
    session_confirmed: &mut bool,
) -> PumpOutcome
where
    S: futures_util::Sink<Message> + Unpin + Send + 'static,
    S::Error: std::fmt::Display,
    R: futures_util::Stream<Item = Result<Message, E>> + Unpin + Send + 'static,
    E: std::fmt::Display,
{
    let (write_tx, write_rx) = mpsc::channel::<Message>(WRITE_QUEUE_LEN);
    let (failed_tx, mut failed_rx) = mpsc::unbounded_channel::<String>();
    let mut writer = tokio::spawn(writer_task(sink, write_rx, failed_tx));

    // When the last heartbeat was sent, used to compute the round-trip on the matching ACK (op 6).
    let mut last_heartbeat: Option<Instant> = None;
    // A gateway that stops acking is dead even though its TCP connection still reads fine, so this
    // watchdog is what stops a zombie session swallowing every frame forever.
    let mut last_ack = Instant::now();
    let outcome = loop {
        tokio::select! {
            outbound = ws_rx.recv() => match outbound {
                Some(message) => {
                    if let Err(reason) = queue_outbound(&write_tx, message) {
                        break PumpOutcome::Closed {
                            code: None,
                            reason: reason.into(),
                            by_remote: false,
                        };
                    }
                }
                None => break PumpOutcome::Stop,
            },
            failure = failed_rx.recv() => {
                break PumpOutcome::Closed {
                    code: None,
                    reason: failure.unwrap_or_else(|| "outbound writer stopped".into()),
                    by_remote: false,
                };
            },
            _ = hb.tick() => {
                // A HELLO can change the period, so read it on every tick instead of caching it.
                let ack_timeout = hb.period() * MISSED_ACKS_BEFORE_DEAD;
                if last_ack.elapsed() > ack_timeout {
                    tracing::warn!(
                        elapsed_ms = last_ack.elapsed().as_millis(),
                        "voice: no heartbeat ack, treating the gateway as dead"
                    );
                    // `code: None` is resumable, so the supervisor reconnects and sends op 7.
                    break PumpOutcome::Closed {
                        code: None,
                        reason: "heartbeat ack timeout".into(),
                        by_remote: false,
                    };
                }
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|since| since.as_millis() as u64)
                    .unwrap_or(0);
                if let Err(reason) = queue_outbound(&write_tx, heartbeat_message(t, *last_seq)) {
                    break PumpOutcome::Closed {
                        code: None,
                        reason: reason.into(),
                        by_remote: false,
                    };
                }
                last_heartbeat = Some(Instant::now());
            },
            inbound = stream.next() => match inbound {
                Some(Ok(Message::Close(frame))) => break close_outcome(frame),
                Some(Ok(message)) => handle_inbound(
                    message,
                    dave_tx,
                    dispatcher,
                    reannounce,
                    state,
                    last_seq,
                    ping,
                    last_heartbeat,
                    &mut last_ack,
                    hb,
                    session_confirmed,
                ),
                Some(Err(error)) => {
                    dispatcher.dispatch(VoiceEvent::GatewayError {
                        message: error.to_string(),
                    });
                    break PumpOutcome::Closed {
                        code: None,
                        reason: "connection error".into(),
                        by_remote: false,
                    };
                }
                None => {
                    break PumpOutcome::Closed {
                        code: None,
                        reason: String::new(),
                        by_remote: false,
                    };
                }
            },
        }
    };

    // Let the writer drain what is already queued, then stop it rather than block on a stuck
    // socket. Closing the channel makes it emit the close frame first.
    drop(write_tx);
    if timeout(CLOSE_FLUSH_GRACE, &mut writer).await.is_err() {
        writer.abort();
    }
    outcome
}

/// Translate a WebSocket close frame into a [`PumpOutcome`].
fn close_outcome(frame: Option<CloseFrame>) -> PumpOutcome {
    match frame {
        Some(frame) => PumpOutcome::Closed {
            code: Some(u16::from(frame.code)),
            reason: frame.reason.to_string(),
            by_remote: true,
        },
        None => PumpOutcome::Closed {
            code: None,
            reason: String::new(),
            by_remote: true,
        },
    }
}

/// Track the server sequence and forward DAVE ops; ignore keep-alive / informational ops.
#[allow(clippy::too_many_arguments)]
fn handle_inbound(
    message: Message,
    dave_tx: &mpsc::UnboundedSender<DaveEvent>,
    dispatcher: &EventDispatcher,
    reannounce: &SpeakingReannounce,
    state: &Arc<AtomicU8>,
    last_seq: &mut u64,
    ping: &Arc<AtomicU64>,
    last_heartbeat: Option<Instant>,
    last_ack: &mut Instant,
    hb: &mut tokio::time::Interval,
    session_confirmed: &mut bool,
) {
    match message {
        // Binary header: seq (2, BE) + op (1) + MLS payload.
        Message::Binary(bytes) => {
            if bytes.len() >= 2 {
                // The wire sequence is 16-bit and wraps, so the latest value must win even when it
                // is numerically smaller than the previous one.
                *last_seq = u16::from_be_bytes([bytes[0], bytes[1]]) as u64;
            }
            forward_dave_binary(&bytes, dave_tx);
        }
        Message::Text(text) => {
            let Ok(value) = serde_json::from_str::<Value>(text.as_str()) else {
                return;
            };
            if let Some(seq) = value["seq"].as_u64() {
                *last_seq = seq;
            }
            let d = &value["d"];
            let Some(op) = value["op"].as_u64() else {
                return;
            };
            forward_dave_json(op, d, dave_tx);
            match op {
                // Op 4 `SESSION_DESCRIPTION`: a fresh session, so the reconnect budget is
                // restored. The transport key/mode can rotate on a repeated description, so the
                // send task has to rebuild its cipher instead of keeping the handshake's key.
                4 => {
                    *session_confirmed = true;
                    match session_description_event(d) {
                        Some(event) => {
                            let _ = dave_tx.send(event);
                        }
                        None => tracing::warn!(
                            "voice: session description without a usable mode or key"
                        ),
                    }
                    // The reference refreshes the speaking/SSRC mapping on every description.
                    reannounce.announce_if_speaking();
                }
                // Op 6 `HEARTBEAT_ACK`: record the round-trip since the last heartbeat as the ping.
                6 => {
                    *last_ack = Instant::now();
                    if let Some(sent) = last_heartbeat {
                        ping.store(sent.elapsed().as_millis() as u64, Ordering::Relaxed);
                    }
                }
                // Op 8 `HELLO`: the announced cadence can change on a repeated HELLO, so rebuild
                // the interval and give the new period a fresh ACK window.
                8 => {
                    if let Some(interval) = d["heartbeat_interval"].as_u64() {
                        *hb = heartbeat_interval(Duration::from_millis(interval));
                        *last_ack = Instant::now();
                    }
                }
                // Op 9 `RESUMED`: mark the session connected again and restore the reconnect budget.
                9 => {
                    tracing::info!("voice: gateway session resumed (RESUMED)");
                    state.store(ConnectionState::Connected as u8, Ordering::SeqCst);
                    *session_confirmed = true;
                }
                // Op 11 `CLIENT_CONNECT`: a batch of `user_ids` that joined. The voice gateway does
                // not carry their audio SSRCs here, so report 0.
                11 => {
                    if let Some(ids) = d["user_ids"].as_array() {
                        for user_id in ids.iter().filter_map(|v| v.as_str()) {
                            dispatcher.dispatch(VoiceEvent::UserConnected {
                                user_id: user_id.to_string(),
                                audio_ssrc: 0,
                            });
                        }
                    }
                }
                // Op 12 `VIDEO`: a single user's stream SSRCs changed (carries `user_id` +
                // `audio_ssrc`).
                12 => {
                    if let Some(user_id) = d["user_id"].as_str() {
                        dispatcher.dispatch(VoiceEvent::UserConnected {
                            user_id: user_id.to_string(),
                            audio_ssrc: d["audio_ssrc"].as_u64().unwrap_or(0) as u32,
                        });
                    }
                    // A user's stream changed: refresh our SSRC mapping, as the reference does.
                    reannounce.announce_if_speaking();
                }
                // Op 13 `CLIENT_DISCONNECT`.
                13 => {
                    if let Some(user_id) = d["user_id"].as_str() {
                        dispatcher.dispatch(VoiceEvent::UserDisconnected {
                            user_id: user_id.to_string(),
                        });
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
}

/// Build the event that carries a repeated `SESSION_DESCRIPTION`'s transport and DAVE settings.
/// `None` when the payload has no mode or no key, in which case the old cipher has to stay.
fn session_description_event(d: &Value) -> Option<DaveEvent> {
    let mode = d["mode"].as_str()?.to_string();
    let secret_key: Vec<u8> = d["secret_key"]
        .as_array()?
        .iter()
        .filter_map(|n| n.as_u64().map(|x| x as u8))
        .collect();
    if secret_key.is_empty() {
        return None;
    }
    Some(DaveEvent::SessionDescription {
        secret_key,
        mode,
        dave_protocol_version: d["dave_protocol_version"].as_u64().unwrap_or(0) as u16,
    })
}

/// Forward a binary MLS op (`[seq: u16 BE][op: u8][mls…]`) to the send task, which owns the DAVE
/// session. Also called during the handshake, since op 25 can precede `SESSION_DESCRIPTION`.
pub(super) fn forward_dave_binary(bytes: &[u8], dave_tx: &mpsc::UnboundedSender<DaveEvent>) {
    if bytes.len() < 3 {
        return;
    }
    let op = bytes[2];
    if matches!(
        op,
        OP_DAVE_MLS_EXTERNAL_SENDER
            | OP_DAVE_MLS_PROPOSALS
            | OP_DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION
            | OP_DAVE_MLS_WELCOME
    ) {
        let _ = dave_tx.send(DaveEvent::Binary {
            op,
            payload: bytes[3..].to_vec(),
        });
    }
}

/// Forward the DAVE-relevant JSON ops to the send task: the 11/13 roster (which MLS Add proposals
/// are validated against) and the 21/22/24 transition ops. Also shared with the handshake.
pub(super) fn forward_dave_json(op: u64, d: &Value, dave_tx: &mpsc::UnboundedSender<DaveEvent>) {
    match op {
        11 => {
            let user_ids: Vec<u64> = d["user_ids"]
                .as_array()
                .map(|ids| {
                    ids.iter()
                        .filter_map(|v| v.as_str()?.parse().ok())
                        .collect()
                })
                .unwrap_or_default();
            if !user_ids.is_empty() {
                let _ = dave_tx.send(DaveEvent::UsersConnected { user_ids });
            }
        }
        13 => {
            if let Some(user_id) = d["user_id"].as_str().and_then(|id| id.parse().ok()) {
                let _ = dave_tx.send(DaveEvent::UserDisconnected { user_id });
            }
        }
        21 => {
            let _ = dave_tx.send(DaveEvent::PrepareTransition {
                protocol_version: d["protocol_version"].as_u64().unwrap_or(0) as u16,
                transition_id: d["transition_id"].as_u64().unwrap_or(0),
            });
        }
        22 => {
            let _ = dave_tx.send(DaveEvent::ExecuteTransition {
                transition_id: d["transition_id"].as_u64().unwrap_or(0),
            });
        }
        24 => {
            let _ = dave_tx.send(DaveEvent::PrepareEpoch {
                protocol_version: d["protocol_version"].as_u64().unwrap_or(0) as u16,
                epoch: d["epoch"].as_u64().unwrap_or(0),
            });
        }
        _ => {}
    }
}

pub(super) async fn reconnect(url: &str) -> Result<(WsSink, WsSource), ConnectError> {
    let (ws, _response) = match timeout(HANDSHAKE_TIMEOUT, connect_async(url)).await {
        Ok(result) => result?,
        Err(_) => return Err("voice gateway reconnect timed out".into()),
    };
    Ok(ws.split())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use futures_util::StreamExt;
    use std::future::Future;
    use std::pin::Pin;

    /// A sink whose writes block after `free` frames, so a test can hold the writer mid-write.
    struct GatedSink {
        sent: mpsc::UnboundedSender<Message>,
        free: usize,
        written: usize,
        stall: Pin<Box<tokio::time::Sleep>>,
    }

    impl GatedSink {
        fn new(free: usize) -> (Self, mpsc::UnboundedReceiver<Message>) {
            let (sent, rx) = mpsc::unbounded_channel();
            (
                Self {
                    sent,
                    free,
                    written: 0,
                    stall: Box::pin(sleep(Duration::from_secs(3_600))),
                },
                rx,
            )
        }
    }

    impl futures_util::Sink<Message> for GatedSink {
        type Error = std::io::Error;

        fn poll_ready(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            if self.written >= self.free {
                return self.stall.as_mut().poll(cx).map(|_| Ok(()));
            }
            std::task::Poll::Ready(Ok(()))
        }

        fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.written += 1;
            self.sent
                .send(item)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed"))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    // Three successful reconnects in a row must not exhaust the budget.
    #[test]
    fn confirmed_reconnects_never_exhaust_the_budget() {
        let mut budget = ReconnectBudget::new();
        for _ in 0..3 {
            assert!(budget.can_attempt());
            budget.record_attempt();
            budget.confirm();
        }
        assert!(
            budget.can_attempt(),
            "a confirmed session restores the budget"
        );
        assert_eq!(budget.attempts(), 0);
    }

    #[test]
    fn unconfirmed_attempts_exhaust_the_budget() {
        let mut budget = ReconnectBudget::new();
        for _ in 0..MAX_RECONNECT_ATTEMPTS {
            assert!(budget.can_attempt());
            budget.record_attempt();
        }
        assert!(
            !budget.can_attempt(),
            "attempts without a confirmed session run out"
        );
    }

    // Op 4 and op 9 both confirm the session, which is what restores the budget.
    #[tokio::test]
    async fn session_description_and_resumed_confirm_the_session() {
        for op in [4u64, 9] {
            let (dave_tx, _dave_rx) = mpsc::unbounded_channel();
            let dispatcher = EventDispatcher::new();
            let (speak_tx, _speak_rx) = mpsc::unbounded_channel();
            let reannounce = SpeakingReannounce {
                ws_tx: speak_tx,
                speaking: Arc::new(AtomicBool::new(false)),
                ssrc: 0,
            };
            let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
            let ping = Arc::new(AtomicU64::new(0));
            let mut last_seq: u64 = 0;
            let mut last_ack = Instant::now();
            let mut hb = heartbeat_interval(Duration::from_millis(41_250));
            let mut confirmed = false;
            let payload = format!(r#"{{"op":{op},"d":{{}}}}"#);

            handle_inbound(
                Message::text(payload),
                &dave_tx,
                &dispatcher,
                &reannounce,
                &state,
                &mut last_seq,
                &ping,
                None,
                &mut last_ack,
                &mut hb,
                &mut confirmed,
            );

            assert!(confirmed, "op {op} must confirm the session");
        }
    }

    // HELLO can arrive mid-connection with a new interval; the reference rebuilds its fixed-rate
    // schedule from that point. The first beat of either schedule waits a full period.
    #[tokio::test]
    async fn hello_rearms_the_heartbeat_interval() {
        let (dave_tx, _dave_rx) = mpsc::unbounded_channel();
        let dispatcher = EventDispatcher::new();
        let (speak_tx, _speak_rx) = mpsc::unbounded_channel();
        let reannounce = SpeakingReannounce {
            ws_tx: speak_tx,
            speaking: Arc::new(AtomicBool::new(false)),
            ssrc: 0,
        };
        let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
        let ping = Arc::new(AtomicU64::new(0));
        let mut last_seq: u64 = 0;
        let mut last_ack = Instant::now();
        let mut hb = heartbeat_interval(Duration::from_millis(41_250));
        let mut confirmed = false;

        assert!(
            hb.tick().now_or_never().is_none(),
            "the first heartbeat must wait one full interval"
        );

        handle_inbound(
            Message::text(json!({"op": 8, "d": {"heartbeat_interval": 30_000}}).to_string()),
            &dave_tx,
            &dispatcher,
            &reannounce,
            &state,
            &mut last_seq,
            &ping,
            None,
            &mut last_ack,
            &mut hb,
            &mut confirmed,
        );

        assert_eq!(
            hb.period(),
            Duration::from_millis(30_000),
            "op 8 must replace the old heartbeat interval"
        );
        assert!(
            hb.tick().now_or_never().is_none(),
            "the re-armed heartbeat must also wait one full interval"
        );
    }

    // A repeated op 4 rotates the transport key/mode and the DAVE version. Without forwarding it,
    // the send task keeps encrypting with the stale key and Discord drops every frame.
    #[tokio::test]
    async fn a_repeated_session_description_forwards_the_new_cipher() {
        let (dave_tx, mut dave_rx) = mpsc::unbounded_channel();
        let dispatcher = EventDispatcher::new();
        let (speak_tx, _speak_rx) = mpsc::unbounded_channel();
        let reannounce = SpeakingReannounce {
            ws_tx: speak_tx,
            speaking: Arc::new(AtomicBool::new(false)),
            ssrc: 0,
        };
        let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
        let ping = Arc::new(AtomicU64::new(0));
        let mut last_seq: u64 = 0;
        let mut last_ack = Instant::now();
        let mut hb = heartbeat_interval(Duration::from_millis(41_250));
        let mut confirmed = false;
        let payload = json!({
            "op": 4,
            "d": {
                "mode": "aead_aes256_gcm_rtpsize",
                "secret_key": vec![7u8; 32],
                "dave_protocol_version": 1,
            }
        })
        .to_string();

        handle_inbound(
            Message::text(payload),
            &dave_tx,
            &dispatcher,
            &reannounce,
            &state,
            &mut last_seq,
            &ping,
            None,
            &mut last_ack,
            &mut hb,
            &mut confirmed,
        );

        assert!(confirmed, "op 4 still confirms the session");
        match dave_rx.try_recv() {
            Ok(DaveEvent::SessionDescription {
                secret_key,
                mode,
                dave_protocol_version,
            }) => {
                assert_eq!(secret_key, vec![7u8; 32]);
                assert_eq!(mode, "aead_aes256_gcm_rtpsize");
                assert_eq!(dave_protocol_version, 1);
            }
            other => panic!("expected a session-description event, got {other:?}"),
        }
    }

    // The inbound sequence is 16-bit and wraps; acking the maximum would pin seq_ack at 65535.
    #[tokio::test]
    async fn sequence_tracks_the_latest_value_across_a_wrap() {
        let (dave_tx, _dave_rx) = mpsc::unbounded_channel();
        let dispatcher = EventDispatcher::new();
        let (speak_tx, _speak_rx) = mpsc::unbounded_channel();
        let reannounce = SpeakingReannounce {
            ws_tx: speak_tx,
            speaking: Arc::new(AtomicBool::new(false)),
            ssrc: 0,
        };
        let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
        let ping = Arc::new(AtomicU64::new(0));
        let mut last_seq: u64 = 0;
        let mut last_ack = Instant::now();
        let mut hb = heartbeat_interval(Duration::from_millis(41_250));
        let mut confirmed = false;

        for seq in [65_535u16, 1] {
            handle_inbound(
                Message::Binary(bytes::Bytes::from(vec![(seq >> 8) as u8, seq as u8, 0])),
                &dave_tx,
                &dispatcher,
                &reannounce,
                &state,
                &mut last_seq,
                &ping,
                None,
                &mut last_ack,
                &mut hb,
                &mut confirmed,
            );
        }
        assert_eq!(last_seq, 1, "the latest sequence must win after a wrap");

        let value: serde_json::Value = serde_json::from_str(
            heartbeat_message(1_700_000_000_000, last_seq)
                .into_text()
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(value["d"]["seq_ack"], 1);
        assert_eq!(value["d"]["t"], 1_700_000_000_000u64);

        let resume = ResumeInfo {
            url: "wss://x/?v=8".into(),
            server_id: 9,
            session_id: "sid".into(),
            token: "tok".into(),
        };
        let value: serde_json::Value = serde_json::from_str(
            resume_message(&resume, last_seq)
                .into_text()
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(value["d"]["seq_ack"], 1);
    }

    #[test]
    fn abnormal_drops_report_1006_abnormal_closure() {
        match closed_event(None, String::new(), false) {
            VoiceEvent::GatewayClosed {
                code,
                reason,
                by_remote,
            } => {
                assert_eq!(code, 1006);
                assert_eq!(reason, "Abnormal closure");
                assert!(!by_remote);
            }
            other => panic!("expected a gateway close, got {other:?}"),
        }
    }

    #[test]
    fn explicit_closes_keep_their_code_and_reason() {
        match closed_event(Some(4009), "heartbeat lapse".into(), true) {
            VoiceEvent::GatewayClosed {
                code,
                reason,
                by_remote,
            } => {
                assert_eq!(code, 4009);
                assert_eq!(reason, "heartbeat lapse");
                assert!(by_remote);
            }
            other => panic!("expected a gateway close, got {other:?}"),
        }
        match closed_event(None, "outbound send failed".into(), false) {
            VoiceEvent::GatewayClosed { code, reason, .. } => {
                assert_eq!(code, 1006);
                assert_eq!(reason, "outbound send failed");
            }
            other => panic!("expected a gateway close, got {other:?}"),
        }
    }

    // A blocked socket write must not stop inbound ops from being handled: the writer is stuck on
    // its first frame while op 9 lands and flips the state back to Connected.
    #[tokio::test]
    async fn a_blocked_write_does_not_stop_inbound_reads() {
        let (sink, mut written) = GatedSink::new(0);
        let stream = futures_util::stream::once(async {
            sleep(Duration::from_millis(5)).await;
            Ok::<_, std::io::Error>(Message::text(json!({"op": 9, "d": {}}).to_string()))
        })
        .chain(futures_util::stream::pending::<
            Result<Message, std::io::Error>,
        >())
        .boxed();

        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel();
        ws_tx.send(Message::text("outbound")).unwrap();

        let (dave_tx, _dave_rx) = mpsc::unbounded_channel();
        let dispatcher = EventDispatcher::new();
        let (speak_tx, _speak_rx) = mpsc::unbounded_channel();
        let reannounce = SpeakingReannounce {
            ws_tx: speak_tx,
            speaking: Arc::new(AtomicBool::new(false)),
            ssrc: 0,
        };
        let state = Arc::new(AtomicU8::new(ConnectionState::Reconnecting as u8));
        let ping = Arc::new(AtomicU64::new(0));

        let task = tokio::spawn({
            let state = state.clone();
            let ping = ping.clone();
            async move {
                let mut last_seq = 0;
                let mut hb = heartbeat_interval(Duration::from_millis(41_250));
                let mut confirmed = false;
                pump(
                    sink,
                    stream,
                    &mut ws_rx,
                    &dave_tx,
                    &dispatcher,
                    &reannounce,
                    &mut hb,
                    &mut last_seq,
                    &ping,
                    &state,
                    &mut confirmed,
                )
                .await
            }
        });

        sleep(Duration::from_millis(50)).await;
        assert_eq!(
            state.load(Ordering::SeqCst),
            ConnectionState::Connected as u8,
            "inbound op 9 must be handled while the writer is blocked"
        );
        assert!(
            written.try_recv().is_err(),
            "the gated sink must not have accepted a write"
        );

        drop(ws_tx);
        let outcome = timeout(Duration::from_secs(2), task)
            .await
            .expect("pump stops after the outbound channel closes")
            .expect("pump task");
        assert!(matches!(outcome, PumpOutcome::Stop));
    }

    // A write that never completes must fail at the write deadline instead of pinning the writer.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_write_times_out() {
        let (sink, _written) = GatedSink::new(0);
        let (write_tx, write_rx) = mpsc::channel(1);
        let (failed_tx, mut failed_rx) = mpsc::unbounded_channel();
        write_tx.send(Message::text("stuck")).await.unwrap();
        let task = tokio::spawn(writer_task(sink, write_rx, failed_tx));

        tokio::time::advance(WRITE_TIMEOUT + Duration::from_millis(1)).await;
        let reason = failed_rx.recv().await.expect("a failure is reported");
        assert_eq!(reason, "outbound send timed out");
        task.await.unwrap();
    }

    // If the gateway stops reading, the bounded queue fills and the session closes rather than
    // buffering every frame while the writer is stuck.
    #[tokio::test]
    async fn a_full_write_queue_closes_without_waiting() {
        let (sink, _written) = GatedSink::new(0);
        let stream = futures_util::stream::pending::<Result<Message, std::io::Error>>();
        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel();
        for _ in 0..WRITE_QUEUE_LEN + 2 {
            ws_tx.send(Message::text("frame")).unwrap();
        }

        let (dave_tx, _dave_rx) = mpsc::unbounded_channel();
        let dispatcher = EventDispatcher::new();
        let (speak_tx, _speak_rx) = mpsc::unbounded_channel();
        let reannounce = SpeakingReannounce {
            ws_tx: speak_tx,
            speaking: Arc::new(AtomicBool::new(false)),
            ssrc: 0,
        };
        let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
        let ping = Arc::new(AtomicU64::new(0));
        let mut last_seq = 0u64;
        let mut confirmed = false;
        let mut hb = heartbeat_interval(Duration::from_millis(41_250));

        let outcome = timeout(
            Duration::from_secs(2),
            pump(
                sink,
                stream,
                &mut ws_rx,
                &dave_tx,
                &dispatcher,
                &reannounce,
                &mut hb,
                &mut last_seq,
                &ping,
                &state,
                &mut confirmed,
            ),
        )
        .await
        .expect("a full queue must close without waiting for the stalled write");

        match outcome {
            PumpOutcome::Closed { reason, .. } => {
                assert_eq!(reason, "outbound queue full");
            }
            other => panic!("expected a closed gateway, got {other:?}"),
        }
    }

    // The reference re-announces speaking on a user's stream change (op 12) and on a session
    // description, but not on CLIENT_CONNECT (op 11).
    #[tokio::test]
    async fn speaking_is_reannounced_on_stream_changes_and_descriptions() {
        let (dave_tx, _dave_rx) = mpsc::unbounded_channel();
        let dispatcher = EventDispatcher::new();
        let (speak_tx, mut speak_rx) = mpsc::unbounded_channel();
        let reannounce = SpeakingReannounce {
            ws_tx: speak_tx,
            speaking: Arc::new(AtomicBool::new(true)),
            ssrc: 77,
        };
        let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
        let ping = Arc::new(AtomicU64::new(0));
        let mut last_seq = 0u64;
        let mut last_ack = Instant::now();
        let mut hb = heartbeat_interval(Duration::from_millis(41_250));
        let mut confirmed = false;

        let mut inbound = |payload: Value| {
            handle_inbound(
                Message::text(payload.to_string()),
                &dave_tx,
                &dispatcher,
                &reannounce,
                &state,
                &mut last_seq,
                &ping,
                None,
                &mut last_ack,
                &mut hb,
                &mut confirmed,
            );
        };

        inbound(json!({"op": 11, "d": {"user_ids": ["1"]}}));
        assert!(
            speak_rx.try_recv().is_err(),
            "op 11 must not re-announce speaking"
        );

        inbound(json!({"op": 12, "d": {"user_id": "1", "audio_ssrc": 5}}));
        let message = speak_rx.try_recv().expect("op 12 re-announces speaking");
        let value: Value = serde_json::from_str(message.into_text().unwrap().as_str()).unwrap();
        assert_eq!(value["op"], 5);
        assert_eq!(value["d"]["speaking"], 1);
        assert_eq!(value["d"]["ssrc"], 77);

        inbound(json!({"op": 4, "d": {}}));
        let message = speak_rx
            .try_recv()
            .expect("a session description re-announces speaking");
        let value: Value = serde_json::from_str(message.into_text().unwrap().as_str()).unwrap();
        assert_eq!(value["op"], 5);
    }
}
