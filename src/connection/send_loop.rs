use super::builders::speaking_message;
use super::dave::handle_dave_event;
use super::*;
use crate::frame::FRAME_DURATION;

// A stage that takes longer than one slot is what makes the frame clock report a stall, so the two
// stages that run on this task say which one did it. Payload bytes are never logged.
fn dave_event_label(event: &DaveEvent) -> &'static str {
    match event {
        DaveEvent::Binary { .. } => "mls",
        DaveEvent::PrepareTransition { .. } => "prepare-transition",
        DaveEvent::ExecuteTransition { .. } => "execute-transition",
        DaveEvent::PrepareEpoch { .. } => "prepare-epoch",
        DaveEvent::UsersConnected { .. } => "users-connected",
        DaveEvent::UserDisconnected { .. } => "user-disconnected",
        DaveEvent::SessionDescription { .. } => "session-description",
    }
}

/// The 20 ms send task, pacing frames through the [`FramePacer`] and applying DAVE MLS messages.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_loop<P>(
    provider: P,
    udp: VoiceUdp,
    dave: DaveEncryptor,
    transport: Box<dyn crate::transport::TransportCipher>,
    ssrc: u32,
    dave_enabled: bool,
    ws_tx: mpsc::UnboundedSender<Message>,
    mut dave_rx: mpsc::UnboundedReceiver<DaveEvent>,
    dispatcher: EventDispatcher,
    speaking_flag: Arc<AtomicBool>,
    state: Arc<AtomicU8>,
) where
    P: OpusFrameProvider,
{
    let speaking_tx = ws_tx.clone();
    let mut pacer = FramePacer::with_transport(provider, udp, dave, transport, ssrc);
    pacer.set_dave_enabled(dave_enabled);
    pacer.on_speaking(move |speaking| {
        // Keep the shared flag in sync so the gateway task can re-announce it on op 11/12.
        speaking_flag.store(speaking, Ordering::Relaxed);
        let _ = speaking_tx.send(speaking_message(speaking, ssrc));
    });

    // Pending protocol-version transitions, keyed by transition id (set on prepare, applied on
    // execute).
    let mut pending: HashMap<u64, u16> = HashMap::new();
    // Users the gateway announced via op 11/13, used to validate MLS Add proposals.
    let mut roster: HashSet<u64> = HashSet::new();
    let mut dave_open = true;
    let mut was_ready = pacer.dave_mut().is_ready();

    // Absolute per-slot deadlines, so a late tick is caught up instead of accumulating.
    let mut clock = FrameClock::new();

    // Transient UDP failures shouldn't tear down the connection, so drop the frame and keep going.
    // Give up after ~1 s of it, so a genuinely dead socket still lets the gateway reconnect.
    let mut consecutive_send_errors: u32 = 0;
    const MAX_CONSECUTIVE_SEND_ERRORS: u32 = 50;

    loop {
        // UDP sends keep succeeding after a fatal gateway close, so without this the pacer would
        // tick and send RTP forever, leaking a 50 fps task.
        if ConnectionState::from_u8(state.load(Ordering::SeqCst)) == ConnectionState::Closed {
            break;
        }
        tokio::select! {
            missed = clock.wait() => {
                let started = Instant::now();
                let outcome = pacer.tick().await;
                let tick = started.elapsed();
                if tick > FRAME_DURATION {
                    tracing::warn!(
                        tick_micros = tick.as_micros() as u64,
                        missed,
                        dropped = clock.dropped_frames(),
                        "voice: send tick overran its frame slot"
                    );
                }
                match outcome {
                    Ok(_) => consecutive_send_errors = 0,
                    Err(error) => {
                        consecutive_send_errors += 1;
                        tracing::warn!(
                            %error,
                            consecutive = consecutive_send_errors,
                            "voice: frame send failed; dropping frame"
                        );
                        if consecutive_send_errors >= MAX_CONSECUTIVE_SEND_ERRORS {
                            tracing::warn!(
                                "voice: too many consecutive send failures, stopping send loop"
                            );
                            // Mark closed before reporting, so the supervisor neither resumes nor
                            // double-reports, then close the gateway so its task stops too.
                            state.store(ConnectionState::Closed as u8, Ordering::SeqCst);
                            dispatcher.dispatch(VoiceEvent::GatewayClosed {
                                code: 4900,
                                reason: "udp send failed".into(),
                                by_remote: false,
                            });
                            let _ = ws_tx.send(close_message());
                            break;
                        }
                    }
                }
            }
            event = dave_rx.recv(), if dave_open => {
                match event {
                    Some(event) => {
                        let label = dave_event_label(&event);
                        let started = Instant::now();
                        // A repeated SESSION_DESCRIPTION rotates the transport key and mode. Build
                        // the new cipher before the next frame; the old key would make Discord
                        // drop every packet it cannot decrypt.
                        if let DaveEvent::SessionDescription {
                            secret_key, mode, ..
                        } = &event
                        {
                            match cipher_for_mode(mode, secret_key) {
                                Ok(cipher) => {
                                    pacer.set_transport(cipher);
                                    tracing::info!(%mode, "voice: transport cipher replaced");
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        %error,
                                        "voice: session description has no usable cipher"
                                    );
                                    // Cannot encrypt for the server, so end this connection and let
                                    // the higher layer rebuild the voice state.
                                    state.store(ConnectionState::Closed as u8, Ordering::SeqCst);
                                    dispatcher.dispatch(VoiceEvent::GatewayClosed {
                                        code: 4900,
                                        reason: "unsupported transport mode".into(),
                                        by_remote: false,
                                    });
                                    let _ = ws_tx.send(close_message());
                                    break;
                                }
                            }
                        }
                        handle_dave_event(
                            pacer.dave_mut(),
                            &mut pending,
                            &mut roster,
                            event,
                            &ws_tx,
                        );
                        let took = started.elapsed();
                        if took > FRAME_DURATION {
                            tracing::warn!(
                                event = label,
                                dave_micros = took.as_micros() as u64,
                                dropped = clock.dropped_frames(),
                                "voice: DAVE handling overran a frame slot"
                            );
                        }
                        // The group flipping to active means end-to-end encryption is on, so
                        // announce it once with the privacy code.
                        let ready = pacer.dave_mut().is_ready();
                        if ready && !was_ready {
                            let privacy_code =
                                pacer.dave_mut().voice_privacy_code().map(str::to_owned);
                            tracing::info!(
                                privacy_code = privacy_code.as_deref(),
                                "voice: DAVE end-to-end encryption active"
                            );
                            dispatcher.dispatch(VoiceEvent::DaveSessionReady { privacy_code });
                        }
                        was_ready = ready;
                    }
                    None => dave_open = false,
                }
            }
        }
    }
}
