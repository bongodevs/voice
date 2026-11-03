use super::builders::{dave_binary, transition_ready_message};
use super::*;
use crate::dave::davey::errors::ProcessCommitError;

/// Apply one DAVE event to the session and emit any required gateway response.
pub(super) fn handle_dave_event(
    dave: &mut DaveEncryptor,
    pending: &mut HashMap<u64, u16>,
    roster: &mut HashSet<u64>,
    event: DaveEvent,
    ws_tx: &mpsc::UnboundedSender<Message>,
) {
    match event {
        DaveEvent::Binary { op, payload } => {
            handle_dave_binary(dave, roster, op, &payload, ws_tx);
        }
        // The roster of users the gateway has announced, which MLS Add proposals are validated
        // against.
        DaveEvent::UsersConnected { user_ids } => roster.extend(user_ids),
        DaveEvent::UserDisconnected { user_id } => {
            roster.remove(&user_id);
        }
        // A repeated op 4 replaces the encryption session. Rebuilding the MLS session here is what
        // the reference does; our key package has to go out for the new group.
        DaveEvent::SessionDescription {
            dave_protocol_version,
            ..
        } => match dave.reinit_with_version(dave_protocol_version) {
            Ok(()) => {
                tracing::info!(
                    dave_protocol_version,
                    "DAVE: new session description applied"
                );
                if dave_protocol_version > 0 {
                    send_key_package(dave, ws_tx);
                }
            }
            Err(error) => tracing::warn!(
                %error,
                dave_protocol_version,
                "DAVE: failed to apply a new session description"
            ),
        },
        DaveEvent::PrepareTransition {
            protocol_version,
            transition_id,
        } => {
            pending.insert(transition_id, protocol_version);
            // Transition 0 is the initial handshake and is not acknowledged.
            if transition_id != 0 {
                let _ = ws_tx.send(transition_ready_message(transition_id));
            }
        }
        DaveEvent::ExecuteTransition { transition_id } => {
            // A v0 downgrade tears the group down; an upgrade already installed the new epoch's
            // ratchet in `process_commit`.
            if pending.remove(&transition_id) == Some(0) {
                dave.reset();
            }
        }
        DaveEvent::PrepareEpoch {
            protocol_version,
            epoch,
        } => {
            tracing::debug!(protocol_version, epoch, "DAVE prepare epoch");
            // Epoch 1 means a fresh MLS group, so reinit first: otherwise davey rejects its
            // proposals with `Wrong Epoch` / `AlreadyInGroup` and every frame fails to encrypt.
            if epoch == 1 {
                if let Err(error) = dave.reinit() {
                    tracing::warn!(%error, "DAVE: failed to reinit session for new epoch");
                }
                send_key_package(dave, ws_tx);
            }
        }
    }
}

/// Create a fresh MLS key package and queue it as op 26. Sent on `SESSION_DESCRIPTION` and again
/// on an op-24 prepare-epoch; davey builds a new single-use package per call.
pub(super) fn send_key_package(dave: &mut DaveEncryptor, ws_tx: &mpsc::UnboundedSender<Message>) {
    match dave.session_mut().create_key_package() {
        Ok(key_package) => {
            tracing::debug!("DAVE: sending key package");
            let _ = ws_tx.send(dave_binary(OP_DAVE_MLS_KEY_PACKAGE, &key_package));
        }
        Err(error) => tracing::warn!(%error, "DAVE: failed to create key package"),
    }
}

/// Apply one inbound binary MLS op, sending any gateway response via `ws_tx`. Per-op framing (the
/// op-27 operation type, the op-29/30 transition id) is stripped before davey sees the MLS bytes.
pub(super) fn handle_dave_binary(
    dave: &mut DaveEncryptor,
    roster: &HashSet<u64>,
    op: u8,
    payload: &[u8],
    ws_tx: &mpsc::UnboundedSender<Message>,
) {
    match op {
        OP_DAVE_MLS_EXTERNAL_SENDER => {
            // Only the external sender is set here. The key package goes out on
            // `SESSION_DESCRIPTION` and on op-24 prepare-epoch, not in response to op 25.
            match dave.session_mut().set_external_sender(payload) {
                Ok(()) => tracing::debug!("DAVE: external sender set"),
                Err(error) => tracing::warn!(%error, "DAVE: failed to set external sender"),
            }
        }
        OP_DAVE_MLS_PROPOSALS => {
            let Some((operation_type, proposals)) = split_proposals(payload) else {
                return;
            };
            // davey needs the recognized-user roster to run its `UnexpectedUser` check; `None`
            // skips it and lets an id the gateway never announced into the group.
            let expected = expected_user_ids(roster, dave.session().user_id());
            match dave
                .session_mut()
                .process_proposals(operation_type, proposals, Some(&expected))
            {
                Ok(Some(commit_welcome)) => {
                    let mut out = commit_welcome.commit;
                    if let Some(welcome) = commit_welcome.welcome {
                        out.extend_from_slice(&welcome);
                    }
                    tracing::debug!(
                        ?operation_type,
                        "DAVE: proposals processed, sending commit/welcome"
                    );
                    let _ = ws_tx.send(dave_binary(OP_DAVE_MLS_COMMIT_WELCOME, &out));
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, "DAVE: failed to process proposals");
                }
            }
        }
        OP_DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION => {
            let Some((transition_id, commit)) = strip_transition_id(payload) else {
                return;
            };
            match dave.session_mut().process_commit(commit) {
                Ok(()) => {
                    tracing::debug!(transition_id, "DAVE: commit processed");
                    send_transition_ready(transition_id, ws_tx);
                }
                // A commit that lands before our own join finishes (`PendingGroup`, `NoGroup`) is a
                // routine broadcast; treating it as invalid loops op 31 and leaves us in plaintext.
                Err(error @ (ProcessCommitError::NoGroup | ProcessCommitError::PendingGroup)) => {
                    tracing::debug!(transition_id, %error, "DAVE: commit ignored");
                }
                Err(error) => {
                    tracing::warn!(transition_id, %error, "DAVE: invalid commit, requesting re-add");
                    recover_from_invalid(dave, transition_id, ws_tx);
                }
            }
        }
        OP_DAVE_MLS_WELCOME => {
            let Some((transition_id, welcome)) = strip_transition_id(payload) else {
                return;
            };
            match dave.session_mut().process_welcome(welcome) {
                Ok(()) => {
                    tracing::debug!(transition_id, "DAVE: welcome processed, group active");
                    send_transition_ready(transition_id, ws_tx);
                }
                // No reinit here: a duplicate welcome fails with `AlreadyInGroup`, and resetting
                // would tear down the group we are already encrypting with.
                Err(error) => {
                    tracing::warn!(transition_id, %error, "DAVE: invalid welcome, requesting re-add");
                    let _ = ws_tx.send(invalid_commit_welcome_message(transition_id));
                    send_key_package(dave, ws_tx);
                }
            }
        }
        _ => {}
    }
}

/// Ack an applied commit or welcome so the gateway can complete the transition for the whole
/// channel. Transition 0 is the initial handshake and is never acked.
fn send_transition_ready(transition_id: u16, ws_tx: &mpsc::UnboundedSender<Message>) {
    if transition_id != 0 {
        let _ = ws_tx.send(transition_ready_message(transition_id as u64));
    }
}

/// Report a bad commit (op 31), reinit, and re-send our key package so the gateway re-adds us.
/// Without the reinit davey would reject the next welcome with `AlreadyInGroup`.
pub(super) fn recover_from_invalid(
    dave: &mut DaveEncryptor,
    transition_id: u16,
    ws_tx: &mpsc::UnboundedSender<Message>,
) {
    let _ = ws_tx.send(invalid_commit_welcome_message(transition_id));
    if let Err(error) = dave.reinit() {
        tracing::warn!(%error, "DAVE: failed to reinit after invalid commit/welcome");
    }
    send_key_package(dave, ws_tx);
}

/// The recognized-user roster plus our own id (we are always a legitimate member of our own group).
fn expected_user_ids(roster: &HashSet<u64>, self_user_id: u64) -> Vec<u64> {
    let mut ids = Vec::with_capacity(roster.len() + 1);
    ids.extend(roster.iter().copied());
    ids.push(self_user_id);
    ids
}

/// Split an op-27 payload into its operation type and the raw MLS proposals:
/// `[operation_type: u8][proposals…]`. `None` if it is empty or the type is unknown.
pub(super) fn split_proposals(payload: &[u8]) -> Option<(ProposalsOperationType, &[u8])> {
    let (&optype, proposals) = payload.split_first()?;
    let operation_type = match optype {
        0 => ProposalsOperationType::APPEND,
        1 => ProposalsOperationType::REVOKE,
        other => {
            tracing::warn!(
                operation_type = other,
                "DAVE: unknown proposals operation type"
            );
            return None;
        }
    };
    Some((operation_type, proposals))
}

/// Split an op-29 or op-30 payload into its 2-byte big-endian `transition_id` and the trailing MLS
/// commit or welcome bytes.
pub(super) fn strip_transition_id(payload: &[u8]) -> Option<(u16, &[u8])> {
    let (id_bytes, mls) = payload.split_at_checked(2)?;
    Some((u16::from_be_bytes([id_bytes[0], id_bytes[1]]), mls))
}

/// Op 31 `dave_mls_invalid_commit_welcome`: a JSON (not binary) message naming the transition whose
/// commit or welcome we could not process, asking the gateway to re-add us.
pub(super) fn invalid_commit_welcome_message(transition_id: u16) -> Message {
    Message::text(
        json!({
            "op": OP_DAVE_MLS_INVALID_COMMIT_WELCOME,
            "d": { "transition_id": transition_id }
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roster_tracks_gateway_users_and_always_expects_self() {
        let mut dave = DaveEncryptor::new(7, 9).expect("create session");
        let mut pending = HashMap::new();
        let mut roster = HashSet::new();
        let (ws_tx, _ws_rx) = mpsc::unbounded_channel();

        for event in [
            DaveEvent::UsersConnected {
                user_ids: vec![1, 2],
            },
            DaveEvent::UserDisconnected { user_id: 1 },
        ] {
            handle_dave_event(&mut dave, &mut pending, &mut roster, event, &ws_tx);
        }
        assert_eq!(roster, HashSet::from([2]));

        let mut expected = expected_user_ids(&roster, dave.session().user_id());
        expected.sort_unstable();
        assert_eq!(expected, vec![2, 7], "roster plus self");
    }
}
