//! The 20 ms frame pacer: pull a frame, DAVE-encrypt it, transport-encrypt it, RTP-frame it, send.
//! With nothing to send it drains [`SILENCE_FRAME_COUNT`] silence frames, then goes idle.

use std::io;

use tokio::time::{sleep_until, Instant};

use crate::dave::DaveEncryptor;
use crate::frame::{FRAME_DURATION, OPUS_SILENCE_FRAME, SAMPLES_PER_FRAME, SILENCE_FRAME_COUNT};
use crate::provider::OpusFrameProvider;
use crate::rtp::{RtpHeader, RTP_HEADER_LEN};
use crate::sink::FrameSink;
use crate::transport::{PlainTransport, TransportCipher};

/// Reused buffer size: header + worst-case DAVE/Opus payload + tag + suffix, under one MTU.
const MAX_PACKET_BYTES: usize = 1400;

/// Past three missed slots the clock stops trying to catch up and resynchronises to now, so a long
/// stall doesn't produce a burst of stale frames.
const MAX_CATCHUP_FRAMES: u64 = 3;

/// The 20 ms frame clock. Slot deadlines are absolute, so a tick that runs late is followed
/// immediately by the next one and lateness never accumulates against Discord's RTP timeline.
pub struct FrameClock {
    next: Instant,
    dropped: u64,
}

impl Default for FrameClock {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameClock {
    /// Start the clock, with the first slot one frame from now.
    pub fn new() -> Self {
        Self {
            next: Instant::now() + FRAME_DURATION,
            dropped: 0,
        }
    }

    /// Wait for the next frame slot, returning how many slots were missed (`0` when on time).
    /// Cancel-safe: the deadline only advances after the sleep, so losing a `select!` race is free.
    pub async fn wait(&mut self) -> u64 {
        let now = Instant::now();
        if now < self.next {
            sleep_until(self.next).await;
            self.next += FRAME_DURATION;
            return 0;
        }

        // Late by truncating division, so being late by less than one whole slot misses nothing and
        // simply runs now.
        let missed = ((now - self.next).as_nanos() / FRAME_DURATION.as_nanos()) as u64;
        self.next = if missed > MAX_CATCHUP_FRAMES {
            tracing::warn!(missed, "voice: frame clock stalled, resynchronising");
            now + FRAME_DURATION
        } else {
            self.next + FRAME_DURATION
        };
        self.dropped = self.dropped.saturating_add(missed);
        missed
    }

    /// Frame slots missed because a tick ran late.
    pub fn dropped_frames(&self) -> u64 {
        self.dropped
    }
}

/// What a single [`FramePacer::tick`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacerStatus {
    /// An audio frame was processed: sent, or dropped because DAVE encryption failed.
    Sent,
    /// A silence frame was sent (draining after audio stopped).
    Silence,
    /// Nothing was sent (no audio and silence already drained).
    Idle,
}

/// Drives an [`OpusFrameProvider`] at a steady 20 ms cadence into a [`FrameSink`], applying DAVE
/// end-to-end encryption and then the transport cipher to every frame.
pub struct FramePacer<P: OpusFrameProvider, S: FrameSink> {
    provider: P,
    sink: S,
    dave: DaveEncryptor,
    transport: Box<dyn TransportCipher>,
    header: RtpHeader,
    /// Reused packet buffer: RTP header + payload, encrypted in place with the tag and nonce
    /// suffix appended. Sized once so the steady-state send path never allocates.
    packet: Vec<u8>,
    silence_left: u8,
    speaking: bool,
    on_speaking: Option<Box<dyn FnMut(bool) + Send>>,
}

impl<P: OpusFrameProvider, S: FrameSink> FramePacer<P, S> {
    /// Create a pacer with no transport encryption, for local testing only. Discord rejects
    /// unencrypted packets, so a real connection needs [`with_transport`](Self::with_transport).
    pub fn new(provider: P, sink: S, dave: DaveEncryptor, ssrc: u32) -> Self {
        Self::with_transport(provider, sink, dave, Box::new(PlainTransport), ssrc)
    }

    /// Create a pacer with the negotiated `transport` cipher, for the given SSRC (assigned by
    /// Discord in the voice `READY` payload).
    pub fn with_transport(
        provider: P,
        sink: S,
        dave: DaveEncryptor,
        transport: Box<dyn TransportCipher>,
        ssrc: u32,
    ) -> Self {
        Self {
            provider,
            sink,
            dave,
            transport,
            header: RtpHeader::new(ssrc),
            packet: Vec::with_capacity(MAX_PACKET_BYTES),
            silence_left: 0,
            speaking: false,
            on_speaking: None,
        }
    }

    /// Replace the transport cipher, e.g. after a repeated `SESSION_DESCRIPTION` rotates the key.
    /// The RTP sequence and timestamp keep running; only the transport key/mode changes.
    pub fn set_transport(&mut self, transport: Box<dyn TransportCipher>) {
        self.transport = transport;
    }

    /// Register a callback invoked when the speaking state changes (send a gateway `SPEAKING`
    /// op from here in a real connection).
    pub fn on_speaking(&mut self, handler: impl FnMut(bool) + Send + 'static) {
        self.on_speaking = Some(Box::new(handler));
    }

    /// Whether the pacer currently considers itself speaking.
    pub fn is_speaking(&self) -> bool {
        self.speaking
    }

    /// Access the DAVE encryptor (e.g. to drive the MLS handshake).
    pub fn dave_mut(&mut self) -> &mut DaveEncryptor {
        &mut self.dave
    }

    /// Process exactly one frame slot (no internal sleep). Callers that want to control timing
    /// themselves can drive this; most should use [`run`](Self::run).
    pub async fn tick(&mut self) -> io::Result<PacerStatus> {
        if let Some(frame) = self.provider.provide() {
            self.set_speaking(true);
            self.silence_left = SILENCE_FRAME_COUNT;
            // `false` => active-group encryption failed; drop the frame rather than leak plaintext.
            if self.build_packet(&frame) {
                self.send().await?;
            } else {
                // Dropped frames still occupy their 20 ms slot: keep the RTP clock on wall time.
                self.header.advance_timestamp(SAMPLES_PER_FRAME);
            }
            Ok(PacerStatus::Sent)
        } else if self.silence_left > 0 {
            // Stop speaking as soon as the silence flush begins; the change-detection in
            // `set_speaking` makes this fire once.
            self.set_speaking(false);
            self.silence_left -= 1;
            if self.build_packet(&OPUS_SILENCE_FRAME) {
                self.send().await?;
            } else {
                // Dropped frames still occupy their 20 ms slot: keep the RTP clock on wall time.
                self.header.advance_timestamp(SAMPLES_PER_FRAME);
            }
            Ok(PacerStatus::Silence)
        } else {
            self.set_speaking(false);
            Ok(PacerStatus::Idle)
        }
    }

    /// Self-paced loop: ticks every 20 ms forever. Spawn this as a task and drop/abort it to
    /// stop. Returns only on a sink I/O error.
    pub async fn run(&mut self) -> io::Result<()> {
        let mut clock = FrameClock::new();
        loop {
            clock.wait().await;
            self.tick().await?;
        }
    }

    /// Write the RTP header and the DAVE-processed frame into the reused packet buffer.
    /// `false` => active-group encryption failed and the frame must be dropped.
    fn build_packet(&mut self, frame: &[u8]) -> bool {
        self.packet.clear();
        self.packet.extend_from_slice(&self.header.to_bytes());
        // Disjoint field borrows: DAVE appends straight into the packet, so the payload is never
        // materialised as its own buffer.
        self.dave.encrypt_into(frame, &mut self.packet)
    }

    /// Transport-encrypt and send the packet built by [`build_packet`](Self::build_packet).
    /// Encrypted in place, so a steady-state frame costs zero allocations.
    async fn send(&mut self) -> io::Result<()> {
        // Drop the frame on an AEAD failure: sending the plaintext would leak audio, and this runs
        // on a shared runtime worker where a panic would take unrelated connections down with it.
        if let Err(cause) = self
            .transport
            .encrypt_in_place(&mut self.packet, RTP_HEADER_LEN)
        {
            tracing::warn!(cause, "voice: transport encryption failed, dropping frame");
        } else {
            self.sink.send(&self.packet).await?;
        }

        self.header.sequence = self.header.sequence.wrapping_add(1);
        self.header.timestamp = self.header.timestamp.wrapping_add(SAMPLES_PER_FRAME);
        Ok(())
    }

    fn set_speaking(&mut self, speaking: bool) {
        if self.speaking != speaking {
            self.speaking = speaking;
            if let Some(handler) = self.on_speaking.as_mut() {
                handler(speaking);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::VecSink;
    use crate::transport::AesGcmRtpSize;

    // A repeated SESSION_DESCRIPTION rotates the key; the next frame must use the new cipher.
    #[tokio::test]
    async fn a_replaced_transport_encrypts_the_next_frame() {
        let sink = VecSink::new();
        let mut frames = vec![
            bytes::Bytes::from_static(b"frame"),
            bytes::Bytes::from_static(b"frame"),
        ];
        let dave = DaveEncryptor::new(1, 2).expect("create session");
        let mut pacer = FramePacer::new(move || frames.pop(), sink.clone(), dave, 0x1234);

        assert_eq!(pacer.tick().await.unwrap(), PacerStatus::Sent);
        assert_eq!(
            sink.packets().pop().expect("plaintext packet").len(),
            RTP_HEADER_LEN + 5,
            "the initial transport is plaintext"
        );

        pacer.set_transport(Box::new(AesGcmRtpSize::new(&[7u8; 32]).expect("cipher")));
        assert_eq!(pacer.tick().await.unwrap(), PacerStatus::Sent);
        assert_eq!(
            sink.packets().pop().expect("encrypted packet").len(),
            RTP_HEADER_LEN + 5 + 16 + 4,
            "tag and nonce suffix come from the replacement cipher"
        );
    }

    #[tokio::test]
    async fn frame_clock_catches_up_a_late_slot_then_resynchronises() {
        let start = Instant::now();
        let mut clock = FrameClock::new();

        assert_eq!(clock.wait().await, 0);
        assert!(Instant::now() - start >= FRAME_DURATION, "first slot waits");

        // The slot overran by 25 ms: one whole slot missed, and the deadline stays in the past so
        // the catch-up frame runs with no sleep at all.
        clock.next -= FRAME_DURATION * 2 + FRAME_DURATION / 4;
        let late = Instant::now();
        assert_eq!(clock.wait().await, 1);
        assert_eq!(clock.dropped_frames(), 1);
        assert_eq!(
            clock.wait().await,
            0,
            "still behind: no missed slot to count"
        );
        assert!(
            Instant::now() - late < FRAME_DURATION,
            "catch-up slots must not sleep"
        );

        // A long stall: too far behind to make up, so resynchronise rather than burst.
        clock.next -= FRAME_DURATION * 10;
        let missed = clock.wait().await;
        assert!(missed > MAX_CATCHUP_FRAMES, "missed {missed} slots");
        assert_eq!(clock.dropped_frames(), 1 + missed);
        let resumed = Instant::now();
        assert_eq!(clock.wait().await, 0);
        assert!(
            Instant::now() - resumed >= FRAME_DURATION,
            "a full frame after the resync"
        );
    }
}
