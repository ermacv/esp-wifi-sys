//! Event edge between AP receive processing and a deferred unicast transmit.
//!
//! The vendor hostap output wrapper owns a dynamically linked power-save
//! queue. Strict mode does not enter that queue. Instead, the radio owner
//! retains the original owned command and is woken only when the peer sends an
//! active-mode data frame. TIM mutation remains a small, measured vendor leaf;
//! it has no calls, loops, allocation, lock, or OS wait in the pinned archive.

use core::{
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
    task::{Context, Poll},
};

use crate::queue::WakerCell;

static ACTIVE_EDGE: WakerCell = WakerCell::new();
static ACTIVE_EPOCH: AtomicUsize = AtomicUsize::new(0);
static PS_POLL_EPOCH: AtomicUsize = AtomicUsize::new(0);
static PS_POLL_PEER: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
static SLEEP_OBSERVATIONS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_OBSERVATIONS: AtomicUsize = AtomicUsize::new(0);
static DEFERRED_TRANSMITS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApPowerSaveSnapshot {
    pub sleep_observations: usize,
    pub active_observations: usize,
    pub ps_poll_observations: usize,
    pub deferred_transmits: usize,
}

pub fn ap_power_save_snapshot() -> ApPowerSaveSnapshot {
    ApPowerSaveSnapshot {
        sleep_observations: SLEEP_OBSERVATIONS.load(Ordering::Acquire),
        active_observations: ACTIVE_OBSERVATIONS.load(Ordering::Acquire),
        ps_poll_observations: PS_POLL_EPOCH.load(Ordering::Acquire),
        deferred_transmits: DEFERRED_TRANSMITS.load(Ordering::Acquire),
    }
}

/// Observe a raw 802.11 frame before the vendor receive callback consumes it.
///
/// Only an infrastructure data frame directed to the AP can publish a client
/// power-management transition. The source address is deliberately not
/// retained: the deferred command is revalidated against its destination node
/// when retried, so another peer can cause at most one bounded failed attempt.
pub(crate) fn observe_frame(frame: &[u8]) {
    if frame.len() < 2 {
        return;
    }
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    let frame_type = (frame_control >> 2) & 3;
    let subtype = (frame_control >> 4) & 0x0f;

    // Legacy PS-Poll is a 16-byte control frame. Address 2 is the station
    // transmitter and binds the one-frame delivery credit to one peer.
    if frame_type == 1 && subtype == 10 && frame.len() >= 16 {
        for (slot, byte) in PS_POLL_PEER.iter().zip(&frame[10..16]) {
            slot.store(*byte, Ordering::Relaxed);
        }
        PS_POLL_EPOCH.fetch_add(1, Ordering::Release);
        ACTIVE_EDGE.wake();
        return;
    }

    if frame.len() < 24 {
        return;
    }
    let is_data = frame_type == 2;
    let to_ds = frame_control & 0x0100 != 0;
    let from_ds = frame_control & 0x0200 != 0;
    if !is_data || !to_ds || from_ds {
        return;
    }

    if frame_control & 0x1000 != 0 {
        SLEEP_OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
    } else {
        ACTIVE_OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
        ACTIVE_EPOCH.fetch_add(1, Ordering::Release);
        ACTIVE_EDGE.wake();
    }
}

pub(crate) fn record_deferred_transmit() {
    DEFERRED_TRANSMITS.fetch_add(1, Ordering::Relaxed);
}

/// Register the radio owner for the next RX-derived active-mode edge.
///
/// Readiness is never produced by inspecting node state, avoiding a status or
/// node polling loop.
pub(crate) fn active_epoch() -> usize {
    ACTIVE_EPOCH.load(Ordering::Acquire)
}

pub(crate) fn ps_poll_epoch() -> usize {
    PS_POLL_EPOCH.load(Ordering::Acquire)
}

fn ps_poll_peer() -> [u8; 6] {
    core::array::from_fn(|index| PS_POLL_PEER[index].load(Ordering::Relaxed))
}

pub(crate) fn ps_poll_credit_after(after: usize, peer: &[u8; 6]) -> Option<usize> {
    let epoch = PS_POLL_EPOCH.load(Ordering::Acquire);
    (epoch != after && ps_poll_peer() == *peer).then_some(epoch)
}

pub(crate) fn poll_peer_edge(
    active_after: usize,
    ps_poll_after: usize,
    peer: &[u8; 6],
    cx: &mut Context<'_>,
) -> Poll<()> {
    ACTIVE_EDGE.register(cx.waker());
    if ACTIVE_EPOCH.load(Ordering::Acquire) != active_after
        || ps_poll_credit_after(ps_poll_after, peer).is_some()
    {
        Poll::Ready(())
    } else {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::{ap_power_save_snapshot, observe_frame, ps_poll_credit_after, ps_poll_epoch};

    #[test]
    fn only_to_ds_data_publishes_power_state() {
        let before = ap_power_save_snapshot();
        let mut frame = [0_u8; 24];
        frame[..2].copy_from_slice(&0x1108_u16.to_le_bytes());
        observe_frame(&frame);
        frame[..2].copy_from_slice(&0x0108_u16.to_le_bytes());
        observe_frame(&frame);
        frame[..2].copy_from_slice(&0x0008_u16.to_le_bytes());
        observe_frame(&frame);
        let after = ap_power_save_snapshot();
        assert_eq!(after.sleep_observations, before.sleep_observations + 1);
        assert_eq!(after.active_observations, before.active_observations + 1);
    }

    #[test]
    fn ps_poll_credit_is_bound_to_transmitter() {
        let before = ps_poll_epoch();
        let peer = [1, 2, 3, 4, 5, 6];
        let mut frame = [0_u8; 16];
        frame[..2].copy_from_slice(&0x00a4_u16.to_le_bytes());
        frame[10..16].copy_from_slice(&peer);
        observe_frame(&frame);
        assert!(ps_poll_credit_after(before, &peer).is_some());
        assert_eq!(ps_poll_credit_after(before, &[9; 6]), None);
    }
}
