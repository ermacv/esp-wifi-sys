//! Event edge between AP receive processing and a deferred unicast transmit.
//!
//! The vendor hostap output wrapper owns a dynamically linked power-save
//! queue. Strict mode does not enter that queue. Instead, the radio owner
//! retains the original owned command and is woken only when the peer sends an
//! active-mode data frame. TIM mutation remains a small, measured vendor leaf;
//! it has no calls, loops, allocation, lock, or OS wait in the pinned archive.

use core::{
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};

use crate::queue::WakerCell;

static ACTIVE_EDGE: WakerCell = WakerCell::new();
static ACTIVE_EPOCH: AtomicUsize = AtomicUsize::new(0);
static SLEEP_OBSERVATIONS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_OBSERVATIONS: AtomicUsize = AtomicUsize::new(0);
static DEFERRED_TRANSMITS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApPowerSaveSnapshot {
    pub sleep_observations: usize,
    pub active_observations: usize,
    pub deferred_transmits: usize,
}

pub fn ap_power_save_snapshot() -> ApPowerSaveSnapshot {
    ApPowerSaveSnapshot {
        sleep_observations: SLEEP_OBSERVATIONS.load(Ordering::Acquire),
        active_observations: ACTIVE_OBSERVATIONS.load(Ordering::Acquire),
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
    if frame.len() < 24 {
        return;
    }
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    let is_data = (frame_control >> 2) & 3 == 2;
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

pub(crate) fn poll_active_edge(after: usize, cx: &mut Context<'_>) -> Poll<()> {
    ACTIVE_EDGE.register(cx.waker());
    if ACTIVE_EPOCH.load(Ordering::Acquire) != after {
        Poll::Ready(())
    } else {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::{ap_power_save_snapshot, observe_frame};

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
}
