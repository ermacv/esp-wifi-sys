//! Event edge between AP receive processing and a deferred unicast transmit.
//!
//! The vendor hostap output wrapper owns a dynamically linked power-save
//! queue. Strict mode does not enter that queue. Instead, the radio owner
//! retains the original owned command and is woken only when that peer sends an
//! active-mode data frame or a PS-Poll. TIM mutation remains a small, measured
//! vendor leaf; it has no calls, loops, allocation, lock, or OS wait in the
//! pinned archive.

use core::{
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
    task::{Context, Poll},
};

use crate::queue::WakerCell;

static ACTIVE_EDGE: WakerCell = WakerCell::new();
static PS_POLL_EPOCH: AtomicUsize = AtomicUsize::new(0);
static PEER_EVENT_EPOCH: AtomicUsize = AtomicUsize::new(0);
static SLEEP_OBSERVATIONS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_OBSERVATIONS: AtomicUsize = AtomicUsize::new(0);
static REMOVAL_OBSERVATIONS: AtomicUsize = AtomicUsize::new(0);
static DEFERRED_TRANSMITS: AtomicUsize = AtomicUsize::new(0);
static CANCELLED_TRANSMITS: AtomicUsize = AtomicUsize::new(0);

// This matches the fixed WPA2 AP association capacity. The table is written
// only by serialized callbacks on the radio owner. Atomic fields keep waker
// publication well-defined without a critical section.
const PEER_EVENT_CAPACITY: usize = crate::wpa2_ap::WPA2_AP_ASSOC_CAPACITY;

struct PeerEventSlot {
    peer: [AtomicU8; 6],
    active_epoch: AtomicUsize,
    ps_poll_epoch: AtomicUsize,
    removal_epoch: AtomicUsize,
}

impl PeerEventSlot {
    const fn new() -> Self {
        Self {
            peer: [const { AtomicU8::new(0) }; 6],
            active_epoch: AtomicUsize::new(0),
            ps_poll_epoch: AtomicUsize::new(0),
            removal_epoch: AtomicUsize::new(0),
        }
    }

    fn matches(&self, peer: &[u8; 6]) -> bool {
        self.peer
            .iter()
            .zip(peer)
            .all(|(stored, expected)| stored.load(Ordering::Relaxed) == *expected)
    }

    fn last_epoch(&self) -> usize {
        self.active_epoch
            .load(Ordering::Acquire)
            .max(self.ps_poll_epoch.load(Ordering::Acquire))
            .max(self.removal_epoch.load(Ordering::Acquire))
    }

    fn replace_peer(&self, peer: &[u8; 6]) {
        // Zero is never a published event. Invalidate the slot before changing
        // its key so a reader cannot attach an old credit to the new peer.
        self.active_epoch.store(0, Ordering::Release);
        self.ps_poll_epoch.store(0, Ordering::Release);
        self.removal_epoch.store(0, Ordering::Release);
        for (stored, value) in self.peer.iter().zip(peer) {
            stored.store(*value, Ordering::Relaxed);
        }
    }
}

static PEER_EVENTS: [PeerEventSlot; PEER_EVENT_CAPACITY] =
    [const { PeerEventSlot::new() }; PEER_EVENT_CAPACITY];

#[derive(Clone, Copy)]
enum PeerEvent {
    Active(usize),
    PsPoll(usize),
    Removed(usize),
}

fn publish_peer_event(peer: &[u8; 6], event: PeerEvent) {
    let mut replacement = 0;
    let mut replacement_epoch = usize::MAX;
    for (index, slot) in PEER_EVENTS.iter().enumerate() {
        if slot.matches(peer) && slot.last_epoch() != 0 {
            publish_in_slot(slot, event);
            return;
        }
        let epoch = slot.last_epoch();
        if epoch < replacement_epoch {
            replacement = index;
            replacement_epoch = epoch;
        }
    }

    let slot = &PEER_EVENTS[replacement];
    slot.replace_peer(peer);
    publish_in_slot(slot, event);
}

fn publish_in_slot(slot: &PeerEventSlot, event: PeerEvent) {
    match event {
        PeerEvent::Active(epoch) => slot.active_epoch.store(epoch, Ordering::Release),
        PeerEvent::PsPoll(epoch) => slot.ps_poll_epoch.store(epoch, Ordering::Release),
        PeerEvent::Removed(epoch) => slot.removal_epoch.store(epoch, Ordering::Release),
    }
}

fn next_peer_event_epoch() -> usize {
    let epoch = PEER_EVENT_EPOCH
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    if epoch == 0 {
        PEER_EVENT_EPOCH
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    } else {
        epoch
    }
}

fn peer_epochs(peer: &[u8; 6]) -> (usize, usize, usize) {
    for slot in &PEER_EVENTS {
        if slot.matches(peer) {
            return (
                slot.active_epoch.load(Ordering::Acquire),
                slot.ps_poll_epoch.load(Ordering::Acquire),
                slot.removal_epoch.load(Ordering::Acquire),
            );
        }
    }
    (0, 0, 0)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApPowerSaveSnapshot {
    pub sleep_observations: usize,
    pub active_observations: usize,
    pub ps_poll_observations: usize,
    pub removal_observations: usize,
    pub deferred_transmits: usize,
    pub cancelled_transmits: usize,
}

pub fn ap_power_save_snapshot() -> ApPowerSaveSnapshot {
    ApPowerSaveSnapshot {
        sleep_observations: SLEEP_OBSERVATIONS.load(Ordering::Acquire),
        active_observations: ACTIVE_OBSERVATIONS.load(Ordering::Acquire),
        ps_poll_observations: PS_POLL_EPOCH.load(Ordering::Acquire),
        removal_observations: REMOVAL_OBSERVATIONS.load(Ordering::Acquire),
        deferred_transmits: DEFERRED_TRANSMITS.load(Ordering::Acquire),
        cancelled_transmits: CANCELLED_TRANSMITS.load(Ordering::Acquire),
    }
}

/// Observe a raw 802.11 frame before the vendor receive callback consumes it.
///
/// Only an infrastructure data frame directed to the AP can publish a client
/// power-management transition. Readiness is retained per source address so
/// one peer cannot wake or cancel a command owned by another peer.
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
        let peer = [
            frame[10], frame[11], frame[12], frame[13], frame[14], frame[15],
        ];
        PS_POLL_EPOCH.fetch_add(1, Ordering::Relaxed);
        let epoch = next_peer_event_epoch();
        publish_peer_event(&peer, PeerEvent::PsPoll(epoch));
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
        let peer = [
            frame[10], frame[11], frame[12], frame[13], frame[14], frame[15],
        ];
        let epoch = next_peer_event_epoch();
        publish_peer_event(&peer, PeerEvent::Active(epoch));
        ACTIVE_EDGE.wake();
    }
}

pub(crate) fn record_deferred_transmit() {
    DEFERRED_TRANSMITS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn observe_peer_removed(peer: &[u8; 6]) {
    REMOVAL_OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
    publish_peer_event(peer, PeerEvent::Removed(next_peer_event_epoch()));
    ACTIVE_EDGE.wake();
}

pub(crate) fn record_cancelled_transmit() {
    CANCELLED_TRANSMITS.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerEdge {
    Retry,
    Removed,
}

/// Register the radio owner for the next RX-derived active-mode edge.
///
/// Readiness is never produced by inspecting node state, avoiding a status or
/// node polling loop.
pub(crate) fn active_epoch(peer: &[u8; 6]) -> usize {
    peer_epochs(peer).0
}

pub(crate) fn ps_poll_epoch(peer: &[u8; 6]) -> usize {
    peer_epochs(peer).1
}

pub(crate) fn removal_epoch(peer: &[u8; 6]) -> usize {
    peer_epochs(peer).2
}

pub(crate) fn ps_poll_credit_after(after: usize, peer: &[u8; 6]) -> Option<usize> {
    let epoch = ps_poll_epoch(peer);
    (epoch != 0 && epoch != after).then_some(epoch)
}

pub(crate) fn poll_peer_edge(
    active_after: usize,
    ps_poll_after: usize,
    removal_after: usize,
    peer: &[u8; 6],
    cx: &mut Context<'_>,
) -> Poll<PeerEdge> {
    ACTIVE_EDGE.register(cx.waker());
    if removal_epoch(peer) != removal_after {
        Poll::Ready(PeerEdge::Removed)
    } else if active_epoch(peer) != active_after
        || ps_poll_credit_after(ps_poll_after, peer).is_some()
    {
        Poll::Ready(PeerEdge::Retry)
    } else {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::{
        active_epoch, ap_power_save_snapshot, observe_frame, observe_peer_removed, poll_peer_edge,
        ps_poll_credit_after, ps_poll_epoch, removal_epoch, PeerEdge,
    };
    use core::task::{Context, Poll, Waker};
    use std::sync::{Mutex, MutexGuard};

    // The production state is intentionally one global radio-owner resource.
    // Serialize tests which mutate that resource so the host test scheduler
    // cannot make per-test counter deltas observe another test's frame.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn only_to_ds_data_publishes_power_state() {
        let _guard = test_guard();
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
        let _guard = test_guard();
        let peer = [1, 2, 3, 4, 5, 6];
        let before = ps_poll_epoch(&peer);
        let mut frame = [0_u8; 16];
        frame[..2].copy_from_slice(&0x00a4_u16.to_le_bytes());
        frame[10..16].copy_from_slice(&peer);
        observe_frame(&frame);
        let published = ps_poll_credit_after(before, &peer).unwrap();
        assert_eq!(ps_poll_credit_after(published, &peer), None);
        assert_eq!(ps_poll_credit_after(before, &[9; 6]), None);
    }

    #[test]
    fn ps_poll_events_for_two_peers_remain_independent() {
        let _guard = test_guard();
        let first = [20, 2, 3, 4, 5, 6];
        let second = [21, 2, 3, 4, 5, 6];
        let first_before = ps_poll_epoch(&first);
        let second_before = ps_poll_epoch(&second);
        let mut frame = [0_u8; 16];
        frame[..2].copy_from_slice(&0x00a4_u16.to_le_bytes());
        frame[10..16].copy_from_slice(&first);
        observe_frame(&frame);
        frame[10..16].copy_from_slice(&second);
        observe_frame(&frame);
        assert!(ps_poll_credit_after(first_before, &first).is_some());
        assert!(ps_poll_credit_after(second_before, &second).is_some());
    }

    #[test]
    fn peer_active_edges_do_not_wake_a_different_peer() {
        let _guard = test_guard();
        let peer = [7, 2, 3, 4, 5, 6];
        let other = [8, 2, 3, 4, 5, 6];
        let before = active_epoch(&peer);
        let other_before = active_epoch(&other);
        let mut frame = [0_u8; 24];
        frame[..2].copy_from_slice(&0x0108_u16.to_le_bytes());
        frame[10..16].copy_from_slice(&peer);
        observe_frame(&frame);
        assert_ne!(active_epoch(&peer), before);
        assert_eq!(active_epoch(&other), other_before);
    }

    #[test]
    fn peer_removal_cancels_only_the_matching_waiter() {
        let _guard = test_guard();
        let peer = [30, 2, 3, 4, 5, 6];
        let other = [31, 2, 3, 4, 5, 6];
        let active_before = active_epoch(&peer);
        let ps_poll_before = ps_poll_epoch(&peer);
        let removal_before = removal_epoch(&peer);
        let other_removal_before = removal_epoch(&other);
        observe_peer_removed(&peer);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert_eq!(
            poll_peer_edge(
                active_before,
                ps_poll_before,
                removal_before,
                &peer,
                &mut context,
            ),
            Poll::Ready(PeerEdge::Removed)
        );
        assert_eq!(removal_epoch(&other), other_removal_before);
    }
}
