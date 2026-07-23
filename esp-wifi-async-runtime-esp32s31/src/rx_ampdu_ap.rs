//! Strict SoftAP receive BlockAck ownership.
//!
//! This HIL layer bridges one measured ADDBA exchange to the allocation-free
//! reorder machine. All mutable protocol state is touched only by the Rust
//! radio owner; the RX interrupt owns only the fixed kind-7 ESF pool.

use core::{
    cell::UnsafeCell,
    ffi::c_void,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};

use crate::{
    queue::WakerCell,
    rx_ampdu::{RxAmpduMpdu, RxAmpduRelease, RxBlockAckReorder, RX_BLOCK_ACK_MAX_WINDOW},
    rx_ampdu_hw::S31RxBlockAckAgreement,
    tx_ampdu::BlockAckAction,
};

const AP_INTERFACE_INDEX: u8 = 1;
const HARDWARE_INDEX: u8 = 0;
const INITIAL_SUPPORTED_TID: u8 = 0;
const ADDBA_RESPONSE_BODY_LEN: usize = 9;

unsafe extern "C" {
    fn esf_buf_recycle(frame: *mut c_void);
}

#[derive(Clone, Copy)]
struct PendingRequest {
    peer: [u8; 6],
    dialog_token: u8,
    tid: u8,
    starting_sequence: u16,
}

struct ActiveAgreement {
    peer: [u8; 6],
    tid: u8,
    reorder: RxBlockAckReorder,
    gap_generation: Option<usize>,
}

struct State {
    pending: Option<PendingRequest>,
    active: Option<ActiveAgreement>,
}

impl State {
    const fn new() -> Self {
        Self {
            pending: None,
            active: None,
        }
    }
}

struct RadioOwnerState(UnsafeCell<State>);

impl RadioOwnerState {
    const fn new() -> Self {
        Self(UnsafeCell::new(State::new()))
    }
}

// The only accessors below first require the strict radio hart and active
// radio-owner context. RX interrupts never touch this object.
unsafe impl Sync for RadioOwnerState {}

static STATE: RadioOwnerState = RadioOwnerState::new();
static GAP_GENERATION: AtomicUsize = AtomicUsize::new(0);
static GAP_EDGE: WakerCell = WakerCell::new();

pub struct RxAmpduGapFuture {
    after: usize,
}

impl Future for RxAmpduGapFuture {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        GAP_EDGE.register(cx.waker());
        let generation = GAP_GENERATION.load(Ordering::Acquire);
        if generation != self.after {
            Poll::Ready(generation)
        } else {
            Poll::Pending
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ingress {
    Retained,
    Release(RxAmpduRelease),
    Reject,
}

fn state() -> Option<&'static mut State> {
    if !crate::critical::on_strict_wifi_hart() || !crate::context::in_radio_context() {
        return None;
    }
    // Soundness: strict takeover admits exactly one radio owner on one hart.
    // This module is not called recursively and the returned borrow does not
    // escape an accessor.
    Some(unsafe { &mut *STATE.0.get() })
}

pub(crate) fn observe_action(frame: &[u8], action: BlockAckAction) {
    if frame.len() < 24 {
        return;
    }
    let mut peer = [0_u8; 6];
    peer.copy_from_slice(&frame[10..16]);
    if peer[0] & 1 != 0 {
        return;
    }
    match action {
        BlockAckAction::AddbaRequest {
            dialog_token,
            tid,
            immediate,
            timeout_tu,
            starting_sequence,
            ..
        } if immediate
            && timeout_tu == 0
            && tid == INITIAL_SUPPORTED_TID
            && starting_sequence <= 0x0fff
            && crate::wpa2_ap::wpa2_ap_peer_association_epoch(&peer).is_some() =>
        {
            let Some(state) = state() else {
                return;
            };
            state.pending = Some(PendingRequest {
                peer,
                dialog_token,
                tid,
                starting_sequence,
            });
        }
        BlockAckAction::Delba { tid, .. } => stop_peer(peer, tid),
        _ => {}
    }
}

/// Turn the bounded vendor decline into one Rust-owned successful response.
///
/// Software reorder state becomes visible before the hardware agreement is
/// enabled. The response is modified only after the finite MMIO transaction
/// succeeds.
pub(crate) fn try_accept_response(peer: [u8; 6], body: &mut [u8]) -> bool {
    if body.len() != ADDBA_RESPONSE_BODY_LEN || body[0] != 3 || body[1] != 1 {
        return false;
    }
    let Some(state) = state() else {
        return false;
    };
    let Some(pending) = state.pending.take() else {
        return false;
    };
    if pending.peer != peer || pending.dialog_token != body[2] || state.active.is_some() {
        return false;
    }
    let Ok(reorder) =
        RxBlockAckReorder::new(pending.starting_sequence, RX_BLOCK_ACK_MAX_WINDOW)
    else {
        return false;
    };
    state.active = Some(ActiveAgreement {
        peer,
        tid: pending.tid,
        reorder,
        gap_generation: None,
    });
    let agreement = S31RxBlockAckAgreement {
        hardware_index: HARDWARE_INDEX,
        interface: AP_INTERFACE_INDEX,
        peer,
        tid: pending.tid,
        starting_sequence: pending.starting_sequence,
        window: RX_BLOCK_ACK_MAX_WINDOW,
    };
    if unsafe { crate::rx_ampdu_hw::program(agreement) }.is_err() {
        state.active = None;
        return false;
    }

    crate::rx_ampdu::write_successful_addba_response(
        body,
        pending.dialog_token,
        pending.tid,
        RX_BLOCK_ACK_MAX_WINDOW,
    )
    .is_ok()
}

pub(crate) fn ingest(packet: *mut u8, frame: &[u8]) -> Ingress {
    let Some(slot) = crate::esf::large_rx_slot_id(packet) else {
        return Ingress::Reject;
    };
    if frame.len() < 26
        || frame[0] & 0x0c != 0x08
        || frame[0] & 0x80 == 0
        || frame[1] & 0x03 != 0x01
    {
        return Ingress::Reject;
    }
    let sequence = u16::from_le_bytes([frame[22], frame[23]]) >> 4;
    let tid = frame[24] & 0x0f;
    let mut peer = [0_u8; 6];
    peer.copy_from_slice(&frame[10..16]);
    let Some(state) = state() else {
        return Ingress::Reject;
    };
    let Some(active) = state.active.as_mut() else {
        return Ingress::Reject;
    };
    if active.peer != peer || active.tid != tid {
        return Ingress::Reject;
    }
    let Ok(release) = active.reorder.ingest(RxAmpduMpdu { sequence, slot }) else {
        return Ingress::Reject;
    };
    if release.rejected.is_some() {
        return Ingress::Reject;
    }
    update_gap_edge(active);
    if release.count == 0 {
        Ingress::Retained
    } else {
        Ingress::Release(release)
    }
}

pub(crate) fn frame_for_slot(slot: u8) -> Option<*mut u8> {
    crate::esf::large_rx_frame(slot)
}

pub fn wait_for_gap(after: usize) -> RxAmpduGapFuture {
    RxAmpduGapFuture { after }
}

pub fn remove_peer(peer: [u8; 6]) {
    let tid = state()
        .and_then(|state| state.active.as_ref())
        .filter(|active| active.peer == peer)
        .map(|active| active.tid);
    if let Some(tid) = tid {
        stop_peer(peer, tid);
    } else if let Some(state) = state() {
        if state
            .pending
            .is_some_and(|pending| pending.peer == peer)
        {
            state.pending = None;
        }
    }
}

pub(crate) fn expire_gap(generation: usize) -> Option<RxAmpduRelease> {
    let state = state()?;
    let active = state.active.as_mut()?;
    if active.gap_generation != Some(generation) {
        return None;
    }
    active.gap_generation = None;
    let release = active.reorder.expire_gap();
    update_gap_edge(active);
    Some(release)
}

fn update_gap_edge(active: &mut ActiveAgreement) {
    if active.reorder.occupied() == 0 {
        active.gap_generation = None;
        return;
    }
    if active.gap_generation.is_some() {
        return;
    }
    let generation = GAP_GENERATION
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1);
    active.gap_generation = Some(generation);
    GAP_EDGE.wake();
}

fn stop_peer(peer: [u8; 6], tid: u8) {
    let Some(state) = state() else {
        return;
    };
    if state
        .pending
        .is_some_and(|pending| pending.peer == peer && pending.tid == tid)
    {
        state.pending = None;
    }
    let Some(active) = state.active.as_ref() else {
        return;
    };
    if active.peer != peer || active.tid != tid {
        return;
    }
    let Some(mut active) = state.active.take() else {
        return;
    };
    let retained = active.reorder.stop();
    for frame in retained.iter() {
        if let Some(packet) = crate::esf::large_rx_frame(frame.slot) {
            unsafe { esf_buf_recycle(packet.cast()) };
        }
    }
    let _ = unsafe { crate::rx_ampdu_hw::clear(HARDWARE_INDEX) };
}
