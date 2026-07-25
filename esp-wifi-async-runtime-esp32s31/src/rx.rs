//! Bounded strict receive pump for the pinned ESP32-S31 PP ABI.

use core::{
    cell::UnsafeCell,
    ptr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use crate::event::PpEvent;

/// Synthetic queue item used to continue a bounded RX drain without touching
/// the vendor event-17 signal counter a second time.
pub(crate) const RX_CONTINUATION_EVENT: u32 = u32::MAX - 7;
const RX_BUDGET: usize = 8;
const RX_CALLBACK_OFFSET: usize = 0x3f8;
const RX_AUX_CALLBACK_1_OFFSET: usize = 0x3fc;
const RX_AUX_CALLBACK_2_OFFSET: usize = 0x400;
const LOCAL_ADDRESS_OFFSET: usize = 0x21a;
// Pinned `sta_input` reconstructs the 14-bit received MPDU length from bytes
// 0x38 and 0x39 of the internal RX control block before decapsulation.
const RX_CONTROL_SIGNAL_LENGTH_OFFSET: usize = 0x38;
const RX_CONTROL_SIGNAL_LENGTH_MASK: u16 = 0x3fff;
// S31 `wifi_pkt_rx_ctrl_t::sig_len` includes the trailing 802.11 FCS. None of
// the Rust protocol parsers consume that hardware-validated trailer.
const RX_FRAME_CHECK_SEQUENCE_LEN: usize = 4;

type RxCallback = unsafe extern "C" fn(*mut u8, i32, u32);

unsafe extern "C" {
    static mut pTxRx: *mut u8;
    static mut g_ic: u8;

    fn ppDequeueRxq_Locked() -> *mut u8;
    fn ppRxProtoProc(packet: *mut u8, rx_control: *mut u8) -> i32;
    fn ppRecycleRxPkt(packet: *mut u8);
    fn ap_rx_cb(packet: *mut u8, rssi: i32, signal_length: u32);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxPumpError {
    StateUnavailable,
    InternalQueueFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxStateAdoptionError {
    TxRxUnavailable,
    UnsupportedApCallback,
    NanCallbackInstalled,
}

struct StrictRxRegistry {
    station_callback: Option<RxCallback>,
    ap_callback_registered: bool,
}

impl StrictRxRegistry {
    const fn empty() -> Self {
        Self {
            station_callback: None,
            ap_callback_registered: false,
        }
    }
}

struct StrictRxRegistryCell(UnsafeCell<StrictRxRegistry>);

// Initialization publishes this immutable callback registry once. Runtime RX
// only reads it from the single strict radio owner.
unsafe impl Sync for StrictRxRegistryCell {}

#[cfg_attr(
    target_arch = "riscv32",
    link_section = ".critical.bss.wifi_strict.rx_registry"
)]
static STRICT_RX_REGISTRY: StrictRxRegistryCell =
    StrictRxRegistryCell(UnsafeCell::new(StrictRxRegistry::empty()));
#[cfg_attr(
    target_arch = "riscv32",
    link_section = ".critical.bss.wifi_strict.rx_registry"
)]
static STRICT_RX_REGISTRY_ADOPTED: AtomicBool = AtomicBool::new(false);

/// Copy the initialized RX callback policy out of the mixed vendor `pTxRx`
/// object before the strict runtime takes ownership.
///
/// The three words at pinned offsets `+0x3f8..+0x400` are the STA, AP and NAN
/// receive callbacks used by `ppRxPkt`. The exact surrounding C structure is
/// intentionally not reproduced: strict basic AP/STA needs only these
/// immutable routing capabilities. NAN is rejected, and the AP slot may only
/// contain the pinned `ap_rx_cb` leaf.
///
/// # Safety
///
/// Wi-Fi initialization must be quiescent, and no callback registration may
/// race this one-shot ownership transfer.
#[cfg(target_arch = "riscv32")]
pub(crate) unsafe fn adopt_vendor_rx_state() -> Result<(), RxStateAdoptionError> {
    if STRICT_RX_REGISTRY_ADOPTED.load(Ordering::Acquire) {
        return Ok(());
    }
    let txrx = ptr::addr_of!(pTxRx).read();
    if txrx.is_null() {
        return Err(RxStateAdoptionError::TxRxUnavailable);
    }
    let station_callback = txrx
        .add(RX_CALLBACK_OFFSET)
        .cast::<Option<RxCallback>>()
        .read();
    let ap_callback = txrx
        .add(RX_AUX_CALLBACK_1_OFFSET)
        .cast::<Option<RxCallback>>()
        .read();
    if let Some(callback) = ap_callback {
        if callback as usize != ap_rx_cb as *const () as usize {
            return Err(RxStateAdoptionError::UnsupportedApCallback);
        }
    }
    if txrx
        .add(RX_AUX_CALLBACK_2_OFFSET)
        .cast::<Option<RxCallback>>()
        .read()
        .is_some()
    {
        return Err(RxStateAdoptionError::NanCallbackInstalled);
    }

    STRICT_RX_REGISTRY.0.get().write(StrictRxRegistry {
        station_callback,
        ap_callback_registered: ap_callback.is_some(),
    });
    STRICT_RX_REGISTRY_ADOPTED.store(true, Ordering::Release);
    Ok(())
}

#[inline(always)]
fn rx_registry() -> Option<&'static StrictRxRegistry> {
    if !STRICT_RX_REGISTRY_ADOPTED.load(Ordering::Acquire) {
        return None;
    }
    Some(unsafe { &*STRICT_RX_REGISTRY.0.get() })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StrictRxSnapshot {
    pub processed: usize,
    pub raw_management: usize,
    pub management_subtypes: [usize; 16],
    pub raw_control: usize,
    pub raw_data: usize,
    pub raw_eapol: usize,
    pub protocol_rejected: usize,
    pub malformed: usize,
    pub block_error: usize,
    pub fragmented: usize,
    pub michael_mic_failure: usize,
    pub callback_missing: usize,
    pub auxiliary_callback: usize,
    pub station_callback: usize,
    pub unrouted: usize,
    pub last_route_flags: usize,
    pub last_descriptor_word: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockAckRxSnapshot {
    pub requests: usize,
    pub request_tids: [usize; 16],
    pub responses: usize,
    pub delba: usize,
    pub to_local: usize,
    pub last_request_dialog_token: usize,
    pub last_request_tid: usize,
    pub last_request_immediate: bool,
    pub last_request_amsdu: bool,
    pub last_request_window: usize,
    pub last_request_timeout_tu: usize,
    pub last_request_starting_sequence: usize,
    pub last_action: usize,
    pub last_dialog_token: usize,
    pub last_tid: usize,
    pub last_immediate: bool,
    pub last_amsdu: bool,
    pub last_window: usize,
    pub last_timeout_tu: usize,
    pub last_starting_sequence: usize,
    pub last_status_or_reason: usize,
    pub last_initiator: bool,
}

struct Counters {
    processed: AtomicUsize,
    raw_management: AtomicUsize,
    management_subtypes: [AtomicUsize; 16],
    raw_control: AtomicUsize,
    raw_data: AtomicUsize,
    raw_eapol: AtomicUsize,
    protocol_rejected: AtomicUsize,
    malformed: AtomicUsize,
    block_error: AtomicUsize,
    fragmented: AtomicUsize,
    michael_mic_failure: AtomicUsize,
    callback_missing: AtomicUsize,
    auxiliary_callback: AtomicUsize,
    station_callback: AtomicUsize,
    unrouted: AtomicUsize,
    last_route_flags: AtomicUsize,
    last_descriptor_word: AtomicUsize,
}

struct BlockAckCounters {
    requests: AtomicUsize,
    request_tids: [AtomicUsize; 16],
    responses: AtomicUsize,
    delba: AtomicUsize,
    to_local: AtomicUsize,
    last_request_dialog_token: AtomicUsize,
    last_request_tid: AtomicUsize,
    last_request_immediate: AtomicUsize,
    last_request_amsdu: AtomicUsize,
    last_request_window: AtomicUsize,
    last_request_timeout_tu: AtomicUsize,
    last_request_starting_sequence: AtomicUsize,
    last_action: AtomicUsize,
    last_dialog_token: AtomicUsize,
    last_tid: AtomicUsize,
    last_immediate: AtomicUsize,
    last_amsdu: AtomicUsize,
    last_window: AtomicUsize,
    last_timeout_tu: AtomicUsize,
    last_starting_sequence: AtomicUsize,
    last_status_or_reason: AtomicUsize,
    last_initiator: AtomicUsize,
}

impl Counters {
    const fn new() -> Self {
        Self {
            processed: AtomicUsize::new(0),
            raw_management: AtomicUsize::new(0),
            management_subtypes: [const { AtomicUsize::new(0) }; 16],
            raw_control: AtomicUsize::new(0),
            raw_data: AtomicUsize::new(0),
            raw_eapol: AtomicUsize::new(0),
            protocol_rejected: AtomicUsize::new(0),
            malformed: AtomicUsize::new(0),
            block_error: AtomicUsize::new(0),
            fragmented: AtomicUsize::new(0),
            michael_mic_failure: AtomicUsize::new(0),
            callback_missing: AtomicUsize::new(0),
            auxiliary_callback: AtomicUsize::new(0),
            station_callback: AtomicUsize::new(0),
            unrouted: AtomicUsize::new(0),
            last_route_flags: AtomicUsize::new(0),
            last_descriptor_word: AtomicUsize::new(0),
        }
    }

    fn snapshot(&self) -> StrictRxSnapshot {
        StrictRxSnapshot {
            processed: self.processed.load(Ordering::Acquire),
            raw_management: self.raw_management.load(Ordering::Acquire),
            management_subtypes: core::array::from_fn(|index| {
                self.management_subtypes[index].load(Ordering::Acquire)
            }),
            raw_control: self.raw_control.load(Ordering::Acquire),
            raw_data: self.raw_data.load(Ordering::Acquire),
            raw_eapol: self.raw_eapol.load(Ordering::Acquire),
            protocol_rejected: self.protocol_rejected.load(Ordering::Acquire),
            malformed: self.malformed.load(Ordering::Acquire),
            block_error: self.block_error.load(Ordering::Acquire),
            fragmented: self.fragmented.load(Ordering::Acquire),
            michael_mic_failure: self.michael_mic_failure.load(Ordering::Acquire),
            callback_missing: self.callback_missing.load(Ordering::Acquire),
            auxiliary_callback: self.auxiliary_callback.load(Ordering::Acquire),
            station_callback: self.station_callback.load(Ordering::Acquire),
            unrouted: self.unrouted.load(Ordering::Acquire),
            last_route_flags: self.last_route_flags.load(Ordering::Acquire),
            last_descriptor_word: self.last_descriptor_word.load(Ordering::Acquire),
        }
    }
}

impl BlockAckCounters {
    const fn new() -> Self {
        Self {
            requests: AtomicUsize::new(0),
            request_tids: [const { AtomicUsize::new(0) }; 16],
            responses: AtomicUsize::new(0),
            delba: AtomicUsize::new(0),
            to_local: AtomicUsize::new(0),
            last_request_dialog_token: AtomicUsize::new(0),
            last_request_tid: AtomicUsize::new(0),
            last_request_immediate: AtomicUsize::new(0),
            last_request_amsdu: AtomicUsize::new(0),
            last_request_window: AtomicUsize::new(0),
            last_request_timeout_tu: AtomicUsize::new(0),
            last_request_starting_sequence: AtomicUsize::new(0),
            last_action: AtomicUsize::new(0),
            last_dialog_token: AtomicUsize::new(0),
            last_tid: AtomicUsize::new(0),
            last_immediate: AtomicUsize::new(0),
            last_amsdu: AtomicUsize::new(0),
            last_window: AtomicUsize::new(0),
            last_timeout_tu: AtomicUsize::new(0),
            last_starting_sequence: AtomicUsize::new(0),
            last_status_or_reason: AtomicUsize::new(0),
            last_initiator: AtomicUsize::new(0),
        }
    }

    fn snapshot(&self) -> BlockAckRxSnapshot {
        BlockAckRxSnapshot {
            requests: self.requests.load(Ordering::Acquire),
            request_tids: core::array::from_fn(|index| {
                self.request_tids[index].load(Ordering::Acquire)
            }),
            responses: self.responses.load(Ordering::Acquire),
            delba: self.delba.load(Ordering::Acquire),
            to_local: self.to_local.load(Ordering::Acquire),
            last_request_dialog_token: self.last_request_dialog_token.load(Ordering::Acquire),
            last_request_tid: self.last_request_tid.load(Ordering::Acquire),
            last_request_immediate: self.last_request_immediate.load(Ordering::Acquire) != 0,
            last_request_amsdu: self.last_request_amsdu.load(Ordering::Acquire) != 0,
            last_request_window: self.last_request_window.load(Ordering::Acquire),
            last_request_timeout_tu: self.last_request_timeout_tu.load(Ordering::Acquire),
            last_request_starting_sequence: self
                .last_request_starting_sequence
                .load(Ordering::Acquire),
            last_action: self.last_action.load(Ordering::Acquire),
            last_dialog_token: self.last_dialog_token.load(Ordering::Acquire),
            last_tid: self.last_tid.load(Ordering::Acquire),
            last_immediate: self.last_immediate.load(Ordering::Acquire) != 0,
            last_amsdu: self.last_amsdu.load(Ordering::Acquire) != 0,
            last_window: self.last_window.load(Ordering::Acquire),
            last_timeout_tu: self.last_timeout_tu.load(Ordering::Acquire),
            last_starting_sequence: self.last_starting_sequence.load(Ordering::Acquire),
            last_status_or_reason: self.last_status_or_reason.load(Ordering::Acquire),
            last_initiator: self.last_initiator.load(Ordering::Acquire) != 0,
        }
    }
}

static COUNTERS: Counters = Counters::new();
static BLOCK_ACK_COUNTERS: BlockAckCounters = BlockAckCounters::new();

pub fn strict_rx_snapshot() -> StrictRxSnapshot {
    COUNTERS.snapshot()
}

pub fn block_ack_rx_snapshot() -> BlockAckRxSnapshot {
    BLOCK_ACK_COUNTERS.snapshot()
}

#[cfg(feature = "hil-rx-ampdu")]
pub fn expire_rx_ampdu_gap(generation: usize) -> usize {
    if rx_registry().is_none() {
        return 0;
    }
    let Some(release) = crate::rx_ampdu_ap::expire_gap(generation) else {
        return 0;
    };
    let mut processed = 0;
    for frame in release.iter() {
        let Some(packet) = crate::rx_ampdu_ap::frame_for_slot(frame.slot) else {
            COUNTERS.malformed.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        unsafe { process_deaggregated(packet) };
        processed += 1;
    }
    processed
}

pub(crate) const fn is_continuation(kind: u32) -> bool {
    kind == RX_CONTINUATION_EVENT
}

/// Drain a bounded number of PP RX buffers on the single radio-owner stack.
pub(crate) unsafe fn dispatch() -> Result<(), RxPumpError> {
    if rx_registry().is_none() {
        return Err(RxPumpError::StateUnavailable);
    }

    let mut processed = 0;
    while processed < RX_BUDGET {
        let packet = unsafe { ppDequeueRxq_Locked() };
        if packet.is_null() {
            return Ok(());
        }
        processed += 1;
        COUNTERS.processed.fetch_add(1, Ordering::Relaxed);
        unsafe { process_one(packet) };
    }

    if !crate::adapter::enqueue_internal_event(PpEvent {
        kind: RX_CONTINUATION_EVENT,
        argument: ptr::null_mut(),
    }) {
        return Err(RxPumpError::InternalQueueFull);
    }
    Ok(())
}

unsafe fn process_one(packet: *mut u8) {
    let descriptor = unsafe { packet.add(0x34).cast::<*mut u8>().read() };
    if descriptor.is_null() {
        COUNTERS.malformed.fetch_add(1, Ordering::Relaxed);
        unsafe { ppRecycleRxPkt(packet) };
        return;
    }
    // `wDev_IndicateAmpdu` has already split the hardware aggregate into
    // individually owned kind-7 ESF objects. Without the RX BlockAck HIL path
    // these objects remain fail-closed; the vendor's software reorder would
    // enter allocated state that strict takeover intentionally did not create.
    let aggregate_kind7 = unsafe { descriptor.cast::<u32>().read() } & 0x10 != 0
        && unsafe { packet.add(26).read() } == 7;
    #[cfg(not(feature = "hil-rx-ampdu"))]
    if aggregate_kind7 {
        COUNTERS.block_error.fetch_add(1, Ordering::Relaxed);
        unsafe { ppRecycleRxPkt(packet) };
        return;
    }

    let rx_control = unsafe { packet.add(0x10).cast::<*mut u8>().read() };
    let payload_owner = unsafe { packet.add(4).cast::<*mut u8>().read() };
    if rx_control.is_null() || payload_owner.is_null() {
        COUNTERS.malformed.fetch_add(1, Ordering::Relaxed);
        unsafe { ppRecycleRxPkt(packet) };
        return;
    }
    unsafe {
        payload_owner
            .add(4)
            .cast::<*mut u8>()
            .write(rx_control.add(64))
    };
    // Rust-owned association intentionally does not initialize the vendor
    // supplicant state consulted by the net80211 EAPOL route. Capture the
    // complete unencrypted EAPOL MPDU at the same bounded RX boundary instead.
    // Unlike the per-block byte count at +20, sig_len covers the complete MPDU
    // and therefore also admits the larger pairwise message 3.
    let mut raw_frame = unsafe { rx_control.add(64) };
    let Some(mut raw_length) =
        unsafe { rx_signal_length(rx_control) }.checked_sub(RX_FRAME_CHECK_SEQUENCE_LEN)
    else {
        COUNTERS.malformed.fetch_add(1, Ordering::Relaxed);
        unsafe { ppRecycleRxPkt(packet) };
        return;
    };
    if unsafe { packet.add(36).cast::<u16>().read_unaligned() } & 0x2000 != 0 {
        if raw_length < 8 {
            COUNTERS.malformed.fetch_add(1, Ordering::Relaxed);
            unsafe { ppRecycleRxPkt(packet) };
            return;
        }
        raw_frame = unsafe { raw_frame.add(8) };
        raw_length -= 8;
    }
    if raw_length >= 2 {
        let raw_bytes = unsafe { core::slice::from_raw_parts(raw_frame, raw_length) };
        let rssi = unsafe { rx_control.cast::<i8>().read() };
        account_raw_frame(raw_bytes, rssi);
        crate::ap_power_save::observe_frame(raw_bytes);
        if raw_length >= 24
            && raw_bytes[0] & 0x0c == 0
            && crate::sta_link::ingest_management_action(raw_bytes)
        {
            unsafe { ppRecycleRxPkt(packet) };
            return;
        }
        if raw_length >= 24
            && is_frame_to_local_address(raw_bytes)
            && crate::wpa2_rx::ingest_sta_80211(raw_bytes)
        {
            unsafe { ppRecycleRxPkt(packet) };
            return;
        }
        #[cfg(feature = "hil-rx-ampdu")]
        if aggregate_kind7 {
            match crate::rx_ampdu_ap::ingest(packet, raw_bytes) {
                crate::rx_ampdu_ap::Ingress::Retained => return,
                crate::rx_ampdu_ap::Ingress::Reject => {
                    COUNTERS.block_error.fetch_add(1, Ordering::Relaxed);
                    unsafe { ppRecycleRxPkt(packet) };
                    return;
                }
                crate::rx_ampdu_ap::Ingress::Release(release) => {
                    for frame in release.iter() {
                        let Some(owned_packet) =
                            crate::rx_ampdu_ap::frame_for_slot(frame.slot)
                        else {
                            COUNTERS.malformed.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        unsafe { process_deaggregated(owned_packet) };
                    }
                    return;
                }
            }
        }
    }
    #[cfg(feature = "hil-rx-ampdu")]
    if aggregate_kind7 {
        COUNTERS.malformed.fetch_add(1, Ordering::Relaxed);
        unsafe { ppRecycleRxPkt(packet) };
        return;
    }

    unsafe { process_protocol(packet, rx_control, payload_owner) };
}

#[cfg(feature = "hil-rx-ampdu")]
unsafe fn process_deaggregated(packet: *mut u8) {
    let descriptor = unsafe { packet.add(0x34).cast::<*mut u8>().read() };
    let rx_control = unsafe { packet.add(0x10).cast::<*mut u8>().read() };
    let payload_owner = unsafe { packet.add(4).cast::<*mut u8>().read() };
    if descriptor.is_null() || rx_control.is_null() || payload_owner.is_null() {
        COUNTERS.malformed.fetch_add(1, Ordering::Relaxed);
        unsafe { ppRecycleRxPkt(packet) };
        return;
    }
    // The aggregate has already been deaggregated and reordered by Rust.
    // Clear only the vendor software-reorder marker before the ordinary
    // protocol leaf; all hardware RX status remains intact.
    let descriptor_word = unsafe { descriptor.cast::<u32>().read() };
    unsafe { descriptor.cast::<u32>().write(descriptor_word & !0x10) };
    unsafe { process_protocol(packet, rx_control, payload_owner) };
}

unsafe fn process_protocol(
    packet: *mut u8,
    rx_control: *mut u8,
    payload_owner: *mut u8,
) {
    if unsafe { ppRxProtoProc(packet, rx_control) } != 0 {
        COUNTERS.protocol_rejected.fetch_add(1, Ordering::Relaxed);
        unsafe { ppRecycleRxPkt(packet) };
        return;
    }

    let frame = unsafe { payload_owner.add(4).cast::<*mut u8>().read() };
    let length = unsafe { rx_control.add(20).read() as usize };
    if frame.is_null() || length < 2 {
        COUNTERS.malformed.fetch_add(1, Ordering::Relaxed);
        unsafe { ppRecycleRxPkt(packet) };
        return;
    }
    let frame = if unsafe { packet.add(36).cast::<u16>().read() } & 0x2000 != 0 {
        unsafe { frame.add(8) }
    } else {
        frame
    };

    if is_fragmented(unsafe { core::slice::from_raw_parts(frame, length) }) {
        COUNTERS.fragmented.fetch_add(1, Ordering::Relaxed);
        unsafe { ppRecycleRxPkt(packet) };
        return;
    }

    let flags = unsafe { rx_control.add(3).read() };
    COUNTERS
        .last_route_flags
        .store(usize::from(flags), Ordering::Relaxed);
    let descriptor = unsafe { packet.add(0x34).cast::<*mut u8>().read() };
    if !descriptor.is_null() {
        COUNTERS.last_descriptor_word.store(
            unsafe { descriptor.cast::<u32>().read() } as usize,
            Ordering::Relaxed,
        );
    }
    if flags & 0x10 != 0 {
        let protocol = unsafe { rx_control.add(60).read() };
        if protocol != 0 && protocol != 198 && protocol != 245 {
            COUNTERS.protocol_rejected.fetch_add(1, Ordering::Relaxed);
            unsafe { ppRecycleRxPkt(packet) };
            return;
        }
        if protocol == 245 {
            COUNTERS.michael_mic_failure.fetch_add(1, Ordering::Relaxed);
            unsafe { ppRecycleRxPkt(packet) };
            return;
        }
        if is_frame_from_local_address(frame, length) {
            unsafe { ppRecycleRxPkt(packet) };
            return;
        }
        let callback = rx_registry().and_then(|registry| registry.station_callback);
        let Some(callback) = callback else {
            COUNTERS.callback_missing.fetch_add(1, Ordering::Relaxed);
            unsafe { ppRecycleRxPkt(packet) };
            return;
        };
        let rssi = unsafe { rx_control.cast::<i8>().read() } as i32;
        let signal_length = unsafe { rx_control.add(20).read() } as u32;
        COUNTERS.station_callback.fetch_add(1, Ordering::Relaxed);
        unsafe { callback(packet, rssi, signal_length) };
        return;
    }

    if flags & 0x20 != 0 {
        if !rx_registry()
            .map(|registry| registry.ap_callback_registered)
            .unwrap_or(false)
        {
            COUNTERS.callback_missing.fetch_add(1, Ordering::Relaxed);
            unsafe { ppRecycleRxPkt(packet) };
            return;
        }
        COUNTERS.auxiliary_callback.fetch_add(1, Ordering::Relaxed);
        let rssi = unsafe { rx_control.cast::<i8>().read() } as i32;
        let signal_length = unsafe { rx_control.add(20).read() } as u32;
        unsafe { ap_rx_cb(packet, rssi, signal_length) };
        return;
    }
    if flags & 0x40 != 0 {
        // Interface two is NAN in the pinned registration table. The strict
        // handoff rejected any installed callback, so it cannot be routed by
        // the basic STA/AP runtime.
        COUNTERS.protocol_rejected.fetch_add(1, Ordering::Relaxed);
        return;
    }
    COUNTERS.unrouted.fetch_add(1, Ordering::Relaxed);
    unsafe { ppRecycleRxPkt(packet) };
}

unsafe fn rx_signal_length(rx_control: *const u8) -> usize {
    usize::from(
        unsafe {
            rx_control
                .add(RX_CONTROL_SIGNAL_LENGTH_OFFSET)
                .cast::<u16>()
                .read_unaligned()
        } & RX_CONTROL_SIGNAL_LENGTH_MASK,
    )
}

fn account_raw_frame(frame: &[u8], rssi: i8) {
    if frame.len() < 2 {
        return;
    }
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    match (frame_control >> 2) & 3 {
        0 => {
            COUNTERS.raw_management.fetch_add(1, Ordering::Relaxed);
            COUNTERS.management_subtypes[usize::from((frame_control >> 4) & 0x0f)]
                .fetch_add(1, Ordering::Relaxed);
            observe_block_ack_action(frame);
            crate::scan::observe_management(frame, rssi);
            crate::sta_link::observe_management(frame);
        }
        1 => {
            COUNTERS.raw_control.fetch_add(1, Ordering::Relaxed);
        }
        2 => {
            COUNTERS.raw_data.fetch_add(1, Ordering::Relaxed);
            let to_ds = frame_control & 0x0100 != 0;
            let from_ds = frame_control & 0x0200 != 0;
            let qos = frame_control & 0x0080 != 0;
            let order = frame_control & 0x8000 != 0;
            let mut header_len = if to_ds && from_ds { 30 } else { 24 };
            if qos {
                header_len += 2;
                if order {
                    header_len += 4;
                }
            }
            const EAPOL_LLC: [u8; 8] = [0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e];
            if frame.len() >= header_len + EAPOL_LLC.len()
                && frame[header_len..header_len + EAPOL_LLC.len()] == EAPOL_LLC
            {
                COUNTERS.raw_eapol.fetch_add(1, Ordering::Relaxed);
            }
        }
        _ => {}
    }
}

fn observe_block_ack_action(frame: &[u8]) {
    if frame.len() < 26 || frame[0] & 0xfc != 0xd0 {
        return;
    }
    let Some(action) = crate::tx_ampdu::parse_block_ack_action(&frame[24..]) else {
        return;
    };
    #[cfg(feature = "hil-rx-ampdu")]
    crate::rx_ampdu_ap::observe_action(frame, action);
    if is_frame_to_local_address(frame) {
        BLOCK_ACK_COUNTERS.to_local.fetch_add(1, Ordering::Relaxed);
    }
    match action {
        crate::tx_ampdu::BlockAckAction::AddbaRequest {
            dialog_token,
            tid,
            immediate,
            amsdu,
            window,
            timeout_tu,
            starting_sequence,
        } => {
            BLOCK_ACK_COUNTERS
                .last_request_dialog_token
                .store(usize::from(dialog_token), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_request_tid
                .store(usize::from(tid), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_request_immediate
                .store(usize::from(immediate), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_request_amsdu
                .store(usize::from(amsdu), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_request_window
                .store(usize::from(window), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_request_timeout_tu
                .store(usize::from(timeout_tu), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_request_starting_sequence
                .store(usize::from(starting_sequence), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_dialog_token
                .store(usize::from(dialog_token), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_tid
                .store(usize::from(tid), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_immediate
                .store(usize::from(immediate), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_amsdu
                .store(usize::from(amsdu), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_window
                .store(usize::from(window), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_timeout_tu
                .store(usize::from(timeout_tu), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_starting_sequence
                .store(usize::from(starting_sequence), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_status_or_reason
                .store(0, Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_initiator
                .store(0, Ordering::Relaxed);
            BLOCK_ACK_COUNTERS.last_action.store(1, Ordering::Release);
            BLOCK_ACK_COUNTERS.request_tids[usize::from(tid)].fetch_add(1, Ordering::Relaxed);
            BLOCK_ACK_COUNTERS.requests.fetch_add(1, Ordering::Relaxed);
        }
        crate::tx_ampdu::BlockAckAction::AddbaResponse {
            dialog_token,
            status,
            tid,
            immediate,
            amsdu,
            window,
            timeout_tu,
        } => {
            BLOCK_ACK_COUNTERS
                .last_dialog_token
                .store(usize::from(dialog_token), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_tid
                .store(usize::from(tid), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_immediate
                .store(usize::from(immediate), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_amsdu
                .store(usize::from(amsdu), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_window
                .store(usize::from(window), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_timeout_tu
                .store(usize::from(timeout_tu), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_starting_sequence
                .store(0, Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_status_or_reason
                .store(usize::from(status), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_initiator
                .store(0, Ordering::Relaxed);
            BLOCK_ACK_COUNTERS.last_action.store(2, Ordering::Release);
            BLOCK_ACK_COUNTERS.responses.fetch_add(1, Ordering::Relaxed);
        }
        crate::tx_ampdu::BlockAckAction::Delba {
            tid,
            initiator,
            reason,
        } => {
            BLOCK_ACK_COUNTERS
                .last_dialog_token
                .store(0, Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_tid
                .store(usize::from(tid), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_immediate
                .store(0, Ordering::Relaxed);
            BLOCK_ACK_COUNTERS.last_amsdu.store(0, Ordering::Relaxed);
            BLOCK_ACK_COUNTERS.last_window.store(0, Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_timeout_tu
                .store(0, Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_starting_sequence
                .store(0, Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_status_or_reason
                .store(usize::from(reason), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS
                .last_initiator
                .store(usize::from(initiator), Ordering::Relaxed);
            BLOCK_ACK_COUNTERS.last_action.store(3, Ordering::Release);
            BLOCK_ACK_COUNTERS.delba.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn is_fragmented(frame: &[u8]) -> bool {
    if frame.len() < 2 || frame[0] & 0x04 != 0 {
        return false;
    }
    if frame[1] & 0x04 != 0 {
        return true;
    }
    frame.len() < 24 || u16::from_le_bytes([frame[22], frame[23]]) & 0x0f != 0
}

fn is_frame_from_local_address(frame: *const u8, length: usize) -> bool {
    if length < 22 || unsafe { frame.add(1).read() } & 3 != 2 {
        return false;
    }
    let local = unsafe { ptr::addr_of!(g_ic).add(LOCAL_ADDRESS_OFFSET) };
    let source = unsafe { frame.add(16) };
    let mut index = 0;
    while index < 6 {
        if unsafe { source.add(index).read() != local.add(index).read() } {
            return false;
        }
        index += 1;
    }
    true
}

fn is_frame_to_local_address(frame: &[u8]) -> bool {
    if frame.len() < 10 {
        return false;
    }
    let local = unsafe { ptr::addr_of!(g_ic).add(LOCAL_ADDRESS_OFFSET) };
    frame[4..10]
        .iter()
        .enumerate()
        .all(|(index, byte)| unsafe { *byte == local.add(index).read() })
}

#[cfg(test)]
mod tests {
    use super::is_fragmented;

    #[test]
    fn fragment_gate_matches_80211_more_and_sequence_bits() {
        let mut frame = [0_u8; 24];
        frame[0] = 0x08;
        assert!(!is_fragmented(&frame));
        frame[1] = 0x04;
        assert!(is_fragmented(&frame));
        frame[1] = 0;
        frame[22] = 1;
        assert!(is_fragmented(&frame));
        frame[0] = 0x04;
        assert!(!is_fragmented(&frame));
    }
}
