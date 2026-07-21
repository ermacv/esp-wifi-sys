//! Bounded strict receive pump for the pinned ESP32-S31 PP ABI.

use core::{
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
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

type RxCallback = unsafe extern "C" fn(*mut u8, i32, u32);

unsafe extern "C" {
    static mut pTxRx: *mut u8;
    static mut g_ic: u8;

    fn ppDequeueRxq_Locked() -> *mut u8;
    fn ppRxProtoProc(packet: *mut u8, rx_control: *mut u8) -> i32;
    fn ppRecycleRxPkt(packet: *mut u8);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxPumpError {
    StateUnavailable,
    InternalQueueFull,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StrictRxSnapshot {
    pub processed: usize,
    pub raw_management: usize,
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
}

struct Counters {
    processed: AtomicUsize,
    raw_management: AtomicUsize,
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
}

impl Counters {
    const fn new() -> Self {
        Self {
            processed: AtomicUsize::new(0),
            raw_management: AtomicUsize::new(0),
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
        }
    }

    fn snapshot(&self) -> StrictRxSnapshot {
        StrictRxSnapshot {
            processed: self.processed.load(Ordering::Acquire),
            raw_management: self.raw_management.load(Ordering::Acquire),
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
        }
    }
}

static COUNTERS: Counters = Counters::new();

pub fn strict_rx_snapshot() -> StrictRxSnapshot {
    COUNTERS.snapshot()
}

pub(crate) const fn is_continuation(kind: u32) -> bool {
    kind == RX_CONTINUATION_EVENT
}

/// Drain a bounded number of PP RX buffers on the single radio-owner stack.
pub(crate) unsafe fn dispatch() -> Result<(), RxPumpError> {
    let txrx = unsafe { ptr::addr_of!(pTxRx).read() };
    if txrx.is_null() {
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
        unsafe { process_one(txrx, packet) };
    }

    if !crate::adapter::enqueue_internal_event(PpEvent {
        kind: RX_CONTINUATION_EVENT,
        argument: ptr::null_mut(),
    }) {
        return Err(RxPumpError::InternalQueueFull);
    }
    Ok(())
}

unsafe fn process_one(txrx: *mut u8, packet: *mut u8) {
    let descriptor = unsafe { packet.add(0x34).cast::<*mut u8>().read() };
    if descriptor.is_null() {
        COUNTERS.malformed.fetch_add(1, Ordering::Relaxed);
        unsafe { ppRecycleRxPkt(packet) };
        return;
    }
    // Kind 7 uses a linked hardware block chain. The stock checker walks it
    // until a sentinel and can assert/log on corruption; that unbounded error
    // path is outside the strict profile. Ordinary and aggregate descriptors
    // with the same flag remain valid and continue below.
    if unsafe { descriptor.cast::<u32>().read() } & 0x10 != 0
        && unsafe { packet.add(26).read() } == 7
    {
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
    account_raw_frame(packet, rx_control);

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
        let callback = unsafe {
            txrx.add(RX_CALLBACK_OFFSET)
                .cast::<Option<RxCallback>>()
                .read()
        };
        let Some(callback) = callback else {
            COUNTERS.callback_missing.fetch_add(1, Ordering::Relaxed);
            unsafe { ppRecycleRxPkt(packet) };
            return;
        };
        let rssi = unsafe { rx_control.cast::<i8>().read() } as i32;
        let signal_length = unsafe { rx_control.add(20).read() } as u32;
        unsafe { callback(packet, rssi, signal_length) };
        return;
    }

    if flags & (0x20 | 0x40) != 0 {
        let offset = if flags & 0x20 != 0 {
            RX_AUX_CALLBACK_1_OFFSET
        } else {
            RX_AUX_CALLBACK_2_OFFSET
        };
        let registered = unsafe { txrx.add(offset).cast::<Option<RxCallback>>().read() }.is_some();
        if registered {
            COUNTERS.auxiliary_callback.fetch_add(1, Ordering::Relaxed);
        }
    }
    unsafe { ppRecycleRxPkt(packet) };
}

fn account_raw_frame(packet: *const u8, rx_control: *const u8) {
    let mut length = unsafe { rx_control.add(20).read() as usize };
    let mut frame = unsafe { rx_control.add(64) };
    if unsafe { packet.add(36).cast::<u16>().read() } & 0x2000 != 0 {
        if length < 8 {
            return;
        }
        frame = unsafe { frame.add(8) };
        length -= 8;
    }
    if length < 2 {
        return;
    }
    let frame_control = u16::from_le_bytes(unsafe { [frame.read(), frame.add(1).read()] });
    match (frame_control >> 2) & 3 {
        0 => {
            COUNTERS.raw_management.fetch_add(1, Ordering::Relaxed);
            let rssi = unsafe { rx_control.cast::<i8>().read() };
            crate::scan::observe_management(
                unsafe { core::slice::from_raw_parts(frame, length) },
                rssi,
            );
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
            if length >= header_len + EAPOL_LLC.len()
                && unsafe { core::slice::from_raw_parts(frame.add(header_len), EAPOL_LLC.len()) }
                    == EAPOL_LLC
            {
                COUNTERS.raw_eapol.fetch_add(1, Ordering::Relaxed);
            }
        }
        _ => {}
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
