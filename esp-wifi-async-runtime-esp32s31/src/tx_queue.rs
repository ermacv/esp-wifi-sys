//! Strict TX-queue selection boundary.
//!
//! The first stage is deliberately an observation wrapper around the pinned
//! `ppSearchTxframe` body. It records the exact subset exercised by WPA2 STA
//! before that stateful search is replaced with one Rust executor action.

use core::{
    ptr,
    sync::atomic::{AtomicU32, Ordering},
};

const TXRX_QUEUE_SIZE: usize = 0x34;
const TX_FRAME_NEXT_OFFSET: usize = 0x30;
const TX_FRAME_DESCRIPTOR_OFFSET: usize = 0x34;
const TX_FRAME_LAYOUT_FLAGS_OFFSET: usize = 0x24;
const TX_DESCRIPTOR_SELECTED_RATE_OFFSET: usize = 0x0c;
const TX_DESCRIPTOR_QUEUE_WORD_OFFSET: usize = 0x10;

unsafe extern "C" {
    static mut pTxRx: *mut u8;

    #[cfg(feature = "hil-vendor-tx")]
    fn __real_ppSearchTxframe(queue: u8) -> *mut u8;
}

/// HIL evidence captured immediately after the vendor queue selector returns.
///
/// All masks are monotonic. `input_logical_masks[event]` maps PP events 0..=4
/// to the descriptor queue numbers actually selected by the pinned blob.
#[cfg(feature = "hil-vendor-tx")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HilTxQueueSearchSnapshot {
    pub calls: [u32; 5],
    pub found: [u32; 5],
    pub input_logical_masks: [u32; 5],
    pub null_frames: u32,
    pub descriptor_null: u32,
    pub invalid_logical_queue: u32,
    pub logical_queue_mask: u32,
    pub access_type_mask: u32,
    pub queue_class_mask: u32,
    pub queue_owner_mask: u32,
    pub selected_rate_low_mask: u32,
    pub selected_rate_high_mask: u32,
    pub descriptor_flags_or: u32,
    pub descriptor_queue_word_or: u32,
    pub layout_flags_or: u32,
    pub next_nonnull: u32,
    pub peer_null: u32,
}

#[cfg(feature = "hil-vendor-tx")]
struct HilTxQueueSearchCounters {
    calls: [AtomicU32; 5],
    found: [AtomicU32; 5],
    input_logical_masks: [AtomicU32; 5],
    null_frames: AtomicU32,
    descriptor_null: AtomicU32,
    invalid_logical_queue: AtomicU32,
    logical_queue_mask: AtomicU32,
    access_type_mask: AtomicU32,
    queue_class_mask: AtomicU32,
    queue_owner_mask: AtomicU32,
    selected_rate_low_mask: AtomicU32,
    selected_rate_high_mask: AtomicU32,
    descriptor_flags_or: AtomicU32,
    descriptor_queue_word_or: AtomicU32,
    layout_flags_or: AtomicU32,
    next_nonnull: AtomicU32,
    peer_null: AtomicU32,
}

#[cfg(feature = "hil-vendor-tx")]
impl HilTxQueueSearchCounters {
    const fn new() -> Self {
        Self {
            calls: [const { AtomicU32::new(0) }; 5],
            found: [const { AtomicU32::new(0) }; 5],
            input_logical_masks: [const { AtomicU32::new(0) }; 5],
            null_frames: AtomicU32::new(0),
            descriptor_null: AtomicU32::new(0),
            invalid_logical_queue: AtomicU32::new(0),
            logical_queue_mask: AtomicU32::new(0),
            access_type_mask: AtomicU32::new(0),
            queue_class_mask: AtomicU32::new(0),
            queue_owner_mask: AtomicU32::new(0),
            selected_rate_low_mask: AtomicU32::new(0),
            selected_rate_high_mask: AtomicU32::new(0),
            descriptor_flags_or: AtomicU32::new(0),
            descriptor_queue_word_or: AtomicU32::new(0),
            layout_flags_or: AtomicU32::new(0),
            next_nonnull: AtomicU32::new(0),
            peer_null: AtomicU32::new(0),
        }
    }
}

#[cfg(feature = "hil-vendor-tx")]
#[link_section = ".critical.bss.wifi_strict.tx_queue_search_hil"]
static HIL_COUNTERS: HilTxQueueSearchCounters = HilTxQueueSearchCounters::new();

#[cfg(feature = "hil-vendor-tx")]
pub fn hil_tx_queue_search_snapshot() -> HilTxQueueSearchSnapshot {
    let counters = &HIL_COUNTERS;
    HilTxQueueSearchSnapshot {
        calls: core::array::from_fn(|index| counters.calls[index].load(Ordering::Acquire)),
        found: core::array::from_fn(|index| counters.found[index].load(Ordering::Acquire)),
        input_logical_masks: core::array::from_fn(|index| {
            counters.input_logical_masks[index].load(Ordering::Acquire)
        }),
        null_frames: counters.null_frames.load(Ordering::Acquire),
        descriptor_null: counters.descriptor_null.load(Ordering::Acquire),
        invalid_logical_queue: counters.invalid_logical_queue.load(Ordering::Acquire),
        logical_queue_mask: counters.logical_queue_mask.load(Ordering::Acquire),
        access_type_mask: counters.access_type_mask.load(Ordering::Acquire),
        queue_class_mask: counters.queue_class_mask.load(Ordering::Acquire),
        queue_owner_mask: counters.queue_owner_mask.load(Ordering::Acquire),
        selected_rate_low_mask: counters.selected_rate_low_mask.load(Ordering::Acquire),
        selected_rate_high_mask: counters.selected_rate_high_mask.load(Ordering::Acquire),
        descriptor_flags_or: counters.descriptor_flags_or.load(Ordering::Acquire),
        descriptor_queue_word_or: counters.descriptor_queue_word_or.load(Ordering::Acquire),
        layout_flags_or: counters.layout_flags_or.load(Ordering::Acquire),
        next_nonnull: counters.next_nonnull.load(Ordering::Acquire),
        peer_null: counters.peer_null.load(Ordering::Acquire),
    }
}

/// Call the pinned selector once and capture the returned frame topology.
///
/// This is a temporary HIL oracle. It does not change queue ownership or make
/// the vendor selector acceptable to the final strict audit.
///
/// # Safety
///
/// Must run under the same single radio owner as `ppProcessTxQ`.
#[cfg(feature = "hil-vendor-tx")]
#[link_section = ".rwtext.wifi_strict.tx_queue_search_hil"]
pub unsafe extern "C" fn hil_tx_queue_search(queue: u8) -> *mut u8 {
    let input = usize::from(queue);
    if input < HIL_COUNTERS.calls.len() {
        HIL_COUNTERS.calls[input].fetch_add(1, Ordering::Relaxed);
    }

    let frame = __real_ppSearchTxframe(queue);
    if frame.is_null() {
        HIL_COUNTERS.null_frames.fetch_add(1, Ordering::Relaxed);
        return frame;
    }
    if input < HIL_COUNTERS.found.len() {
        HIL_COUNTERS.found[input].fetch_add(1, Ordering::Relaxed);
    }

    HIL_COUNTERS.layout_flags_or.fetch_or(
        frame.add(TX_FRAME_LAYOUT_FLAGS_OFFSET).cast::<u32>().read(),
        Ordering::Relaxed,
    );
    if !frame
        .add(TX_FRAME_NEXT_OFFSET)
        .cast::<*mut u8>()
        .read()
        .is_null()
    {
        HIL_COUNTERS.next_nonnull.fetch_add(1, Ordering::Relaxed);
    }
    if frame.add(0x2c).cast::<*mut u8>().read().is_null() {
        HIL_COUNTERS.peer_null.fetch_add(1, Ordering::Relaxed);
    }

    let descriptor = frame
        .add(TX_FRAME_DESCRIPTOR_OFFSET)
        .cast::<*mut u8>()
        .read();
    if descriptor.is_null() {
        HIL_COUNTERS.descriptor_null.fetch_add(1, Ordering::Relaxed);
        return frame;
    }
    HIL_COUNTERS
        .descriptor_flags_or
        .fetch_or(descriptor.cast::<u32>().read(), Ordering::Relaxed);
    let queue_word = descriptor
        .add(TX_DESCRIPTOR_QUEUE_WORD_OFFSET)
        .cast::<u32>()
        .read();
    HIL_COUNTERS
        .descriptor_queue_word_or
        .fetch_or(queue_word, Ordering::Relaxed);

    let logical_queue = ((queue_word >> 20) & 0x0f) as usize;
    let logical_bit = 1_u32 << logical_queue;
    HIL_COUNTERS
        .logical_queue_mask
        .fetch_or(logical_bit, Ordering::Relaxed);
    if input < HIL_COUNTERS.input_logical_masks.len() {
        HIL_COUNTERS.input_logical_masks[input].fetch_or(logical_bit, Ordering::Relaxed);
    }

    let txrx = ptr::addr_of!(pTxRx).read();
    if txrx.is_null() || logical_queue >= 16 {
        HIL_COUNTERS
            .invalid_logical_queue
            .fetch_add(1, Ordering::Relaxed);
        return frame;
    }
    let entry = txrx.add(logical_queue * TXRX_QUEUE_SIZE);
    for (counter, value) in [
        (&HIL_COUNTERS.access_type_mask, entry.add(0x2c).read()),
        (&HIL_COUNTERS.queue_class_mask, entry.add(0x2d).read()),
        (&HIL_COUNTERS.queue_owner_mask, entry.add(0x2e).read()),
    ] {
        if value < 32 {
            counter.fetch_or(1_u32 << value, Ordering::Relaxed);
        }
    }

    let rate = descriptor.add(TX_DESCRIPTOR_SELECTED_RATE_OFFSET).read();
    if rate < 32 {
        HIL_COUNTERS
            .selected_rate_low_mask
            .fetch_or(1_u32 << rate, Ordering::Relaxed);
    } else if rate < 64 {
        HIL_COUNTERS
            .selected_rate_high_mask
            .fetch_or(1_u32 << (rate - 32), Ordering::Relaxed);
    }
    frame
}
