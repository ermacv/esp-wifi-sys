//! Strict TX-queue processing boundary.
//!
//! The first stage is deliberately an observation wrapper around the pinned
//! finite `ppProcessTxQ` body. It records the exact post-selection frame and
//! queue state exercised by WPA2 STA before that state machine is replaced by
//! one Rust executor action.

use core::{
    ptr,
    sync::atomic::{AtomicU32, Ordering},
};

const TX_QUEUE_STATE_SIZE: usize = 0x38;
const TX_QUEUE_HARDWARE_INDEX_OFFSET: usize = 0x04;
const TX_QUEUE_STATUS_OFFSET: usize = 0x12;
const TX_QUEUE_KIND_OFFSET: usize = 0x1d;
const TX_FRAME_NEXT_OFFSET: usize = 0x30;
const TX_FRAME_DESCRIPTOR_OFFSET: usize = 0x34;
const TX_FRAME_LAYOUT_FLAGS_OFFSET: usize = 0x24;
const TX_DESCRIPTOR_SELECTED_RATE_OFFSET: usize = 0x0c;
const TX_DESCRIPTOR_QUEUE_WORD_OFFSET: usize = 0x10;

unsafe extern "C" {
    static mut our_instances_ptr: *mut u8;
    fn ppProcessTxQ(queue: u8) -> i32;
}

/// HIL evidence captured immediately after one vendor TX-queue action returns.
///
/// `submitted` is the exact return-zero path that reached `lmacTxFrame`.
/// `input_logical_masks[event]` maps PP events 0..=4 to the descriptor queue
/// numbers actually installed in the matching hardware-queue SRAM state.
#[cfg(feature = "hil-vendor-tx")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HilTxQueueProcessSnapshot {
    pub calls: [u32; 5],
    pub submitted: [u32; 5],
    pub idle_or_disallowed: [u32; 5],
    pub no_frame: [u32; 5],
    pub unexpected_result: u32,
    pub input_logical_masks: [u32; 5],
    pub frame_null_after_submit: u32,
    pub descriptor_null: u32,
    pub hardware_queue_mask: u32,
    pub queue_status_mask: u32,
    pub queue_kind_mask: u32,
    pub logical_queue_mask: u32,
    pub selected_rate_low_mask: u32,
    pub selected_rate_high_mask: u32,
    pub descriptor_flags_or: u32,
    pub descriptor_queue_word_or: u32,
    pub layout_flags_or: u32,
    pub next_nonnull: u32,
    pub peer_null: u32,
}

#[cfg(feature = "hil-vendor-tx")]
struct HilTxQueueProcessCounters {
    calls: [AtomicU32; 5],
    submitted: [AtomicU32; 5],
    idle_or_disallowed: [AtomicU32; 5],
    no_frame: [AtomicU32; 5],
    unexpected_result: AtomicU32,
    input_logical_masks: [AtomicU32; 5],
    frame_null_after_submit: AtomicU32,
    descriptor_null: AtomicU32,
    hardware_queue_mask: AtomicU32,
    queue_status_mask: AtomicU32,
    queue_kind_mask: AtomicU32,
    logical_queue_mask: AtomicU32,
    selected_rate_low_mask: AtomicU32,
    selected_rate_high_mask: AtomicU32,
    descriptor_flags_or: AtomicU32,
    descriptor_queue_word_or: AtomicU32,
    layout_flags_or: AtomicU32,
    next_nonnull: AtomicU32,
    peer_null: AtomicU32,
}

#[cfg(feature = "hil-vendor-tx")]
impl HilTxQueueProcessCounters {
    const fn new() -> Self {
        Self {
            calls: [const { AtomicU32::new(0) }; 5],
            submitted: [const { AtomicU32::new(0) }; 5],
            idle_or_disallowed: [const { AtomicU32::new(0) }; 5],
            no_frame: [const { AtomicU32::new(0) }; 5],
            unexpected_result: AtomicU32::new(0),
            input_logical_masks: [const { AtomicU32::new(0) }; 5],
            frame_null_after_submit: AtomicU32::new(0),
            descriptor_null: AtomicU32::new(0),
            hardware_queue_mask: AtomicU32::new(0),
            queue_status_mask: AtomicU32::new(0),
            queue_kind_mask: AtomicU32::new(0),
            logical_queue_mask: AtomicU32::new(0),
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
#[link_section = ".critical.bss.wifi_strict.tx_queue_process_hil"]
static HIL_COUNTERS: HilTxQueueProcessCounters = HilTxQueueProcessCounters::new();

#[cfg(feature = "hil-vendor-tx")]
pub fn hil_tx_queue_process_snapshot() -> HilTxQueueProcessSnapshot {
    let counters = &HIL_COUNTERS;
    HilTxQueueProcessSnapshot {
        calls: load_array(&counters.calls),
        submitted: load_array(&counters.submitted),
        idle_or_disallowed: load_array(&counters.idle_or_disallowed),
        no_frame: load_array(&counters.no_frame),
        unexpected_result: counters.unexpected_result.load(Ordering::Acquire),
        input_logical_masks: load_array(&counters.input_logical_masks),
        frame_null_after_submit: counters.frame_null_after_submit.load(Ordering::Acquire),
        descriptor_null: counters.descriptor_null.load(Ordering::Acquire),
        hardware_queue_mask: counters.hardware_queue_mask.load(Ordering::Acquire),
        queue_status_mask: counters.queue_status_mask.load(Ordering::Acquire),
        queue_kind_mask: counters.queue_kind_mask.load(Ordering::Acquire),
        logical_queue_mask: counters.logical_queue_mask.load(Ordering::Acquire),
        selected_rate_low_mask: counters.selected_rate_low_mask.load(Ordering::Acquire),
        selected_rate_high_mask: counters.selected_rate_high_mask.load(Ordering::Acquire),
        descriptor_flags_or: counters.descriptor_flags_or.load(Ordering::Acquire),
        descriptor_queue_word_or: counters.descriptor_queue_word_or.load(Ordering::Acquire),
        layout_flags_or: counters.layout_flags_or.load(Ordering::Acquire),
        next_nonnull: counters.next_nonnull.load(Ordering::Acquire),
        peer_null: counters.peer_null.load(Ordering::Acquire),
    }
}

#[cfg(feature = "hil-vendor-tx")]
fn load_array(counters: &[AtomicU32; 5]) -> [u32; 5] {
    core::array::from_fn(|index| counters[index].load(Ordering::Acquire))
}

/// Run one unchanged vendor TX-queue action and record its returned state.
///
/// This is a temporary HIL oracle. The `ppProcessTxQ` call remains an explicit
/// strict-audit root until the measured state transition is reproduced in
/// Rust.
///
/// # Safety
///
/// Must run under the same single radio owner as the original PP dispatcher.
#[cfg(feature = "hil-vendor-tx")]
#[link_section = ".rwtext.wifi_strict.tx_queue_process_hil"]
pub unsafe fn hil_process_tx_queue(queue: u8) {
    let input = usize::from(queue);
    if input < HIL_COUNTERS.calls.len() {
        HIL_COUNTERS.calls[input].fetch_add(1, Ordering::Relaxed);
    }

    let result = ppProcessTxQ(queue);
    let result_counters = match result {
        0 => &HIL_COUNTERS.submitted,
        -1 => &HIL_COUNTERS.idle_or_disallowed,
        -2 => &HIL_COUNTERS.no_frame,
        _ => {
            HIL_COUNTERS
                .unexpected_result
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    if input < result_counters.len() {
        result_counters[input].fetch_add(1, Ordering::Relaxed);
    }
    if result != 0 {
        return;
    }

    let instances = ptr::addr_of!(our_instances_ptr).read();
    if instances.is_null() || input >= 5 {
        HIL_COUNTERS
            .frame_null_after_submit
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    let queue_state = instances.add(input * TX_QUEUE_STATE_SIZE);
    record_small_mask(
        &HIL_COUNTERS.hardware_queue_mask,
        queue_state.add(TX_QUEUE_HARDWARE_INDEX_OFFSET).read(),
    );
    record_small_mask(
        &HIL_COUNTERS.queue_status_mask,
        queue_state.add(TX_QUEUE_STATUS_OFFSET).read(),
    );
    record_small_mask(
        &HIL_COUNTERS.queue_kind_mask,
        queue_state.add(TX_QUEUE_KIND_OFFSET).read(),
    );

    let frame = queue_state.cast::<*mut u8>().read();
    if frame.is_null() {
        HIL_COUNTERS
            .frame_null_after_submit
            .fetch_add(1, Ordering::Relaxed);
        return;
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
        return;
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

    let logical_queue = ((queue_word >> 20) & 0x0f) as u8;
    let logical_bit = 1_u32 << logical_queue;
    HIL_COUNTERS
        .logical_queue_mask
        .fetch_or(logical_bit, Ordering::Relaxed);
    HIL_COUNTERS.input_logical_masks[input].fetch_or(logical_bit, Ordering::Relaxed);

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
}

#[cfg(feature = "hil-vendor-tx")]
fn record_small_mask(counter: &AtomicU32, value: u8) {
    if value < 32 {
        counter.fetch_or(1_u32 << value, Ordering::Relaxed);
    }
}
