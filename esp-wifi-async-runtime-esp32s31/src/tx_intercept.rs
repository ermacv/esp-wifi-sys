//! HIL-only bridge from the prepared vendor MPDU boundary to Rust A-MPDU.
//!
//! This module deliberately remains behind `hil-ampdu-intercept`: it calls the
//! real `ppMapTxQueue`, which is useful for hardware qualification but is not
//! an acceptable final strict-runtime dependency.

use core::{
    cell::UnsafeCell,
    ffi::c_void,
    ptr,
    sync::atomic::{compiler_fence, AtomicBool, AtomicU32, Ordering},
};

use crate::tx_ampdu::TX_AMPDU_SLOT_CAPACITY;

pub(crate) const HIL_AMPDU_INTERCEPT_EVENT: u32 = u32::MAX - 5;

const HIL_HARDWARE_QUEUE: u8 = 2;
const MAX_HIL_SUBFRAMES: usize = 20;
const MAX_HIL_AGGREGATE_LENGTH: u16 = 0x7fff;
const TX_QUEUE_STATE_SIZE: usize = 0x38;
const TX_QUEUE_HARDWARE_INDEX_OFFSET: usize = 0x04;
const TX_QUEUE_STATUS_OFFSET: usize = 0x12;
const TX_QUEUE_KIND_OFFSET: usize = 0x1d;
const FRAME_FIRST_BUFFER_OFFSET: usize = 0x04;
const FRAME_LAYOUT_FLAGS_OFFSET: usize = 0x24;
const FRAME_DESCRIPTOR_OFFSET: usize = 0x34;
const BUFFER_DATA_OFFSET: usize = 0x04;
const DESCRIPTOR_RATE_OFFSET: usize = 0x0c;
const DESCRIPTOR_UNSUPPORTED_MASK: u32 = 0x8060_0000;
const MIN_HIL_MPDU_LENGTH: u32 = 1_200;

unsafe extern "C" {
    fn __real_ppMapTxQueue(frame: *mut u8) -> i32;
    static mut our_instances_ptr: *mut u8;
}

struct InterceptState {
    event_pending: bool,
    waiting_hardware: bool,
    window: u8,
    count: u8,
    retry_prefix: u8,
    frames: [*mut u8; TX_AMPDU_SLOT_CAPACITY],
}

impl InterceptState {
    const fn new() -> Self {
        Self {
            event_pending: false,
            waiting_hardware: false,
            window: 0,
            count: 0,
            retry_prefix: 0,
            frames: [ptr::null_mut(); TX_AMPDU_SLOT_CAPACITY],
        }
    }
}

struct InterceptCell(UnsafeCell<InterceptState>);

unsafe impl Sync for InterceptCell {}

#[link_section = ".critical.bss.wifi_strict.hil_ampdu_intercept"]
static STATE: InterceptCell = InterceptCell(UnsafeCell::new(InterceptState::new()));
// Activation crosses from the Rust RX/management path into the vendor TX
// callback. Keep it atomic even on the single radio hart: interrupts are an
// independent execution context, and an ordinary private bool can otherwise
// be proven permanently false by whole-program LTO.
static ENABLED: AtomicBool = AtomicBool::new(false);
static FAILED: AtomicBool = AtomicBool::new(false);
static RETAINED: AtomicU32 = AtomicU32::new(0);
static SUBMITTED: AtomicU32 = AtomicU32::new(0);
static COMPLETED: AtomicU32 = AtomicU32::new(0);
static SUBFRAMES: AtomicU32 = AtomicU32::new(0);
static READY: AtomicU32 = AtomicU32::new(0);
static ENABLED_CALLS: AtomicU32 = AtomicU32::new(0);
static MAPPED_ZERO: AtomicU32 = AtomicU32::new(0);
static MAPPED_ONE: AtomicU32 = AtomicU32::new(0);
static MAPPED_TWO: AtomicU32 = AtomicU32::new(0);
static MAPPED_OTHER: AtomicU32 = AtomicU32::new(0);
static ELIGIBLE: AtomicU32 = AtomicU32::new(0);
static BELOW_MIN_LENGTH: AtomicU32 = AtomicU32::new(0);
static LAST_MAPPED: AtomicU32 = AtomicU32::new(u32::MAX);
static LAST_DESCRIPTOR: AtomicU32 = AtomicU32::new(0);
static LAST_RATE: AtomicU32 = AtomicU32::new(0);
static LAST_LAYOUT: AtomicU32 = AtomicU32::new(0);
static LAST_FRAME_CONTROL: AtomicU32 = AtomicU32::new(0);
static SUBMIT_QUEUE_STATE: AtomicU32 = AtomicU32::new(0);
static SUBMIT_FRAME: AtomicU32 = AtomicU32::new(0);
static SUBMIT_DESCRIPTOR: AtomicU32 = AtomicU32::new(0);
static SUBMIT_REGISTERS: [AtomicU32; 11] = [const { AtomicU32::new(0) }; 11];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HilAmpduInterceptSnapshot {
    pub enabled: bool,
    pub enabled_calls: u32,
    pub mapped_zero: u32,
    pub mapped_one: u32,
    pub mapped_two: u32,
    pub mapped_other: u32,
    pub eligible: u32,
    pub below_min_length: u32,
    pub last_mapped: u32,
    pub last_descriptor: u32,
    pub last_rate: u8,
    pub last_layout: u16,
    pub last_frame_control: u16,
    pub retained: u32,
    pub submitted: u32,
    pub completed: u32,
    pub subframes: u32,
    pub ready: u32,
    pub failed: bool,
}

pub fn hil_ampdu_intercept_snapshot() -> HilAmpduInterceptSnapshot {
    HilAmpduInterceptSnapshot {
        enabled: unsafe { load_enabled_from_callback_context() },
        enabled_calls: ENABLED_CALLS.load(Ordering::Acquire),
        mapped_zero: MAPPED_ZERO.load(Ordering::Acquire),
        mapped_one: MAPPED_ONE.load(Ordering::Acquire),
        mapped_two: MAPPED_TWO.load(Ordering::Acquire),
        mapped_other: MAPPED_OTHER.load(Ordering::Acquire),
        eligible: ELIGIBLE.load(Ordering::Acquire),
        below_min_length: BELOW_MIN_LENGTH.load(Ordering::Acquire),
        last_mapped: LAST_MAPPED.load(Ordering::Acquire),
        last_descriptor: LAST_DESCRIPTOR.load(Ordering::Acquire),
        last_rate: LAST_RATE.load(Ordering::Acquire) as u8,
        last_layout: LAST_LAYOUT.load(Ordering::Acquire) as u16,
        last_frame_control: LAST_FRAME_CONTROL.load(Ordering::Acquire) as u16,
        retained: RETAINED.load(Ordering::Acquire),
        submitted: SUBMITTED.load(Ordering::Acquire),
        completed: COMPLETED.load(Ordering::Acquire),
        subframes: SUBFRAMES.load(Ordering::Acquire),
        ready: READY.load(Ordering::Acquire),
        failed: FAILED.load(Ordering::Acquire),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HilAmpduHardwareSnapshot {
    /// Packed bytes: hardware queue, software status, queue kind, byte 0x28.
    pub submit_queue_state: u32,
    pub submit_frame: u32,
    pub submit_descriptor: u32,
    /// protection, PPDU control, config, PLCP0, PLCP1, PTI, HTSIG, power,
    /// HT control, data length, and length control captured after enable.
    pub submit_registers: [u32; 11],
    pub live_interrupt_state: u32,
    pub live_complete_state: u32,
    pub live_registers: [u32; 11],
    /// Primary/secondary completion words followed by the three BlockAck
    /// words and the two adjacent completion auxiliaries for TXQ2.
    pub live_completion_registers: [u32; 7],
}

/// Read-only HIL evidence. Mutable queue SRAM is copied to atomics by the
/// radio owner at submission; this accessor reads only those atomics and MMIO,
/// so diagnostics on the network hart cannot race Rust-owned queue state.
pub fn hil_ampdu_hardware_snapshot() -> HilAmpduHardwareSnapshot {
    let mut submit_registers = [0_u32; 11];
    let mut index = 0_usize;
    while index < submit_registers.len() {
        submit_registers[index] = SUBMIT_REGISTERS[index].load(Ordering::Acquire);
        index += 1;
    }
    let live_registers = unsafe { read_hardware_registers() };
    const QUEUE_OFFSET: usize = HIL_HARDWARE_QUEUE as usize * 0x7c;
    HilAmpduHardwareSnapshot {
        submit_queue_state: SUBMIT_QUEUE_STATE.load(Ordering::Acquire),
        submit_frame: SUBMIT_FRAME.load(Ordering::Acquire),
        submit_descriptor: SUBMIT_DESCRIPTOR.load(Ordering::Acquire),
        submit_registers,
        live_interrupt_state: unsafe { (0x2010_4cb4_usize as *const u32).read_volatile() },
        live_complete_state: unsafe { (0x2010_4cbc_usize as *const u32).read_volatile() },
        live_registers,
        live_completion_registers: unsafe {
            [
                ((0x2010_553c_usize - QUEUE_OFFSET) as *const u32).read_volatile(),
                ((0x2010_5540_usize - QUEUE_OFFSET) as *const u32).read_volatile(),
                ((0x2010_5530_usize - QUEUE_OFFSET) as *const u32).read_volatile(),
                ((0x2010_552c_usize - QUEUE_OFFSET) as *const u32).read_volatile(),
                ((0x2010_5528_usize - QUEUE_OFFSET) as *const u32).read_volatile(),
                ((0x2010_5534_usize - QUEUE_OFFSET) as *const u32).read_volatile(),
                ((0x2010_5524_usize - QUEUE_OFFSET) as *const u32).read_volatile(),
            ]
        },
    }
}

unsafe fn read_hardware_registers() -> [u32; 11] {
    const QUEUE_16: usize = HIL_HARDWARE_QUEUE as usize * 0x10;
    const QUEUE_124: usize = HIL_HARDWARE_QUEUE as usize * 0x7c;
    [
        ((0x2010_4d64_usize - QUEUE_16) as *const u32).read_volatile(),
        ((0x2010_4d68_usize - QUEUE_16) as *const u32).read_volatile(),
        ((0x2010_4d6c_usize - QUEUE_16) as *const u32).read_volatile(),
        ((0x2010_4d70_usize - QUEUE_16) as *const u32).read_volatile(),
        ((0x2010_54d8_usize - QUEUE_124) as *const u32).read_volatile(),
        ((0x2010_54e0_usize - QUEUE_124) as *const u32).read_volatile(),
        ((0x2010_54e8_usize - QUEUE_124) as *const u32).read_volatile(),
        ((0x2010_5500_usize - QUEUE_124) as *const u32).read_volatile(),
        ((0x2010_5504_usize - QUEUE_124) as *const u32).read_volatile(),
        ((0x2010_550c_usize - QUEUE_124) as *const u32).read_volatile(),
        ((0x2010_5510_usize - QUEUE_124) as *const u32).read_volatile(),
    ]
}

unsafe fn record_hardware_submit(queue_state: *mut u8) {
    let frame = queue_state.cast::<*mut u8>().read();
    let descriptor = if frame.is_null() {
        ptr::null_mut()
    } else {
        frame.add(FRAME_DESCRIPTOR_OFFSET).cast::<*mut u8>().read()
    };
    let packed = u32::from(queue_state.add(TX_QUEUE_HARDWARE_INDEX_OFFSET).read())
        | (u32::from(queue_state.add(TX_QUEUE_STATUS_OFFSET).read()) << 8)
        | (u32::from(queue_state.add(TX_QUEUE_KIND_OFFSET).read()) << 16)
        | (u32::from(queue_state.add(0x28).read()) << 24);
    SUBMIT_QUEUE_STATE.store(packed, Ordering::Release);
    SUBMIT_FRAME.store(frame as usize as u32, Ordering::Release);
    SUBMIT_DESCRIPTOR.store(descriptor as usize as u32, Ordering::Release);
    let registers = read_hardware_registers();
    let mut index = 0_usize;
    while index < registers.len() {
        SUBMIT_REGISTERS[index].store(registers[index], Ordering::Release);
        index += 1;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxInterceptError {
    PreviousFailure,
    InternalQueueFull,
    ReadyQueueFull,
    InstancesUnavailable,
    InvalidHardwareQueue(u8),
    Aggregate(crate::tx_ampdu::BasicHtAmpduChainError),
    Submit(crate::lmac::LmacAsyncError),
}

/// Enable the laboratory bridge only after Rust has accepted the peer's
/// ADDBA response. No vendor aggregation operational bit is changed.
pub(crate) unsafe fn enable(window: u16) {
    let state = &mut *STATE.0.get();
    state.window = window.clamp(2, TX_AMPDU_SLOT_CAPACITY as u16) as u8;
    ENABLED.store(true, Ordering::Release);
}

/// GNU-ld wrapper around the last vendor preparation leaf used by `ppTxPkt`.
/// Returning a value other than 0/1/2 makes `ppTxPkt` return without inserting
/// the frame into any vendor PP list or recycling it.
#[link_section = ".rwtext.wifi_strict.hil_ampdu_intercept"]
pub unsafe extern "C" fn hil_ampdu_intercept_pp_map_tx_queue(frame: *mut u8) -> i32 {
    let mapped = __real_ppMapTxQueue(frame);
    let state = &mut *STATE.0.get();
    // The activation edge is delivered by a management RX callback that is
    // outside LLVM's ordinary call graph. An explicit RISC-V atomic byte load
    // keeps that external edge visible under fat whole-program LTO.
    let enabled = load_enabled_from_callback_context();
    if !enabled {
        return mapped;
    }
    ENABLED_CALLS.fetch_add(1, Ordering::Relaxed);
    LAST_MAPPED.store(mapped as u32, Ordering::Release);
    match mapped {
        0 => MAPPED_ZERO.fetch_add(1, Ordering::Relaxed),
        1 => MAPPED_ONE.fetch_add(1, Ordering::Relaxed),
        2 => MAPPED_TWO.fetch_add(1, Ordering::Relaxed),
        _ => MAPPED_OTHER.fetch_add(1, Ordering::Relaxed),
    };
    if mapped != 0 || !eligible_qos_data(frame) {
        return mapped;
    }
    ELIGIBLE.fetch_add(1, Ordering::Relaxed);
    if push_ready(state, frame).is_err() {
        fail_and_trap();
    }
    RETAINED.fetch_add(1, Ordering::Relaxed);
    if state.count >= 2 && schedule(state).is_err() {
        fail_and_trap();
    }
    // `ppTxPkt` treats all values except 0, 1 and 2 as an already consumed
    // frame. Ownership is now exclusively in STATE.
    3
}

#[inline(always)]
unsafe fn load_enabled_from_callback_context() -> bool {
    let value: usize;
    core::arch::asm!(
        "lbu {value}, 0({address})",
        value = out(reg) value,
        address = in(reg) ENABLED.as_ptr(),
        options(nostack, readonly),
    );
    compiler_fence(Ordering::Acquire);
    value != 0
}

unsafe fn eligible_qos_data(frame: *mut u8) -> bool {
    if frame.is_null() {
        return false;
    }
    let descriptor = frame.add(FRAME_DESCRIPTOR_OFFSET).cast::<*mut u8>().read();
    if descriptor.is_null() {
        return false;
    }
    let descriptor_word = descriptor.cast::<u32>().read();
    LAST_DESCRIPTOR.store(descriptor_word, Ordering::Release);
    if descriptor_word & DESCRIPTOR_UNSUPPORTED_MASK != 0 {
        return false;
    }
    let rate = descriptor.add(DESCRIPTOR_RATE_OFFSET).read();
    LAST_RATE.store(u32::from(rate), Ordering::Release);
    if !(16..=35).contains(&rate) {
        return false;
    }
    let first_buffer = frame
        .add(FRAME_FIRST_BUFFER_OFFSET)
        .cast::<*mut u8>()
        .read();
    if first_buffer.is_null() {
        return false;
    }
    let mut header = first_buffer
        .add(BUFFER_DATA_OFFSET)
        .cast::<*mut u8>()
        .read();
    if header.is_null() {
        return false;
    }
    let layout = frame.add(FRAME_LAYOUT_FLAGS_OFFSET).cast::<u16>().read();
    LAST_LAYOUT.store(u32::from(layout), Ordering::Release);
    // The qualified oracle is the strict CCMP layout with an eight-byte PP
    // prefix and MPDUs large enough to form the captured >=2500-byte
    // aggregate. Leave short control-plane traffic on the proven one-frame
    // path until its A-MPDU hardware format is independently qualified.
    if layout & 0x2000 == 0 {
        return false;
    }
    let mpdu_length = header.cast::<u32>().read() & 0x3fff;
    if mpdu_length < MIN_HIL_MPDU_LENGTH {
        BELOW_MIN_LENGTH.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    header = header.add(8);
    let frame_control = header.cast::<u16>().read_unaligned();
    LAST_FRAME_CONTROL.store(u32::from(frame_control), Ordering::Release);
    frame_control & 0x008c == 0x0088
}

unsafe fn push_ready(state: &mut InterceptState, frame: *mut u8) -> Result<(), TxInterceptError> {
    let index = usize::from(state.count);
    if index >= TX_AMPDU_SLOT_CAPACITY {
        return Err(TxInterceptError::ReadyQueueFull);
    }
    state.frames[index] = frame;
    state.count = state.count.wrapping_add(1);
    READY.store(u32::from(state.count), Ordering::Release);
    Ok(())
}

unsafe fn push_retry_front(
    state: &mut InterceptState,
    frame: *mut u8,
) -> Result<(), TxInterceptError> {
    let count = usize::from(state.count);
    if count >= TX_AMPDU_SLOT_CAPACITY {
        return Err(TxInterceptError::ReadyQueueFull);
    }
    let insertion = usize::from(state.retry_prefix);
    let mut index = count;
    while index != insertion {
        state.frames[index] = state.frames[index - 1];
        index -= 1;
    }
    state.frames[insertion] = frame;
    state.count = state.count.wrapping_add(1);
    state.retry_prefix = state.retry_prefix.wrapping_add(1);
    READY.store(u32::from(state.count), Ordering::Release);
    Ok(())
}

fn schedule(state: &mut InterceptState) -> Result<(), TxInterceptError> {
    if state.event_pending {
        return Ok(());
    }
    if !crate::adapter::enqueue_internal_event(crate::event::PpEvent {
        kind: HIL_AMPDU_INTERCEPT_EVENT,
        argument: ptr::null_mut::<c_void>(),
    }) {
        return Err(TxInterceptError::InternalQueueFull);
    }
    state.event_pending = true;
    Ok(())
}

pub(crate) const fn is_event(kind: u32) -> bool {
    kind == HIL_AMPDU_INTERCEPT_EVENT
}

#[link_section = ".rwtext.wifi_strict.hil_ampdu_intercept"]
pub(crate) unsafe fn dispatch() -> Result<(), TxInterceptError> {
    if FAILED.load(Ordering::Acquire) {
        return Err(TxInterceptError::PreviousFailure);
    }
    let state = &mut *STATE.0.get();
    state.event_pending = false;

    // Completion transfers at most one retry into this queue per executor
    // event. The following event either transfers another or submits a batch.
    if let Some(retry) = crate::lmac::take_basic_ht_ampdu_retry() {
        let _sequence = retry.sequence;
        push_retry_front(state, retry.frame)?;
        schedule(state)?;
        return Ok(());
    }
    if state.count < 2 || state.waiting_hardware {
        return Ok(());
    }

    let instances = ptr::addr_of!(our_instances_ptr).read();
    if instances.is_null() {
        return fail(TxInterceptError::InstancesUnavailable);
    }
    let queue_state = instances.add(usize::from(HIL_HARDWARE_QUEUE) * TX_QUEUE_STATE_SIZE);
    let hardware_queue = queue_state.add(TX_QUEUE_HARDWARE_INDEX_OFFSET).read();
    if hardware_queue != HIL_HARDWARE_QUEUE {
        return fail(TxInterceptError::InvalidHardwareQueue(hardware_queue));
    }
    if queue_state.add(TX_QUEUE_STATUS_OFFSET).read() != 0 {
        state.waiting_hardware = true;
        return Ok(());
    }

    let count = usize::from(state.count);
    let mut selected = count.min(usize::from(state.window)).min(MAX_HIL_SUBFRAMES);
    let first_descriptor = state.frames[0]
        .add(FRAME_DESCRIPTOR_OFFSET)
        .cast::<*mut u8>()
        .read();
    let first_rate = first_descriptor.add(DESCRIPTOR_RATE_OFFSET).read();
    let mut index = 1_usize;
    while index < selected {
        let descriptor = state.frames[index]
            .add(FRAME_DESCRIPTOR_OFFSET)
            .cast::<*mut u8>()
            .read();
        if descriptor.is_null() || descriptor.add(DESCRIPTOR_RATE_OFFSET).read() != first_rate {
            selected = index;
            break;
        }
        index += 1;
    }
    if selected < 2 {
        return Ok(());
    }

    let chain = crate::tx_ampdu::prepare_basic_ht_ampdu_chain(
        &state.frames[..selected],
        MAX_HIL_AGGREGATE_LENGTH,
    )
    .map_err(TxInterceptError::Aggregate)?;
    if let Err(error) = crate::lmac::submit_basic_ht_ampdu(queue_state, chain) {
        // Submission validates queue/descriptor state before ownership
        // transfer. A failure after preparation is fatal for this laboratory
        // bridge; silently falling back would duplicate frame ownership.
        return fail(TxInterceptError::Submit(error));
    }
    record_hardware_submit(queue_state);

    let remaining = count - selected;
    let mut source = selected;
    while source < count {
        state.frames[source - selected] = state.frames[source];
        source += 1;
    }
    let mut clear = remaining;
    while clear < count {
        state.frames[clear] = ptr::null_mut();
        clear += 1;
    }
    state.count = remaining as u8;
    state.retry_prefix = state.retry_prefix.saturating_sub(selected as u8);
    state.waiting_hardware = true;
    READY.store(remaining as u32, Ordering::Release);
    SUBMITTED.fetch_add(1, Ordering::Relaxed);
    SUBFRAMES.fetch_add(selected as u32, Ordering::Relaxed);
    Ok(())
}

/// Called by the Rust BlockAck completion after it has retained every missing
/// MPDU. It only posts a private executor event; it never submits recursively.
pub(crate) fn on_hardware_completion() -> Result<(), TxInterceptError> {
    let state = unsafe { &mut *STATE.0.get() };
    state.waiting_hardware = false;
    COMPLETED.fetch_add(1, Ordering::Relaxed);
    schedule(state)
}

fn fail<T>(error: TxInterceptError) -> Result<T, TxInterceptError> {
    FAILED.store(true, Ordering::Release);
    Err(error)
}

#[inline(always)]
unsafe fn fail_and_trap() -> ! {
    FAILED.store(true, Ordering::Release);
    core::arch::asm!("ebreak", options(noreturn))
}
