use core::{
    cell::UnsafeCell,
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{adapter::schedule_internal_timer, timer::RawOsiTimer};

pub(crate) const TX_DISCARD_CONTINUATION: u32 = u32::MAX - 1;

const TX_DISABLE_SETTLE_US: u32 = 16;
const TXQ_INTERRUPT_CLEAR_REG: *mut u32 = 0x2010_4cb0 as *mut u32;
const TXQ_INTERRUPT_STATE_REG: *const u32 = 0x2010_4cb4 as *const u32;
const TXQ_COMPLETE_STATE_REG: *const u32 = 0x2010_4cbc as *const u32;
const TX_QUEUE_STATE_SIZE: usize = 0x38;
const TX_QUEUE_STATUS_OFFSET: usize = 0x12;
const TX_QUEUE_KIND_OFFSET: usize = 0x1d;
const TX_QUEUE_DROP_COUNT_OFFSET: usize = 0x24;
const TX_FRAME_DESCRIPTOR_OFFSET: usize = 0x34;
const TX_FRAME_NEXT_OFFSET: usize = 0x30;
const TX_DESCRIPTOR_REASON_OFFSET: usize = 0x13;
const TX_DESCRIPTOR_QUEUE_WORD_OFFSET: usize = 0x10;
const TX_FRAME_ABORTED_BIT: u32 = 0x0002_0000;
const TX_FRAME_BAR_BIT: u32 = 0x0020_0000;
const TX_FRAME_AMPDU_BIT: u32 = 0x0040_0000;
const TX_FRAME_HE_BIT: u32 = 0x8000_0000;
const TX_FRAME_DEQUEUE_MASK: u32 = 0x0000_00c0;
const TX_FRAME_DEQUEUE_VALUE: u32 = 0x0000_0080;
const TXRX_QUEUE_SIZE: usize = 0x34;
const TXRX_QUEUE_HEAD_OFFSET: usize = 0x20;
const TXRX_QUEUE_TAIL_LINK_OFFSET: usize = 0x24;

const DISCARD_IDLE: u8 = 0;
const DISCARD_FIND_TAIL: u8 = 1;
const DISCARD_FRAME: u8 = 2;
const DISCARD_WAIT_TX_DONE: u8 = 3;

unsafe extern "C" {
    static mut our_instances_ptr: *mut u8;
    static mut pTxRx: *mut u8;
    static lmacConfMib: [u8; 48];

    fn hal_mac_tx_set_cca(value: u32);
    fn hal_mac_get_txq_state(kind: u32) -> u32;
    #[link_name = "hal_mac_get_txq_complete"]
    fn vendor_hal_mac_get_txq_complete(
        queue_state: *mut u8,
        queue: u8,
        completion: *mut u8,
        auxiliary: *mut u8,
    ) -> i32;
    fn hal_mac_is_txq_valid(queue: u8) -> u32;
    fn hal_mac_set_txq_invalid(queue: u8);
    fn hal_mac_txq_disable(queue: u8);
    fn lmacReleaseTxopQueue(queue: u8);
    fn lmacTxDone(frame: *mut c_void, mode: u32);
    fn pp_post(kind: u32, argument: *mut c_void) -> i32;
    fn ppDequeueTxQ(queue: u8) -> *mut u8;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LmacAsyncError {
    InstancesUnavailable,
    TimerUnavailable,
    InternalQueueFull,
    PreviousContinuationFailure,
    UnsupportedAggregatedFrame(u32),
    TxRxUnavailable,
    InvalidDiscardContinuation,
    TxDone(crate::txdone::TxDoneError),
    TxQueueSplitFailed,
}

#[derive(Clone, Copy)]
struct TxTimeoutState {
    active: bool,
    pending: bool,
    failed: bool,
    remaining: u32,
    current_queue: u8,
    discard_phase: u8,
    discard_reason: u8,
    queue_state: *mut u8,
    discard_frame: *mut u8,
    discard_tail: *mut u8,
}

impl TxTimeoutState {
    const fn new() -> Self {
        Self {
            active: false,
            pending: false,
            failed: false,
            remaining: 0,
            current_queue: 0,
            discard_phase: DISCARD_IDLE,
            discard_reason: 0,
            queue_state: ptr::null_mut(),
            discard_frame: ptr::null_mut(),
            discard_tail: ptr::null_mut(),
        }
    }
}

struct StateCell(UnsafeCell<TxTimeoutState>);

unsafe impl Sync for StateCell {}

struct TimerCell(UnsafeCell<RawOsiTimer>);

impl TimerCell {
    const fn new() -> Self {
        Self(UnsafeCell::new(RawOsiTimer {
            next: ptr::null_mut(),
            expire: 0,
            period: 0,
            callback: None,
            argument: ptr::null_mut(),
        }))
    }
}

unsafe impl Sync for TimerCell {}

static STATE: StateCell = StateCell(UnsafeCell::new(TxTimeoutState::new()));
static TIMER: TimerCell = TimerCell::new();
static TXQ_SPLIT_FAILED: AtomicBool = AtomicBool::new(false);

/// Final-link replacement for `hal_mac_get_txq_state`. The vendor complete
/// and collision handlers consume every returned bitmap bit in one call. The
/// strict wrapper exposes exactly one bit and posts another PP event for the
/// remainder, turning that loop into executor-visible continuations. It also
/// bypasses the original statistics/logging hooks.
#[no_mangle]
pub unsafe extern "C" fn __wrap_hal_mac_get_txq_state(kind: u32) -> u32 {
    let (bits, continuation) = match kind {
        0 => (TXQ_INTERRUPT_STATE_REG.read_volatile() & 0x0f, 24),
        1 => return (TXQ_INTERRUPT_STATE_REG.read_volatile() >> 16) & 0x0f,
        2 => (TXQ_COMPLETE_STATE_REG.read_volatile() & 0x0f, 23),
        _ => return 0,
    };
    if bits == 0 {
        return 0;
    }
    let one = 1_u32 << bits.trailing_zeros();
    if bits & !one != 0 && pp_post(continuation, ptr::null_mut()) != 0 {
        TXQ_SPLIT_FAILED.store(true, Ordering::Release);
        return 0;
    }
    one
}

/// Strict basic-HT replacement for the 0x81e-byte vendor completion reader.
///
/// The stock body starts with these fixed register decodes, then enters HE
/// MPLEN maintenance, connection-state queries, formatters, and debug logs.
/// Strict STA advertises HT rather than HE and keeps AMPDU/AMSDU disabled, so
/// those tails are forbidden invariants rather than required completion work.
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.txq_complete"]
pub unsafe extern "C" fn __wrap_hal_mac_get_txq_complete(
    queue_state: *mut u8,
    queue: u8,
    completion: *mut u8,
    auxiliary: *mut u8,
) -> i32 {
    if queue >= 4 || queue_state.is_null() || completion.is_null() {
        reject_txq_completion();
    }

    // Match the stock ABI even though every byte is overwritten below. This
    // also makes future extensions deterministic if another completion field
    // is recovered from the pinned body.
    completion.write(0);
    completion.add(1).write(0);
    completion.add(2).write(0);
    completion.add(3).write(0);
    completion.add(4).write(0);
    completion.add(5).write(0);
    if !auxiliary.is_null() {
        auxiliary.cast::<u32>().write(0);
        auxiliary.add(4).cast::<u32>().write(0);
    }

    let frame = queue_state.cast::<*mut u8>().read();
    if frame.is_null() {
        reject_txq_completion();
    }
    let descriptor = frame
        .add(TX_FRAME_DESCRIPTOR_OFFSET)
        .cast::<*mut u32>()
        .read();
    if descriptor.is_null()
        || descriptor.read() & (TX_FRAME_HE_BIT | TX_FRAME_BAR_BIT | TX_FRAME_AMPDU_BIT) != 0
    {
        reject_txq_completion();
    }

    // `hal_mac_tx_clr_mplen` is a no-op unless this per-queue bit is set. A
    // set bit would make its linked-list walk and HE callbacks reachable.
    let mplen_state = (0x2010_4d68_usize - usize::from(queue) * 0x10) as *const u32;
    if mplen_state.read_volatile() & 0x08 != 0 {
        reject_txq_completion();
    }

    let queue_offset = usize::from(queue) * 0x7c;
    let primary = (0x2010_553c_usize - queue_offset) as *const u32;
    let secondary = (0x2010_5540_usize - queue_offset) as *const u32;
    let primary_word = primary.read_volatile();
    let secondary_word = secondary.read_volatile();

    let use_secondary = if auxiliary.is_null() {
        false
    } else {
        let completion_aux = decode_txq_completion_auxiliary(queue_offset);
        auxiliary.cast::<u32>().write(completion_aux.0);
        auxiliary.add(4).cast::<u32>().write(completion_aux.1);
        completion_aux.0 & 0x0010_0000 != 0
    };
    let status = if use_secondary {
        secondary_word
    } else {
        primary_word
    };

    completion.write(status as u8);
    completion.add(1).write((status >> 8) as u8);
    completion.add(2).write((primary_word >> 16) as u8);
    completion.add(3).write(((primary_word >> 25) & 0x03) as u8);
    let signed_metric = ((secondary_word >> 24) & 0x7f) as u8;
    completion.add(4).write(if signed_metric & 0x40 != 0 {
        signed_metric.wrapping_sub(0x80)
    } else {
        signed_metric
    });
    completion.add(5).write((secondary_word >> 16) as u8);

    0
}

#[inline(always)]
unsafe fn reject_txq_completion() -> ! {
    // The vendor caller discards this function's return value and immediately
    // interprets the completion bytes. Returning an error could therefore
    // turn an unsupported descriptor into a false success. Record the fault
    // and stop at the exact boundary instead.
    TXQ_SPLIT_FAILED.store(true, Ordering::Release);
    core::arch::asm!("ebreak", options(noreturn))
}

unsafe fn decode_txq_completion_auxiliary(queue_offset: usize) -> (u32, u32) {
    let status_534 = ((0x2010_5534_usize - queue_offset) as *const u32).read_volatile();
    let status_524 = ((0x2010_5524_usize - queue_offset) as *const u32).read_volatile();
    let status_54c = ((0x2010_554c_usize - queue_offset) as *const u32).read_volatile();

    let mut word0 = (status_534 & 0x000f_0000) << 12;
    word0 |= status_524 & 0x000f_e000;
    word0 |= status_524 & 0x0010_0000;
    word0 |= (status_524 >> 25) << 21;
    let mut word1 = (status_534 >> 20) & 0x03;
    word1 |= (status_54c >> 5) & 0x01fc;
    (word0, word1)
}

pub(crate) fn txq_split_failed() -> bool {
    TXQ_SPLIT_FAILED.load(Ordering::Acquire)
}

pub(crate) fn runtime_tx_link_wrappers_active() -> bool {
    core::ptr::eq(
        hal_mac_get_txq_state as *const (),
        __wrap_hal_mac_get_txq_state as *const (),
    ) && core::ptr::eq(
        vendor_hal_mac_get_txq_complete as *const (),
        __wrap_hal_mac_get_txq_complete as *const (),
    ) && core::ptr::eq(
        lmacTxDone as *const (),
        crate::txdone::__wrap_lmacTxDone as *const (),
    ) && crate::txdone::runtime_callback_link_wrappers_active()
}

/// Start the async replacement for PP event 22 (`lmacProcessTxTimeout`).
///
/// Each active TX queue becomes a separate two-phase continuation around the
/// original 16-us hardware settling interval. Repeated timeout events are
/// coalesced and re-sample hardware state after the active pass completes.
///
/// # Safety
/// Must run under the single radio owner with the pinned S31 archive. The
/// hardware adapter must have installed the executor-driven timer clock.
pub unsafe fn begin_tx_timeout() -> Result<(), LmacAsyncError> {
    let state = &mut *STATE.0.get();
    if state.failed {
        return Err(LmacAsyncError::PreviousContinuationFailure);
    }
    if state.active {
        state.pending = true;
        return Ok(());
    }
    start_pass(state)
}

unsafe fn start_pass(state: &mut TxTimeoutState) -> Result<(), LmacAsyncError> {
    // `hal_mac_get_txq_state(1)` is just this field plus optional test/log
    // hooks. Calling it would make logging callbacks reachable in strict mode.
    state.remaining = (TXQ_INTERRUPT_STATE_REG.read_volatile() >> 16) & 0x0f;
    if state.remaining == 0 {
        state.active = false;
        state.pending = false;
        return Ok(());
    }
    state.active = true;
    arm_next_queue(state)
}

unsafe fn arm_next_queue(state: &mut TxTimeoutState) -> Result<(), LmacAsyncError> {
    let queue = state.remaining.trailing_zeros() as u8;
    state.remaining &= !(1u32 << queue);
    state.current_queue = queue;

    hal_mac_tx_set_cca(3);
    if !schedule_internal_timer(
        TIMER.0.get().cast(),
        tx_disable_settled,
        ptr::null_mut(),
        TX_DISABLE_SETTLE_US,
    ) {
        state.failed = true;
        state.active = false;
        hal_mac_tx_set_cca(0);
        return Err(LmacAsyncError::TimerUnavailable);
    }
    Ok(())
}

unsafe extern "C" fn tx_disable_settled(_argument: *mut c_void) {
    let state = &mut *STATE.0.get();
    match finish_queue(state, state.current_queue) {
        Ok(true) => finish_current_queue(state),
        Ok(false) => {}
        Err(_) => fail(state),
    }
}

unsafe fn finish_current_queue(state: &mut TxTimeoutState) {
    TXQ_INTERRUPT_CLEAR_REG.write_volatile(1u32 << (state.current_queue + 16));

    let result = if state.remaining != 0 {
        arm_next_queue(state)
    } else if state.pending {
        state.pending = false;
        start_pass(state)
    } else {
        state.active = false;
        Ok(())
    };
    if result.is_err() {
        fail(state);
    }
}

unsafe fn fail(state: &mut TxTimeoutState) {
    state.failed = true;
    state.active = false;
    state.discard_phase = DISCARD_IDLE;
}

unsafe fn finish_queue(state: &mut TxTimeoutState, queue: u8) -> Result<bool, LmacAsyncError> {
    let instances = ptr::addr_of!(our_instances_ptr).read();
    if instances.is_null() {
        hal_mac_tx_set_cca(0);
        return Err(LmacAsyncError::InstancesUnavailable);
    }

    let queue_state = instances.add(usize::from(queue) * TX_QUEUE_STATE_SIZE);
    let frame = queue_state.cast::<*mut u8>().read();
    let was_valid = hal_mac_is_txq_valid(queue) != 0;
    hal_mac_set_txq_invalid(queue);
    hal_mac_tx_set_cca(0);

    if was_valid {
        hal_mac_txq_disable(queue);
        queue_state.add(TX_QUEUE_STATUS_OFFSET).write(6);
        if !frame.is_null() {
            // MPLEN is an aggregation-only hardware field. The strict basic
            // profile disables AMPDU/AMSDU before init and checks descriptor
            // aggregation bits again in `begin_discard`.
            begin_discard(state, queue_state, frame)?;
            return Ok(false);
        }
    } else if !frame.is_null() {
        let descriptor = frame
            .add(TX_FRAME_DESCRIPTOR_OFFSET)
            .cast::<*mut u32>()
            .read();
        if !descriptor.is_null() {
            descriptor.write(descriptor.read() | TX_FRAME_ABORTED_BIT);
        }
    }
    Ok(true)
}

unsafe fn begin_discard(
    state: &mut TxTimeoutState,
    queue_state: *mut u8,
    frame: *mut u8,
) -> Result<(), LmacAsyncError> {
    queue_state.add(TX_QUEUE_STATUS_OFFSET).write(0);
    queue_state.cast::<*mut u8>().write(ptr::null_mut());

    let descriptor = frame
        .add(TX_FRAME_DESCRIPTOR_OFFSET)
        .cast::<*mut u8>()
        .read();
    if descriptor.is_null() {
        return Err(LmacAsyncError::InvalidDiscardContinuation);
    }
    let flags = descriptor.cast::<u32>().read();
    if flags & (TX_FRAME_BAR_BIT | TX_FRAME_AMPDU_BIT) != 0 {
        return Err(LmacAsyncError::UnsupportedAggregatedFrame(flags));
    }

    let retry_count = descriptor.add(6).read();
    let ack_count = descriptor.add(7).read();
    state.discard_reason = if retry_count >= lmacConfMib[0x15] {
        2
    } else if ack_count >= lmacConfMib[0x14] {
        3
    } else {
        4
    };
    state.queue_state = queue_state;
    state.discard_frame = frame;

    let next = frame.add(TX_FRAME_NEXT_OFFSET).cast::<*mut u8>().read();
    if queue_state.add(TX_QUEUE_KIND_OFFSET).read() <= 2 && !next.is_null() {
        state.discard_tail = next;
        state.discard_phase = DISCARD_FIND_TAIL;
    } else {
        state.discard_tail = ptr::null_mut();
        state.discard_phase = DISCARD_FRAME;
    }
    enqueue_discard_continuation()
}

fn enqueue_discard_continuation() -> Result<(), LmacAsyncError> {
    if crate::adapter::enqueue_internal_event(crate::event::PpEvent {
        kind: TX_DISCARD_CONTINUATION,
        argument: ptr::null_mut(),
    }) {
        Ok(())
    } else {
        Err(LmacAsyncError::InternalQueueFull)
    }
}

pub(crate) const fn is_continuation(kind: u32) -> bool {
    kind == TX_DISCARD_CONTINUATION
}

/// Advance at most one pointer or one discarded MSDU. This turns both loops
/// recovered from `lmacDiscardMSDU` into executor-visible continuations.
pub(crate) unsafe fn dispatch_continuation() -> Result<(), LmacAsyncError> {
    let state = &mut *STATE.0.get();
    let result = match state.discard_phase {
        DISCARD_FIND_TAIL => find_tail_step(state),
        DISCARD_FRAME => discard_frame_step(state),
        DISCARD_WAIT_TX_DONE => finish_discard_frame_step(state),
        _ => Err(LmacAsyncError::InvalidDiscardContinuation),
    };
    if result.is_err() {
        fail(state);
    }
    result
}

unsafe fn find_tail_step(state: &mut TxTimeoutState) -> Result<(), LmacAsyncError> {
    let next = state
        .discard_tail
        .add(TX_FRAME_NEXT_OFFSET)
        .cast::<*mut u8>()
        .read();
    if !next.is_null() {
        state.discard_tail = next;
        return enqueue_discard_continuation();
    }

    let txrx = ptr::addr_of!(pTxRx).read();
    if txrx.is_null() {
        return Err(LmacAsyncError::TxRxUnavailable);
    }
    let descriptor = descriptor(state.discard_frame)?;
    let queue = descriptor_queue(descriptor);
    let entry = txrx.add(usize::from(queue) * TXRX_QUEUE_SIZE);
    let chain_head = state
        .discard_frame
        .add(TX_FRAME_NEXT_OFFSET)
        .cast::<*mut u8>()
        .read();
    let old_head = entry.add(TXRX_QUEUE_HEAD_OFFSET).cast::<*mut u8>().read();
    state
        .discard_tail
        .add(TX_FRAME_NEXT_OFFSET)
        .cast::<*mut u8>()
        .write(old_head);
    if old_head.is_null() {
        entry
            .add(TXRX_QUEUE_TAIL_LINK_OFFSET)
            .cast::<*mut u8>()
            .write(state.discard_tail.add(TX_FRAME_NEXT_OFFSET));
    }
    entry
        .add(TXRX_QUEUE_HEAD_OFFSET)
        .cast::<*mut u8>()
        .write(chain_head);

    state.discard_phase = DISCARD_FRAME;
    enqueue_discard_continuation()
}

unsafe fn discard_frame_step(state: &mut TxTimeoutState) -> Result<(), LmacAsyncError> {
    let frame = state.discard_frame;
    let queue_state = state.queue_state;
    let count = queue_state.add(TX_QUEUE_DROP_COUNT_OFFSET).cast::<u32>();
    count.write(count.read().wrapping_add(1));

    let descriptor = descriptor(frame)?;
    descriptor
        .add(TX_DESCRIPTOR_REASON_OFFSET)
        .write(state.discard_reason);
    state.discard_phase = DISCARD_WAIT_TX_DONE;
    crate::txdone::begin_from_lmac(frame).map_err(LmacAsyncError::TxDone)
}

pub(crate) fn resume_after_tx_done() -> Result<(), LmacAsyncError> {
    enqueue_discard_continuation()
}

unsafe fn finish_discard_frame_step(state: &mut TxTimeoutState) -> Result<(), LmacAsyncError> {
    let frame = state.discard_frame;
    let queue_state = state.queue_state;
    let descriptor = descriptor(frame)?;
    let flags = descriptor.cast::<u32>().read();
    let queue = descriptor_queue(descriptor);
    if flags & TX_FRAME_DEQUEUE_MASK == TX_FRAME_DEQUEUE_VALUE {
        let next = ppDequeueTxQ(queue);
        if !next.is_null() {
            state.discard_frame = next;
            state.discard_phase = DISCARD_FRAME;
            return enqueue_discard_continuation();
        }
    } else {
        // The strict TX-done prefix has already posted event 16. Release TXOP
        // and queue TX processing behind that event instead of tail-calling
        // the vendor dispatcher synchronously.
        if queue_state.add(TX_QUEUE_KIND_OFFSET).read() <= 2 {
            lmacReleaseTxopQueue(queue);
        }
        if pp_post(u32::from(queue), ptr::null_mut()) != 0 {
            return Err(LmacAsyncError::InternalQueueFull);
        }
    }

    state.discard_phase = DISCARD_IDLE;
    state.queue_state = ptr::null_mut();
    state.discard_frame = ptr::null_mut();
    state.discard_tail = ptr::null_mut();
    finish_current_queue(state);
    Ok(())
}

unsafe fn descriptor(frame: *mut u8) -> Result<*mut u8, LmacAsyncError> {
    let descriptor = frame
        .add(TX_FRAME_DESCRIPTOR_OFFSET)
        .cast::<*mut u8>()
        .read();
    if descriptor.is_null() {
        Err(LmacAsyncError::InvalidDiscardContinuation)
    } else {
        Ok(descriptor)
    }
}

unsafe fn descriptor_queue(descriptor: *mut u8) -> u8 {
    ((descriptor
        .add(TX_DESCRIPTOR_QUEUE_WORD_OFFSET)
        .cast::<u32>()
        .read()
        >> 20)
        & 0x0f) as u8
}
