use core::{
    cell::UnsafeCell,
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

static FTM_ATTEMPTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "riscv32")]
use crate::{
    rx_descriptor::{
        descriptor_buffer_length, descriptor_owned_by_hardware, recycled_descriptor_word,
    },
    timer::RawOsiTimer,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WdevRxContinuationError {
    WrongHart,
    ResetStateUnavailable,
    MissingLastDescriptor,
    CurrentDescriptorMismatch,
    MissingRxMetadata,
    DescriptorCountOverflow,
    DescriptorChainTooLong,
}

#[cfg(target_arch = "riscv32")]
const MAX_RX_RECYCLE_DESCRIPTORS_PER_CHAIN: usize = 64;
#[cfg(target_arch = "riscv32")]
const RX_RELOAD_SETTLE_US: u32 = 5;
#[cfg(target_arch = "riscv32")]
const RX_DESCRIPTOR_NEXT_OFFSET: usize = 8;
#[cfg(target_arch = "riscv32")]
const RX_DESCRIPTOR_BUFFER_OFFSET: usize = 4;
#[cfg(target_arch = "riscv32")]
const RX_DESCRIPTOR_SENTINEL: u32 = 0xdead_beef;
#[cfg(target_arch = "riscv32")]
const WIFI_MAC_RX_CONTROL_REGISTER: *const u32 = 0x2010_4080 as *const u32;
#[cfg(target_arch = "riscv32")]
const WIFI_MAC_RX_BASE_REGISTER: *const u32 = 0x2010_4084 as *const u32;

#[cfg(target_arch = "riscv32")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RxRecycleError {
    WrongHart,
    MissingHead,
    MissingTail,
    MissingBuffer,
    TailMismatch,
    ChainTooLong,
    TimerUnavailable,
    TimerCancelFailed,
    ReloadStillActive,
    MissingHardwareTail,
    UnexpectedCallback,
}

#[cfg(target_arch = "riscv32")]
struct RxRecycleState {
    reload_active: bool,
    failed: bool,
    reload_tail: *mut u8,
    pending_head: *mut u8,
    pending_tail: *mut u8,
}

#[cfg(target_arch = "riscv32")]
impl RxRecycleState {
    const fn new() -> Self {
        Self {
            reload_active: false,
            failed: false,
            reload_tail: ptr::null_mut(),
            pending_head: ptr::null_mut(),
            pending_tail: ptr::null_mut(),
        }
    }
}

#[cfg(target_arch = "riscv32")]
struct RxRecycleStateCell(UnsafeCell<RxRecycleState>);

#[cfg(target_arch = "riscv32")]
unsafe impl Sync for RxRecycleStateCell {}

#[cfg(target_arch = "riscv32")]
struct RxRecycleTimerCell(UnsafeCell<RawOsiTimer>);

#[cfg(target_arch = "riscv32")]
unsafe impl Sync for RxRecycleTimerCell {}

#[cfg(target_arch = "riscv32")]
struct RxRecycleProbe {
    calls: AtomicUsize,
    immediate: AtomicUsize,
    deferred: AtomicUsize,
    timers_armed: AtomicUsize,
    completions: AtomicUsize,
    terminal_restarts: AtomicUsize,
    reload_active: AtomicUsize,
    pending_chains: AtomicUsize,
}

#[cfg(target_arch = "riscv32")]
impl RxRecycleProbe {
    const fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            immediate: AtomicUsize::new(0),
            deferred: AtomicUsize::new(0),
            timers_armed: AtomicUsize::new(0),
            completions: AtomicUsize::new(0),
            terminal_restarts: AtomicUsize::new(0),
            reload_active: AtomicUsize::new(0),
            pending_chains: AtomicUsize::new(0),
        }
    }
}

#[cfg(target_arch = "riscv32")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WdevRxRecycleSnapshot {
    pub calls: usize,
    pub immediate: usize,
    pub deferred: usize,
    pub timers_armed: usize,
    pub completions: usize,
    pub terminal_restarts: usize,
    pub reload_active: bool,
    pub pending_chains: usize,
    pub software_head: usize,
    pub software_tail: usize,
    pub hardware_control: u32,
    pub hardware_base: usize,
    pub hardware_next: usize,
    pub hardware_last_raw: usize,
    pub hardware_last: usize,
    pub hardware_end_state: u32,
}

#[cfg(target_arch = "riscv32")]
struct IndicateFrameProbe {
    calls: AtomicUsize,
    validated: AtomicUsize,
    max_descriptors: AtomicUsize,
}

#[cfg(target_arch = "riscv32")]
impl IndicateFrameProbe {
    const fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            validated: AtomicUsize::new(0),
            max_descriptors: AtomicUsize::new(0),
        }
    }
}

#[cfg(target_arch = "riscv32")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WdevIndicateFrameSnapshot {
    pub calls: usize,
    pub validated: usize,
    pub max_descriptors: usize,
}

#[cfg(target_arch = "riscv32")]
#[link_section = ".critical.bss.wifi_strict.rx_recycle_state"]
static RX_RECYCLE_STATE: RxRecycleStateCell =
    RxRecycleStateCell(UnsafeCell::new(RxRecycleState::new()));

#[cfg(target_arch = "riscv32")]
#[link_section = ".critical.bss.wifi_strict.rx_recycle_timer"]
static RX_RECYCLE_TIMER: RxRecycleTimerCell = RxRecycleTimerCell(UnsafeCell::new(RawOsiTimer {
    next: ptr::null_mut(),
    expire: 0,
    period: 0,
    callback: None,
    argument: ptr::null_mut(),
}));

#[cfg(target_arch = "riscv32")]
#[link_section = ".critical.bss.wifi_strict.rx_recycle_probe"]
static RX_RECYCLE_PROBE: RxRecycleProbe = RxRecycleProbe::new();

#[cfg(target_arch = "riscv32")]
#[link_section = ".critical.bss.wifi_strict.indicate_frame_probe"]
static INDICATE_FRAME_PROBE: IndicateFrameProbe = IndicateFrameProbe::new();

unsafe extern "C" {
    #[link_name = "wDev_record_ftm_data"]
    fn vendor_record_ftm_data(rx_control: *mut c_void, frame: *mut c_void);
    #[link_name = "pm_on_beacon_rx"]
    fn vendor_pm_on_beacon_rx(
        interface: *mut c_void,
        frame: *mut u8,
        frame_end: *mut u8,
        from_task: u32,
    );
    #[link_name = "pm_on_data_rx"]
    fn vendor_pm_on_data_rx(
        receiver: *mut u8,
        packet_class: u32,
        transmitter: *mut u8,
        interface: u32,
    );
    #[link_name = "pm_on_data_tx"]
    fn vendor_pm_on_data_tx();
    #[link_name = "pm_set_beacon_duration"]
    fn vendor_pm_set_beacon_duration(duration: u32);
    #[link_name = "wDev_ftm_set_t1t4"]
    fn vendor_ftm_set_t1t4(frame: *mut c_void);
    #[link_name = "wDev_isNANPktInValidSlot"]
    fn vendor_is_nan_packet_in_valid_slot(frame: *mut u8) -> i32;
    #[link_name = "wDev_SnifferRxData"]
    fn vendor_sniffer_rx_data();
    #[link_name = "wdev_csi_rx_process"]
    fn vendor_csi_rx_process();
    #[link_name = "wDev_IndicateCtrlFrame"]
    fn vendor_indicate_ctrl_frame(frame: *mut u8, count: u32, kind: u32) -> i32;
    fn __real_wDev_isNANPktInValidSlot(frame: *mut u8) -> i32;
    fn __real_wDev_IndicateCtrlFrame(frame: *mut u8, count: u32, kind: u32) -> i32;
}

#[cfg(target_arch = "riscv32")]
const MAX_RX_SUCCESS_DESCRIPTORS_PER_EVENT: usize = 64;

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    static mut wDevCtrl: u8;
    static mut g_wdev_last_desc_reset_ptr: *mut u8;
    static mut g_wdev_csi_rx: usize;
    #[link_name = "wDev_AppendRxBlocks"]
    fn vendor_append_rx_blocks(head: *mut u8, tail: *mut u8, count: u32);
    fn __real_wDev_AppendRxBlocks(head: *mut u8, tail: *mut u8, count: u32);
    fn hal_mac_rx_get_last_dscr() -> *mut u8;
    fn hal_mac_rx_get_end_state() -> u32;
    fn hal_mac_rx_is_dscr_reload() -> u32;
    fn hal_mac_rx_read_rxdscrlast() -> *mut u8;
    fn hal_mac_rx_read_rxdscrnext() -> *mut u8;
    fn hal_mac_rx_set_base(descriptor: *mut u8);
    fn hal_mac_rx_set_dscr_reload();
    fn wDev_ProcessRxSucData(descriptor: *mut u8, subframe_count: u32);
}

#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.rx_recycle"]
unsafe fn prepare_rx_recycle_chain(
    head: *mut u8,
    expected_tail: *mut u8,
) -> Result<(), RxRecycleError> {
    if head.is_null() {
        return Err(RxRecycleError::MissingHead);
    }
    if expected_tail.is_null() {
        return Err(RxRecycleError::MissingTail);
    }

    let mut descriptor = head;
    let mut last = ptr::null_mut();
    let mut seen = 0;
    while !descriptor.is_null() {
        if seen == MAX_RX_RECYCLE_DESCRIPTORS_PER_CHAIN {
            return Err(RxRecycleError::ChainTooLong);
        }
        seen += 1;

        let word_ptr = descriptor.cast::<u32>();
        let word = word_ptr.read_unaligned();
        let buffer = descriptor
            .add(RX_DESCRIPTOR_BUFFER_OFFSET)
            .cast::<*mut u8>()
            .read_unaligned();
        if buffer.is_null() {
            return Err(RxRecycleError::MissingBuffer);
        }
        let next = descriptor
            .add(RX_DESCRIPTOR_NEXT_OFFSET)
            .cast::<*mut u8>()
            .read_unaligned();

        word_ptr.write_unaligned(recycled_descriptor_word(word));
        buffer.cast::<u32>().write_unaligned(RX_DESCRIPTOR_SENTINEL);
        buffer
            .add(descriptor_buffer_length(word))
            .cast::<u32>()
            .write_unaligned(RX_DESCRIPTOR_SENTINEL);

        last = descriptor;
        descriptor = next;
    }
    if last != expected_tail {
        return Err(RxRecycleError::TailMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.rx_recycle"]
unsafe fn append_pending_rx_recycle_chain(
    state: &mut RxRecycleState,
    head: *mut u8,
    tail: *mut u8,
) -> Result<(), RxRecycleError> {
    if state.pending_head.is_null() {
        if !state.pending_tail.is_null() {
            return Err(RxRecycleError::MissingHead);
        }
        state.pending_head = head;
        state.pending_tail = tail;
        return Ok(());
    }
    if state.pending_tail.is_null() {
        return Err(RxRecycleError::MissingTail);
    }
    state
        .pending_tail
        .add(RX_DESCRIPTOR_NEXT_OFFSET)
        .cast::<*mut u8>()
        .write_unaligned(head);
    state.pending_tail = tail;
    Ok(())
}

#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.rx_recycle"]
unsafe fn arm_rx_reload_settle_timer() -> Result<(), RxRecycleError> {
    if crate::adapter::schedule_internal_timer(
        RX_RECYCLE_TIMER.0.get().cast(),
        rx_reload_settled,
        ptr::null_mut(),
        RX_RELOAD_SETTLE_US,
    ) {
        RX_RECYCLE_PROBE
            .timers_armed
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    } else {
        Err(RxRecycleError::TimerUnavailable)
    }
}

/// Attach one prepared descriptor chain without waiting for the MAC reload bit.
///
/// Returns `true` when a later timer continuation is required. The caller owns
/// `state` and execution is serialized on the strict Wi-Fi hart.
#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.rx_recycle"]
unsafe fn publish_rx_recycle_chain(
    state: &mut RxRecycleState,
    head: *mut u8,
    tail: *mut u8,
) -> Result<bool, RxRecycleError> {
    let interrupt_state = crate::critical::strict_wifi_int_disable();
    let control = ptr::addr_of_mut!(wDevCtrl);
    let published_head = control.cast::<*mut u8>().read_unaligned();
    if published_head.is_null() {
        control.cast::<*mut u8>().write_unaligned(head);
        control.add(4).cast::<*mut u8>().write_unaligned(tail);
        hal_mac_rx_set_base(head);
        crate::critical::strict_wifi_int_restore(interrupt_state);
        return Ok(false);
    }

    let published_tail = control.add(4).cast::<*mut u8>().read_unaligned();
    if published_tail.is_null() {
        crate::critical::strict_wifi_int_restore(interrupt_state);
        return Err(RxRecycleError::MissingTail);
    }
    published_tail
        .add(RX_DESCRIPTOR_NEXT_OFFSET)
        .cast::<*mut u8>()
        .write_unaligned(head);
    // The pinned vendor leaf keeps the previously published tail visible
    // until MAC reload completes. Publishing the future tail here lets RX
    // interrupt code observe a chain endpoint which hardware has not accepted
    // yet and eventually corrupts the descriptor list under sustained load.
    state.reload_active = true;
    state.reload_tail = tail;
    RX_RECYCLE_PROBE
        .reload_active
        .store(1, Ordering::Release);
    hal_mac_rx_set_dscr_reload();
    crate::critical::strict_wifi_int_restore(interrupt_state);
    Ok(true)
}

#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.rx_recycle"]
unsafe fn publish_or_defer_rx_recycle_chain(
    state: &mut RxRecycleState,
    head: *mut u8,
    tail: *mut u8,
) -> Result<(), RxRecycleError> {
    if state.reload_active {
        RX_RECYCLE_PROBE.deferred.fetch_add(1, Ordering::Relaxed);
        let interrupt_state = crate::critical::strict_wifi_int_disable();
        let result = append_pending_rx_recycle_chain(state, head, tail);
        crate::critical::strict_wifi_int_restore(interrupt_state);
        if result.is_ok() {
            RX_RECYCLE_PROBE
                .pending_chains
                .fetch_add(1, Ordering::Relaxed);
        }
        return result;
    }
    if publish_rx_recycle_chain(state, head, tail)? {
        arm_rx_reload_settle_timer()?;
    } else {
        RX_RECYCLE_PROBE.immediate.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.rx_recycle"]
unsafe extern "C" fn rx_reload_settled(_argument: *mut c_void) {
    let state = &mut *RX_RECYCLE_STATE.0.get();
    if state.failed || !state.reload_active {
        fail_rx_recycle(state, RxRecycleError::UnexpectedCallback);
    }
    if !crate::critical::on_strict_wifi_hart() {
        fail_rx_recycle(state, RxRecycleError::WrongHart);
    }
    // Exactly one status observation per async continuation. A MAC which has
    // not completed within the declared settle interval is a hard invariant
    // failure; it is never converted back into polling or a retry timer.
    if hal_mac_rx_is_dscr_reload() != 0 {
        fail_rx_recycle(state, RxRecycleError::ReloadStillActive);
    }
    complete_rx_reload(state);
}

#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.rx_recycle"]
unsafe fn complete_rx_reload(state: &mut RxRecycleState) {
    RX_RECYCLE_PROBE.completions.fetch_add(1, Ordering::Relaxed);

    let reload_tail = state.reload_tail;
    if hal_mac_rx_read_rxdscrnext().is_null() {
        let hardware_tail = hal_mac_rx_get_last_dscr();
        if hardware_tail != reload_tail {
            if hardware_tail.is_null() {
                fail_rx_recycle(state, RxRecycleError::MissingHardwareTail);
            }
            let next = hardware_tail
                .add(RX_DESCRIPTOR_NEXT_OFFSET)
                .cast::<*mut u8>()
                .read_unaligned();
            if !next.is_null() {
                hal_mac_rx_set_base(next);
            }
        } else {
            // The asynchronous path can observe a state the vendor's inline
            // spin almost never reaches: MAC consumed exactly through the
            // accepted tail, software already recycled every received frame,
            // and no later RX edge exists to restart the engine.  Only the
            // hardware-owner bit makes the current software head eligible;
            // a completed but undecoded descriptor has this bit clear and
            // must never be submitted again.
            let software_head = ptr::addr_of!(wDevCtrl)
                .cast::<*mut u8>()
                .read_unaligned();
            if !software_head.is_null()
                && descriptor_owned_by_hardware(
                    software_head.cast::<u32>().read_unaligned(),
                )
            {
                hal_mac_rx_set_base(software_head);
                RX_RECYCLE_PROBE
                    .terminal_restarts
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    // Match the terminal store in `wDev_AppendRxBlocks`: the new tail becomes
    // globally visible only after the reload bit cleared and any base repair
    // completed.
    let interrupt_state = crate::critical::strict_wifi_int_disable();
    ptr::addr_of_mut!(wDevCtrl)
        .add(4)
        .cast::<*mut u8>()
        .write_unaligned(reload_tail);
    crate::critical::strict_wifi_int_restore(interrupt_state);
    state.reload_active = false;
    RX_RECYCLE_PROBE
        .reload_active
        .store(0, Ordering::Release);
    state.reload_tail = ptr::null_mut();
    let pending_head = state.pending_head;
    let pending_tail = state.pending_tail;
    state.pending_head = ptr::null_mut();
    state.pending_tail = ptr::null_mut();
    RX_RECYCLE_PROBE
        .pending_chains
        .store(0, Ordering::Release);
    if !pending_head.is_null() {
        if let Err(error) = publish_or_defer_rx_recycle_chain(state, pending_head, pending_tail) {
            fail_rx_recycle(state, error);
        }
    }
}

/// Finish a descriptor reload before decoding the RX event which proves that
/// the MAC has already advanced.
///
/// A hardware RX event can reach the executor before the conservative settle
/// timer.  Decoding that event while `wDevCtrl.tail` still names the previous
/// chain lets `wDev_DiscardFrame` recycle descriptors against stale software
/// list metadata.  Observe the reload bit exactly once here; when it is clear,
/// cancel the fallback timer and publish the accepted tail before entering the
/// vendor per-frame decoder.  A still-active reload remains owned by the
/// already armed timer and this function returns immediately.
#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.rx_recycle"]
pub(crate) unsafe fn settle_rx_reload_before_success() {
    let state = &mut *RX_RECYCLE_STATE.0.get();
    if state.failed || !state.reload_active || hal_mac_rx_is_dscr_reload() != 0 {
        return;
    }
    if !crate::adapter::cancel_internal_timer(RX_RECYCLE_TIMER.0.get().cast()) {
        fail_rx_recycle(state, RxRecycleError::TimerCancelFailed);
    }
    complete_rx_reload(state);
}

#[cfg(target_arch = "riscv32")]
#[cold]
#[inline(never)]
#[link_section = ".rwtext.wifi_strict.rx_recycle"]
unsafe fn fail_rx_recycle(state: &mut RxRecycleState, _error: RxRecycleError) -> ! {
    state.failed = true;
    core::arch::asm!("ebreak", options(noreturn))
}

/// Allocation-free replacement for the vendor RX descriptor recycle leaf.
///
/// The stock implementation spins up to 100,001 times on the MAC reload bit.
/// Strict mode instead formats a finite descriptor chain, publishes it under a
/// local interrupt critical section and returns. Completion is checked once by
/// an executor-driven Rust timer; additional chains coalesce in SRAM.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.rx_recycle"]
pub unsafe extern "C" fn __wrap_wDev_AppendRxBlocks(head: *mut u8, tail: *mut u8, _count: u32) {
    if !crate::critical::strict_wifi_hart_armed() {
        __real_wDev_AppendRxBlocks(head, tail, _count);
        return;
    }
    let state = &mut *RX_RECYCLE_STATE.0.get();
    if state.failed || !crate::critical::on_strict_wifi_hart() {
        fail_rx_recycle(state, RxRecycleError::WrongHart);
    }
    RX_RECYCLE_PROBE.calls.fetch_add(1, Ordering::Relaxed);
    if let Err(error) = prepare_rx_recycle_chain(head, tail)
        .and_then(|()| publish_or_defer_rx_recycle_chain(state, head, tail))
    {
        fail_rx_recycle(state, error);
    }
}

#[cfg(target_arch = "riscv32")]
pub fn rx_recycle_snapshot() -> WdevRxRecycleSnapshot {
    let control = ptr::addr_of!(wDevCtrl);
    WdevRxRecycleSnapshot {
        calls: RX_RECYCLE_PROBE.calls.load(Ordering::Acquire),
        immediate: RX_RECYCLE_PROBE.immediate.load(Ordering::Acquire),
        deferred: RX_RECYCLE_PROBE.deferred.load(Ordering::Acquire),
        timers_armed: RX_RECYCLE_PROBE.timers_armed.load(Ordering::Acquire),
        completions: RX_RECYCLE_PROBE.completions.load(Ordering::Acquire),
        terminal_restarts: RX_RECYCLE_PROBE
            .terminal_restarts
            .load(Ordering::Acquire),
        reload_active: RX_RECYCLE_PROBE.reload_active.load(Ordering::Acquire) != 0,
        pending_chains: RX_RECYCLE_PROBE.pending_chains.load(Ordering::Acquire),
        software_head: unsafe { control.cast::<*mut u8>().read_unaligned() as usize },
        software_tail: unsafe { control.add(4).cast::<*mut u8>().read_unaligned() as usize },
        hardware_control: unsafe { WIFI_MAC_RX_CONTROL_REGISTER.read_volatile() },
        hardware_base: unsafe { WIFI_MAC_RX_BASE_REGISTER.read_volatile() as usize },
        hardware_next: unsafe { hal_mac_rx_read_rxdscrnext() as usize },
        hardware_last_raw: unsafe { hal_mac_rx_read_rxdscrlast() as usize },
        hardware_last: unsafe { hal_mac_rx_get_last_dscr() as usize },
        hardware_end_state: unsafe { hal_mac_rx_get_end_state() },
    }
}

#[cfg(target_arch = "riscv32")]
fn runtime_rx_recycle_link_wrapper_active() -> bool {
    core::ptr::eq(
        vendor_append_rx_blocks as *const (),
        __wrap_wDev_AppendRxBlocks as *const (),
    )
}

#[cfg(not(target_arch = "riscv32"))]
fn runtime_rx_recycle_link_wrapper_active() -> bool {
    true
}

/// Replace the vendor event-25 outer descriptor walk and both indirect OSI
/// critical-section calls.
///
/// The hardware publishes one finite linked prefix ending at the descriptor
/// returned by `hal_mac_rx_get_last_dscr`. Rust preserves the vendor rule that
/// bit 30 marks the final descriptor of a receive unit and passes the bounded
/// prefix count to the still-audited per-unit decoder. A malformed list can no
/// longer cycle forever: at most 64 descriptors are consumed per executor
/// event, and every error restores local interrupts before returning.
#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.rx_success_dispatch"]
#[inline(never)]
pub(crate) unsafe fn process_rx_success() -> Result<(), WdevRxContinuationError> {
    if !crate::critical::on_strict_wifi_hart() {
        return Err(WdevRxContinuationError::WrongHart);
    }
    let reset = ptr::addr_of!(g_wdev_last_desc_reset_ptr).read();
    if reset.is_null() {
        return Err(WdevRxContinuationError::ResetStateUnavailable);
    }

    let mut last = hal_mac_rx_get_last_dscr();
    if reset.read() != 0 {
        if !last.is_null() {
            reset.write(0);
        }
    } else if last.is_null() {
        return Err(WdevRxContinuationError::MissingLastDescriptor);
    }

    let interrupt_state = crate::critical::strict_wifi_int_disable();
    let mut descriptor = ptr::addr_of!(wDevCtrl).cast::<*mut u8>().read_unaligned();
    let mut subframe_count = 0_u32;
    let mut descriptors_seen = 0_usize;
    while !descriptor.is_null() {
        if descriptors_seen == MAX_RX_SUCCESS_DESCRIPTORS_PER_EVENT {
            crate::critical::strict_wifi_int_restore(interrupt_state);
            return Err(WdevRxContinuationError::DescriptorChainTooLong);
        }
        descriptors_seen += 1;
        let next = descriptor.add(8).cast::<*mut u8>().read_unaligned();
        if descriptor
            .add(RX_DESCRIPTOR_BUFFER_OFFSET)
            .cast::<*mut u8>()
            .read_unaligned()
            .is_null()
        {
            crate::critical::strict_wifi_int_restore(interrupt_state);
            return Err(WdevRxContinuationError::MissingRxMetadata);
        }
        subframe_count = match subframe_count.checked_add(1) {
            Some(count) if count <= u32::from(u16::MAX) => count,
            _ => {
                crate::critical::strict_wifi_int_restore(interrupt_state);
                return Err(WdevRxContinuationError::DescriptorCountOverflow);
            }
        };

        if descriptor.cast::<u32>().read_unaligned() & (1 << 30) != 0 {
            let published = ptr::addr_of!(wDevCtrl).cast::<*mut u8>().read_unaligned();
            if published != descriptor {
                crate::critical::strict_wifi_int_restore(interrupt_state);
                return Err(WdevRxContinuationError::CurrentDescriptorMismatch);
            }
            INDICATE_FRAME_PROBE.calls.fetch_add(1, Ordering::Relaxed);
            INDICATE_FRAME_PROBE
                .validated
                .fetch_add(1, Ordering::Relaxed);
            INDICATE_FRAME_PROBE
                .max_descriptors
                .fetch_max(subframe_count as usize, Ordering::Relaxed);
            crate::critical::strict_wifi_int_restore(interrupt_state);
            wDev_ProcessRxSucData(descriptor, subframe_count);
            subframe_count = 0;
            if descriptor == last {
                return Ok(());
            }
            last = hal_mac_rx_get_last_dscr();
            if reset.read() == 0 && last.is_null() {
                return Err(WdevRxContinuationError::MissingLastDescriptor);
            }
            descriptor = next;
            if descriptor.is_null() {
                return Ok(());
            }
            // Match the vendor outer walk: only the pointer publication is
            // protected; the per-unit decoder executes with interrupts on.
            let new_interrupt_state = crate::critical::strict_wifi_int_disable();
            // The strict local primitive can only return the current MIE bit.
            // It must match the state initially captured for this radio event.
            if new_interrupt_state & 8 != interrupt_state & 8 {
                crate::critical::strict_wifi_int_restore(new_interrupt_state);
                return Err(WdevRxContinuationError::WrongHart);
            }
            continue;
        }
        if descriptor == last {
            crate::critical::strict_wifi_int_restore(interrupt_state);
            return Ok(());
        }
        last = hal_mac_rx_get_last_dscr();
        if reset.read() == 0 && last.is_null() {
            crate::critical::strict_wifi_int_restore(interrupt_state);
            return Err(WdevRxContinuationError::MissingLastDescriptor);
        }
        descriptor = next;
    }
    crate::critical::strict_wifi_int_restore(interrupt_state);
    Ok(())
}

#[cfg(target_arch = "riscv32")]
pub(crate) unsafe fn strict_optional_rx_mode_state() -> (u8, u8, usize) {
    let control = ptr::addr_of!(wDevCtrl);
    (
        control.add(0x30).read(),
        control.add(0x46).read(),
        ptr::addr_of!(g_wdev_csi_rx).read(),
    )
}

pub(crate) fn runtime_wdev_link_wrapper_active() -> bool {
    core::ptr::eq(
        vendor_record_ftm_data as *const (),
        __wrap_wDev_record_ftm_data as *const (),
    ) && core::ptr::eq(
        vendor_pm_on_beacon_rx as *const (),
        __wrap_pm_on_beacon_rx as *const (),
    ) && core::ptr::eq(
        vendor_pm_on_data_rx as *const (),
        __wrap_pm_on_data_rx as *const (),
    ) && core::ptr::eq(
        vendor_pm_on_data_tx as *const (),
        __wrap_pm_on_data_tx as *const (),
    ) && core::ptr::eq(
        vendor_pm_set_beacon_duration as *const (),
        __wrap_pm_set_beacon_duration as *const (),
    ) && core::ptr::eq(
        vendor_ftm_set_t1t4 as *const (),
        __wrap_wDev_ftm_set_t1t4 as *const (),
    ) && core::ptr::eq(
        vendor_is_nan_packet_in_valid_slot as *const (),
        __wrap_wDev_isNANPktInValidSlot as *const (),
    ) && core::ptr::eq(
        vendor_sniffer_rx_data as *const (),
        __wrap_wDev_SnifferRxData as *const (),
    ) && core::ptr::eq(
        vendor_csi_rx_process as *const (),
        __wrap_wdev_csi_rx_process as *const (),
    ) && core::ptr::eq(
        vendor_indicate_ctrl_frame as *const (),
        __wrap_wDev_IndicateCtrlFrame as *const (),
    ) && runtime_rx_recycle_link_wrapper_active()
}

pub(crate) fn take_ftm_attempted() -> bool {
    FTM_ATTEMPTED.swap(false, Ordering::AcqRel)
}

/// Reject Fine Timing Measurement RX accounting in the strict profile.
///
/// The pinned vendor implementation starts with `ets_delay_us(50)`. The final
/// link must use `--wrap=wDev_record_ftm_data`; the enclosing event handler
/// observes this marker and fails after returning from its finite RX section.
#[no_mangle]
pub unsafe extern "C" fn __wrap_wDev_record_ftm_data(
    _rx_control: *mut c_void,
    _frame: *mut c_void,
) {
    FTM_ATTEMPTED.store(true, Ordering::Release);
}

/// Reject the optional TX FTM timestamp callback under the disabled-FTM
/// invariant.
#[no_mangle]
pub unsafe extern "C" fn __wrap_wDev_ftm_set_t1t4(_frame: *mut c_void) {
    FTM_ATTEMPTED.store(true, Ordering::Release);
}

/// Preserve ordinary AP/STA TX while rejecting the callback-driven NAN path.
#[no_mangle]
pub unsafe extern "C" fn __wrap_wDev_isNANPktInValidSlot(frame: *mut u8) -> i32 {
    if !crate::critical::strict_wifi_hart_armed() {
        return __real_wDev_isNANPktInValidSlot(frame);
    }
    if frame.is_null() {
        return 0;
    }
    let descriptor = frame.add(0x34).cast::<*mut u8>().read();
    if descriptor.is_null() {
        return 0;
    }
    let packet_kind = descriptor.add(0x10).cast::<u32>().read() & 0x00c0_0000;
    i32::from(packet_kind != 0x0080_0000)
}

/// Remove promiscuous delivery from the strict basic AP/STA receive profile.
///
/// Preparation disables promiscuous mode through the public control API,
/// verifies its readback and the pinned `wDevCtrl` state, and unregisters the
/// callback before the RTOS handoff.
#[no_mangle]
pub unsafe extern "C" fn __wrap_wDev_SnifferRxData() {}

/// Remove CSI capture from the strict basic AP/STA receive profile.
///
/// The pinned vendor implementation allocates a 100-byte callback envelope.
/// Strict configuration rejects CSI and preparation verifies that the callback
/// pointer remains null before this boundary can be armed.
#[no_mangle]
pub unsafe extern "C" fn __wrap_wdev_csi_rx_process() {}

/// Elide the allocation-only CSI control-frame envelope in strict AP/STA mode.
///
/// The pinned function returns one on every path. Its only observable work is
/// an OSI Wi-Fi allocation, two finite copies, `wdev_csi_rx_process`, and the
/// matching OSI free. Preparation has disabled CSI and verified both the
/// callback and `wDevCtrl` state, so the constant return preserves the caller's
/// control-flow result without constructing an unused dynamic envelope.
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.csi_control"]
pub unsafe extern "C" fn __wrap_wDev_IndicateCtrlFrame(
    frame: *mut u8,
    count: u32,
    kind: u32,
) -> i32 {
    if crate::critical::strict_wifi_hart_armed() {
        1
    } else {
        __real_wDev_IndicateCtrlFrame(frame, count, kind)
    }
}

#[cfg(target_arch = "riscv32")]
pub fn indicate_frame_snapshot() -> WdevIndicateFrameSnapshot {
    WdevIndicateFrameSnapshot {
        calls: INDICATE_FRAME_PROBE.calls.load(Ordering::Acquire),
        validated: INDICATE_FRAME_PROBE.validated.load(Ordering::Acquire),
        max_descriptors: INDICATE_FRAME_PROBE.max_descriptors.load(Ordering::Acquire),
    }
}

/// Remove the vendor power-save/mesh beacon tail under `WIFI_PS_NONE`.
///
/// PP/net80211 has already parsed and delivered the beacon before this hook.
/// The stock function only updates power-save state and contains the path from
/// TIM processing to radio shutdown and `ets_delay_us`.
#[no_mangle]
pub unsafe extern "C" fn __wrap_pm_on_beacon_rx(
    _interface: *mut c_void,
    _frame: *mut u8,
    _frame_end: *mut u8,
    _from_task: u32,
) {
}

/// Remove RX power-management accounting under the verified `WIFI_PS_NONE`
/// invariant.
///
/// `ppRxProtoProc` has already classified the ordinary frame and retains its
/// independent receive-rate update. The stock ROM hook only advances modem
/// sleep state and may enter OSI timers and Wi-Fi API locks.
#[no_mangle]
pub unsafe extern "C" fn __wrap_pm_on_data_rx(
    _receiver: *mut u8,
    _packet_class: u32,
    _transmitter: *mut u8,
    _interface: u32,
) {
}

/// Remove TX power-management accounting under the verified `WIFI_PS_NONE`
/// invariant. The stock eight-byte trampoline enters the complete sleep/null
/// frame state machine even though that mode is disabled.
#[no_mangle]
pub unsafe extern "C" fn __wrap_pm_on_data_tx() {}

/// Remove the sampled-beacon-duration update under `WIFI_PS_NONE`.
///
/// The stock function only maintains modem-sleep state. Its first-sample path
/// invokes two optional beacon-offset callbacks; neither is part of an always
/// awake STA/AP profile.
#[no_mangle]
pub unsafe extern "C" fn __wrap_pm_set_beacon_duration(_duration: u32) {}
