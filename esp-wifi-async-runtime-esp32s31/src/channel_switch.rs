use core::{
    cell::UnsafeCell,
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicU32, Ordering},
};

use crate::{adapter::schedule_internal_timer, timer::RawOsiTimer};

const MAC_CONTROL: *mut u32 = 0x2010_4cac as *mut u32;
const MAC_STOP_MASK: u32 = 0x00ff_1000;
const MAC_ACTIVE_MASK: u32 = 0x0000_e000;
const MAC_COMMAND_SETTLE_US: u32 = 20;
const MAC_IDLE_SETTLE_US: u32 = 5;

type ChannelCallback = unsafe extern "C" fn(*mut c_void, u32);

unsafe extern "C" {
    static mut g_chm: *mut u8;
    static mut g_mac_deinit_count: u32;
    static mut g_mac_deinit_rxing: u8;
    static mut g_mac_deinit_txing: u8;

    fn chm_start_op(
        channel: *const u8,
        first_dwell_us: u32,
        final_dwell_us: u32,
        start: Option<ChannelCallback>,
        end: Option<ChannelCallback>,
        context: *mut c_void,
    ) -> i32;
    fn __real_chm_start_op(
        channel: *const u8,
        first_dwell_us: u32,
        final_dwell_us: u32,
        start: Option<ChannelCallback>,
        end: Option<ChannelCallback>,
        context: *mut c_void,
    ) -> i32;
    fn chm_return_home_channel();
    fn __real_chm_return_home_channel();
    fn chm_get_chan_info(primary: u8) -> *const u8;
    fn ic_set_current_channel(channel: *const u8);
    fn phy_change_channel(frequency_mhz: u16, init: u32, noise_floor: u32, cbw: u32);
    fn hal_mac_set_csi_cbw(cbw: u32);
    fn ic_mac_init() -> i32;
    fn chm_end_op_timeout_process(which: u32);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ChannelSwitchError {
    None = 0,
    WrongHart = 1,
    StateUnavailable = 2,
    Busy = 3,
    InvalidChannel = 4,
    TimerUnavailable = 5,
    MacDidNotBecomeIdle = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelSwitchSnapshot {
    pub started: u32,
    pub completed: u32,
    pub failed: ChannelSwitchError,
    pub mac_status: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Completion {
    Operation,
    Home,
}

#[derive(Clone, Copy)]
struct State {
    active: bool,
    channel: [u8; 2],
    frequency_mhz: u16,
    cbw: u8,
    completion: Completion,
    started: u32,
    completed: u32,
}

impl State {
    const fn new() -> Self {
        Self {
            active: false,
            channel: [0; 2],
            frequency_mhz: 0,
            cbw: 0,
            completion: Completion::Operation,
            started: 0,
            completed: 0,
        }
    }
}

struct StateCell(UnsafeCell<State>);
unsafe impl Sync for StateCell {}

struct TimerCell(UnsafeCell<RawOsiTimer>);
unsafe impl Sync for TimerCell {}

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

static STATE: StateCell = StateCell(UnsafeCell::new(State::new()));
static SETTLE_TIMER: TimerCell = TimerCell::new();
static FIRST_DWELL_TIMER: TimerCell = TimerCell::new();
static FINAL_DWELL_TIMER: TimerCell = TimerCell::new();
static FAILURE: AtomicU32 = AtomicU32::new(ChannelSwitchError::None as u32);
static MAC_FAILURE_STATUS: AtomicU32 = AtomicU32::new(0);

pub(crate) fn link_wrappers_active() -> bool {
    core::ptr::eq(chm_start_op as *const (), __wrap_chm_start_op as *const ())
        && core::ptr::eq(
            chm_return_home_channel as *const (),
            __wrap_chm_return_home_channel as *const (),
        )
}

pub fn channel_switch_snapshot() -> ChannelSwitchSnapshot {
    let state = unsafe { &*STATE.0.get() };
    ChannelSwitchSnapshot {
        started: state.started,
        completed: state.completed,
        failed: decode_error(FAILURE.load(Ordering::Acquire)),
        mac_status: MAC_FAILURE_STATUS.load(Ordering::Acquire),
    }
}

pub(crate) fn failure() -> Option<ChannelSwitchError> {
    let error = decode_error(FAILURE.load(Ordering::Acquire));
    (error != ChannelSwitchError::None).then_some(error)
}

const fn decode_error(raw: u32) -> ChannelSwitchError {
    match raw {
        1 => ChannelSwitchError::WrongHart,
        2 => ChannelSwitchError::StateUnavailable,
        3 => ChannelSwitchError::Busy,
        4 => ChannelSwitchError::InvalidChannel,
        5 => ChannelSwitchError::TimerUnavailable,
        6 => ChannelSwitchError::MacDidNotBecomeIdle,
        _ => ChannelSwitchError::None,
    }
}

unsafe fn fail(error: ChannelSwitchError, detail: u32) {
    let state = &mut *STATE.0.get();
    state.active = false;
    MAC_FAILURE_STATUS.store(detail, Ordering::Relaxed);
    FAILURE.store(error as u32, Ordering::Release);
}

unsafe fn prepare_channel(channel: [u8; 2]) -> Option<(u16, u8)> {
    let info = chm_get_chan_info(channel[0]);
    if info.is_null() {
        return None;
    }
    let mut frequency = info.add(2).cast::<u16>().read_unaligned();
    let cbw = match channel[1] {
        2 if (5..=13).contains(&channel[0]) => {
            frequency = frequency.checked_sub(10)?;
            3
        }
        1 if (1..=9).contains(&channel[0]) => {
            frequency = frequency.checked_add(10)?;
            2
        }
        // `_env_is_chip()` is true for the only supported target: real S31
        // silicon. The alternate value is an emulator-only PHY convention.
        _ => 0,
    };
    Some((frequency, cbw))
}

unsafe fn begin(channel: [u8; 2], completion: Completion) -> Result<(), ChannelSwitchError> {
    if !crate::critical::on_strict_wifi_hart() {
        return Err(ChannelSwitchError::WrongHart);
    }
    if failure().is_some() {
        return Err(ChannelSwitchError::Busy);
    }
    let state = &mut *STATE.0.get();
    if state.active {
        return Err(ChannelSwitchError::Busy);
    }
    let Some((frequency_mhz, cbw)) = prepare_channel(channel) else {
        return Err(ChannelSwitchError::InvalidChannel);
    };

    state.active = true;
    state.channel = channel;
    state.frequency_mhz = frequency_mhz;
    state.cbw = cbw;
    state.completion = completion;
    state.started = state.started.wrapping_add(1);

    ic_set_current_channel(state.channel.as_ptr());

    g_mac_deinit_count = g_mac_deinit_count.wrapping_add(1);
    let status = MAC_CONTROL.read_volatile();
    g_mac_deinit_rxing = ((status >> 14) & 1) as u8;
    g_mac_deinit_txing = ((status >> 13) & 1) as u8;
    MAC_CONTROL.write_volatile(status | MAC_STOP_MASK);

    if !schedule_internal_timer(
        SETTLE_TIMER.0.get().cast(),
        mac_command_settled,
        ptr::null_mut(),
        MAC_COMMAND_SETTLE_US,
    ) {
        fail(ChannelSwitchError::TimerUnavailable, 0);
        return Err(ChannelSwitchError::TimerUnavailable);
    }
    Ok(())
}

unsafe extern "C" fn mac_command_settled(_argument: *mut c_void) {
    let status = MAC_CONTROL.read_volatile();
    if status & MAC_ACTIVE_MASK != 0 {
        fail(ChannelSwitchError::MacDidNotBecomeIdle, status);
        return;
    }
    if !schedule_internal_timer(
        SETTLE_TIMER.0.get().cast(),
        mac_idle_settled,
        ptr::null_mut(),
        MAC_IDLE_SETTLE_US,
    ) {
        fail(ChannelSwitchError::TimerUnavailable, 0);
    }
}

unsafe extern "C" fn mac_idle_settled(_argument: *mut c_void) {
    let state = &mut *STATE.0.get();
    if !state.active {
        fail(ChannelSwitchError::Busy, 0);
        return;
    }

    phy_change_channel(state.frequency_mhz, 1, 0, u32::from(state.cbw));
    hal_mac_set_csi_cbw(u32::from(state.cbw));
    let _ = ic_mac_init();

    let chm = g_chm;
    if chm.is_null() {
        fail(ChannelSwitchError::StateUnavailable, 0);
        return;
    }
    let interrupt_state = crate::critical::strict_wifi_int_disable();
    chm.add(82).write(state.channel[0]);
    chm.add(83).write(state.channel[1]);
    crate::critical::strict_wifi_int_restore(interrupt_state);

    let completion = state.completion;
    state.active = false;
    state.completed = state.completed.wrapping_add(1);
    if completion == Completion::Operation {
        finish_operation(chm);
    }
}

unsafe fn finish_operation(chm: *mut u8) {
    let start = chm
        .add(20)
        .cast::<Option<ChannelCallback>>()
        .read_unaligned();
    let context = chm.add(16).cast::<*mut c_void>().read_unaligned();
    if let Some(start) = start {
        start(context, 0);
    }

    let first = chm.add(8).cast::<u32>().read_unaligned();
    let final_dwell = chm.add(12).cast::<u32>().read_unaligned();
    if first == 0 && final_dwell == 0 {
        ptr::write_bytes(chm.add(4), 0, 24);
        chm.add(4).write(u8::MAX);
        return;
    }
    if first != 0 && first < final_dwell {
        if !schedule_internal_timer(
            FIRST_DWELL_TIMER.0.get().cast(),
            first_dwell_elapsed,
            ptr::null_mut(),
            first,
        ) {
            fail(ChannelSwitchError::TimerUnavailable, 0);
            return;
        }
    }
    if !schedule_internal_timer(
        FINAL_DWELL_TIMER.0.get().cast(),
        final_dwell_elapsed,
        ptr::null_mut(),
        final_dwell,
    ) {
        fail(ChannelSwitchError::TimerUnavailable, 0);
    }
}

unsafe extern "C" fn first_dwell_elapsed(_argument: *mut c_void) {
    let _ = crate::adapter::cancel_internal_timer(FINAL_DWELL_TIMER.0.get().cast());
    chm_end_op_timeout_process(0);
}

unsafe extern "C" fn final_dwell_elapsed(_argument: *mut c_void) {
    chm_end_op_timeout_process(1);
}

/// Strict final-link channel-operation boundary. The vendor state and callback
/// ABI are preserved, but the two mandatory MAC settling intervals become
/// executor timers and the hardware-ready loop becomes exactly one check.
#[no_mangle]
pub unsafe extern "C" fn __wrap_chm_start_op(
    channel: *const u8,
    first_dwell_us: u32,
    final_dwell_us: u32,
    start: Option<ChannelCallback>,
    end: Option<ChannelCallback>,
    context: *mut c_void,
) -> i32 {
    if !crate::critical::strict_wifi_hart_armed() {
        return __real_chm_start_op(channel, first_dwell_us, final_dwell_us, start, end, context);
    }
    if channel.is_null() || !crate::critical::on_strict_wifi_hart() {
        return 3;
    }
    let chm = g_chm;
    if chm.is_null() || chm.add(4).read() != u8::MAX {
        return 3;
    }

    let selected = [channel.read(), channel.add(1).read()];
    chm.add(4).write(selected[0]);
    chm.add(5).write(selected[1]);
    chm.add(8).cast::<u32>().write_unaligned(first_dwell_us);
    chm.add(12).cast::<u32>().write_unaligned(final_dwell_us);
    chm.add(16).cast::<*mut c_void>().write_unaligned(context);
    chm.add(20)
        .cast::<Option<ChannelCallback>>()
        .write_unaligned(start);
    chm.add(24)
        .cast::<Option<ChannelCallback>>()
        .write_unaligned(end);

    if let Err(error) = begin(selected, Completion::Operation) {
        ptr::write_bytes(chm.add(4), 0, 24);
        chm.add(4).write(u8::MAX);
        fail(error, 0);
        return 3;
    }
    0
}

/// Return-to-home is also split at the final-link boundary. `scan_done`
/// continues its finite state cleanup, while the radio owner completes the
/// physical 25-us transition before processing another queued PP event.
#[no_mangle]
pub unsafe extern "C" fn __wrap_chm_return_home_channel() {
    if !crate::critical::strict_wifi_hart_armed() {
        __real_chm_return_home_channel();
        return;
    }
    let chm = g_chm;
    if chm.is_null() {
        fail(ChannelSwitchError::StateUnavailable, 0);
        return;
    }
    let home = [chm.add(80).read(), chm.add(81).read()];
    let current = [chm.add(82).read(), chm.add(83).read()];
    if home != current {
        if let Err(error) = begin(home, Completion::Home) {
            fail(error, 0);
        }
    }
}
