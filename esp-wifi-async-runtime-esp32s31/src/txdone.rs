use core::{
    cell::UnsafeCell,
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(feature = "hil-vendor-tx")]
use core::sync::atomic::{AtomicU8, AtomicUsize};

use esp_wifi_sys_esp32s31::include::wifi_osi_funcs_t;

use crate::event::PpEvent;

pub(crate) const TX_DONE_CONTINUATION: u32 = u32::MAX - 2;
pub(crate) const LMAC_TX_DONE_CONTINUATION: u32 = u32::MAX - 3;

const TX_DONE_HEAD_OFFSET: usize = 0x38c;
const TX_DONE_TAIL_LINK_OFFSET: usize = 0x390;
const TX_CALLBACK_MODE0_MASK_OFFSET: usize = 0x39c;
const TX_CALLBACK_MODE1_MASK_OFFSET: usize = 0x410;
const TX_CALLBACK_TABLE_FIRST_OFFSET: usize = (0xe8 + 1) * 4;
const FRAME_NEXT_OFFSET: usize = 0x30;
const FRAME_DESCRIPTOR_OFFSET: usize = 0x34;
const FRAME_TYPE_OFFSET: usize = 0x1a;
const DESCRIPTOR_CALLBACK_MASK_OFFSET: usize = 0x14;
const DESCRIPTOR_FRAGMENT_BIT: u32 = 0x0080_0000;
const DESCRIPTOR_DIRECT_RECYCLE_BIT: u32 = 0x0400_0000;
const DESCRIPTOR_RATE_CONTROL_BIT: u32 = 0x0000_0008;
const DESCRIPTOR_RATE_CONTROL_SKIP_MASK: u32 = 0x4040_4000;
const DESCRIPTOR_RATE_CONTROL_SKIP_VALUE: u32 = 0x0040_0000;

const CALLBACK_MGMT: u8 = 2;
const CALLBACK_STA_EAPOL: u8 = 3;
const CALLBACK_AP_BEACON: u8 = 4;
const CALLBACK_AP_DATA: u8 = 11;
const BASIC_MODE0_CALLBACKS: u32 =
    (1 << CALLBACK_MGMT) | (1 << CALLBACK_AP_BEACON) | (1 << CALLBACK_AP_DATA);
const BASIC_MODE1_CALLBACKS: u32 = 1 << CALLBACK_STA_EAPOL;

const PHASE_IDLE: u8 = 0;
const PHASE_LOAD: u8 = 1;
const PHASE_CALLBACK: u8 = 2;
const PHASE_RECYCLE: u8 = 3;

#[cfg(feature = "hil-vendor-tx")]
static HIL_EAPOL_TXDONE_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static HIL_EAPOL_FRAME_CONTROL: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static HIL_EAPOL_QOS_CONTROL: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static HIL_EAPOL_HW_STATUS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static HIL_EAPOL_DESCRIPTOR_STATUS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static HIL_DATA_TXDONE_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static HIL_DATA_FRAME_CONTROL: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static HIL_DATA_HW_STATUS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static HIL_DATA_DESCRIPTOR_STATUS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static HIL_DATA_TRANSMITTER: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
#[cfg(feature = "hil-vendor-tx")]
static HIL_DATA_CCMP_HEADER: [AtomicU8; 8] = [const { AtomicU8::new(0) }; 8];
#[cfg(feature = "hil-vendor-tx")]
static HIL_DATA_PAYLOAD_PREFIX: [AtomicU8; 8] = [const { AtomicU8::new(0) }; 8];

#[cfg(feature = "hil-vendor-tx")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HilEapolTxDoneSnapshot {
    pub count: usize,
    pub frame_control: u16,
    pub qos_control: u16,
    pub hardware_status: u8,
    pub descriptor_status: u32,
}

#[cfg(feature = "hil-vendor-tx")]
pub fn hil_eapol_tx_done_snapshot() -> HilEapolTxDoneSnapshot {
    HilEapolTxDoneSnapshot {
        count: HIL_EAPOL_TXDONE_COUNT.load(Ordering::Acquire),
        frame_control: HIL_EAPOL_FRAME_CONTROL.load(Ordering::Acquire) as u16,
        qos_control: HIL_EAPOL_QOS_CONTROL.load(Ordering::Acquire) as u16,
        hardware_status: HIL_EAPOL_HW_STATUS.load(Ordering::Acquire) as u8,
        descriptor_status: HIL_EAPOL_DESCRIPTOR_STATUS.load(Ordering::Acquire) as u32,
    }
}

#[cfg(feature = "hil-vendor-tx")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HilDataTxDoneSnapshot {
    pub count: usize,
    pub frame_control: u16,
    pub hardware_status: u8,
    pub descriptor_status: u32,
    pub transmitter: [u8; 6],
    pub ccmp_header: [u8; 8],
    pub payload_prefix: [u8; 8],
}

#[cfg(feature = "hil-vendor-tx")]
pub fn hil_data_tx_done_snapshot() -> HilDataTxDoneSnapshot {
    let count = HIL_DATA_TXDONE_COUNT.load(Ordering::Acquire);
    HilDataTxDoneSnapshot {
        count,
        frame_control: HIL_DATA_FRAME_CONTROL.load(Ordering::Acquire) as u16,
        hardware_status: HIL_DATA_HW_STATUS.load(Ordering::Acquire) as u8,
        descriptor_status: HIL_DATA_DESCRIPTOR_STATUS.load(Ordering::Acquire) as u32,
        transmitter: load_hil_bytes(&HIL_DATA_TRANSMITTER),
        ccmp_header: load_hil_bytes(&HIL_DATA_CCMP_HEADER),
        payload_prefix: load_hil_bytes(&HIL_DATA_PAYLOAD_PREFIX),
    }
}

#[cfg(feature = "hil-vendor-tx")]
fn load_hil_bytes<const N: usize>(source: &[AtomicU8; N]) -> [u8; N] {
    let mut bytes = [0; N];
    let mut index = 0;
    while index < N {
        bytes[index] = source[index].load(Ordering::Acquire);
        index += 1;
    }
    bytes
}

type TxCallback = unsafe extern "C" fn(*mut c_void);

unsafe extern "C" {
    static mut pTxRx: *mut u8;
    static mut our_instances_ptr: *mut u8;
    static mut g_tx_done_cb_func: usize;
    static g_wifi_menuconfig: u8;
    static mut g_ic: u8;
    static mut g_osi_funcs_p: *const wifi_osi_funcs_t;
    static TmpSTAAPCloseAP: u8;
    #[link_name = "__esp_s31_beacon_send_start_flag"]
    static mut BEACON_SEND_START_FLAG: u8;
    #[link_name = "__esp_s31_beacon_timer"]
    static mut BEACON_TIMER: [u8; 0x14];
    #[link_name = "__esp_s31_beacon_next_tbtt"]
    static mut BEACON_NEXT_TBTT: u32;
    #[link_name = "__esp_s31_beacon_dtim_send_mc"]
    static BEACON_DTIM_SEND_MC: u8;

    fn sta_eapol_txdone_cb(frame: *mut c_void);
    #[link_name = "ieee80211_tx_mgt_cb"]
    fn vendor_tx_mgt_cb(frame: *mut c_void);
    #[link_name = "ieee80211_hostapd_beacon_txcb"]
    fn vendor_hostapd_beacon_txcb(frame: *mut c_void);
    fn ieee80211_hostapd_data_txcb(frame: *mut c_void);
    fn ic_get_next_tbtt() -> u32;
    fn pp_coex_tx_release(frame: *mut c_void);
    fn esf_buf_recycle(frame: *mut c_void);
    fn rcUpdateTxDone(rate_control: *mut c_void, descriptor: *mut c_void);
    fn lmacReleaseTxopQueue(queue: u8);
    fn pp_post(kind: u32, argument: *mut c_void) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxDoneError {
    PreviousFailure,
    TxRxUnavailable,
    InternalQueueFull,
    MissingDescriptor,
    MissingTxDoneTail,
    UnsupportedCallbackBits(u32),
    CallbackRegistryMismatch(u8),
    UserCallbackInstalled,
    UnsupportedDescriptorFlags(u32),
    NonStaticFrameType(u8),
    LmacPipelineBusy,
    UnsupportedLmacDescriptorFlags(u32),
    UnsupportedLmacMode(u32),
    InstancesUnavailable,
    TxTimeRecordingEnabled,
    InvalidPhase,
    StrictCallbackFailed,
}

#[derive(Clone, Copy)]
struct TxDoneState {
    active: bool,
    failed: bool,
    phase: u8,
    frame: *mut u8,
    callbacks: u32,
    resume_timeout: bool,
    resume_queue: bool,
}

impl TxDoneState {
    const fn new() -> Self {
        Self {
            active: false,
            failed: false,
            phase: PHASE_IDLE,
            frame: ptr::null_mut(),
            callbacks: 0,
            resume_timeout: false,
            resume_queue: false,
        }
    }
}

struct StateCell(UnsafeCell<TxDoneState>);

unsafe impl Sync for StateCell {}

#[cfg_attr(
    target_arch = "riscv32",
    link_section = ".critical.bss.wifi_strict.tx_done_state"
)]
static STATE: StateCell = StateCell(UnsafeCell::new(TxDoneState::new()));
#[cfg_attr(
    target_arch = "riscv32",
    link_section = ".critical.bss.wifi_strict.lmac_tx_done_state"
)]
static LMAC_STATE: StateCell = StateCell(UnsafeCell::new(TxDoneState::new()));
static STRICT_CALLBACK_FAILED: AtomicBool = AtomicBool::new(false);

pub(crate) fn runtime_callback_link_wrappers_active() -> bool {
    core::ptr::eq(
        vendor_hostapd_beacon_txcb as *const (),
        __wrap_ieee80211_hostapd_beacon_txcb as *const (),
    ) && core::ptr::eq(
        vendor_tx_mgt_cb as *const (),
        __wrap_ieee80211_tx_mgt_cb as *const (),
    )
}

unsafe fn strict_management_txdone(frame: *mut u8) -> Result<(), ()> {
    if frame.is_null() {
        return Err(());
    }
    let buffer = frame.add(4).cast::<*mut u8>().read();
    if buffer.is_null() {
        return Err(());
    }
    let mut header = buffer.add(4).cast::<*const u8>().read();
    if header.is_null() {
        return Err(());
    }
    if frame.add(0x24).cast::<u16>().read() & 0x2000 != 0 {
        header = header.add(8);
    }
    let frame_control = header.read();
    if frame_control & 0x0c != 0 {
        return Err(());
    }
    match frame_control & 0xf0 {
        // Disconnect and off-channel action completions enter node/key/channel
        // state machines in the stock callback. They require explicit async
        // commands and are not allowed to run implicitly from TX completion.
        0xd0 if crate::sta_link::complete_owned_action_management() => Ok(()),
        0xa0 | 0xc0 | 0xd0 => Err(()),
        _ => {
            let descriptor = frame.add(0x34).cast::<*mut u8>().read();
            if descriptor.is_null() {
                return Err(());
            }
            crate::sta_link::management_tx_done(
                u16::from_le_bytes([frame_control, header.add(1).read()]),
                descriptor.add(19).read(),
                descriptor.add(0x10).cast::<u32>().read(),
            );
            Ok(())
        }
    }
}

/// Strict fixed-channel management completion. Authentication, association,
/// probe, and ordinary beacon frames need no stock completion side effect.
#[no_mangle]
pub unsafe extern "C" fn __wrap_ieee80211_tx_mgt_cb(frame: *mut c_void) {
    if strict_management_txdone(frame.cast()).is_err() {
        STRICT_CALLBACK_FAILED.store(true, Ordering::Release);
    }
}

unsafe fn strict_ap_beacon_txdone() -> Result<(), ()> {
    let ic = ptr::addr_of_mut!(g_ic).cast::<u8>();
    if TmpSTAAPCloseAP != 0 || ic.add(0x74).cast::<usize>().read() != 0 {
        return Err(());
    }
    let interface = ic.add(0x14).cast::<*mut u8>().read();
    if !interface.is_null()
        && BEACON_DTIM_SEND_MC != 0
        && !interface.add(0xec).cast::<*mut u8>().read().is_null()
    {
        // Sleeping-client multicast queues require `pwrsave_flushq`, whose
        // send/PM path is deliberately outside the PS-none strict profile.
        return Err(());
    }

    BEACON_SEND_START_FLAG &= !1;
    let next_tbtt = ic_get_next_tbtt();
    BEACON_NEXT_TBTT = next_tbtt;
    let Some(osi) = ptr::addr_of!(g_osi_funcs_p).read().as_ref() else {
        return Err(());
    };
    let Some(disarm) = osi._timer_disarm else {
        return Err(());
    };
    let Some(arm_us) = osi._timer_arm_us else {
        return Err(());
    };
    let timer = ptr::addr_of_mut!(BEACON_TIMER).cast::<c_void>();
    disarm(timer);
    arm_us(timer, next_tbtt, false);
    Ok(())
}

/// Strict AP-beacon completion. The final link redirects the callback table
/// with `--wrap=ieee80211_hostapd_beacon_txcb`; no vendor power-save, mesh, or
/// indirect application callback is entered.
#[no_mangle]
pub unsafe extern "C" fn __wrap_ieee80211_hostapd_beacon_txcb(_frame: *mut c_void) {
    if strict_ap_beacon_txdone().is_err() {
        STRICT_CALLBACK_FAILED.store(true, Ordering::Release);
    }
}

pub(crate) const fn is_continuation(kind: u32) -> bool {
    kind == TX_DONE_CONTINUATION
}

pub(crate) const fn is_lmac_continuation(kind: u32) -> bool {
    kind == LMAC_TX_DONE_CONTINUATION
}

/// Replace the finite `lmacTxDone(frame, 0)` prefix used by the strict
/// timeout/discard path. Mode-1 callbacks are split into separate executor
/// events before the frame is appended to the vendor TX-done list.
pub(crate) unsafe fn begin_from_lmac(frame: *mut u8) -> Result<(), TxDoneError> {
    begin_lmac(frame, true, false)
}

/// Continue a Rust-owned successful LMAC completion. This is the recovered
/// mode-1 `lmacTxDone` ownership transfer: callback work and queue resumption
/// remain separate bounded executor events.
pub(crate) unsafe fn begin_from_tx_success(frame: *mut u8) -> Result<(), TxDoneError> {
    crate::channel_switch::tx_done_edge();
    begin_lmac(frame, false, true)
}

unsafe fn begin_lmac(
    frame: *mut u8,
    resume_timeout: bool,
    resume_queue: bool,
) -> Result<(), TxDoneError> {
    let state = &mut *LMAC_STATE.0.get();
    if state.failed {
        return Err(TxDoneError::PreviousFailure);
    }
    if state.active {
        return Err(TxDoneError::LmacPipelineBusy);
    }
    let descriptor = descriptor(frame)?;
    let txrx = txrx()?;
    let registered = txrx.add(TX_CALLBACK_MODE1_MASK_OFFSET).cast::<u32>().read();
    let callbacks = descriptor
        .add(DESCRIPTOR_CALLBACK_MASK_OFFSET)
        .cast::<u32>()
        .read()
        & registered;
    let unsupported = callbacks & !BASIC_MODE1_CALLBACKS;
    if unsupported != 0 {
        return Err(TxDoneError::UnsupportedCallbackBits(unsupported));
    }

    state.active = true;
    state.frame = frame;
    state.callbacks = callbacks;
    state.resume_timeout = resume_timeout;
    state.resume_queue = resume_queue;
    state.phase = if callbacks == 0 {
        PHASE_RECYCLE
    } else {
        PHASE_CALLBACK
    };
    run_lmac_step(state)
}

pub(crate) unsafe fn dispatch_lmac_continuation() -> Result<(), TxDoneError> {
    let state = &mut *LMAC_STATE.0.get();
    if state.failed {
        return Err(TxDoneError::PreviousFailure);
    }
    run_lmac_step(state)
}

unsafe fn run_lmac_step(state: &mut TxDoneState) -> Result<(), TxDoneError> {
    let result = match state.phase {
        PHASE_CALLBACK => dispatch_one_lmac_callback(state),
        PHASE_RECYCLE => commit_lmac_tx_done(state),
        _ => Err(TxDoneError::InvalidPhase),
    };
    if result.is_err() {
        state.failed = true;
        state.active = false;
        state.phase = PHASE_IDLE;
    }
    result
}

unsafe fn dispatch_one_lmac_callback(state: &mut TxDoneState) -> Result<(), TxDoneError> {
    let bit = state.callbacks.trailing_zeros() as u8;
    let callback =
        lmac_callback_for_bit(bit).ok_or(TxDoneError::UnsupportedCallbackBits(1 << bit))?;
    let registered = txrx()?
        .add(TX_CALLBACK_TABLE_FIRST_OFFSET + usize::from(bit) * 4)
        .cast::<usize>()
        .read();
    if registered != callback as usize {
        return Err(TxDoneError::CallbackRegistryMismatch(bit));
    }

    #[cfg(feature = "hil-vendor-tx")]
    if bit == CALLBACK_STA_EAPOL {
        capture_hil_eapol_tx_done(state.frame)?;
    }

    callback(state.frame.cast());
    if STRICT_CALLBACK_FAILED.load(Ordering::Acquire) {
        return Err(TxDoneError::StrictCallbackFailed);
    }
    state.callbacks &= !(1 << bit);
    if state.callbacks == 0 {
        state.phase = PHASE_RECYCLE;
    }
    enqueue_lmac_step()
}

#[cfg(feature = "hil-vendor-tx")]
unsafe fn capture_hil_eapol_tx_done(frame: *mut u8) -> Result<(), TxDoneError> {
    let descriptor = descriptor(frame)?;
    let payload_owner = frame.add(4).cast::<*const u8>().read();
    if payload_owner.is_null() {
        return Err(TxDoneError::MissingDescriptor);
    }
    let mut payload = payload_owner.add(4).cast::<*const u8>().read();
    if payload.is_null() {
        return Err(TxDoneError::MissingDescriptor);
    }
    if frame.add(36).cast::<u16>().read() & 0x2000 != 0 {
        payload = payload.add(8);
    }
    let frame_control = u16::from_le_bytes([payload.read(), payload.add(1).read()]);
    let qos_offset = if frame_control & 0x0300 == 0x0300 {
        30
    } else {
        24
    };
    let qos_control = if frame_control & 0x0080 != 0 {
        payload.add(qos_offset).cast::<u16>().read_unaligned()
    } else {
        0
    };
    let descriptor_status = descriptor.add(0x10).cast::<u32>().read();
    HIL_EAPOL_FRAME_CONTROL.store(usize::from(frame_control), Ordering::Release);
    HIL_EAPOL_QOS_CONTROL.store(usize::from(qos_control), Ordering::Release);
    HIL_EAPOL_HW_STATUS.store(usize::from(descriptor.add(19).read()), Ordering::Release);
    HIL_EAPOL_DESCRIPTOR_STATUS.store(descriptor_status as usize, Ordering::Release);
    HIL_EAPOL_TXDONE_COUNT.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

unsafe fn commit_lmac_tx_done(state: &mut TxDoneState) -> Result<(), TxDoneError> {
    let frame = state.frame;
    let descriptor = descriptor(frame)?;
    let flags = descriptor.cast::<u32>().read();
    if flags & DESCRIPTOR_DIRECT_RECYCLE_BIT != 0 {
        return Err(TxDoneError::UnsupportedLmacDescriptorFlags(flags));
    }
    if ptr::addr_of!(g_wifi_menuconfig)
        .cast::<u8>()
        .add(0x40)
        .read()
        & 0x08
        != 0
    {
        return Err(TxDoneError::TxTimeRecordingEnabled);
    }

    append_tx_done(txrx()?, frame)?;
    if flags & DESCRIPTOR_RATE_CONTROL_BIT != 0
        && flags & DESCRIPTOR_RATE_CONTROL_SKIP_MASK != DESCRIPTOR_RATE_CONTROL_SKIP_VALUE
    {
        rcUpdateTxDone(frame.add(0x2c).cast(), descriptor.cast());
    }
    if pp_post(16, ptr::null_mut()) != 0 {
        return Err(TxDoneError::InternalQueueFull);
    }

    let resume_timeout = state.resume_timeout;
    let resume_queue = state.resume_queue;
    let queue = descriptor_queue(descriptor);
    state.active = false;
    state.phase = PHASE_IDLE;
    state.frame = ptr::null_mut();
    state.resume_timeout = false;
    state.resume_queue = false;
    if resume_timeout {
        return crate::lmac::resume_after_tx_done().map_err(|_| TxDoneError::InternalQueueFull);
    }
    if resume_queue {
        let instances = ptr::addr_of!(our_instances_ptr).read();
        if instances.is_null() {
            return Err(TxDoneError::InstancesUnavailable);
        }
        if instances.add(usize::from(queue) * 0x38 + 0x1d).read() <= 2 {
            lmacReleaseTxopQueue(queue);
        }
        if pp_post(u32::from(queue), ptr::null_mut()) != 0 {
            return Err(TxDoneError::InternalQueueFull);
        }
    }
    Ok(())
}

unsafe fn begin_from_wrapped_lmac(frame: *mut u8, mode: u32) -> Result<(), TxDoneError> {
    match mode {
        0 => begin_lmac(frame, false, false),
        1 => begin_lmac(frame, false, true),
        value => Err(TxDoneError::UnsupportedLmacMode(value)),
    }
}

/// Final-link replacement for the vendor TX-done convergence point. GNU ld
/// must receive `--wrap=lmacTxDone`; the archive itself is not modified.
/// Every mode-1 callback and the queue resume become executor continuations,
/// so the stock inline `ppProcTxDone`/power-management tail is never entered.
#[no_mangle]
#[cfg_attr(
    target_arch = "riscv32",
    link_section = ".rwtext.wifi_strict.lmac_tx_done"
)]
pub unsafe extern "C" fn __wrap_lmacTxDone(frame: *mut c_void, mode: u32) {
    crate::channel_switch::tx_done_edge();
    if begin_from_wrapped_lmac(frame.cast(), mode).is_err() {
        let state = &mut *LMAC_STATE.0.get();
        state.failed = true;
        state.active = false;
        state.phase = PHASE_IDLE;
        state.frame = ptr::null_mut();
        state.resume_timeout = false;
        state.resume_queue = false;
        // A wrapper cannot return a Rust error through the vendor C ABI. Post
        // a private event so the radio owner observes `PreviousFailure` and
        // terminates instead of continuing with partially completed TX state.
        let _ = enqueue_lmac_step();
    }
}

unsafe fn append_tx_done(txrx: *mut u8, frame: *mut u8) -> Result<(), TxDoneError> {
    let tail_link = txrx
        .add(TX_DONE_TAIL_LINK_OFFSET)
        .cast::<*mut *mut u8>()
        .read();
    if tail_link.is_null() {
        return Err(TxDoneError::MissingTxDoneTail);
    }
    frame
        .add(FRAME_NEXT_OFFSET)
        .cast::<*mut u8>()
        .write(ptr::null_mut());
    tail_link.write(frame);
    txrx.add(TX_DONE_TAIL_LINK_OFFSET)
        .cast::<*mut *mut u8>()
        .write(frame.add(FRAME_NEXT_OFFSET).cast());
    Ok(())
}

fn enqueue_lmac_step() -> Result<(), TxDoneError> {
    if crate::adapter::enqueue_internal_event(PpEvent {
        kind: LMAC_TX_DONE_CONTINUATION,
        argument: ptr::null_mut(),
    }) {
        Ok(())
    } else {
        Err(TxDoneError::InternalQueueFull)
    }
}

/// Begin the strict replacement for PP event 16. Repeated vendor events can
/// coalesce because the linked TX-done list remains the source of truth.
pub(crate) unsafe fn begin() -> Result<(), TxDoneError> {
    let state = &mut *STATE.0.get();
    if state.failed {
        return Err(TxDoneError::PreviousFailure);
    }
    if state.active {
        return Ok(());
    }
    state.active = true;
    state.phase = PHASE_LOAD;
    run_step(state)
}

pub(crate) unsafe fn dispatch_continuation() -> Result<(), TxDoneError> {
    let state = &mut *STATE.0.get();
    if state.failed {
        return Err(TxDoneError::PreviousFailure);
    }
    run_step(state)
}

unsafe fn run_step(state: &mut TxDoneState) -> Result<(), TxDoneError> {
    let result = dispatch_step(state);
    if result.is_err() {
        state.failed = true;
        state.active = false;
        state.phase = PHASE_IDLE;
    }
    result
}

unsafe fn dispatch_step(state: &mut TxDoneState) -> Result<(), TxDoneError> {
    match state.phase {
        PHASE_LOAD => load_one(state),
        PHASE_CALLBACK => dispatch_one_callback(state),
        PHASE_RECYCLE => recycle_one(state),
        _ => Err(TxDoneError::InvalidPhase),
    }
}

unsafe fn load_one(state: &mut TxDoneState) -> Result<(), TxDoneError> {
    let txrx = txrx()?;
    let head = txrx.add(TX_DONE_HEAD_OFFSET).cast::<*mut u8>();
    let frame = head.read();
    if frame.is_null() {
        state.active = false;
        state.phase = PHASE_IDLE;
        return Ok(());
    }

    let next = frame.add(FRAME_NEXT_OFFSET).cast::<*mut u8>().read();
    head.write(next);
    if next.is_null() {
        txrx.add(TX_DONE_TAIL_LINK_OFFSET)
            .cast::<*mut u8>()
            .write(head.cast());
    }

    let descriptor = descriptor(frame)?;
    let registered = txrx.add(TX_CALLBACK_MODE0_MASK_OFFSET).cast::<u32>().read();
    let callbacks = descriptor
        .add(DESCRIPTOR_CALLBACK_MASK_OFFSET)
        .cast::<u32>()
        .read()
        & registered;
    let unsupported = callbacks & !BASIC_MODE0_CALLBACKS;
    if unsupported != 0 {
        return Err(TxDoneError::UnsupportedCallbackBits(unsupported));
    }

    state.frame = frame;
    state.callbacks = callbacks;
    state.phase = if callbacks == 0 {
        PHASE_RECYCLE
    } else {
        PHASE_CALLBACK
    };
    enqueue_step()
}

unsafe fn dispatch_one_callback(state: &mut TxDoneState) -> Result<(), TxDoneError> {
    let bit = state.callbacks.trailing_zeros() as u8;
    let callback = callback_for_bit(bit).ok_or(TxDoneError::UnsupportedCallbackBits(1 << bit))?;
    let txrx = txrx()?;
    let registered = txrx
        .add(TX_CALLBACK_TABLE_FIRST_OFFSET + usize::from(bit) * 4)
        .cast::<usize>()
        .read();
    if registered != callback as usize {
        return Err(TxDoneError::CallbackRegistryMismatch(bit));
    }

    callback(state.frame.cast());
    if STRICT_CALLBACK_FAILED.load(Ordering::Acquire) {
        return Err(TxDoneError::StrictCallbackFailed);
    }
    state.callbacks &= !(1 << bit);
    if state.callbacks == 0 {
        state.phase = PHASE_RECYCLE;
    }
    enqueue_step()
}

unsafe fn recycle_one(state: &mut TxDoneState) -> Result<(), TxDoneError> {
    let frame = state.frame;
    let descriptor = descriptor(frame)?;
    #[cfg(feature = "hil-vendor-tx")]
    capture_hil_data_tx_done(frame, descriptor)?;
    let flags = descriptor.cast::<u32>().read();
    // The stock bit-13 branch only feeds `trc_onPPTxDone` after inspecting
    // optional tracing metadata. Strict mode has no tracing consumer and
    // intentionally omits that side effect; the bit does not alter ownership
    // or recycling. Fragment completion, in contrast, rewrites and requeues
    // the frame and remains unsupported.
    let unsupported = flags & DESCRIPTOR_FRAGMENT_BIT;
    if unsupported != 0 {
        return Err(TxDoneError::UnsupportedDescriptorFlags(unsupported));
    }
    if ptr::addr_of!(g_tx_done_cb_func).read() != 0 {
        return Err(TxDoneError::UserCallbackInstalled);
    }
    let frame_type = frame.add(FRAME_TYPE_OFFSET).read();
    if !crate::esf::is_strict_recyclable_frame(frame) {
        return Err(TxDoneError::NonStaticFrameType(frame_type));
    }

    pp_coex_tx_release(frame.cast());
    // The strict ESF wrapper accepts only its fixed Rust management pool or
    // initialized vendor static free lists; dynamic/cache branches remain
    // unreachable.
    esf_buf_recycle(frame.cast());
    crate::data_tx::complete_hardware_wifi_data_tx(frame);

    state.frame = ptr::null_mut();
    state.phase = PHASE_LOAD;
    enqueue_step()
}

#[cfg(feature = "hil-vendor-tx")]
unsafe fn capture_hil_data_tx_done(frame: *mut u8, descriptor: *mut u8) -> Result<(), TxDoneError> {
    let payload_owner = frame.add(4).cast::<*const u8>().read();
    if payload_owner.is_null() {
        return Err(TxDoneError::MissingDescriptor);
    }
    let mut payload = payload_owner.add(4).cast::<*const u8>().read();
    if payload.is_null() {
        return Err(TxDoneError::MissingDescriptor);
    }
    if frame.add(36).cast::<u16>().read() & 0x2000 != 0 {
        payload = payload.add(8);
    }
    let frame_control = u16::from_le_bytes([payload.read(), payload.add(1).read()]);
    if frame_control & 0x000c != 0x0008 {
        return Ok(());
    }
    if frame_control & 0x4000 != 0 {
        store_hil_bytes(&HIL_DATA_TRANSMITTER, payload.add(10));
        store_hil_bytes(&HIL_DATA_CCMP_HEADER, payload.add(24));
        // CCMP is applied while hardware consumes the DMA buffer. RAM keeps
        // the plaintext LLC/SNAP prefix after the inserted CCMP header.
        store_hil_bytes(&HIL_DATA_PAYLOAD_PREFIX, payload.add(32));
    }
    HIL_DATA_FRAME_CONTROL.store(usize::from(frame_control), Ordering::Release);
    HIL_DATA_HW_STATUS.store(usize::from(descriptor.add(19).read()), Ordering::Release);
    HIL_DATA_DESCRIPTOR_STATUS.store(
        descriptor.add(0x10).cast::<u32>().read() as usize,
        Ordering::Release,
    );
    HIL_DATA_TXDONE_COUNT.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

#[cfg(feature = "hil-vendor-tx")]
unsafe fn store_hil_bytes<const N: usize>(destination: &[AtomicU8; N], source: *const u8) {
    let mut index = 0;
    while index < N {
        destination[index].store(source.add(index).read(), Ordering::Release);
        index += 1;
    }
}

fn enqueue_step() -> Result<(), TxDoneError> {
    if crate::adapter::enqueue_internal_event(PpEvent {
        kind: TX_DONE_CONTINUATION,
        argument: ptr::null_mut(),
    }) {
        Ok(())
    } else {
        Err(TxDoneError::InternalQueueFull)
    }
}

unsafe fn txrx() -> Result<*mut u8, TxDoneError> {
    let txrx = ptr::addr_of!(pTxRx).read();
    if txrx.is_null() {
        Err(TxDoneError::TxRxUnavailable)
    } else {
        Ok(txrx)
    }
}

unsafe fn descriptor(frame: *mut u8) -> Result<*mut u8, TxDoneError> {
    let descriptor = frame.add(FRAME_DESCRIPTOR_OFFSET).cast::<*mut u8>().read();
    if descriptor.is_null() {
        Err(TxDoneError::MissingDescriptor)
    } else {
        Ok(descriptor)
    }
}

unsafe fn descriptor_queue(descriptor: *mut u8) -> u8 {
    ((descriptor.add(0x10).cast::<u32>().read() >> 20) & 0x0f) as u8
}

fn callback_for_bit(bit: u8) -> Option<TxCallback> {
    match bit {
        CALLBACK_MGMT => Some(__wrap_ieee80211_tx_mgt_cb),
        CALLBACK_AP_BEACON => Some(__wrap_ieee80211_hostapd_beacon_txcb),
        CALLBACK_AP_DATA => Some(ieee80211_hostapd_data_txcb),
        _ => None,
    }
}

fn lmac_callback_for_bit(bit: u8) -> Option<TxCallback> {
    match bit {
        CALLBACK_STA_EAPOL => Some(sta_eapol_txdone_cb),
        _ => None,
    }
}
