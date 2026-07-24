//! Allocation-free, bounded replacements for selected upper Wi-Fi APIs.
//!
//! The pinned `esp_wifi_stop` wrapper allocates a 24-byte ioctl command and,
//! after its first stop phase, may retry up to 500 times with an OSI delay
//! between attempts. The strict cold-start path calls it only while the radio
//! state is not started, before changing mode from NULL to STA or AP. In that
//! state the vendor process returns `ESP_ERR_WIFI_NOT_STARTED`, which the
//! wrapper converts to success.
//!
//! This interposition reproduces only that qualified cold behavior. It performs
//! one volatile state read and returns. An active-radio call is rejected and
//! counted; stopping a running radio belongs in an asynchronous Rust lifecycle
//! future, not in this synchronous ABI.

use core::sync::atomic::{AtomicU32, Ordering};

const API_REQUEST_SIZE: usize = 24;
const API_REQUEST_ARGUMENT_OFFSET: usize = 8;
#[cfg(all(target_arch = "riscv32", feature = "rust-direct-cold-stop"))]
const WIFI_STATE_OFFSET: usize = 0x1f5;
const WIFI_STATE_STARTED: u8 = 2;
const ESP_OK: i32 = 0;
const ESP_ERR_INVALID_ARG: i32 = 0x102;
const ESP_ERR_WIFI_NOT_INIT: i32 = 0x3001;
const ESP_ERR_WIFI_NOT_STARTED: i32 = 0x3002;
const MAX_PS_TYPE: u32 = 2;

static CALLS: AtomicU32 = AtomicU32::new(0);
static PRESTART_SUCCESSES: AtomicU32 = AtomicU32::new(0);
static ACTIVE_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static LAST_STATE: AtomicU32 = AtomicU32::new(0);
static SET_MODE_CALLS: AtomicU32 = AtomicU32::new(0);
static SET_MODE_NOT_INITIALIZED: AtomicU32 = AtomicU32::new(0);
static SET_MODE_LAST_MODE: AtomicU32 = AtomicU32::new(0);
static SET_MODE_LAST_RESULT: AtomicU32 = AtomicU32::new(0);
static SET_PS_CALLS: AtomicU32 = AtomicU32::new(0);
static SET_PS_NOT_INITIALIZED: AtomicU32 = AtomicU32::new(0);
static SET_PS_INVALID_ARGUMENTS: AtomicU32 = AtomicU32::new(0);
static SET_PS_LAST_TYPE: AtomicU32 = AtomicU32::new(0);
static SET_PS_LAST_RESULT: AtomicU32 = AtomicU32::new(0);
static REG_RXCB_CALLS: AtomicU32 = AtomicU32::new(0);
static REG_RXCB_NOT_INITIALIZED: AtomicU32 = AtomicU32::new(0);
static REG_RXCB_INVALID_INTERFACES: AtomicU32 = AtomicU32::new(0);
static REG_RXCB_LAST_INTERFACE: AtomicU32 = AtomicU32::new(0);
static REG_RXCB_LAST_RESULT: AtomicU32 = AtomicU32::new(0);
static REG_MGMT_FRAME_CALLS: AtomicU32 = AtomicU32::new(0);
static REG_MGMT_FRAME_NOT_INITIALIZED: AtomicU32 = AtomicU32::new(0);
static REG_MGMT_FRAME_LAST_MASK: AtomicU32 = AtomicU32::new(0);
static REG_MGMT_FRAME_LAST_CONTEXT: AtomicU32 = AtomicU32::new(0);
static REG_MGMT_FRAME_LAST_RESULT: AtomicU32 = AtomicU32::new(0);

#[repr(C, align(4))]
struct ApiRequest {
    bytes: [u8; API_REQUEST_SIZE],
}

impl ApiRequest {
    unsafe fn with_byte_argument(argument: u8) -> core::mem::MaybeUninit<Self> {
        let mut request = core::mem::MaybeUninit::<Self>::uninit();
        request
            .as_mut_ptr()
            .cast::<u8>()
            .add(API_REQUEST_ARGUMENT_OFFSET)
            .write(argument);
        request
    }

    unsafe fn with_rx_callback(interface: u8, callback: u32) -> core::mem::MaybeUninit<Self> {
        let mut request = Self::with_byte_argument(interface);
        request
            .as_mut_ptr()
            .cast::<u8>()
            .add(12)
            .cast::<u32>()
            .write_unaligned(callback);
        request
    }

    unsafe fn with_mgmt_frame_registration(
        frame_subtype_mask: u32,
        context: u32,
    ) -> core::mem::MaybeUninit<Self> {
        let mut request = core::mem::MaybeUninit::<Self>::uninit();
        let bytes = request.as_mut_ptr().cast::<u8>();
        bytes
            .add(12)
            .cast::<u32>()
            .write_unaligned(frame_subtype_mask);
        bytes.add(20).cast::<u32>().write_unaligned(context);
        request
    }
}

/// Observation counters for the bounded cold-stop boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectColdStopSnapshot {
    pub calls: u32,
    pub prestart_successes: u32,
    pub active_rejections: u32,
    pub last_state: u8,
}

/// Observation counters for direct set-mode process calls.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectSetModeSnapshot {
    pub calls: u32,
    pub not_initialized: u32,
    pub last_mode: u8,
    pub last_result: i32,
}

/// Observation counters for direct power-save process calls.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectSetPsSnapshot {
    pub calls: u32,
    pub not_initialized: u32,
    pub invalid_arguments: u32,
    pub last_ps_type: u8,
    pub last_result: i32,
}

/// Observation counters for direct RX callback registration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectRegRxcbSnapshot {
    pub calls: u32,
    pub not_initialized: u32,
    pub invalid_interfaces: u32,
    pub last_interface: u8,
    pub last_result: i32,
}

/// Observation counters for direct management-frame registration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectRegMgmtFrameSnapshot {
    pub calls: u32,
    pub not_initialized: u32,
    pub last_frame_subtype_mask: u32,
    pub last_context: usize,
    pub last_result: i32,
}

/// Return the current cold-stop interposition counters.
pub fn direct_cold_stop_snapshot() -> DirectColdStopSnapshot {
    DirectColdStopSnapshot {
        calls: CALLS.load(Ordering::Relaxed),
        prestart_successes: PRESTART_SUCCESSES.load(Ordering::Relaxed),
        active_rejections: ACTIVE_REJECTIONS.load(Ordering::Relaxed),
        last_state: LAST_STATE.load(Ordering::Relaxed) as u8,
    }
}

/// Return the current direct set-mode counters.
pub fn direct_set_mode_snapshot() -> DirectSetModeSnapshot {
    DirectSetModeSnapshot {
        calls: SET_MODE_CALLS.load(Ordering::Relaxed),
        not_initialized: SET_MODE_NOT_INITIALIZED.load(Ordering::Relaxed),
        last_mode: SET_MODE_LAST_MODE.load(Ordering::Relaxed) as u8,
        last_result: SET_MODE_LAST_RESULT.load(Ordering::Relaxed) as i32,
    }
}

/// Return the current direct power-save counters.
pub fn direct_set_ps_snapshot() -> DirectSetPsSnapshot {
    DirectSetPsSnapshot {
        calls: SET_PS_CALLS.load(Ordering::Relaxed),
        not_initialized: SET_PS_NOT_INITIALIZED.load(Ordering::Relaxed),
        invalid_arguments: SET_PS_INVALID_ARGUMENTS.load(Ordering::Relaxed),
        last_ps_type: SET_PS_LAST_TYPE.load(Ordering::Relaxed) as u8,
        last_result: SET_PS_LAST_RESULT.load(Ordering::Relaxed) as i32,
    }
}

/// Return the current direct RX callback registration counters.
pub fn direct_reg_rxcb_snapshot() -> DirectRegRxcbSnapshot {
    DirectRegRxcbSnapshot {
        calls: REG_RXCB_CALLS.load(Ordering::Relaxed),
        not_initialized: REG_RXCB_NOT_INITIALIZED.load(Ordering::Relaxed),
        invalid_interfaces: REG_RXCB_INVALID_INTERFACES.load(Ordering::Relaxed),
        last_interface: REG_RXCB_LAST_INTERFACE.load(Ordering::Relaxed) as u8,
        last_result: REG_RXCB_LAST_RESULT.load(Ordering::Relaxed) as i32,
    }
}

/// Return the current direct management-frame registration counters.
pub fn direct_reg_mgmt_frame_snapshot() -> DirectRegMgmtFrameSnapshot {
    DirectRegMgmtFrameSnapshot {
        calls: REG_MGMT_FRAME_CALLS.load(Ordering::Relaxed),
        not_initialized: REG_MGMT_FRAME_NOT_INITIALIZED.load(Ordering::Relaxed),
        last_frame_subtype_mask: REG_MGMT_FRAME_LAST_MASK.load(Ordering::Relaxed),
        last_context: REG_MGMT_FRAME_LAST_CONTEXT.load(Ordering::Relaxed) as usize,
        last_result: REG_MGMT_FRAME_LAST_RESULT.load(Ordering::Relaxed) as i32,
    }
}

fn classify_cold_stop(state: u8) -> i32 {
    if state < WIFI_STATE_STARTED {
        ESP_OK
    } else {
        ESP_ERR_WIFI_NOT_STARTED
    }
}

fn validate_ps_type(ps_type: u32) -> Result<u8, i32> {
    if ps_type <= MAX_PS_TYPE {
        Ok(ps_type as u8)
    } else {
        Err(ESP_ERR_INVALID_ARG)
    }
}

#[cfg(all(target_arch = "riscv32", feature = "rust-direct-cold-stop"))]
unsafe extern "C" {
    static g_ic: u8;
}

#[cfg(all(
    target_arch = "riscv32",
    any(
        feature = "rust-direct-set-mode",
        feature = "rust-direct-set-ps",
        feature = "rust-direct-reg-rxcb",
        feature = "rust-direct-reg-mgmt-frame"
    )
))]
unsafe extern "C" {
    fn wifi_init_completed() -> i32;
}

#[cfg(all(target_arch = "riscv32", feature = "rust-direct-reg-rxcb"))]
unsafe extern "C" {
    fn wifi_set_rxcb_process(request: *mut core::ffi::c_void) -> i32;
}

#[cfg(all(target_arch = "riscv32", feature = "rust-direct-reg-mgmt-frame"))]
unsafe extern "C" {
    fn wifi_register_mgmt_frame(request: *mut core::ffi::c_void) -> i32;
}

#[cfg(all(target_arch = "riscv32", feature = "rust-direct-set-mode"))]
unsafe extern "C" {
    fn wifi_set_mode_process(request: *mut core::ffi::c_void) -> i32;
}

#[cfg(all(target_arch = "riscv32", feature = "rust-direct-set-ps"))]
unsafe extern "C" {
    fn wifi_set_ps_process(request: *mut core::ffi::c_void) -> i32;
}

/// Replace only the qualified pre-start use of `esp_wifi_stop`.
///
/// This function is linked through `--wrap=esp_wifi_stop`. It deliberately
/// does not delegate active-radio calls to `__real_esp_wifi_stop`, because that
/// body contains the forbidden delay/retry loop.
#[cfg(all(target_arch = "riscv32", feature = "rust-direct-cold-stop"))]
#[no_mangle]
pub unsafe extern "C" fn __wrap_esp_wifi_stop() -> i32 {
    let state = core::ptr::read_volatile(core::ptr::addr_of!(g_ic).add(WIFI_STATE_OFFSET));
    CALLS.fetch_add(1, Ordering::Relaxed);
    LAST_STATE.store(u32::from(state), Ordering::Relaxed);
    let result = classify_cold_stop(state);
    if result == ESP_OK {
        PRESTART_SUCCESSES.fetch_add(1, Ordering::Relaxed);
    } else {
        ACTIVE_REJECTIONS.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Invoke the pinned set-mode process with its exact request layout on stack.
///
/// The process remains the vendor run-to-completion state transition. This
/// wrapper removes only the allocator plus `ieee80211_ioctl` envelope. Strict
/// integration guarantees that upper API calls are serialized by the single
/// Rust radio owner.
#[cfg(all(target_arch = "riscv32", feature = "rust-direct-set-mode"))]
#[no_mangle]
pub unsafe extern "C" fn __wrap_esp_wifi_set_mode(mode: u32) -> i32 {
    SET_MODE_CALLS.fetch_add(1, Ordering::Relaxed);
    SET_MODE_LAST_MODE.store(mode, Ordering::Relaxed);
    if wifi_init_completed() == 0 {
        SET_MODE_NOT_INITIALIZED.fetch_add(1, Ordering::Relaxed);
        SET_MODE_LAST_RESULT.store(ESP_ERR_WIFI_NOT_INIT as u32, Ordering::Relaxed);
        return ESP_ERR_WIFI_NOT_INIT;
    }
    let mut request = ApiRequest::with_byte_argument(mode as u8);
    let result = wifi_set_mode_process(request.as_mut_ptr().cast());
    SET_MODE_LAST_RESULT.store(result as u32, Ordering::Relaxed);
    result
}

/// Invoke the pinned power-save process with its exact request layout on stack.
///
/// The process reads only byte 8 and delegates finite state changes and timer
/// rearming to the already patched asynchronous OSI timer table. Valid values
/// are the vendor ABI's NONE, MIN_MODEM and MAX_MODEM variants (`0..=2`).
#[cfg(all(target_arch = "riscv32", feature = "rust-direct-set-ps"))]
#[no_mangle]
pub unsafe extern "C" fn __wrap_esp_wifi_set_ps(ps_type: u32) -> i32 {
    SET_PS_CALLS.fetch_add(1, Ordering::Relaxed);
    SET_PS_LAST_TYPE.store(ps_type, Ordering::Relaxed);
    if wifi_init_completed() == 0 {
        SET_PS_NOT_INITIALIZED.fetch_add(1, Ordering::Relaxed);
        SET_PS_LAST_RESULT.store(ESP_ERR_WIFI_NOT_INIT as u32, Ordering::Relaxed);
        return ESP_ERR_WIFI_NOT_INIT;
    }
    let ps_type = match validate_ps_type(ps_type) {
        Ok(ps_type) => ps_type,
        Err(error) => {
            SET_PS_INVALID_ARGUMENTS.fetch_add(1, Ordering::Relaxed);
            SET_PS_LAST_RESULT.store(error as u32, Ordering::Relaxed);
            return error;
        }
    };
    let mut request = ApiRequest::with_byte_argument(ps_type);
    let result = wifi_set_ps_process(request.as_mut_ptr().cast());
    SET_PS_LAST_RESULT.store(result as u32, Ordering::Relaxed);
    result
}

/// Register an RX callback through the pinned finite interface dispatcher.
#[cfg(all(target_arch = "riscv32", feature = "rust-direct-reg-rxcb"))]
#[no_mangle]
pub unsafe extern "C" fn __wrap_esp_wifi_internal_reg_rxcb(interface: u32, callback: usize) -> i32 {
    const MAX_INTERFACE: u32 = 2;
    const ESP_ERR_WIFI_IF: i32 = 0x3004;

    REG_RXCB_CALLS.fetch_add(1, Ordering::Relaxed);
    REG_RXCB_LAST_INTERFACE.store(interface, Ordering::Relaxed);
    if wifi_init_completed() == 0 {
        REG_RXCB_NOT_INITIALIZED.fetch_add(1, Ordering::Relaxed);
        REG_RXCB_LAST_RESULT.store(ESP_ERR_WIFI_NOT_INIT as u32, Ordering::Relaxed);
        return ESP_ERR_WIFI_NOT_INIT;
    }
    if interface > MAX_INTERFACE {
        REG_RXCB_INVALID_INTERFACES.fetch_add(1, Ordering::Relaxed);
        REG_RXCB_LAST_RESULT.store(ESP_ERR_WIFI_IF as u32, Ordering::Relaxed);
        return ESP_ERR_WIFI_IF;
    }
    let mut request = ApiRequest::with_rx_callback(interface as u8, callback as u32);
    let result = wifi_set_rxcb_process(request.as_mut_ptr().cast());
    REG_RXCB_LAST_RESULT.store(result as u32, Ordering::Relaxed);
    result
}

/// Publish the management-frame subtype mask and callback context directly.
///
/// The pinned process leaf reads only request words 12 and 20, stores them in
/// the vendor control block, and returns success. The Rust radio owner
/// serializes registration with all other upper API state transitions.
#[cfg(all(target_arch = "riscv32", feature = "rust-direct-reg-mgmt-frame"))]
#[no_mangle]
pub unsafe extern "C" fn __wrap_esp_wifi_register_mgmt_frame_internal(
    frame_subtype_mask: u32,
    context: usize,
) -> i32 {
    REG_MGMT_FRAME_CALLS.fetch_add(1, Ordering::Relaxed);
    REG_MGMT_FRAME_LAST_MASK.store(frame_subtype_mask, Ordering::Relaxed);
    REG_MGMT_FRAME_LAST_CONTEXT.store(context as u32, Ordering::Relaxed);
    if wifi_init_completed() == 0 {
        REG_MGMT_FRAME_NOT_INITIALIZED.fetch_add(1, Ordering::Relaxed);
        REG_MGMT_FRAME_LAST_RESULT.store(ESP_ERR_WIFI_NOT_INIT as u32, Ordering::Relaxed);
        return ESP_ERR_WIFI_NOT_INIT;
    }
    let mut request = ApiRequest::with_mgmt_frame_registration(frame_subtype_mask, context as u32);
    let result = wifi_register_mgmt_frame(request.as_mut_ptr().cast());
    REG_MGMT_FRAME_LAST_RESULT.store(result as u32, Ordering::Relaxed);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prestart_states_are_finite_successes() {
        assert_eq!(classify_cold_stop(0), ESP_OK);
        assert_eq!(classify_cold_stop(1), ESP_OK);
    }

    #[test]
    fn active_and_unknown_states_fail_closed() {
        assert_eq!(classify_cold_stop(2), ESP_ERR_WIFI_NOT_STARTED);
        assert_eq!(classify_cold_stop(3), ESP_ERR_WIFI_NOT_STARTED);
        assert_eq!(classify_cold_stop(u8::MAX), ESP_ERR_WIFI_NOT_STARTED);
    }

    #[test]
    fn set_mode_request_has_exact_vendor_layout() {
        assert_eq!(core::mem::size_of::<ApiRequest>(), API_REQUEST_SIZE);
        assert_eq!(core::mem::align_of::<ApiRequest>(), 4);
        assert_eq!(core::mem::offset_of!(ApiRequest, bytes), 0);
        let request = unsafe { ApiRequest::with_byte_argument(3) };
        assert_eq!(
            unsafe {
                request
                    .as_ptr()
                    .cast::<u8>()
                    .add(API_REQUEST_ARGUMENT_OFFSET)
                    .read()
            },
            3
        );
    }

    #[test]
    fn power_save_type_matches_the_vendor_public_validation() {
        assert_eq!(validate_ps_type(0), Ok(0));
        assert_eq!(validate_ps_type(1), Ok(1));
        assert_eq!(validate_ps_type(2), Ok(2));
        assert_eq!(validate_ps_type(3), Err(ESP_ERR_INVALID_ARG));
        assert_eq!(validate_ps_type(u32::MAX), Err(ESP_ERR_INVALID_ARG));
    }

    #[test]
    fn rx_callback_request_has_exact_vendor_fields() {
        let request = unsafe { ApiRequest::with_rx_callback(2, 0x1234_5678) };
        let bytes = request.as_ptr().cast::<u8>();
        assert_eq!(unsafe { bytes.add(API_REQUEST_ARGUMENT_OFFSET).read() }, 2);
        assert_eq!(
            unsafe { bytes.add(12).cast::<u32>().read_unaligned() },
            0x1234_5678
        );
    }

    #[test]
    fn management_frame_registration_has_exact_vendor_fields() {
        let request = unsafe { ApiRequest::with_mgmt_frame_registration(0x0000_080a, 0x1234_5678) };
        let bytes = request.as_ptr().cast::<u8>();
        assert_eq!(
            unsafe { bytes.add(12).cast::<u32>().read_unaligned() },
            0x0000_080a
        );
        assert_eq!(
            unsafe { bytes.add(20).cast::<u32>().read_unaligned() },
            0x1234_5678
        );
    }
}
