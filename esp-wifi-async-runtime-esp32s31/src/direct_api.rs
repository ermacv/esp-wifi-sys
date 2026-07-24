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
const ESP_ERR_WIFI_NOT_INIT: i32 = 0x3001;
const ESP_ERR_WIFI_NOT_STARTED: i32 = 0x3002;

static CALLS: AtomicU32 = AtomicU32::new(0);
static PRESTART_SUCCESSES: AtomicU32 = AtomicU32::new(0);
static ACTIVE_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static LAST_STATE: AtomicU32 = AtomicU32::new(0);
static SET_MODE_CALLS: AtomicU32 = AtomicU32::new(0);
static SET_MODE_NOT_INITIALIZED: AtomicU32 = AtomicU32::new(0);
static SET_MODE_LAST_MODE: AtomicU32 = AtomicU32::new(0);
static SET_MODE_LAST_RESULT: AtomicU32 = AtomicU32::new(0);

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

fn classify_cold_stop(state: u8) -> i32 {
    if state < WIFI_STATE_STARTED {
        ESP_OK
    } else {
        ESP_ERR_WIFI_NOT_STARTED
    }
}

#[cfg(all(target_arch = "riscv32", feature = "rust-direct-cold-stop"))]
unsafe extern "C" {
    static g_ic: u8;
}

#[cfg(all(target_arch = "riscv32", feature = "rust-direct-set-mode"))]
unsafe extern "C" {
    fn wifi_init_completed() -> i32;
    fn wifi_set_mode_process(request: *mut core::ffi::c_void) -> i32;
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
}
