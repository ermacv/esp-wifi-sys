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

#[cfg(all(target_arch = "riscv32", feature = "rust-direct-cold-stop"))]
const WIFI_STATE_OFFSET: usize = 0x1f5;
const WIFI_STATE_STARTED: u8 = 2;
const ESP_OK: i32 = 0;
const ESP_ERR_WIFI_NOT_STARTED: i32 = 0x3002;

static CALLS: AtomicU32 = AtomicU32::new(0);
static PRESTART_SUCCESSES: AtomicU32 = AtomicU32::new(0);
static ACTIVE_REJECTIONS: AtomicU32 = AtomicU32::new(0);
static LAST_STATE: AtomicU32 = AtomicU32::new(0);

/// Observation counters for the bounded cold-stop boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirectColdStopSnapshot {
    pub calls: u32,
    pub prestart_successes: u32,
    pub active_rejections: u32,
    pub last_state: u8,
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
}
