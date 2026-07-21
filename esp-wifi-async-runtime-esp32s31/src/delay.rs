use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::{adapter::blocking_probe, context::current_event, diagnostics::BlockingCall};

static CALLS: AtomicU32 = AtomicU32::new(0);
static LAST_MICROSECONDS: AtomicU32 = AtomicU32::new(0);
static LAST_CALLER: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    #[link_name = "ets_delay_us"]
    fn linked_ets_delay_us(microseconds: u32);
    fn __real_ets_delay_us(microseconds: u32);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectDelaySnapshot {
    pub calls: u32,
    pub last_microseconds: u32,
    pub last_caller: usize,
}

pub fn direct_delay_snapshot() -> DirectDelaySnapshot {
    DirectDelaySnapshot {
        calls: CALLS.load(Ordering::Acquire),
        last_microseconds: LAST_MICROSECONDS.load(Ordering::Relaxed),
        last_caller: LAST_CALLER.load(Ordering::Relaxed),
    }
}

pub(crate) fn runtime_delay_link_wrapper_active() -> bool {
    core::ptr::eq(
        linked_ets_delay_us as *const (),
        __wrap_ets_delay_us as *const (),
    )
}

/// Trace the still-unreconstructed ROM busy-delay after strict takeover.
///
/// This wrapper deliberately delegates after recording: returning early was
/// proven on hardware to strand the channel-change PHY sequence in its next
/// status loop. Consequently any non-zero post-takeover count is a strict
/// audit failure, not an accepted runtime primitive.
#[no_mangle]
pub unsafe extern "C" fn __wrap_ets_delay_us(microseconds: u32) {
    let caller: usize;
    core::arch::asm!(
        "mv {caller}, ra",
        caller = out(reg) caller,
        options(nomem, nostack, preserves_flags)
    );
    if crate::critical::strict_wifi_hart_armed() {
        LAST_CALLER.store(caller, Ordering::Relaxed);
        LAST_MICROSECONDS.store(microseconds, Ordering::Relaxed);
        CALLS.fetch_add(1, Ordering::Release);
        blocking_probe().record(BlockingCall::EtsDelayUs, current_event(), caller);
    }
    __real_ets_delay_us(microseconds);
}
