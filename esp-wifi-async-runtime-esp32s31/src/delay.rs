use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::{adapter::blocking_probe, context::current_event, diagnostics::BlockingCall};

static CALLS: AtomicU32 = AtomicU32::new(0);
static LAST_MICROSECONDS: AtomicU32 = AtomicU32::new(0);
static LAST_CALLER: AtomicUsize = AtomicUsize::new(0);
static DROPPED_SITES: AtomicU32 = AtomicU32::new(0);

pub const DIRECT_DELAY_SITE_CAPACITY: usize = 16;

static SITE_CALLERS: [AtomicUsize; DIRECT_DELAY_SITE_CAPACITY] =
    [const { AtomicUsize::new(0) }; DIRECT_DELAY_SITE_CAPACITY];
static SITE_MICROSECONDS: [AtomicU32; DIRECT_DELAY_SITE_CAPACITY] =
    [const { AtomicU32::new(0) }; DIRECT_DELAY_SITE_CAPACITY];
static SITE_CALLS: [AtomicU32; DIRECT_DELAY_SITE_CAPACITY] =
    [const { AtomicU32::new(0) }; DIRECT_DELAY_SITE_CAPACITY];

unsafe extern "C" {
    #[link_name = "ets_delay_us"]
    fn linked_ets_delay_us(microseconds: u32);
    fn __real_ets_delay_us(microseconds: u32);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectDelaySiteSnapshot {
    pub caller: usize,
    pub microseconds: u32,
    pub calls: u32,
}

impl DirectDelaySiteSnapshot {
    const EMPTY: Self = Self {
        caller: 0,
        microseconds: 0,
        calls: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectDelaySnapshot {
    pub calls: u32,
    pub last_microseconds: u32,
    pub last_caller: usize,
    pub dropped_sites: u32,
    pub sites: [DirectDelaySiteSnapshot; DIRECT_DELAY_SITE_CAPACITY],
}

pub fn direct_delay_snapshot() -> DirectDelaySnapshot {
    let mut sites = [DirectDelaySiteSnapshot::EMPTY; DIRECT_DELAY_SITE_CAPACITY];
    let mut index = 0;
    while index < DIRECT_DELAY_SITE_CAPACITY {
        sites[index] = DirectDelaySiteSnapshot {
            caller: SITE_CALLERS[index].load(Ordering::Acquire),
            microseconds: SITE_MICROSECONDS[index].load(Ordering::Relaxed),
            calls: SITE_CALLS[index].load(Ordering::Relaxed),
        };
        index += 1;
    }
    DirectDelaySnapshot {
        calls: CALLS.load(Ordering::Acquire),
        last_microseconds: LAST_MICROSECONDS.load(Ordering::Relaxed),
        last_caller: LAST_CALLER.load(Ordering::Relaxed),
        dropped_sites: DROPPED_SITES.load(Ordering::Relaxed),
        sites,
    }
}

fn record_site(caller: usize, microseconds: u32) {
    let mut index = 0;
    while index < DIRECT_DELAY_SITE_CAPACITY {
        let recorded = SITE_CALLERS[index].load(Ordering::Acquire);
        if recorded == caller {
            SITE_MICROSECONDS[index].store(microseconds, Ordering::Relaxed);
            SITE_CALLS[index].fetch_add(1, Ordering::Relaxed);
            return;
        }
        if recorded == 0 {
            match SITE_CALLERS[index].compare_exchange(
                0,
                caller,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    SITE_MICROSECONDS[index].store(microseconds, Ordering::Relaxed);
                    SITE_CALLS[index].store(1, Ordering::Release);
                    return;
                }
                Err(actual) if actual == caller => {
                    SITE_MICROSECONDS[index].store(microseconds, Ordering::Relaxed);
                    SITE_CALLS[index].fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(_) => {}
            }
        }
        index += 1;
    }
    DROPPED_SITES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn runtime_delay_link_wrapper_active() -> bool {
    core::ptr::eq(
        linked_ets_delay_us as *const (),
        __wrap_ets_delay_us as *const (),
    )
}

/// Reject a ROM busy-delay after strict takeover.
///
/// Initialization still delegates to the pinned ROM entry. Once the strict
/// runtime owns Wi-Fi, an attempted delay is recorded and returns immediately;
/// no synchronous wait is allowed to enter the async execution phase.
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
        record_site(caller, microseconds);
        blocking_probe().record(BlockingCall::EtsDelayUs, current_event(), caller);
        return;
    }
    __real_ets_delay_us(microseconds);
}
