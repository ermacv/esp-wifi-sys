#![cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::context::in_radio_context;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationSnapshot {
    pub allocations: usize,
    pub reallocations: usize,
    pub frees: usize,
    pub requested_bytes: usize,
    pub largest_request: usize,
    pub failures: usize,
    pub radio_context_calls: usize,
}

/// Counters shared by OSI allocator callbacks and final-link `__wrap_*`
/// guards for direct C allocator references in vendor archives.
pub struct AllocationProbe {
    allocations: AtomicUsize,
    reallocations: AtomicUsize,
    frees: AtomicUsize,
    requested_bytes: AtomicUsize,
    largest_request: AtomicUsize,
    failures: AtomicUsize,
    radio_context_calls: AtomicUsize,
}

impl AllocationProbe {
    pub const fn new() -> Self {
        Self {
            allocations: AtomicUsize::new(0),
            reallocations: AtomicUsize::new(0),
            frees: AtomicUsize::new(0),
            requested_bytes: AtomicUsize::new(0),
            largest_request: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
            radio_context_calls: AtomicUsize::new(0),
        }
    }

    fn record_request(&self, size: usize, failed: bool, realloc: bool) {
        if realloc {
            self.reallocations.fetch_add(1, Ordering::Relaxed);
        } else {
            self.allocations.fetch_add(1, Ordering::Relaxed);
        }
        self.requested_bytes.fetch_add(size, Ordering::Relaxed);
        self.largest_request.fetch_max(size, Ordering::Relaxed);
        if failed {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
        if in_radio_context() {
            self.radio_context_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_free(&self) {
        self.frees.fetch_add(1, Ordering::Relaxed);
        if in_radio_context() {
            self.radio_context_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> AllocationSnapshot {
        AllocationSnapshot {
            allocations: self.allocations.load(Ordering::Acquire),
            reallocations: self.reallocations.load(Ordering::Acquire),
            frees: self.frees.load(Ordering::Acquire),
            requested_bytes: self.requested_bytes.load(Ordering::Acquire),
            largest_request: self.largest_request.load(Ordering::Acquire),
            failures: self.failures.load(Ordering::Acquire),
            radio_context_calls: self.radio_context_calls.load(Ordering::Acquire),
        }
    }
}

impl Default for AllocationProbe {
    fn default() -> Self {
        Self::new()
    }
}

static PROBE: AllocationProbe = AllocationProbe::new();

pub fn allocation_probe() -> &'static AllocationProbe {
    &PROBE
}

#[cfg(target_arch = "riscv32")]
mod target {
    use core::{
        ffi::c_void,
        mem,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use esp_wifi_sys_esp32s31::include::wifi_osi_funcs_t;

    use super::PROBE;

    type Malloc = unsafe extern "C" fn(usize) -> *mut c_void;
    type Free = unsafe extern "C" fn(*mut c_void);
    type Realloc = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
    type Calloc = unsafe extern "C" fn(usize, usize) -> *mut c_void;

    static MALLOC: AtomicUsize = AtomicUsize::new(0);
    static FREE: AtomicUsize = AtomicUsize::new(0);
    static MALLOC_INTERNAL: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_INTERNAL: AtomicUsize = AtomicUsize::new(0);
    static CALLOC_INTERNAL: AtomicUsize = AtomicUsize::new(0);
    static ZALLOC_INTERNAL: AtomicUsize = AtomicUsize::new(0);
    static WIFI_MALLOC: AtomicUsize = AtomicUsize::new(0);
    static WIFI_REALLOC: AtomicUsize = AtomicUsize::new(0);
    static WIFI_CALLOC: AtomicUsize = AtomicUsize::new(0);
    static WIFI_ZALLOC: AtomicUsize = AtomicUsize::new(0);
    static CALLBACKS_PATCHED: AtomicUsize = AtomicUsize::new(0);
    static RUNTIME_HEAP_FORBIDDEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" {
        static mut g_osi_funcs_p: *const wifi_osi_funcs_t;
    }

    /// Wrap every OSI allocator callback while preserving the original
    /// allocator for initialization. `prepare_strict_runtime` later switches
    /// these wrappers to a heap-denying runtime phase.
    ///
    /// # Safety
    /// Installation must be serialized with Wi-Fi init and performed only
    /// once. The captured original callbacks must remain valid permanently.
    pub unsafe fn patch_allocator_probes(table: &mut wifi_osi_funcs_t) {
        wrap(&mut table._malloc, &MALLOC, malloc);
        if let Some(original) = table._free {
            FREE.store(original as usize, Ordering::Release);
            table._free = Some(free);
        }
        wrap(
            &mut table._malloc_internal,
            &MALLOC_INTERNAL,
            malloc_internal,
        );
        wrap_realloc(
            &mut table._realloc_internal,
            &REALLOC_INTERNAL,
            realloc_internal,
        );
        wrap_calloc(
            &mut table._calloc_internal,
            &CALLOC_INTERNAL,
            calloc_internal,
        );
        wrap(
            &mut table._zalloc_internal,
            &ZALLOC_INTERNAL,
            zalloc_internal,
        );
        wrap(&mut table._wifi_malloc, &WIFI_MALLOC, wifi_malloc);
        wrap_realloc(&mut table._wifi_realloc, &WIFI_REALLOC, wifi_realloc);
        wrap_calloc(&mut table._wifi_calloc, &WIFI_CALLOC, wifi_calloc);
        wrap(&mut table._wifi_zalloc, &WIFI_ZALLOC, wifi_zalloc);
        CALLBACKS_PATCHED.store(1, Ordering::Release);
    }

    pub(crate) fn forbid_runtime_heap() -> bool {
        if !allocator_callbacks_patched() {
            return false;
        }
        RUNTIME_HEAP_FORBIDDEN.store(1, Ordering::Release);
        true
    }

    pub(crate) fn allocator_callbacks_patched() -> bool {
        if CALLBACKS_PATCHED.load(Ordering::Acquire) == 0 {
            return false;
        }
        let table = unsafe { core::ptr::addr_of!(g_osi_funcs_p).read().as_ref() };
        let Some(table) = table else {
            return false;
        };
        macro_rules! callback_is {
            ($field:ident, $callback:expr) => {
                table.$field.is_some_and(|registered| {
                    registered as *const () as usize == $callback as *const () as usize
                })
            };
        }
        callback_is!(_malloc, malloc)
            && callback_is!(_free, free)
            && callback_is!(_malloc_internal, malloc_internal)
            && callback_is!(_realloc_internal, realloc_internal)
            && callback_is!(_calloc_internal, calloc_internal)
            && callback_is!(_zalloc_internal, zalloc_internal)
            && callback_is!(_wifi_malloc, wifi_malloc)
            && callback_is!(_wifi_realloc, wifi_realloc)
            && callback_is!(_wifi_calloc, wifi_calloc)
            && callback_is!(_wifi_zalloc, wifi_zalloc)
    }

    /// Re-enable the captured allocators after the strict executor and all
    /// references to its state have stopped.
    ///
    /// # Safety
    /// No strict runtime callback may execute concurrently or afterwards.
    pub unsafe fn allow_heap_for_wifi_teardown() {
        RUNTIME_HEAP_FORBIDDEN.store(0, Ordering::Release);
    }

    fn heap_forbidden() -> bool {
        RUNTIME_HEAP_FORBIDDEN.load(Ordering::Acquire) != 0
    }

    unsafe extern "C" {
        #[link_name = "malloc"]
        fn direct_malloc(size: usize) -> *mut c_void;
        #[link_name = "calloc"]
        fn direct_calloc(count: usize, size: usize) -> *mut c_void;
        #[link_name = "realloc"]
        fn direct_realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
        #[link_name = "free"]
        fn direct_free(ptr: *mut c_void);
        fn __real_malloc(size: usize) -> *mut c_void;
        fn __real_calloc(count: usize, size: usize) -> *mut c_void;
        fn __real_realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
        fn __real_free(ptr: *mut c_void);
    }

    pub(crate) fn direct_heap_link_wrappers_active() -> bool {
        core::ptr::eq(direct_malloc as *const (), __wrap_malloc as *const ())
            && core::ptr::eq(direct_calloc as *const (), __wrap_calloc as *const ())
            && core::ptr::eq(direct_realloc as *const (), __wrap_realloc as *const ())
            && core::ptr::eq(direct_free as *const (), __wrap_free as *const ())
    }

    /// Final-link guard for direct C `malloc` references in vendor archives.
    /// Requires `-Wl,--wrap=malloc` in the firmware link.
    #[no_mangle]
    pub unsafe extern "C" fn __wrap_malloc(size: usize) -> *mut c_void {
        if heap_forbidden() {
            PROBE.record_request(size, true, false);
            return core::ptr::null_mut();
        }
        let result = __real_malloc(size);
        PROBE.record_request(size, result.is_null(), false);
        result
    }

    /// Final-link guard for direct C `calloc` references.
    #[no_mangle]
    pub unsafe extern "C" fn __wrap_calloc(count: usize, size: usize) -> *mut c_void {
        let requested = count.saturating_mul(size);
        if heap_forbidden() {
            PROBE.record_request(requested, true, false);
            return core::ptr::null_mut();
        }
        let result = __real_calloc(count, size);
        PROBE.record_request(requested, result.is_null(), false);
        result
    }

    /// Final-link guard for direct C `realloc` references.
    #[no_mangle]
    pub unsafe extern "C" fn __wrap_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
        if heap_forbidden() {
            PROBE.record_request(size, true, true);
            return core::ptr::null_mut();
        }
        let result = __real_realloc(ptr, size);
        PROBE.record_request(size, result.is_null() && size != 0, true);
        result
    }

    /// Final-link guard for direct C `free` references.
    #[no_mangle]
    pub unsafe extern "C" fn __wrap_free(ptr: *mut c_void) {
        PROBE.record_free();
        if !heap_forbidden() {
            __real_free(ptr);
        }
    }

    unsafe fn wrap(slot: &mut Option<Malloc>, saved: &AtomicUsize, wrapper: Malloc) {
        if let Some(original) = *slot {
            saved.store(original as usize, Ordering::Release);
            *slot = Some(wrapper);
        }
    }

    unsafe fn wrap_realloc(slot: &mut Option<Realloc>, saved: &AtomicUsize, wrapper: Realloc) {
        if let Some(original) = *slot {
            saved.store(original as usize, Ordering::Release);
            *slot = Some(wrapper);
        }
    }

    unsafe fn wrap_calloc(slot: &mut Option<Calloc>, saved: &AtomicUsize, wrapper: Calloc) {
        if let Some(original) = *slot {
            saved.store(original as usize, Ordering::Release);
            *slot = Some(wrapper);
        }
    }

    unsafe fn call_malloc(saved: &AtomicUsize, size: usize) -> *mut c_void {
        if heap_forbidden() {
            PROBE.record_request(size, true, false);
            return core::ptr::null_mut();
        }
        let original = mem::transmute::<usize, Malloc>(saved.load(Ordering::Acquire));
        let result = original(size);
        PROBE.record_request(size, result.is_null(), false);
        result
    }

    unsafe fn call_realloc(saved: &AtomicUsize, ptr: *mut c_void, size: usize) -> *mut c_void {
        if heap_forbidden() {
            PROBE.record_request(size, true, true);
            return core::ptr::null_mut();
        }
        let original = mem::transmute::<usize, Realloc>(saved.load(Ordering::Acquire));
        let result = original(ptr, size);
        PROBE.record_request(size, result.is_null() && size != 0, true);
        result
    }

    unsafe fn call_calloc(saved: &AtomicUsize, count: usize, size: usize) -> *mut c_void {
        if heap_forbidden() {
            PROBE.record_request(count.saturating_mul(size), true, false);
            return core::ptr::null_mut();
        }
        let original = mem::transmute::<usize, Calloc>(saved.load(Ordering::Acquire));
        let result = original(count, size);
        PROBE.record_request(count.saturating_mul(size), result.is_null(), false);
        result
    }

    unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
        call_malloc(&MALLOC, size)
    }
    unsafe extern "C" fn free(ptr: *mut c_void) {
        PROBE.record_free();
        if heap_forbidden() {
            return;
        }
        let original = mem::transmute::<usize, Free>(FREE.load(Ordering::Acquire));
        original(ptr);
    }
    unsafe extern "C" fn malloc_internal(size: usize) -> *mut c_void {
        call_malloc(&MALLOC_INTERNAL, size)
    }
    unsafe extern "C" fn realloc_internal(ptr: *mut c_void, size: usize) -> *mut c_void {
        call_realloc(&REALLOC_INTERNAL, ptr, size)
    }
    unsafe extern "C" fn calloc_internal(count: usize, size: usize) -> *mut c_void {
        call_calloc(&CALLOC_INTERNAL, count, size)
    }
    unsafe extern "C" fn zalloc_internal(size: usize) -> *mut c_void {
        call_malloc(&ZALLOC_INTERNAL, size)
    }
    unsafe extern "C" fn wifi_malloc(size: usize) -> *mut c_void {
        call_malloc(&WIFI_MALLOC, size)
    }
    unsafe extern "C" fn wifi_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
        call_realloc(&WIFI_REALLOC, ptr, size)
    }
    unsafe extern "C" fn wifi_calloc(count: usize, size: usize) -> *mut c_void {
        call_calloc(&WIFI_CALLOC, count, size)
    }
    unsafe extern "C" fn wifi_zalloc(size: usize) -> *mut c_void {
        call_malloc(&WIFI_ZALLOC, size)
    }
}

#[cfg(target_arch = "riscv32")]
pub(crate) use target::{
    allocator_callbacks_patched, direct_heap_link_wrappers_active, forbid_runtime_heap,
};
#[cfg(target_arch = "riscv32")]
pub use target::{allow_heap_for_wifi_teardown, patch_allocator_probes};

#[cfg(test)]
mod tests {
    use super::AllocationProbe;

    #[test]
    fn allocation_probe_tracks_requests() {
        let probe = AllocationProbe::new();
        probe.record_request(16, false, false);
        probe.record_request(48, true, true);
        probe.record_free();
        let snapshot = probe.snapshot();
        assert_eq!(snapshot.allocations, 1);
        assert_eq!(snapshot.reallocations, 1);
        assert_eq!(snapshot.frees, 1);
        assert_eq!(snapshot.requested_bytes, 64);
        assert_eq!(snapshot.largest_request, 48);
        assert_eq!(snapshot.failures, 1);
    }
}
