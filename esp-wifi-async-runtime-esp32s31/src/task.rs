use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(target_arch = "riscv32")]
extern "C" {
    fn ppTask(argument: *mut c_void);
}

/// Logical task handle returned to the blob for the virtualized `ppTask`.
pub const PP_TASK_HANDLE: *mut c_void = core::ptr::dangling_mut::<c_void>();

/// State used by the OSI `_task_create*` adapter to suppress creation of the
/// stackful vendor `ppTask`.
pub struct VirtualPpTask {
    started: AtomicBool,
    startup_signal: AtomicBool,
}

impl VirtualPpTask {
    pub const fn new() -> Self {
        Self {
            started: AtomicBool::new(false),
            startup_signal: AtomicBool::new(false),
        }
    }

    pub fn is_pp_entry(entry: *const c_void) -> bool {
        #[cfg(target_arch = "riscv32")]
        {
            entry == ppTask as *const () as *const c_void
        }
        #[cfg(not(target_arch = "riscv32"))]
        {
            let _ = entry;
            false
        }
    }

    /// Register `ppTask` as a virtual async component and write the task handle
    /// expected by `pp_create_task`.
    ///
    /// Returns `false` for all other task entry points so the caller can log or
    /// reject them independently (notably the WPA event loop).
    ///
    /// # Safety
    /// `out_handle` must be the writable handle pointer supplied to the OSI
    /// task-create callback.
    pub unsafe fn try_start(&self, entry: *const c_void, out_handle: *mut *mut c_void) -> bool {
        if !Self::is_pp_entry(entry) {
            return false;
        }

        if !out_handle.is_null() {
            out_handle.write(PP_TASK_HANDLE);
        }
        self.started.store(true, Ordering::Release);
        self.startup_signal.store(true, Ordering::Release);
        true
    }

    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    /// Consume the virtual startup signal that replaces the first
    /// `sem_give(s_pp_task_create_sem)` performed by the real `ppTask`.
    pub fn take_startup_signal(&self) -> bool {
        self.startup_signal.swap(false, Ordering::AcqRel)
    }

    pub fn stop(&self) {
        self.started.store(false, Ordering::Release);
        self.startup_signal.store(false, Ordering::Release);
    }
}

impl Default for VirtualPpTask {
    fn default() -> Self {
        Self::new()
    }
}
