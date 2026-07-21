use crate::{adapter::blocking_probe, context::current_event, diagnostics::BlockingCall};

unsafe extern "C" {
    #[link_name = "ets_delay_us"]
    fn linked_ets_delay_us(microseconds: u32);
    fn __real_ets_delay_us(microseconds: u32);
}

pub(crate) fn runtime_delay_link_wrapper_active() -> bool {
    core::ptr::eq(
        linked_ets_delay_us as *const (),
        __wrap_ets_delay_us as *const (),
    )
}

/// Permit ROM busy-delay only during vendor/hardware initialization.
///
/// Once strict takeover is armed, an unexpected direct delay is recorded and
/// returns immediately. The caller can neither occupy the executor nor hide a
/// hardware-status polling loop behind this ROM leaf.
#[no_mangle]
pub unsafe extern "C" fn __wrap_ets_delay_us(microseconds: u32) {
    if !crate::critical::strict_wifi_hart_armed() {
        __real_ets_delay_us(microseconds);
        return;
    }
    blocking_probe().record(
        BlockingCall::EtsDelayUs,
        current_event(),
        microseconds as usize,
    );
}
