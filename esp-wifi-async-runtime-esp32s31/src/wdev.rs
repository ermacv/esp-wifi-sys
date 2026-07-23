use core::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

static FTM_ATTEMPTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WdevRxContinuationError {
    WrongHart,
    ResetStateUnavailable,
    MissingLastDescriptor,
    CurrentDescriptorMismatch,
    MissingRxMetadata,
    DescriptorCountOverflow,
    DescriptorChainTooLong,
}

unsafe extern "C" {
    #[link_name = "wDev_record_ftm_data"]
    fn vendor_record_ftm_data(rx_control: *mut c_void, frame: *mut c_void);
    #[link_name = "pm_on_beacon_rx"]
    fn vendor_pm_on_beacon_rx(
        interface: *mut c_void,
        frame: *mut u8,
        frame_end: *mut u8,
        from_task: u32,
    );
    #[link_name = "pm_on_data_rx"]
    fn vendor_pm_on_data_rx(
        receiver: *mut u8,
        packet_class: u32,
        transmitter: *mut u8,
        interface: u32,
    );
    #[link_name = "pm_on_data_tx"]
    fn vendor_pm_on_data_tx();
    #[link_name = "pm_set_beacon_duration"]
    fn vendor_pm_set_beacon_duration(duration: u32);
    #[link_name = "wDev_ftm_set_t1t4"]
    fn vendor_ftm_set_t1t4(frame: *mut c_void);
    #[link_name = "wDev_isNANPktInValidSlot"]
    fn vendor_is_nan_packet_in_valid_slot(frame: *mut u8) -> i32;
    #[link_name = "wDev_SnifferRxData"]
    fn vendor_sniffer_rx_data();
    #[link_name = "wdev_csi_rx_process"]
    fn vendor_csi_rx_process();
    fn __real_wDev_isNANPktInValidSlot(frame: *mut u8) -> i32;
}

#[cfg(target_arch = "riscv32")]
const MAX_RX_SUCCESS_DESCRIPTORS_PER_EVENT: usize = 64;

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    static mut wDevCtrl: u8;
    static mut g_wdev_last_desc_reset_ptr: *mut u8;
    static mut g_wdev_csi_rx: usize;
    fn hal_mac_rx_get_last_dscr() -> *mut u8;
    fn wDev_ProcessRxSucData(descriptor: *mut u8, subframe_count: u32);
}

/// Replace the vendor event-25 outer descriptor walk and both indirect OSI
/// critical-section calls.
///
/// The hardware publishes one finite linked prefix ending at the descriptor
/// returned by `hal_mac_rx_get_last_dscr`. Rust preserves the vendor rule that
/// bit 30 marks the final descriptor of a receive unit and passes the bounded
/// prefix count to the still-audited per-unit decoder. A malformed list can no
/// longer cycle forever: at most 64 descriptors are consumed per executor
/// event, and every error restores local interrupts before returning.
#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.rx_success_dispatch"]
#[inline(never)]
pub(crate) unsafe fn process_rx_success() -> Result<(), WdevRxContinuationError> {
    if !crate::critical::on_strict_wifi_hart() {
        return Err(WdevRxContinuationError::WrongHart);
    }
    let reset = ptr::addr_of!(g_wdev_last_desc_reset_ptr).read();
    if reset.is_null() {
        return Err(WdevRxContinuationError::ResetStateUnavailable);
    }

    let mut last = hal_mac_rx_get_last_dscr();
    if reset.read() != 0 {
        if !last.is_null() {
            reset.write(0);
        }
    } else if last.is_null() {
        return Err(WdevRxContinuationError::MissingLastDescriptor);
    }

    let interrupt_state = crate::critical::strict_wifi_int_disable();
    let mut descriptor = ptr::addr_of!(wDevCtrl).cast::<*mut u8>().read_unaligned();
    let mut subframe_count = 0_u32;
    let mut descriptors_seen = 0_usize;
    while !descriptor.is_null() {
        if descriptors_seen == MAX_RX_SUCCESS_DESCRIPTORS_PER_EVENT {
            crate::critical::strict_wifi_int_restore(interrupt_state);
            return Err(WdevRxContinuationError::DescriptorChainTooLong);
        }
        descriptors_seen += 1;
        let next = descriptor.add(8).cast::<*mut u8>().read_unaligned();
        subframe_count = match subframe_count.checked_add(1) {
            Some(count) if count <= u32::from(u16::MAX) => count,
            _ => {
                crate::critical::strict_wifi_int_restore(interrupt_state);
                return Err(WdevRxContinuationError::DescriptorCountOverflow);
            }
        };

        if descriptor.cast::<u32>().read_unaligned() & (1 << 30) != 0 {
            let published = ptr::addr_of!(wDevCtrl).cast::<*mut u8>().read_unaligned();
            if published != descriptor {
                crate::critical::strict_wifi_int_restore(interrupt_state);
                return Err(WdevRxContinuationError::CurrentDescriptorMismatch);
            }
            if descriptor
                .add(4)
                .cast::<*mut u8>()
                .read_unaligned()
                .is_null()
            {
                crate::critical::strict_wifi_int_restore(interrupt_state);
                return Err(WdevRxContinuationError::MissingRxMetadata);
            }
            crate::critical::strict_wifi_int_restore(interrupt_state);
            wDev_ProcessRxSucData(descriptor, subframe_count);
            subframe_count = 0;
            if descriptor == last {
                return Ok(());
            }
            last = hal_mac_rx_get_last_dscr();
            if reset.read() == 0 && last.is_null() {
                return Err(WdevRxContinuationError::MissingLastDescriptor);
            }
            descriptor = next;
            if descriptor.is_null() {
                return Ok(());
            }
            // Match the vendor outer walk: only the pointer publication is
            // protected; the per-unit decoder executes with interrupts on.
            let new_interrupt_state = crate::critical::strict_wifi_int_disable();
            // The strict local primitive can only return the current MIE bit.
            // It must match the state initially captured for this radio event.
            if new_interrupt_state & 8 != interrupt_state & 8 {
                crate::critical::strict_wifi_int_restore(new_interrupt_state);
                return Err(WdevRxContinuationError::WrongHart);
            }
            continue;
        }
        if descriptor == last {
            crate::critical::strict_wifi_int_restore(interrupt_state);
            return Ok(());
        }
        last = hal_mac_rx_get_last_dscr();
        if reset.read() == 0 && last.is_null() {
            crate::critical::strict_wifi_int_restore(interrupt_state);
            return Err(WdevRxContinuationError::MissingLastDescriptor);
        }
        descriptor = next;
    }
    crate::critical::strict_wifi_int_restore(interrupt_state);
    Ok(())
}

#[cfg(target_arch = "riscv32")]
pub(crate) unsafe fn strict_optional_rx_mode_state() -> (u8, u8, usize) {
    let control = ptr::addr_of!(wDevCtrl);
    (
        control.add(0x30).read(),
        control.add(0x46).read(),
        ptr::addr_of!(g_wdev_csi_rx).read(),
    )
}

pub(crate) fn runtime_wdev_link_wrapper_active() -> bool {
    core::ptr::eq(
        vendor_record_ftm_data as *const (),
        __wrap_wDev_record_ftm_data as *const (),
    ) && core::ptr::eq(
        vendor_pm_on_beacon_rx as *const (),
        __wrap_pm_on_beacon_rx as *const (),
    ) && core::ptr::eq(
        vendor_pm_on_data_rx as *const (),
        __wrap_pm_on_data_rx as *const (),
    ) && core::ptr::eq(
        vendor_pm_on_data_tx as *const (),
        __wrap_pm_on_data_tx as *const (),
    ) && core::ptr::eq(
        vendor_pm_set_beacon_duration as *const (),
        __wrap_pm_set_beacon_duration as *const (),
    ) && core::ptr::eq(
        vendor_ftm_set_t1t4 as *const (),
        __wrap_wDev_ftm_set_t1t4 as *const (),
    ) && core::ptr::eq(
        vendor_is_nan_packet_in_valid_slot as *const (),
        __wrap_wDev_isNANPktInValidSlot as *const (),
    ) && core::ptr::eq(
        vendor_sniffer_rx_data as *const (),
        __wrap_wDev_SnifferRxData as *const (),
    ) && core::ptr::eq(
        vendor_csi_rx_process as *const (),
        __wrap_wdev_csi_rx_process as *const (),
    )
}

pub(crate) fn take_ftm_attempted() -> bool {
    FTM_ATTEMPTED.swap(false, Ordering::AcqRel)
}

/// Reject Fine Timing Measurement RX accounting in the strict profile.
///
/// The pinned vendor implementation starts with `ets_delay_us(50)`. The final
/// link must use `--wrap=wDev_record_ftm_data`; the enclosing event handler
/// observes this marker and fails after returning from its finite RX section.
#[no_mangle]
pub unsafe extern "C" fn __wrap_wDev_record_ftm_data(
    _rx_control: *mut c_void,
    _frame: *mut c_void,
) {
    FTM_ATTEMPTED.store(true, Ordering::Release);
}

/// Reject the optional TX FTM timestamp callback under the disabled-FTM
/// invariant.
#[no_mangle]
pub unsafe extern "C" fn __wrap_wDev_ftm_set_t1t4(_frame: *mut c_void) {
    FTM_ATTEMPTED.store(true, Ordering::Release);
}

/// Preserve ordinary AP/STA TX while rejecting the callback-driven NAN path.
#[no_mangle]
pub unsafe extern "C" fn __wrap_wDev_isNANPktInValidSlot(frame: *mut u8) -> i32 {
    if !crate::critical::strict_wifi_hart_armed() {
        return __real_wDev_isNANPktInValidSlot(frame);
    }
    if frame.is_null() {
        return 0;
    }
    let descriptor = frame.add(0x34).cast::<*mut u8>().read();
    if descriptor.is_null() {
        return 0;
    }
    let packet_kind = descriptor.add(0x10).cast::<u32>().read() & 0x00c0_0000;
    i32::from(packet_kind != 0x0080_0000)
}

/// Remove promiscuous delivery from the strict basic AP/STA receive profile.
///
/// Preparation disables promiscuous mode through the public control API,
/// verifies its readback and the pinned `wDevCtrl` state, and unregisters the
/// callback before the RTOS handoff.
#[no_mangle]
pub unsafe extern "C" fn __wrap_wDev_SnifferRxData() {}

/// Remove CSI capture from the strict basic AP/STA receive profile.
///
/// The pinned vendor implementation allocates a 100-byte callback envelope.
/// Strict configuration rejects CSI and preparation verifies that the callback
/// pointer remains null before this boundary can be armed.
#[no_mangle]
pub unsafe extern "C" fn __wrap_wdev_csi_rx_process() {}

/// Remove the vendor power-save/mesh beacon tail under `WIFI_PS_NONE`.
///
/// PP/net80211 has already parsed and delivered the beacon before this hook.
/// The stock function only updates power-save state and contains the path from
/// TIM processing to radio shutdown and `ets_delay_us`.
#[no_mangle]
pub unsafe extern "C" fn __wrap_pm_on_beacon_rx(
    _interface: *mut c_void,
    _frame: *mut u8,
    _frame_end: *mut u8,
    _from_task: u32,
) {
}

/// Remove RX power-management accounting under the verified `WIFI_PS_NONE`
/// invariant.
///
/// `ppRxProtoProc` has already classified the ordinary frame and retains its
/// independent receive-rate update. The stock ROM hook only advances modem
/// sleep state and may enter OSI timers and Wi-Fi API locks.
#[no_mangle]
pub unsafe extern "C" fn __wrap_pm_on_data_rx(
    _receiver: *mut u8,
    _packet_class: u32,
    _transmitter: *mut u8,
    _interface: u32,
) {
}

/// Remove TX power-management accounting under the verified `WIFI_PS_NONE`
/// invariant. The stock eight-byte trampoline enters the complete sleep/null
/// frame state machine even though that mode is disabled.
#[no_mangle]
pub unsafe extern "C" fn __wrap_pm_on_data_tx() {}

/// Remove the sampled-beacon-duration update under `WIFI_PS_NONE`.
///
/// The stock function only maintains modem-sleep state. Its first-sample path
/// invokes two optional beacon-offset callbacks; neither is part of an always
/// awake STA/AP profile.
#[no_mangle]
pub unsafe extern "C" fn __wrap_pm_set_beacon_duration(_duration: u32) {}
