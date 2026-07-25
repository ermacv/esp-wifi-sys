//! Explicit ESP32-S31 PHY-parameter transfer boundaries.
//!
//! These are complete, finite bodies recovered from
//! `libphy.a[phy_init.o]`. They temporarily address the vendor-defined
//! `phy_param` object by symbol. Keeping every bulk mutation here makes the
//! remaining transition to Rust-owned storage explicit: once the other live
//! `phy_init.o` functions have been replaced, the extern declaration can be
//! changed to a Rust static without changing these transforms.

const PHY_PARAM_LEN: usize = 0x1fc;
const PHY_INIT_DATA_LEN: usize = 0x80;
const PHY_CALIBRATION_PAYLOAD_OFFSET: usize = 0x0c;

fn apply_init_data(parameter: &mut [u8; PHY_PARAM_LEN], init: &[u8; PHY_INIT_DATA_LEN]) {
    parameter[0x4e] = init[0x00];

    let mut index = 0;
    while index != 18 {
        parameter[0x50 + index] = init[0x02 + index];
        index += 1;
    }

    parameter[0x64] = init[0x18];

    index = 0;
    while index != 14 {
        parameter[0x6e + index] = init[0x19 + index];
        parameter[0x7c + index] = init[0x27 + index];
        parameter[0x8a + index] = init[0x35 + index];
        index += 1;
    }

    index = 0;
    while index != 9 {
        parameter[0x65 + index] = init[0x43 + index];
        index += 1;
    }
}

fn backup_parameter(
    parameter: &[u8; PHY_PARAM_LEN],
    calibration: &mut [u8; PHY_CALIBRATION_PAYLOAD_OFFSET + PHY_PARAM_LEN],
) {
    let mut index = 0;
    while index != PHY_PARAM_LEN {
        calibration[PHY_CALIBRATION_PAYLOAD_OFFSET + index] = parameter[index];
        index += 1;
    }
}

fn recover_parameter(
    parameter: &mut [u8; PHY_PARAM_LEN],
    calibration: &[u8; PHY_CALIBRATION_PAYLOAD_OFFSET + PHY_PARAM_LEN],
) {
    let mut index = 0;
    while index != PHY_PARAM_LEN {
        parameter[index] = calibration[PHY_CALIBRATION_PAYLOAD_OFFSET + index];
        index += 1;
    }
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    static mut phy_param: [u8; PHY_PARAM_LEN];
}

#[cfg(target_arch = "riscv32")]
#[inline(always)]
unsafe fn trap_invalid_pointer() -> ! {
    core::arch::asm!("ebreak", options(noreturn));
}

/// Apply the evidenced fields from an ESP32-S31 128-byte PHY init profile.
///
/// Reference: pinned
/// `libphy.a[phy_init.o]::register_chipv7_phy_init_param`, size `0x94`.
/// The body copies 71 bytes into six disjoint `phy_param` ranges. Field names
/// beyond the offsets are intentionally not guessed.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_register_chipv7_phy_init_param(init: *const u8) {
    if init.is_null() {
        trap_invalid_pointer();
    }

    let parameter = &mut *core::ptr::addr_of_mut!(phy_param);
    let init = &*init.cast::<[u8; PHY_INIT_DATA_LEN]>();
    apply_init_data(parameter, init);
}

/// Copy the complete 508-byte PHY parameter image to or from calibration data.
///
/// Reference: pinned `libphy.a[phy_init.o]::phy_rfcal_data_sub_new`, size
/// `0x64`, and the complete rev0 ROM `phy_byte_to_word` body at `0x2f826034`.
/// The calibration payload begins at byte 12. A nonzero direction copies to
/// the calibration buffer; zero restores `phy_param`. The loop bound is
/// compile-time fixed and has no allocation, wait, callback, or MMIO.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_phy_rfcal_data_sub_new(
    calibration: *mut u8,
    backup: u32,
) {
    if calibration.is_null() {
        trap_invalid_pointer();
    }

    let parameter = &mut *core::ptr::addr_of_mut!(phy_param);
    if backup != 0 {
        let calibration = &mut *calibration
            .cast::<[u8; PHY_CALIBRATION_PAYLOAD_OFFSET + PHY_PARAM_LEN]>();
        backup_parameter(parameter, calibration);
    } else {
        let calibration =
            &*calibration.cast::<[u8; PHY_CALIBRATION_PAYLOAD_OFFSET + PHY_PARAM_LEN]>();
        recover_parameter(parameter, calibration);
    }
}

/// Back up `phy_param` into the calibration payload and return the vendor's
/// constant success result.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_phy_rf_cal_data_backup_new(
    calibration: *mut u8,
) -> i32 {
    wifi_strict_phy_rfcal_data_sub_new(calibration, 1);
    0
}

/// Restore `phy_param` from the calibration payload.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_phy_rf_cal_data_recovery_new(calibration: *mut u8) {
    wifi_strict_phy_rfcal_data_sub_new(calibration, 0);
}

#[cfg(test)]
mod tests {
    use super::{
        apply_init_data, backup_parameter, recover_parameter, PHY_CALIBRATION_PAYLOAD_OFFSET,
        PHY_INIT_DATA_LEN, PHY_PARAM_LEN,
    };

    #[test]
    fn init_mapping_matches_all_recovered_disjoint_ranges() {
        let mut parameter = [0xa5; PHY_PARAM_LEN];
        let mut init = [0_u8; PHY_INIT_DATA_LEN];
        let mut index = 0;
        while index != init.len() {
            init[index] = index as u8;
            index += 1;
        }

        apply_init_data(&mut parameter, &init);

        let mut expected = [0xa5; PHY_PARAM_LEN];
        expected[0x4e] = init[0];
        expected[0x50..0x62].copy_from_slice(&init[0x02..0x14]);
        expected[0x64] = init[0x18];
        expected[0x65..0x6e].copy_from_slice(&init[0x43..0x4c]);
        expected[0x6e..0x7c].copy_from_slice(&init[0x19..0x27]);
        expected[0x7c..0x8a].copy_from_slice(&init[0x27..0x35]);
        expected[0x8a..0x98].copy_from_slice(&init[0x35..0x43]);
        assert_eq!(parameter, expected);
    }

    #[test]
    fn calibration_transfer_owns_exactly_bytes_12_through_519() {
        let mut parameter = [0_u8; PHY_PARAM_LEN];
        let mut index = 0;
        while index != parameter.len() {
            parameter[index] = index.wrapping_mul(37) as u8;
            index += 1;
        }

        let mut calibration = [0x5a; PHY_CALIBRATION_PAYLOAD_OFFSET + PHY_PARAM_LEN];
        backup_parameter(&parameter, &mut calibration);
        assert_eq!(
            &calibration[..PHY_CALIBRATION_PAYLOAD_OFFSET],
            &[0x5a; PHY_CALIBRATION_PAYLOAD_OFFSET]
        );
        assert_eq!(
            &calibration[PHY_CALIBRATION_PAYLOAD_OFFSET..],
            parameter.as_slice()
        );

        let mut recovered = [0; PHY_PARAM_LEN];
        recover_parameter(&mut recovered, &calibration);
        assert_eq!(recovered, parameter);
    }
}
