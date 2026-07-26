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
const PHY_CALIBRATION_CHECKSUM_OFFSET: usize = PHY_CALIBRATION_PAYLOAD_OFFSET + PHY_PARAM_LEN;
const PHY_CALIBRATION_PREFIX_LEN: usize = PHY_CALIBRATION_CHECKSUM_OFFSET + 4;
const EFUSE_RD_MAC_SYS0_ADDRESS: usize = 0x2071_5050;
const EFUSE_RD_MAC_SYS1_ADDRESS: usize = 0x2071_5054;
const PHY_ROM_FUNCTION_TABLE_POINTER_CELL: usize = 0x2f07_fc3c;
const PHY_PARAM_ROM_CELL: usize = 0x2f07_fc40;
const PHY_ROM_FUNCTION_TABLE_ADDRESS: u32 = 0x2f07_f944;
const PHY_ROM_TXCAL_DEBUG_MODE_ADDRESS: u32 = 0x2f82_44fe;
const PHY_ROM_TONE_SAR_DOUT_ADDRESS: u32 = 0x2f82_66da;

/// Named layout of the rev0 ROM PHY callback table at `0x2f07_f944`.
///
/// The pointer ABI is always 32-bit on ESP32-S31, so storing addresses as
/// `u32` keeps this layout testable on the host as well as exact on RV32.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PhyRomFunctionTable {
    i2c_enter_critical: u32,
    i2c_exit_critical: u32,
    get_i2c_read_mask: u32,
    get_i2c_host_id: u32,
    txcal_debug_mode: u32,
    set_rx_compensation: u32,
    set_temperature_sensor_power: u32,
    set_temperature_sensor_range: u32,
    get_temperature_sensor_value: u32,
    get_wifi_tx_table: u32,
    get_bt_tx_table: u32,
    get_tone_sar_dout: u32,
    configure_tx_gain_compensation: u32,
}

#[derive(Clone, Copy)]
struct PhyRomFunctionOverrides {
    i2c_enter_critical: u32,
    i2c_exit_critical: u32,
    get_i2c_read_mask: u32,
    get_i2c_host_id: u32,
    set_rx_compensation: u32,
    set_temperature_sensor_power: u32,
    set_temperature_sensor_range: u32,
    get_temperature_sensor_value: u32,
    get_wifi_tx_table: u32,
    get_bt_tx_table: u32,
    configure_tx_gain_compensation: u32,
}

const _: () = {
    assert!(core::mem::size_of::<PhyRomFunctionTable>() == 52);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, i2c_enter_critical) == 0x00);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, i2c_exit_critical) == 0x04);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, get_i2c_read_mask) == 0x08);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, get_i2c_host_id) == 0x0c);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, txcal_debug_mode) == 0x10);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, set_rx_compensation) == 0x14);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, set_temperature_sensor_power) == 0x18);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, set_temperature_sensor_range) == 0x1c);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, get_temperature_sensor_value) == 0x20);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, get_wifi_tx_table) == 0x24);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, get_bt_tx_table) == 0x28);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, get_tone_sar_dout) == 0x2c);
    assert!(core::mem::offset_of!(PhyRomFunctionTable, configure_tx_gain_compensation) == 0x30);
};

fn apply_rom_function_overrides(
    original: PhyRomFunctionTable,
    replacements: PhyRomFunctionOverrides,
) -> PhyRomFunctionTable {
    PhyRomFunctionTable {
        i2c_enter_critical: replacements.i2c_enter_critical,
        i2c_exit_critical: replacements.i2c_exit_critical,
        get_i2c_read_mask: replacements.get_i2c_read_mask,
        get_i2c_host_id: replacements.get_i2c_host_id,
        txcal_debug_mode: original.txcal_debug_mode,
        set_rx_compensation: replacements.set_rx_compensation,
        set_temperature_sensor_power: replacements.set_temperature_sensor_power,
        set_temperature_sensor_range: replacements.set_temperature_sensor_range,
        get_temperature_sensor_value: replacements.get_temperature_sensor_value,
        get_wifi_tx_table: replacements.get_wifi_tx_table,
        get_bt_tx_table: replacements.get_bt_tx_table,
        get_tone_sar_dout: original.get_tone_sar_dout,
        configure_tx_gain_compensation: replacements.configure_tx_gain_compensation,
    }
}

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

fn calibration_identity_from_efuse_words(mac_sys0: u32, mac_sys1: u32) -> [u8; 8] {
    [
        (mac_sys1 >> 8) as u8,
        mac_sys1 as u8,
        (mac_sys0 >> 24) as u8,
        (mac_sys0 >> 16) as u8,
        (mac_sys0 >> 8) as u8,
        mac_sys0 as u8,
        (mac_sys1 >> 24) as u8,
        (mac_sys1 >> 16) as u8,
    ]
}

fn read_u32_le(bytes: &[u8; PHY_CALIBRATION_PREFIX_LEN], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn write_u32_le(bytes: &mut [u8; PHY_CALIBRATION_PREFIX_LEN], offset: usize, value: u32) {
    let value = value.to_le_bytes();
    bytes[offset] = value[0];
    bytes[offset + 1] = value[1];
    bytes[offset + 2] = value[2];
    bytes[offset + 3] = value[3];
}

fn calibration_record_check_or_write(
    calibration: &mut [u8; PHY_CALIBRATION_PREFIX_LEN],
    check: bool,
    version: u32,
    mac_sys0: u32,
    mac_sys1: u32,
) -> i32 {
    write_u32_le(calibration, 0, version);
    let identity = calibration_identity_from_efuse_words(mac_sys0, mac_sys1);
    let mut index = 0;
    while index != identity.len() {
        calibration[4 + index] = identity[index];
        index += 1;
    }

    let mut sum = 0_u32;
    let mut offset = 0;
    while offset != PHY_CALIBRATION_CHECKSUM_OFFSET {
        sum = sum.wrapping_add(read_u32_le(calibration, offset));
        offset += 4;
    }
    let checksum = !sum;

    if check {
        i32::from(checksum != read_u32_le(calibration, PHY_CALIBRATION_CHECKSUM_OFFSET))
    } else {
        write_u32_le(calibration, PHY_CALIBRATION_CHECKSUM_OFFSET, checksum);
        0
    }
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    static mut phy_param: [u8; PHY_PARAM_LEN];
    static mut g_phyFuns: *mut PhyRomFunctionTable;

    fn phy_get_i2c_read_mask_new();
    fn phy_get_i2c_hostid_new();
    fn phy_set_rx_comp_new();
    fn phy_set_tsens_power();
    fn phy_set_tsens_range();
    fn phy_get_tsens_value();
    fn phy_wifi_get_tx_tab_new();
    fn phy_bt_get_tx_tab_new();
    fn phy_txgain_comp_pacfg_new();
}

#[cfg(target_arch = "riscv32")]
#[inline(always)]
unsafe fn trap_invalid_pointer() -> ! {
    core::arch::asm!("ebreak", options(noreturn));
}

/// No-op critical-section callbacks used by the one-owner Rust PHY path.
///
/// The pinned weak vendor definitions are both a single `ret`. Keep these
/// callbacks in SRAM because ROM may call through the table while cached
/// execution is unavailable.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.phy_cold"]
pub unsafe extern "C" fn wifi_strict_phy_i2c_enter_critical() {}

#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.phy_cold"]
pub unsafe extern "C" fn wifi_strict_phy_i2c_exit_critical() {}

/// Publish the Rust PHY parameter object and typed rev0 ROM callback table.
///
/// Reference: pinned `libphy.a[phy_init.o]::phy_get_romfunc_addr`, size
/// `0x98`, plus complete rev0 ROM leaves `phy_get_romfuncs` at `0x2f824a82`
/// and `phy_param_addr` at `0x2f824a8c`.
///
/// The two ROM leaves only load the pointer cell at `0x2f07fc3c` and store
/// the parameter pointer to `0x2f07fc40`; Rust performs those transactions
/// explicitly. The two callback slots not replaced by the vendor body are
/// validated against the pinned rev0 table before any callback publication.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_phy_get_romfunc_addr() {
    let table_address = (PHY_ROM_FUNCTION_TABLE_POINTER_CELL as *const u32).read_volatile();
    if table_address != PHY_ROM_FUNCTION_TABLE_ADDRESS {
        trap_invalid_pointer();
    }

    let table = table_address as usize as *mut PhyRomFunctionTable;
    let original = table.read_volatile();
    if original.txcal_debug_mode != PHY_ROM_TXCAL_DEBUG_MODE_ADDRESS
        || original.get_tone_sar_dout != PHY_ROM_TONE_SAR_DOUT_ADDRESS
    {
        trap_invalid_pointer();
    }

    let parameter_address = core::ptr::addr_of_mut!(phy_param).cast::<u8>() as usize as u32;
    (PHY_PARAM_ROM_CELL as *mut u32).write_volatile(parameter_address);
    core::ptr::addr_of_mut!(g_phyFuns).write_volatile(table);

    let replacements = PhyRomFunctionOverrides {
        i2c_enter_critical: wifi_strict_phy_i2c_enter_critical as usize as u32,
        i2c_exit_critical: wifi_strict_phy_i2c_exit_critical as usize as u32,
        get_i2c_read_mask: phy_get_i2c_read_mask_new as usize as u32,
        get_i2c_host_id: phy_get_i2c_hostid_new as usize as u32,
        set_rx_compensation: phy_set_rx_comp_new as usize as u32,
        set_temperature_sensor_power: phy_set_tsens_power as usize as u32,
        set_temperature_sensor_range: phy_set_tsens_range as usize as u32,
        get_temperature_sensor_value: phy_get_tsens_value as usize as u32,
        get_wifi_tx_table: phy_wifi_get_tx_tab_new as usize as u32,
        get_bt_tx_table: phy_bt_get_tx_tab_new as usize as u32,
        configure_tx_gain_compensation: phy_txgain_comp_pacfg_new as usize as u32,
    };
    let published = apply_rom_function_overrides(original, replacements);

    // Preserve the exact store order from phy_get_romfunc_addr. In
    // particular, the two validated ROM-owned fields are never rewritten.
    core::ptr::addr_of_mut!((*table).i2c_enter_critical)
        .write_volatile(published.i2c_enter_critical);
    core::ptr::addr_of_mut!((*table).i2c_exit_critical).write_volatile(published.i2c_exit_critical);
    core::ptr::addr_of_mut!((*table).set_temperature_sensor_power)
        .write_volatile(published.set_temperature_sensor_power);
    core::ptr::addr_of_mut!((*table).get_temperature_sensor_value)
        .write_volatile(published.get_temperature_sensor_value);
    core::ptr::addr_of_mut!((*table).set_temperature_sensor_range)
        .write_volatile(published.set_temperature_sensor_range);
    core::ptr::addr_of_mut!((*table).get_i2c_read_mask).write_volatile(published.get_i2c_read_mask);
    core::ptr::addr_of_mut!((*table).get_i2c_host_id).write_volatile(published.get_i2c_host_id);
    core::ptr::addr_of_mut!((*table).configure_tx_gain_compensation)
        .write_volatile(published.configure_tx_gain_compensation);
    core::ptr::addr_of_mut!((*table).get_wifi_tx_table).write_volatile(published.get_wifi_tx_table);
    core::ptr::addr_of_mut!((*table).set_rx_compensation)
        .write_volatile(published.set_rx_compensation);
    core::ptr::addr_of_mut!((*table).get_bt_tx_table).write_volatile(published.get_bt_tx_table);
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
pub unsafe extern "C" fn wifi_strict_phy_rfcal_data_sub_new(calibration: *mut u8, backup: u32) {
    if calibration.is_null() {
        trap_invalid_pointer();
    }

    let parameter = &mut *core::ptr::addr_of_mut!(phy_param);
    if backup != 0 {
        let calibration =
            &mut *calibration.cast::<[u8; PHY_CALIBRATION_PAYLOAD_OFFSET + PHY_PARAM_LEN]>();
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
pub unsafe extern "C" fn wifi_strict_phy_rf_cal_data_backup_new(calibration: *mut u8) -> i32 {
    wifi_strict_phy_rfcal_data_sub_new(calibration, 1);
    0
}

/// Restore `phy_param` from the calibration payload.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_phy_rf_cal_data_recovery_new(calibration: *mut u8) {
    wifi_strict_phy_rfcal_data_sub_new(calibration, 0);
}

/// Refresh and write or validate the bounded PHY calibration-record checksum.
///
/// Reference: the complete pinned
/// `libphy.a[phy_init.o]::phy_rfcal_data_check_new` body, size `0x7e`, and
/// the complete rev0 ROM leaves `phy_set_mac_data`, `phy_get_mac_addr`, and
/// `phy_byte_to_word`. The first 520 bytes are 130 little-endian words; the
/// checksum at bytes 520 through 523 is the one's complement of their
/// wrapping sum. The third ABI argument is instruction-proven unused.
///
/// The two direct eFuse reads use the public S31 `EFUSE_RD_MAC_SYS0/1`
/// addresses. There is no allocation, wait, callback, hidden mutable state,
/// or hardware-dependent loop bound.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_phy_rfcal_data_check_new(
    check: u32,
    calibration: *mut u8,
    _init_data: *const u8,
    version: u32,
) -> i32 {
    if calibration.is_null() {
        trap_invalid_pointer();
    }

    let mac_sys0 = (EFUSE_RD_MAC_SYS0_ADDRESS as *const u32).read_volatile();
    let mac_sys1 = (EFUSE_RD_MAC_SYS1_ADDRESS as *const u32).read_volatile();
    let calibration = &mut *calibration.cast::<[u8; PHY_CALIBRATION_PREFIX_LEN]>();
    calibration_record_check_or_write(calibration, check != 0, version, mac_sys0, mac_sys1)
}

#[cfg(test)]
mod tests {
    use super::{
        apply_init_data, apply_rom_function_overrides, backup_parameter,
        calibration_identity_from_efuse_words, calibration_record_check_or_write, read_u32_le,
        recover_parameter, PhyRomFunctionOverrides, PhyRomFunctionTable,
        PHY_CALIBRATION_CHECKSUM_OFFSET, PHY_CALIBRATION_PAYLOAD_OFFSET,
        PHY_CALIBRATION_PREFIX_LEN, PHY_INIT_DATA_LEN, PHY_PARAM_LEN,
        PHY_ROM_TONE_SAR_DOUT_ADDRESS, PHY_ROM_TXCAL_DEBUG_MODE_ADDRESS,
    };

    #[test]
    fn rom_callback_publication_preserves_only_the_two_unmodified_slots() {
        let original = PhyRomFunctionTable {
            i2c_enter_critical: 0,
            i2c_exit_critical: 1,
            get_i2c_read_mask: 2,
            get_i2c_host_id: 3,
            txcal_debug_mode: PHY_ROM_TXCAL_DEBUG_MODE_ADDRESS,
            set_rx_compensation: 5,
            set_temperature_sensor_power: 6,
            set_temperature_sensor_range: 7,
            get_temperature_sensor_value: 8,
            get_wifi_tx_table: 9,
            get_bt_tx_table: 10,
            get_tone_sar_dout: PHY_ROM_TONE_SAR_DOUT_ADDRESS,
            configure_tx_gain_compensation: 12,
        };
        let replacements = PhyRomFunctionOverrides {
            i2c_enter_critical: 0x100,
            i2c_exit_critical: 0x101,
            get_i2c_read_mask: 0x102,
            get_i2c_host_id: 0x103,
            set_rx_compensation: 0x105,
            set_temperature_sensor_power: 0x106,
            set_temperature_sensor_range: 0x107,
            get_temperature_sensor_value: 0x108,
            get_wifi_tx_table: 0x109,
            get_bt_tx_table: 0x10a,
            configure_tx_gain_compensation: 0x10c,
        };

        let published = apply_rom_function_overrides(original, replacements);
        assert_eq!(published.txcal_debug_mode, PHY_ROM_TXCAL_DEBUG_MODE_ADDRESS);
        assert_eq!(published.get_tone_sar_dout, PHY_ROM_TONE_SAR_DOUT_ADDRESS);
        assert_eq!(published.i2c_enter_critical, 0x100);
        assert_eq!(published.i2c_exit_critical, 0x101);
        assert_eq!(published.get_i2c_read_mask, 0x102);
        assert_eq!(published.get_i2c_host_id, 0x103);
        assert_eq!(published.set_rx_compensation, 0x105);
        assert_eq!(published.set_temperature_sensor_power, 0x106);
        assert_eq!(published.set_temperature_sensor_range, 0x107);
        assert_eq!(published.get_temperature_sensor_value, 0x108);
        assert_eq!(published.get_wifi_tx_table, 0x109);
        assert_eq!(published.get_bt_tx_table, 0x10a);
        assert_eq!(published.configure_tx_gain_compensation, 0x10c);
    }

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

    #[test]
    fn calibration_record_identity_checksum_and_mismatch_match_the_pinned_transform() {
        let mut calibration = [0_u8; PHY_CALIBRATION_PREFIX_LEN];
        let mut index = 0;
        while index != calibration.len() {
            calibration[index] = index.wrapping_mul(29) as u8;
            index += 1;
        }

        let version = 0x1234_5678;
        let mac_sys0 = 0xa1b2_c3d4;
        let mac_sys1 = 0xe5f6_0718;
        assert_eq!(
            calibration_identity_from_efuse_words(mac_sys0, mac_sys1),
            [0x07, 0x18, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]
        );
        assert_eq!(
            calibration_record_check_or_write(&mut calibration, false, version, mac_sys0, mac_sys1,),
            0
        );
        assert_eq!(&calibration[..4], &version.to_le_bytes());
        assert_eq!(
            &calibration[4..12],
            &[0x07, 0x18, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]
        );

        let mut sum = 0_u32;
        let mut offset = 0;
        while offset != PHY_CALIBRATION_CHECKSUM_OFFSET {
            sum = sum.wrapping_add(read_u32_le(&calibration, offset));
            offset += 4;
        }
        assert_eq!(
            read_u32_le(&calibration, PHY_CALIBRATION_CHECKSUM_OFFSET),
            !sum
        );
        assert_eq!(
            calibration_record_check_or_write(&mut calibration, true, version, mac_sys0, mac_sys1,),
            0
        );

        calibration[0x40] ^= 0x80;
        assert_eq!(
            calibration_record_check_or_write(&mut calibration, true, version, mac_sys0, mac_sys1,),
            1
        );
    }
}
