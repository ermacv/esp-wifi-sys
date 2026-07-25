//! Narrow ESP32-S31 radio-register leaves.
//!
//! These functions reproduce complete, finite ROM bodies whose only state is
//! documented MMIO. They are temporary runtime-local HAL boundaries until the
//! register layer moves into the ESP32-S31 radio HAL crate.

const TSF_CONTROL_ADDRESS: usize = 0x2010_d814;
const TSF_LOW_ADDRESS: usize = 0x2010_d820;
const TSF_HIGH_ADDRESS: usize = 0x2010_d824;
const RX_DESCRIPTOR_LAST_LOW_ADDRESS: usize = 0x2010_408c;
const RX_DESCRIPTOR_LAST_HIGH_ADDRESS: usize = 0x2010_4c70;

const fn tsf_latch_mask(interface: u32) -> u32 {
    if interface == 0 {
        1
    } else {
        2
    }
}

const fn join_rx_descriptor_address(low_word: u32, high_word: u32) -> usize {
    ((low_word & 0x000f_ffff) | (high_word & 0xfff0_0000)) as usize
}

/// Read one of the two MAC TSF domains through the hardware latch.
///
/// Reference: `esp32s31_rev0_rom.elf`, SHA-256
/// `a52ad7513deb656a910a5740125f1cce2c7941f11ce57213b7b43aea93d5ab87`,
/// `hal_get_tsf_time` at `0x2f82b9f8`, size `0x3e`.
///
/// The meaning of the three registers is inferred from the complete ROM body:
/// setting control bit zero or one latches the selected domain, the ROM reads
/// high then low, and clearing the same bit releases the latch. No polling,
/// delay, call, allocation, or ROM-owned RAM is involved.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.radio_hal"]
pub unsafe extern "C" fn wifi_strict_hal_get_tsf_time(interface: u32) -> u64 {
    let mask = tsf_latch_mask(interface);
    let control = TSF_CONTROL_ADDRESS as *mut u32;
    control.write_volatile(control.read_volatile() | mask);

    // Preserve the ROM read order while returning the standard RV32 u64 ABI:
    // low in a0 and high in a1.
    let high = (TSF_HIGH_ADDRESS as *const u32).read_volatile();
    let low = (TSF_LOW_ADDRESS as *const u32).read_volatile();

    control.write_volatile(control.read_volatile() & !mask);
    (u64::from(high) << 32) | u64::from(low)
}

/// Read the MAC's last completed RX descriptor address.
///
/// Reference: `esp32s31_rev0_rom.elf`, SHA-256
/// `a52ad7513deb656a910a5740125f1cce2c7941f11ce57213b7b43aea93d5ab87`,
/// `hal_mac_rx_get_last_dscr` at `0x2f8386a2`, size `0x1e`.
///
/// The complete ROM body reads the low-address register first, keeps its low
/// 20 bits, reads the high-address register, keeps its high 12 bits, and joins
/// the two fields. It has no call, cycle, wait, allocation, or ROM-owned RAM
/// access. Preserve that read order because the hardware publication contract
/// beyond the recovered two-register snapshot is not yet known.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.radio_hal"]
pub unsafe extern "C" fn wifi_strict_hal_mac_rx_get_last_dscr() -> *mut u8 {
    let low_word = (RX_DESCRIPTOR_LAST_LOW_ADDRESS as *const u32).read_volatile();
    let high_word = (RX_DESCRIPTOR_LAST_HIGH_ADDRESS as *const u32).read_volatile();
    join_rx_descriptor_address(low_word, high_word) as *mut u8
}

#[cfg(test)]
mod tests {
    use super::{join_rx_descriptor_address, tsf_latch_mask};

    #[test]
    fn selects_the_two_recovered_tsf_latch_bits() {
        assert_eq!(tsf_latch_mask(0), 1);
        assert_eq!(tsf_latch_mask(1), 2);
        assert_eq!(tsf_latch_mask(u32::MAX), 2);
    }

    #[test]
    fn joins_only_the_recovered_rx_descriptor_address_fields() {
        assert_eq!(
            join_rx_descriptor_address(0xabc5_4321, 0x123f_edcb),
            0x1235_4321
        );
        assert_eq!(join_rx_descriptor_address(u32::MAX, 0), 0x000f_ffff);
        assert_eq!(join_rx_descriptor_address(0, u32::MAX), 0xfff0_0000);
    }
}
