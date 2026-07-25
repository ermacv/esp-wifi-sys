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
const TX_CCA_CONTROL_ADDRESS: usize = 0x2010_4c5c;
const TX_QUEUE_CONTROL_BASE_ADDRESS: usize = 0x0100_4d70;
const TX_QUEUE_CONTROL_STRIDE: usize = 0x10;

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

const fn tx_queue_control_address(queue: u8) -> usize {
    TX_QUEUE_CONTROL_BASE_ADDRESS.wrapping_sub((queue as usize) * TX_QUEUE_CONTROL_STRIDE)
}

const fn with_tx_cca(value: u32, cca: u32) -> u32 {
    (value & 0x3fff_ffff) | (cca << 30)
}

const fn tx_queue_is_valid(value: u32) -> u32 {
    (value >> 30) & 1
}

const fn without_tx_queue_valid(value: u32) -> u32 {
    value & 0xbfff_ffff
}

const fn without_tx_queue_enable(value: u32) -> u32 {
    value & 0x3fff_ffff
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

/// Select the two-bit MAC clear-channel-assessment mode.
///
/// Reference: pinned `libpp.a[hal_mac.o]::hal_mac_tx_set_cca`, size `0x18`.
/// The complete body replaces bits 31:30 of `0x2010_4c5c` and returns zero.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.radio_hal"]
pub unsafe extern "C" fn wifi_strict_hal_mac_tx_set_cca(cca: u32) -> u32 {
    let control = TX_CCA_CONTROL_ADDRESS as *mut u32;
    control.write_volatile(with_tx_cca(control.read_volatile(), cca));
    0
}

/// Return the recovered TX queue valid bit.
///
/// Reference: pinned `libpp.a[hal_mac.o]::hal_mac_is_txq_valid`, size `0x14`.
/// Queue zero starts at `0x0100_4d70`; successive queue registers descend by
/// 16 bytes. The result is register bit 30 normalized to zero or one.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.radio_hal"]
pub unsafe extern "C" fn wifi_strict_hal_mac_is_txq_valid(queue: u8) -> u32 {
    let control = tx_queue_control_address(queue) as *const u32;
    tx_queue_is_valid(control.read_volatile())
}

/// Clear only the recovered TX queue valid bit.
///
/// Reference: pinned `libpp.a[hal_mac.o]::hal_mac_set_txq_invalid`, size
/// `0x1c`. The body is one finite read/modify/write of register bit 30.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.radio_hal"]
pub unsafe extern "C" fn wifi_strict_hal_mac_set_txq_invalid(queue: u8) {
    let control = tx_queue_control_address(queue) as *mut u32;
    control.write_volatile(without_tx_queue_valid(control.read_volatile()));
}

/// Clear both recovered TX queue control bits.
///
/// Reference: pinned `libpp.a[hal_mac_tx.o]::hal_mac_txq_disable`, size
/// `0x18`. The body is one finite read/modify/write of bits 31:30.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.radio_hal"]
pub unsafe extern "C" fn wifi_strict_hal_mac_txq_disable(queue: u8) {
    let control = tx_queue_control_address(queue) as *mut u32;
    control.write_volatile(without_tx_queue_enable(control.read_volatile()));
}

/// Preserve the ESP32-S31 CSI bandwidth hook's explicit no-op contract.
///
/// The complete pinned `libpp.a[hal_mac_ctl.o]::hal_mac_set_csi_cbw` body is
/// one two-byte `ret`; it ignores its argument and owns no state.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.radio_hal"]
pub unsafe extern "C" fn wifi_strict_hal_mac_set_csi_cbw(_cbw: u32) {}

#[cfg(test)]
mod tests {
    use super::{
        join_rx_descriptor_address, tsf_latch_mask, tx_queue_control_address, tx_queue_is_valid,
        with_tx_cca, without_tx_queue_enable, without_tx_queue_valid,
    };

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

    #[test]
    fn tx_queue_registers_descend_by_the_recovered_stride() {
        assert_eq!(tx_queue_control_address(0), 0x0100_4d70);
        assert_eq!(tx_queue_control_address(1), 0x0100_4d60);
        assert_eq!(tx_queue_control_address(3), 0x0100_4d40);
    }

    #[test]
    fn tx_queue_control_fields_match_the_pinned_leaves() {
        assert_eq!(with_tx_cca(0xffff_ffff, 0), 0x3fff_ffff);
        assert_eq!(with_tx_cca(0x0123_4567, 1), 0x4123_4567);
        assert_eq!(with_tx_cca(0x0123_4567, 2), 0x8123_4567);
        assert_eq!(with_tx_cca(0x0123_4567, 3), 0xc123_4567);
        assert_eq!(with_tx_cca(0, 7), 0xc000_0000);
        assert_eq!(tx_queue_is_valid(0x4000_0000), 1);
        assert_eq!(tx_queue_is_valid(0x8000_0000), 0);
        assert_eq!(without_tx_queue_valid(u32::MAX), 0xbfff_ffff);
        assert_eq!(without_tx_queue_enable(u32::MAX), 0x3fff_ffff);
    }
}
