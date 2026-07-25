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
const PHY_RX_COMP_LOW_ADDRESS: usize = 0x2010_702c;
const PHY_DC_MEMORY_CONTROL_ADDRESS: usize = 0x2010_703c;
const PHY_RX_COMP_HIGH_ADDRESS: usize = 0x2010_70a0;
const PHY_DC_MEMORY_CLEAR_BIT: u32 = 1 << 20;
const PHY_GAIN_MEMORY_INDEX_SOURCE_ADDRESS: usize = 0x2010_0408;
const PHY_GAIN_MEMORY_CONTROL_ADDRESS: usize = 0x2010_0844;
const PHY_GAIN_MEMORY_WORD0_ADDRESS: usize = 0x2010_0848;
const PHY_GAIN_MEMORY_WORD1_ADDRESS: usize = 0x2010_084c;
const PHY_GAIN_MEMORY_WORD2_ADDRESS: usize = 0x2010_0850;
const PHY_GAIN_MEMORY_MAX_ENTRIES: u32 = 32;

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

const fn with_phy_rx_comp_low(value: u32) -> u32 {
    (value & 0xffff_ff00) | 0xed
}

const fn with_phy_rx_comp_high(value: u32) -> u32 {
    (value & 0x00ff_ffff) | 0xed00_0000
}

const fn tx_baseband_gain_index(gain: u16) -> usize {
    match gain {
        0x0080 => 1,
        0x0100 => 2,
        0x0020 => 3,
        0x00a0 => 4,
        _ => 0,
    }
}

const fn encode_phy_gain_memory_words(
    gain_72: u16,
    gain_64: u16,
    gain_32: u8,
    seed_0: u16,
    seed_1: u16,
    seed_2: u16,
    seed_3: u16,
    config: u16,
) -> (u32, u32, u32) {
    let gain_72 = gain_72 as u32;
    let gain_64 = gain_64 as u32;
    let word_0 = ((config & 0x1fff) as u32)
        | ((seed_2 as u32) << 22)
        | ((seed_1 as u32) << 31)
        | ((seed_3 as u32) << 13);
    let word_1 = ((seed_0 as u32) << 8)
        | ((seed_1 as u32) >> 1)
        | (((gain_64 >> 6) & 0xff) << 17)
        | ((gain_72 & 7) << 31)
        | ((gain_64 & 0x3f) << 20)
        | 0x1000_0000;
    let word_2 = ((gain_72 & 7) >> 1)
        | ((gain_72 >> 1) & 0x1c)
        | ((gain_32 as u32) << 15)
        | 0x0000_7f80;
    (word_0, word_1, word_2)
}

const fn with_phy_gain_memory_index(value: u32, index: u8) -> u32 {
    (value & 0xfff0_0000) | ((index as u32) << 11) | 0x0008_0000
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

/// Program the two recovered PHY RX compensation fields.
///
/// Reference: pinned `libphy.a[phy_reg.o]::phy_set_rx_comp_new`, size `0x28`.
/// The complete body replaces bits 7:0 of `0x2010_702c` and bits 31:24 of
/// `0x2010_70a0` with `0xed`, in that order. The field meaning is not yet
/// known; this function intentionally documents only the evidenced register
/// transaction. It contains no call, loop, wait, allocation, or data-symbol
/// access.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.radio_hal"]
pub unsafe extern "C" fn wifi_strict_phy_set_rx_comp_new() {
    let low = PHY_RX_COMP_LOW_ADDRESS as *mut u32;
    low.write_volatile(with_phy_rx_comp_low(low.read_volatile()));

    let high = PHY_RX_COMP_HIGH_ADDRESS as *mut u32;
    high.write_volatile(with_phy_rx_comp_high(high.read_volatile()));
}

/// Pulse the recovered PHY DC-memory clear control bit.
///
/// Reference: pinned `libphy.a[phy_reg.o]::phy_dc_mem_clr`, size `0x1c`.
/// The complete body sets then clears bit 20 of `0x2010_703c`, performing a
/// fresh volatile read before each write. The exact hardware side effect is
/// not yet documented beyond the vendor symbol name and this transaction.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.radio_hal"]
pub unsafe extern "C" fn wifi_strict_phy_dc_mem_clr() {
    let control = PHY_DC_MEMORY_CONTROL_ADDRESS as *mut u32;
    control.write_volatile(control.read_volatile() | PHY_DC_MEMORY_CLEAR_BIT);
    control.write_volatile(control.read_volatile() & !PHY_DC_MEMORY_CLEAR_BIT);
}

/// Encode and publish a finite PHY transmit-gain table.
///
/// Reference: pinned
/// `libphy.a[phy_tx_gain.o]::phy_set_tx_gain_mem_new`, size `0x130`, plus the
/// complete rev0 ROM leaves `phy_txbbgain_to_index` at `0x2f826ac8` and
/// `phy_write_gain_mem` at `0x2f8274f0`.
///
/// The vendor body accepts 16 BT or 32 Wi-Fi entries. The strict runtime only
/// calls the 32-entry Wi-Fi form, but this ABI boundary preserves both finite
/// counts and traps any larger input rather than admitting an unbounded raw
/// pointer walk. `seed_and_output_32` names the start of the vendor's
/// contiguous `6 * u32` seed followed immediately by its `8 * u32` 32-byte
/// gain output. This unusual overlap is part of the recovered ABI: baseband
/// gain indices three and four select words in the latter region.
///
/// Every iteration performs three ordinary input reads, selects four
/// halfwords from that contiguous layout, encodes three register words, then
/// writes `0x2010_0848`, `0x2010_084c`, `0x2010_0850` and finally updates
/// `0x2010_0844`. There is no allocation, wait, indirect call, hidden state,
/// or hardware-dependent loop exit.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.radio_hal"]
pub unsafe extern "C" fn wifi_strict_phy_set_tx_gain_mem_new(
    bank: u32,
    entries: u32,
    output_72: *const u32,
    output_64: *const u32,
    output_32: *const u32,
    seed_and_output_32: *const u32,
    config: *const u16,
) {
    if entries > PHY_GAIN_MEMORY_MAX_ENTRIES
        || (entries != 0
            && (output_72.is_null()
                || output_64.is_null()
                || output_32.is_null()
                || seed_and_output_32.is_null()
                || config.is_null()))
    {
        core::arch::asm!("ebreak", options(noreturn));
    }

    let hardware_base =
        ((PHY_GAIN_MEMORY_INDEX_SOURCE_ADDRESS as *const u32).read_volatile() >> 24) as u8;
    let memory_base = hardware_base.wrapping_add(if bank == 0 { 0 } else { 32 });
    let seed_halfwords = seed_and_output_32.cast::<u16>();
    let output_72_halfwords = output_72.cast::<u16>();
    let output_64_halfwords = output_64.cast::<u16>();
    let output_32_bytes = output_32.cast::<u8>();

    let mut entry = 0_u32;
    while entry != entries {
        let entry_index = entry as usize;
        let gain_72 = output_72_halfwords.add(entry_index).read();
        let gain_64 = output_64_halfwords.add(entry_index).read();
        let gain_32 = output_32_bytes.add(entry_index).read();
        let seed_index = tx_baseband_gain_index(gain_64) * 4;
        let (word_0, word_1, word_2) = encode_phy_gain_memory_words(
            gain_72,
            gain_64,
            gain_32,
            seed_halfwords.add(seed_index).read(),
            seed_halfwords.add(seed_index + 1).read(),
            seed_halfwords.add(seed_index + 2).read(),
            seed_halfwords.add(seed_index + 3).read(),
            config.read(),
        );

        (PHY_GAIN_MEMORY_WORD0_ADDRESS as *mut u32).write_volatile(word_0);
        (PHY_GAIN_MEMORY_WORD1_ADDRESS as *mut u32).write_volatile(word_1);
        (PHY_GAIN_MEMORY_WORD2_ADDRESS as *mut u32).write_volatile(word_2);
        let control = PHY_GAIN_MEMORY_CONTROL_ADDRESS as *mut u32;
        control.write_volatile(with_phy_gain_memory_index(
            control.read_volatile(),
            memory_base.wrapping_add(entry as u8),
        ));
        entry += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        encode_phy_gain_memory_words, join_rx_descriptor_address, tsf_latch_mask,
        tx_baseband_gain_index, tx_queue_control_address, tx_queue_is_valid,
        with_phy_gain_memory_index, with_phy_rx_comp_high, with_phy_rx_comp_low, with_tx_cca,
        without_tx_queue_enable, without_tx_queue_valid,
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

    #[test]
    fn phy_rx_comp_fields_match_the_pinned_leaf() {
        assert_eq!(with_phy_rx_comp_low(0x1234_5678), 0x1234_56ed);
        assert_eq!(with_phy_rx_comp_low(u32::MAX), 0xffff_ffed);
        assert_eq!(with_phy_rx_comp_high(0x1234_5678), 0xed34_5678);
        assert_eq!(with_phy_rx_comp_high(u32::MAX), 0xedff_ffff);
    }

    #[test]
    fn phy_baseband_gain_indices_match_the_rom_leaf() {
        assert_eq!(tx_baseband_gain_index(0x0080), 1);
        assert_eq!(tx_baseband_gain_index(0x0100), 2);
        assert_eq!(tx_baseband_gain_index(0x0020), 3);
        assert_eq!(tx_baseband_gain_index(0x00a0), 4);
        assert_eq!(tx_baseband_gain_index(0), 0);
        assert_eq!(tx_baseband_gain_index(u16::MAX), 0);
    }

    #[test]
    fn phy_gain_words_match_the_complete_vendor_transform() {
        assert_eq!(
            encode_phy_gain_memory_words(0, 0, 0, 0, 0, 0, 0, 0),
            (0, 0x1000_0000, 0x0000_7f80)
        );
        assert_eq!(
            encode_phy_gain_memory_words(
                0x0007, 0x00bf, 0xa5, 0x1234, 0x5678, 0x9abc, 0xdef0, 0xffff,
            ),
            (0xbfde_1fff, 0x93f6_3f3c, 0x0052_ff83)
        );
        assert_eq!(
            with_phy_gain_memory_index(0xabc5_4321, 0x12),
            0xabc8_9000
        );
    }
}
