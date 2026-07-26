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
const TX_QUEUE_CONTROL_BASE_ADDRESS: usize = 0x2010_4d70;
const TX_QUEUE_CONTROL_STRIDE: usize = 0x10;
const MAC_ADDRESS_LOW_BASE_ADDRESS: usize = 0x2010_405c;
const MAC_ADDRESS_HIGH_BASE_ADDRESS: usize = 0x2010_4060;
const MAC_ADDRESS_STRIDE: usize = 8;
const MAC_RX_ADDRESS_POLICY_BASE_ADDRESS: usize = 0x2010_4004;
const MAC_RX_ADDRESS_POLICY_STRIDE: usize = 8;
const MAC_RX_FRAME_POLICY_BASE_ADDRESS: usize = 0x2010_40d8;
const MAC_RX_MANAGEMENT_POLICY_BASE_ADDRESS: usize = 0x2010_4060;
const MAC_RX_MANAGEMENT_POLICY_STRIDE: usize = 8;
const MAC_CONTROL_ADDRESS: usize = 0x2010_4cac;
const WIFI_MAC_REGDMA_CONTROL_ADDRESS: usize = 0x2010_d83c;
const MAC_ADDRESS_VALID_BIT: u32 = 1 << 16;
const MAC_RX_MODE_MASK: u32 = (1 << 10) | (1 << 4);
const MAC_RX_CONTROL_POLICY_BIT: u32 = 1 << 6;
const MAC_RX_CONTROL_ADDRESS_BIT: u32 = 1 << 31;
const MAC_RX_MANAGEMENT_POLICY_BIT: u32 = 1 << 16;
const MAC_RX_UNIQUE_BSSID_BITS: u32 = (1 << 8) | (1 << 1);
const MAC_NO_RETENTION_CLEAR_BITS: u32 = 0x00ff_1000;
const WIFI_MAC_REGDMA_LINK_MASK: u32 = 0x001e_0000;
const WIFI_MAC_ACTIVE_REGDMA_LINK: u32 = 4;
const MAC_INTERFACE_COUNT: u32 = 4;
const MAC_RX_POLICY_QUEUE_COUNT: u32 = 3;
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
const PHY_FE_CLOCK_GATE_ADDRESS: usize = 0x2010_0400;
const PHY_FE_BB_CLOCK_CONTROL_ADDRESS: usize = 0x2010_0800;
const PHY_BB_CLOCK_GATE_ADDRESS: usize = 0x2010_7c80;
const PHY_AGC_CONTROL_ADDRESS: usize = 0x2010_705c;
const PHY_AGC_SAT_GAIN_LOW_ADDRESS: usize = 0x2010_7064;
const PHY_AGC_SAT_GAIN_HIGH_ADDRESS: usize = 0x2010_7114;
const PHY_AGC_WINDOW_ADDRESS: usize = 0x2010_7104;
const PHY_RX_CONTROL_ADDRESS: usize = 0x2010_78c8;
const PHY_FTM_CONTROL_ADDRESS: usize = 0x2010_7d4c;
const PHY_AGC_SAT_GAIN_VALUE: u32 = 0x0818_212d;

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

const fn mac_address_registers(interface: u32) -> (usize, usize) {
    let offset = (interface as usize) * MAC_ADDRESS_STRIDE;
    (
        MAC_ADDRESS_LOW_BASE_ADDRESS + offset,
        MAC_ADDRESS_HIGH_BASE_ADDRESS + offset,
    )
}

const fn encode_mac_address(address: [u8; 6]) -> (u32, u32) {
    (
        u32::from_le_bytes([address[0], address[1], address[2], address[3]]),
        u16::from_le_bytes([address[4], address[5]]) as u32 | MAC_ADDRESS_VALID_BIT,
    )
}

const fn mac_rx_frame_policy_address(queue: u32) -> usize {
    MAC_RX_FRAME_POLICY_BASE_ADDRESS + (queue as usize) * core::mem::size_of::<u32>()
}

const fn mac_rx_address_policy_address(queue: u32) -> usize {
    MAC_RX_ADDRESS_POLICY_BASE_ADDRESS + (queue as usize) * MAC_RX_ADDRESS_POLICY_STRIDE
}

const fn mac_rx_management_policy_address(queue: u32) -> usize {
    MAC_RX_MANAGEMENT_POLICY_BASE_ADDRESS + (queue as usize) * MAC_RX_MANAGEMENT_POLICY_STRIDE
}

const fn with_mac_rx_mode(value: u32, mode: u32) -> u32 {
    if mode <= 1 {
        value & !MAC_RX_MODE_MASK
    } else {
        value | MAC_RX_MODE_MASK
    }
}

const fn with_mac_rx_control_policy(value: u32, control: u32) -> u32 {
    if control <= 1 {
        value & !MAC_RX_CONTROL_POLICY_BIT
    } else {
        value | MAC_RX_CONTROL_POLICY_BIT
    }
}

const fn with_mac_rx_control_address_policy(value: u32, control: u32) -> u32 {
    match control {
        0 => value & !MAC_RX_CONTROL_ADDRESS_BIT,
        1 => value | MAC_RX_CONTROL_ADDRESS_BIT,
        _ => value,
    }
}

const fn with_mac_rx_management_policy(value: u32, management: u32) -> u32 {
    if management == 0 {
        value & !MAC_RX_MANAGEMENT_POLICY_BIT
    } else {
        value | MAC_RX_MANAGEMENT_POLICY_BIT
    }
}

const fn with_mac_rx_unique_bssid_policy(value: u32, enabled: u32) -> u32 {
    if enabled == 0 {
        value & !MAC_RX_UNIQUE_BSSID_BITS
    } else {
        value | MAC_RX_UNIQUE_BSSID_BITS
    }
}

const fn without_mac_tx_retention(value: u32) -> u32 {
    value & !MAC_NO_RETENTION_CLEAR_BITS
}

const fn with_wifi_mac_regdma_link(value: u32, link: u32) -> u32 {
    (value & !WIFI_MAC_REGDMA_LINK_MASK) | ((link << 17) & WIFI_MAC_REGDMA_LINK_MASK)
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

const fn without_fe_bb_clock_enable(value: u32) -> u32 {
    value & !0x3
}

const fn with_phy_agc_control(value: u32) -> u32 {
    value | 0x0400_0000
}

const fn with_phy_agc_window(value: u32) -> u32 {
    (value & !0x1ff) | 0x1c0
}

const fn with_phy_rx_control_low(value: u32) -> u32 {
    (value & !0x7f) | 0x17
}

const fn with_phy_rx_control_high(value: u32) -> u32 {
    (value & 0xffff_c07f) | 0x0b80
}

const fn with_phy_ftm_enable(value: u32, enable: u32) -> u32 {
    (value & !1) | (enable & 1)
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
    let word_2 =
        ((gain_72 & 7) >> 1) | ((gain_72 >> 1) & 0x1c) | ((gain_32 as u32) << 15) | 0x0000_7f80;
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

/// Program one of the four recovered MAC-address register pairs.
///
/// References: pinned `libpp.a[if_hwctrl.o]::ic_set_mac`, an exact tail call,
/// and `libpp.a[hal_mac.o]::hal_mac_set_addr`, size `0x48`. The complete leaf
/// packs the six input bytes little-endian, writes the low four bytes first,
/// writes the high two bytes, then sets bit 16 in the high register through a
/// fresh read/modify/write. No C/ROM-owned state, call, loop, wait, delay or
/// allocation remains. The meaning of high-register bit 16 is inferred only
/// as address-valid from that transaction.
///
/// The archive callers are interface setup paths, not radio interrupt
/// handlers. This leaf therefore remains flash-mapped so it does not consume
/// the interrupt-only SRAM reserve.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_ic_set_mac(interface: u32, address: *const u8) {
    if interface >= MAC_INTERFACE_COUNT || address.is_null() {
        core::arch::asm!("ebreak", options(noreturn));
    }

    let bytes = [
        address.read(),
        address.add(1).read(),
        address.add(2).read(),
        address.add(3).read(),
        address.add(4).read(),
        address.add(5).read(),
    ];
    let (low_word, high_word) = encode_mac_address(bytes);
    let (low_address, high_address) = mac_address_registers(interface);
    (low_address as *mut u32).write_volatile(low_word);

    let high = high_address as *mut u32;
    high.write_volatile(high_word & !MAC_ADDRESS_VALID_BIT);
    high.write_volatile(high.read_volatile() | MAC_ADDRESS_VALID_BIT);
}

/// Program the recovered RX frame/control/management policy for one queue.
///
/// References: pinned `libpp.a[if_hwctrl.o]::ic_set_rx_policy`, size `0x14`,
/// and `libpp.a[hal_mac.o]::hal_mac_rx_set_policy`, size `0xd2`.
/// The wrapper accepts queues 0..=2 and returns one after the finite MMIO
/// transaction. Register field names describe only the vendor arguments and
/// exact masks; broader MAC semantics are not assumed.
///
/// The evidenced callers configure scan/supplicant state from the radio
/// executor, not an interrupt. Keep this leaf flash-mapped.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_ic_set_rx_policy(
    queue: u32,
    mode: u32,
    control: u32,
    management: u32,
) -> u32 {
    if queue >= MAC_RX_POLICY_QUEUE_COUNT {
        return 1;
    }

    let frame_policy = mac_rx_frame_policy_address(queue) as *mut u32;
    frame_policy.write_volatile(with_mac_rx_mode(frame_policy.read_volatile(), mode));

    let address_policy = mac_rx_address_policy_address(queue) as *mut u32;
    if queue == 1 {
        // The pinned body sets bit 30 only for queue one before applying the
        // shared control-address policy below.
        address_policy.write_volatile(address_policy.read_volatile() | (1 << 30));
    } else {
        address_policy.write_volatile(address_policy.read_volatile() & !(1 << 30));
    }

    frame_policy.write_volatile(with_mac_rx_control_policy(
        frame_policy.read_volatile(),
        control,
    ));
    if control <= 1 {
        address_policy.write_volatile(with_mac_rx_control_address_policy(
            address_policy.read_volatile(),
            control,
        ));
    }

    let management_policy = mac_rx_management_policy_address(queue) as *mut u32;
    management_policy.write_volatile(with_mac_rx_management_policy(
        management_policy.read_volatile(),
        management,
    ));
    1
}

/// Enable or disable the recovered unique-BSSID checks for one RX queue.
///
/// References: pinned
/// `libpp.a[if_hwctrl.o]::ic_set_rx_policy_ubssid_check`, size `0x1e`, and
/// `libpp.a[hal_mac.o]::hal_mac_set_rxq_policy`, size `0x2c`. The vendor
/// wrapper admits queues 0..=3, returns zero outside that range, and otherwise
/// returns one after two ordered read/modify/write operations.
///
/// The evidenced caller is the same non-interrupt policy setup path, so this
/// leaf is flash-mapped.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_ic_set_rx_policy_ubssid_check(
    queue: u32,
    enabled: u32,
) -> u32 {
    if queue >= MAC_INTERFACE_COUNT {
        return 0;
    }

    let policy = mac_rx_frame_policy_address(queue) as *mut u32;
    if enabled == 0 {
        policy.write_volatile(policy.read_volatile() & !(1 << 8));
        policy.write_volatile(policy.read_volatile() & !(1 << 1));
    } else {
        policy.write_volatile(policy.read_volatile() | (1 << 8));
        policy.write_volatile(policy.read_volatile() | (1 << 1));
    }
    1
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
/// Queue zero starts at `0x2010_4d70`; successive queue registers descend by
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

/// Restart the MAC for the strict `WIFI_PS_NONE` profile.
///
/// The complete pinned chain is
/// `libpp.a[if_hwctrl.o]::ic_mac_init` (40 bytes),
/// `libpp.a[hal_mac.o]::hal_mac_init` (48 bytes), and
/// `libpp.a[hal_pwr.o]::pwr_hal_select_wifimac_regdma_link` (32 bytes).
/// With power save disabled, `pm_get_tx_blocks_retention_mask` returns all
/// ones, so the first read/modify/write clears `0x00ff_1000` at
/// `0x2010_4cac`. The second selects evidenced REGDMA link four in bits
/// 20:17 of `0x2010_d83c`.
///
/// The vendor tail also writes one to
/// `g_wifimac_regdma_link_selected`. That byte is a cache for the vendor PM
/// getters; every strict PM hook is disabled under the read-back-verified
/// `WIFI_PS_NONE` invariant, so publishing it would retain hidden C state
/// without a strict consumer.
///
/// This finite leaf contains no call, loop, wait, allocation, or non-MMIO
/// state. The surrounding Rust channel state machine owns serialization.
#[cfg(target_arch = "riscv32")]
#[inline(always)]
pub(crate) unsafe fn restart_mac_without_power_save() {
    let mac_control = MAC_CONTROL_ADDRESS as *mut u32;
    mac_control.write_volatile(without_mac_tx_retention(mac_control.read_volatile()));

    let regdma_control = WIFI_MAC_REGDMA_CONTROL_ADDRESS as *mut u32;
    regdma_control.write_volatile(with_wifi_mac_regdma_link(
        regdma_control.read_volatile(),
        WIFI_MAC_ACTIVE_REGDMA_LINK,
    ));
}

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

/// Close the recovered front-end and baseband clock gates.
///
/// Reference: the complete pinned
/// `libphy.a[phy_init.o]::phy_close_fe_bb_clk` body, size `0x20`. It writes
/// zero to `0x2010_0400`, clears bits 1:0 of `0x2010_0800`, then writes zero
/// to `0x2010_7c80`. The field names are retained from the vendor symbol; no
/// broader register meaning is assumed. There is no call, loop, wait,
/// allocation, or non-MMIO state access.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
#[link_section = ".rwtext.wifi_strict.radio_hal"]
pub unsafe extern "C" fn wifi_strict_phy_close_fe_bb_clk() {
    (PHY_FE_CLOCK_GATE_ADDRESS as *mut u32).write_volatile(0);

    let control = PHY_FE_BB_CLOCK_CONTROL_ADDRESS as *mut u32;
    control.write_volatile(without_fe_bb_clock_enable(control.read_volatile()));

    (PHY_BB_CLOCK_GATE_ADDRESS as *mut u32).write_volatile(0);
}

#[cfg(target_arch = "riscv32")]
#[inline(always)]
unsafe fn write_phy_wifi_agc_sat_gain(value: u32) {
    (PHY_AGC_SAT_GAIN_LOW_ADDRESS as *mut u32).write_volatile(value);
    (PHY_AGC_SAT_GAIN_HIGH_ADDRESS as *mut u32).write_volatile(value);
}

#[cfg(target_arch = "riscv32")]
#[inline(always)]
unsafe fn write_phy_ftm_enable(enable: u32) {
    let control = PHY_FTM_CONTROL_ADDRESS as *mut u32;
    control.write_volatile(with_phy_ftm_enable(control.read_volatile(), enable));
}

/// Apply the complete recovered post-initialization PHY register update.
///
/// Reference: the complete pinned
/// `libphy.a[phy_init.o]::phy_reg_update_new` body, size `0x70`, plus the
/// complete rev0 ROM `phy_wifi_agc_sat_gain` body at `0x2f827db0`, size
/// `0x0c`, and pinned `libphy.a[phy_reg.o]::phy_set_ftm_en`, size `0x14`.
/// Every read/modify/write and the two saturation-gain writes retain vendor
/// order, including the fresh second read of `0x2010_78c8`.
///
/// This is a finite MMIO-only transaction: no callback, ROM/vendor call,
/// allocation, wait, delay, loop, or hidden mutable state remains.
/// Its two evidenced callers are `register_chipv7_phy` and
/// caller-task `phy_wakeup_init`; neither is an interrupt handler, so this
/// cold/wakeup leaf intentionally remains flash-mapped instead of consuming
/// the interrupt-only SRAM reserve.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_phy_reg_update_new() {
    let agc_control = PHY_AGC_CONTROL_ADDRESS as *mut u32;
    agc_control.write_volatile(with_phy_agc_control(agc_control.read_volatile()));

    write_phy_wifi_agc_sat_gain(PHY_AGC_SAT_GAIN_VALUE);

    let agc_window = PHY_AGC_WINDOW_ADDRESS as *mut u32;
    agc_window.write_volatile(with_phy_agc_window(agc_window.read_volatile()));

    let rx_control = PHY_RX_CONTROL_ADDRESS as *mut u32;
    rx_control.write_volatile(with_phy_rx_control_low(rx_control.read_volatile()));
    rx_control.write_volatile(with_phy_rx_control_high(rx_control.read_volatile()));

    write_phy_ftm_enable(1);
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
        encode_mac_address, encode_phy_gain_memory_words, join_rx_descriptor_address,
        mac_address_registers, mac_rx_address_policy_address, mac_rx_frame_policy_address,
        mac_rx_management_policy_address, tsf_latch_mask, tx_baseband_gain_index,
        tx_queue_control_address, tx_queue_is_valid, with_mac_rx_control_address_policy,
        with_mac_rx_control_policy, with_mac_rx_management_policy, with_mac_rx_mode,
        with_mac_rx_unique_bssid_policy, with_phy_agc_control, with_phy_agc_window,
        with_phy_ftm_enable, with_phy_gain_memory_index, with_phy_rx_comp_high,
        with_phy_rx_comp_low, with_phy_rx_control_high, with_phy_rx_control_low, with_tx_cca,
        with_wifi_mac_regdma_link, without_fe_bb_clock_enable, without_mac_tx_retention,
        without_tx_queue_enable, without_tx_queue_valid, WIFI_MAC_ACTIVE_REGDMA_LINK,
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
        assert_eq!(tx_queue_control_address(0), 0x2010_4d70);
        assert_eq!(tx_queue_control_address(1), 0x2010_4d60);
        assert_eq!(tx_queue_control_address(3), 0x2010_4d40);
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
    fn mac_address_registers_and_encoding_match_the_pinned_leaf() {
        assert_eq!(mac_address_registers(0), (0x2010_405c, 0x2010_4060));
        assert_eq!(mac_address_registers(3), (0x2010_4074, 0x2010_4078));
        assert_eq!(
            encode_mac_address([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
            (0x3322_1102, 0x0001_5544)
        );
    }

    #[test]
    fn rx_policy_addresses_and_masks_match_the_pinned_leaf() {
        assert_eq!(mac_rx_frame_policy_address(0), 0x2010_40d8);
        assert_eq!(mac_rx_frame_policy_address(3), 0x2010_40e4);
        assert_eq!(mac_rx_address_policy_address(2), 0x2010_4014);
        assert_eq!(mac_rx_management_policy_address(2), 0x2010_4070);

        assert_eq!(with_mac_rx_mode(u32::MAX, 0), 0xffff_fbef);
        assert_eq!(with_mac_rx_mode(0, 2), 0x0000_0410);
        assert_eq!(with_mac_rx_control_policy(u32::MAX, 1), 0xffff_ffbf);
        assert_eq!(with_mac_rx_control_policy(0, 2), 0x0000_0040);
        assert_eq!(with_mac_rx_control_address_policy(u32::MAX, 0), 0x7fff_ffff);
        assert_eq!(with_mac_rx_control_address_policy(0, 1), 0x8000_0000);
        assert_eq!(
            with_mac_rx_control_address_policy(0x1234_5678, 2),
            0x1234_5678
        );
        assert_eq!(with_mac_rx_management_policy(u32::MAX, 0), 0xfffe_ffff);
        assert_eq!(with_mac_rx_management_policy(0, 1), 0x0001_0000);
        assert_eq!(with_mac_rx_unique_bssid_policy(u32::MAX, 0), 0xffff_fefd);
        assert_eq!(with_mac_rx_unique_bssid_policy(0, 1), 0x0000_0102);
    }

    #[test]
    fn no_power_save_mac_restart_matches_the_complete_pinned_chain() {
        assert_eq!(without_mac_tx_retention(u32::MAX), 0xff00_efff);
        assert_eq!(
            without_mac_tx_retention(0x12ff_3456),
            0x1200_2456
        );

        assert_eq!(
            with_wifi_mac_regdma_link(0, WIFI_MAC_ACTIVE_REGDMA_LINK),
            0x0008_0000
        );
        assert_eq!(
            with_wifi_mac_regdma_link(u32::MAX, WIFI_MAC_ACTIVE_REGDMA_LINK),
            0xffe9_ffff
        );
        assert_eq!(
            with_wifi_mac_regdma_link(0x1234_5678, 0),
            0x1220_5678
        );
    }

    #[test]
    fn phy_rx_comp_fields_match_the_pinned_leaf() {
        assert_eq!(with_phy_rx_comp_low(0x1234_5678), 0x1234_56ed);
        assert_eq!(with_phy_rx_comp_low(u32::MAX), 0xffff_ffed);
        assert_eq!(with_phy_rx_comp_high(0x1234_5678), 0xed34_5678);
        assert_eq!(with_phy_rx_comp_high(u32::MAX), 0xedff_ffff);
    }

    #[test]
    fn phy_fe_bb_clock_mask_matches_the_pinned_leaf() {
        assert_eq!(without_fe_bb_clock_enable(u32::MAX), 0xffff_fffc);
        assert_eq!(without_fe_bb_clock_enable(0x1234_567b), 0x1234_5678);
    }

    #[test]
    fn phy_post_init_register_masks_match_the_complete_pinned_chain() {
        assert_eq!(with_phy_agc_control(0), 0x0400_0000);
        assert_eq!(with_phy_agc_control(u32::MAX), u32::MAX);
        assert_eq!(with_phy_agc_window(u32::MAX), 0xffff_ffc0);
        assert_eq!(with_phy_agc_window(0x1234_5600), 0x1234_57c0);
        assert_eq!(with_phy_rx_control_low(u32::MAX), 0xffff_ff97);
        assert_eq!(with_phy_rx_control_high(u32::MAX), 0xffff_cbff);
        assert_eq!(with_phy_rx_control_high(0), 0x0000_0b80);
        assert_eq!(with_phy_ftm_enable(0xffff_fffe, 1), u32::MAX);
        assert_eq!(with_phy_ftm_enable(u32::MAX, 0), 0xffff_fffe);
        assert_eq!(with_phy_ftm_enable(0, 3), 1);
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
        assert_eq!(with_phy_gain_memory_index(0xabc5_4321, 0x12), 0xabc8_9000);
    }
}
