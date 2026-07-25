use core::{cell::UnsafeCell, ptr};

const PHY_FREQUENCY_OFFSET: usize = 0x20;
const PHY_CHANNEL_14_MIC: usize = 0x26;
const PHY_11P_ENABLE: usize = 0x28;
const PHY_11P_CONFIG: usize = 0x29;
const PHY_XTAL_SELECTOR: usize = 0x4f;
const PHY_CURRENT_CHANNEL: usize = 0x11c;
const PHY_INIT_COMPLETE: usize = 0x11e;
const PHY_CURRENT_CBW: usize = 0x11f;

unsafe extern "C" {
    static mut phy_param: u8;

    fn phy_chan_to_freq(channel: u16) -> u16;
    fn phy_mhz2ieee(frequency_mhz: u16) -> u16;
    fn phy_disable_agc();
    fn phy_bbpll_cal(enable: u32);
    fn phy_tsens_temp_read();
    fn phy_set_channel_rfpll_freq(frequency_mhz: u16, xtal_selector: u8, offset: i16);
    fn phy_chip_set_chan_misc_new(channel: u16);
    fn phy_i2c_master_mem_txcap();
    fn phy_bb_cbw_chan_cfg(cbw: u8);
    fn phy_chan14_mic_cfg_new(enable: u32);
    fn phy_set_rx_comp_new();
    fn phy_dc_mem_clr();
    fn phy_enable_agc();
}

#[derive(Clone, Copy)]
struct PhyChannelState {
    adopted: bool,
    frequency_offset: i16,
    xtal_selector: u8,
    channel_14_mic: bool,
    dot11p_enable: u8,
    dot11p_config: u8,
    current_channel: u16,
    init_complete: bool,
    current_cbw: u8,
}

impl PhyChannelState {
    const fn new() -> Self {
        Self {
            adopted: false,
            frequency_offset: 0,
            xtal_selector: 0,
            channel_14_mic: false,
            dot11p_enable: 0,
            dot11p_config: 0,
            current_channel: 0,
            init_complete: false,
            current_cbw: 0,
        }
    }
}

struct PhyChannelResources(UnsafeCell<PhyChannelState>);

// Adoption runs before strict handoff and every subsequent mutation belongs
// to the single radio owner. No interrupt handler reads this object.
unsafe impl Sync for PhyChannelResources {}

#[link_section = ".critical.bss.wifi_strict.phy_channel"]
static RESOURCES: PhyChannelResources =
    PhyChannelResources(UnsafeCell::new(PhyChannelState::new()));

/// Adopt only the fields read or written by the pinned
/// `libphy.a[phy_rfpll.o]::phy_chip_set_chan` body.
///
/// The offsets are instruction operands in that object. Unknown bytes in the
/// 508-byte `phy_param` object deliberately remain outside this Rust type.
///
/// # Safety
/// PHY cold initialization must be complete and no channel transition may run
/// concurrently.
pub(crate) unsafe fn adopt_vendor_phy_channel_state() {
    let source = ptr::addr_of!(phy_param);
    let state = &mut *RESOURCES.0.get();
    state.frequency_offset = source
        .add(PHY_FREQUENCY_OFFSET)
        .cast::<i16>()
        .read_volatile();
    state.channel_14_mic = source.add(PHY_CHANNEL_14_MIC).read_volatile() != 0;
    state.dot11p_enable = source.add(PHY_11P_ENABLE).read_volatile();
    state.dot11p_config = source.add(PHY_11P_CONFIG).read_volatile();
    state.xtal_selector = source.add(PHY_XTAL_SELECTOR).read_volatile();
    state.current_channel = source
        .add(PHY_CURRENT_CHANNEL)
        .cast::<u16>()
        .read_volatile();
    state.init_complete = source.add(PHY_INIT_COMPLETE).read_volatile() != 0;
    state.current_cbw = source.add(PHY_CURRENT_CBW).read_volatile();
    state.adopted = true;
}

#[inline(never)]
unsafe fn trap_invalid_phy_channel_state() -> ! {
    core::arch::asm!("ebreak", options(noreturn))
}

/// Strict channel-programming sequence recovered from the pinned
/// `phy_rfpll.o` implementation.
///
/// The two vendor I2C critical-section callbacks are intentionally absent:
/// the qualified S31 image binds both to a single `ret`, while strict runtime
/// serializes this whole sequence in the Rust radio owner. The ROM function
/// table call at slot `+0x14` is the cold-published
/// `phy_set_rx_comp_new` leaf and is therefore direct here.
pub(crate) unsafe fn program_channel(frequency_mhz: u16, cbw: u8) {
    if !crate::critical::strict_wifi_hart_armed() || !crate::critical::on_strict_wifi_hart() {
        trap_invalid_phy_channel_state();
    }

    let state = &mut *RESOURCES.0.get();
    if !state.adopted {
        trap_invalid_phy_channel_state();
    }

    let channel = phy_mhz2ieee(frequency_mhz);
    let frequency_mhz = phy_chan_to_freq(channel);
    state.current_channel = channel;
    state.init_complete = cbw != 0;
    state.current_cbw = cbw;

    phy_disable_agc();
    phy_bbpll_cal(1);
    phy_tsens_temp_read();
    phy_set_channel_rfpll_freq(frequency_mhz, state.xtal_selector, state.frequency_offset);
    phy_chip_set_chan_misc_new(channel);
    phy_i2c_master_mem_txcap();
    phy_bb_cbw_chan_cfg(cbw);
    if state.channel_14_mic {
        phy_chan14_mic_cfg_new(u32::from(channel == 14));
    }
    // The pinned `phy_11p_set` body only writes these same two values back to
    // `phy_param[0x28..=0x29]`; Rust already owns them after handoff.
    phy_set_rx_comp_new();
    phy_bbpll_cal(0);
    phy_dc_mem_clr();
    phy_enable_agc();
}
