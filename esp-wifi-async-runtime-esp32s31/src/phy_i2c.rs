//! Non-blocking ESP32-S31 PHY-I2C command encoding and RC-calibration plan.
//!
//! The rev0 ROM PHY-I2C leaves busy-wait on bit 25 of the host command
//! register. This module deliberately does not reproduce those loops. It
//! separates command publication from completion observation so an outer
//! Rust async owner can arrange a wakeup and inspect the register once.
//!
//! Reference: `esp32s31_rev0_rom.elf`, SHA-256
//! `a52ad7513deb656a910a5740125f1cce2c7941f11ce57213b7b43aea93d5ab87`.
//! The relevant complete ROM bodies are `phy_chip_i2c_readReg_org` at
//! `0x2f82_9ffa`, `phy_chip_i2c_writeReg` at `0x2f82_a30e`, and
//! `phy_get_rc_dout` at `0x2f82_61ac`. The ELF is an analysis oracle and is
//! not linked into the firmware.

use crate::phy_param::{saturate_phy_value, PHY_PARAM_LEN};
use crate::phy_pbus::{
    PhyPbusClearAction, PhyPbusClearCompletion, PhyPbusClearOutcome, PhyPbusClearTransition,
    PhyPbusForceTest,
};

const PHY_I2C_HOST_CONFIG_ADDRESS: usize = 0x2010_f820;
const PHY_I2C_READ_MASK_ADDRESS: usize = 0x2010_f81c;
const PHY_I2C_COMMAND_BASE_ADDRESS: usize = 0x2010_f800;
const PHY_I2C_MASTER_COMMAND_MEMORY_ADDRESS: usize = 0x2010_fc00;
const MODEM_LPCON_CLK_CONF_ADDRESS: usize = 0x2070_4184;
const MODEM_LPCON_I2C_MST_CLK_CONF_ADDRESS: usize = 0x2070_40f0;
const MODEM_LPCON_I2C_MST_DATE_ADDRESS: usize = 0x2070_4208;
const PHY_I2C_BUSY: u32 = 1 << 25;
const PHY_I2C_READ: u32 = 1 << 30;
const PHY_I2C_WRITE: u32 = 1 << 28 | 1 << 30;
const PHY_I2C_MASTER_COMMAND_COUNT: usize = 45;
const PHY_I2C_SDM_STABLE_VALUE: u8 = 0x5b;
const PHY_I2C_SDM_DEADLINE_CYCLES: u32 = 9_999;

const PHY_I2C_READ_MASKS: [u16; 13] = [
    0x0100, 0x0020, 0x0010, 0x0000, 0x0000, 0x0080, 0x0004, 0x0000, 0x0200, 0x0040, 0x0008, 0x0000,
    0x0400,
];
const PHY_I2C_HOST_ONE_BLOCKS: u16 = 0x0647;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyI2cAddress {
    block: u8,
    register: u8,
}

impl PhyI2cAddress {
    pub const fn new(block: u8, register: u8) -> Option<Self> {
        if block >= 0x61 && block <= 0x6d {
            Some(Self { block, register })
        } else {
            None
        }
    }

    pub const fn block(self) -> u8 {
        self.block
    }

    pub const fn register(self) -> u8 {
        self.register
    }

    pub const fn host(self) -> u8 {
        let index = self.block.wrapping_sub(0x61);
        ((PHY_I2C_HOST_ONE_BLOCKS >> index) & 1) as u8
    }

    pub const fn read_mask(self) -> u16 {
        PHY_I2C_READ_MASKS[self.block.wrapping_sub(0x61) as usize]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyI2cError {
    Busy,
}

const fn command_register_address(host: u8) -> usize {
    PHY_I2C_COMMAND_BASE_ADDRESS + (host as usize * 4)
}

const fn with_phy_i2c_host_config(value: u32) -> u32 {
    (value & 0xffff_e00f) | 0x0000_1a00
}

const fn encode_read(address: PhyI2cAddress) -> u32 {
    PHY_I2C_READ | ((address.register as u32) << 8) | address.block as u32
}

const fn encode_write(address: PhyI2cAddress, value: u8) -> u32 {
    PHY_I2C_WRITE | ((value as u32) << 16) | ((address.register as u32) << 8) | address.block as u32
}

const fn command_is_busy(command: u32) -> bool {
    command & PHY_I2C_BUSY != 0
}

const fn read_result(command: u32) -> u8 {
    (command >> 16) as u8
}

const fn encode_master_command(block: u8, register: u8, value: u8) -> u32 {
    block as u32 | ((register as u32) << 8) | ((value as u32) << 16)
}

// Complete command order recovered from
// `libphy.a[phy_i2c.o]::phy_i2c_master_cmd_mem_init`. Values which depend on
// the explicit PHY parameter image are replaced in `master_command`.
const PHY_I2C_MASTER_TEMPLATE: [(u8, u8, u8); PHY_I2C_MASTER_COMMAND_COUNT] = [
    (0x67, 0x02, 0x07),
    (0x6b, 0x01, 0x01),
    (0x6b, 0x02, 0x73),
    (0x6b, 0x03, 0xba),
    (0x6b, 0x04, 0x88),
    (0x6b, 0x05, 0x01),
    (0x6b, 0x06, 0x11),
    (0x6b, 0x07, 0xfd),
    (0x6b, 0x08, 0xbb),
    (0x6b, 0x09, 0x02),
    (0x6b, 0x0a, 0x08),
    (0x6b, 0x0b, 0x04),
    (0x6b, 0x0c, 0xa7),
    (0x6b, 0x0d, 0x7a),
    (0x6b, 0x0e, 0xf4),
    (0x6b, 0x0f, 0x81),
    (0x62, 0x00, 0x68),
    (0x62, 0x04, 0xa8),
    (0x62, 0x0b, 0x44),
    (0x62, 0x0d, 0x0a),
    (0x62, 0x0f, 0x00),
    (0x62, 0x15, 0x08),
    (0x66, 0x02, 0x70),
    (0x67, 0x02, 0x27),
    (0x67, 0x04, 0x00),
    (0x67, 0x05, 0x00),
    (0x67, 0x06, 0x00),
    (0x67, 0x07, 0x00),
    (0x67, 0x0c, 0x00),
    (0x67, 0x0d, 0x00),
    (0x67, 0x0e, 0x00),
    (0x67, 0x0f, 0x00),
    (0x67, 0x14, 0x00),
    (0x67, 0x15, 0x00),
    (0x67, 0x16, 0x00),
    (0x67, 0x17, 0x00),
    (0x67, 0x18, 0x00),
    (0x67, 0x19, 0x00),
    (0x67, 0x1c, 0x00),
    (0x67, 0x1d, 0x00),
    (0x67, 0x1e, 0x00),
    (0x67, 0x1f, 0x00),
    (0x63, 0x06, 0x00),
    (0x6a, 0x00, 0xaf),
    (0x6a, 0x01, 0x7f),
];

const PHY_I2C_MASTER_DYNAMIC_INDICES: [usize; 19] = [
    20, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
];

fn master_dynamic_values(parameter: &[u8; PHY_PARAM_LEN]) -> [u8; 19] {
    let high_filter = saturate_phy_value(parameter[0xed] as i32 + 6, 0x3c, 2);
    let low_filter = saturate_phy_value(parameter[0xed] as i32 - 2, 0x3c, 2);
    let auxiliary = parameter[0xee].wrapping_add(2);
    [
        parameter[0x18e],
        parameter[0xe9],
        parameter[0xe9],
        parameter[0xea],
        parameter[0xea],
        parameter[0xe9],
        parameter[0xe9],
        parameter[0xea],
        parameter[0xea],
        high_filter,
        high_filter,
        low_filter,
        parameter[0xed],
        auxiliary,
        auxiliary,
        parameter[0xf0],
        parameter[0xf0],
        parameter[0xf0] | 0x40,
        parameter[0xf0],
    ]
}

fn master_command(index: usize, parameter: &[u8; PHY_PARAM_LEN]) -> u32 {
    let (block, register, fixed_value) = PHY_I2C_MASTER_TEMPLATE[index];
    let dynamic_values = master_dynamic_values(parameter);
    let mut cursor = 0;
    let mut value = fixed_value;
    while cursor != PHY_I2C_MASTER_DYNAMIC_INDICES.len() {
        if PHY_I2C_MASTER_DYNAMIC_INDICES[cursor] == index {
            value = dynamic_values[cursor];
            break;
        }
        cursor += 1;
    }
    encode_master_command(block, register, value)
}

/// Reproduce the complete finite vendor initialization of the PHY-I2C master
/// command RAM.
///
/// This is not an I2C transaction: it writes 45 encoded command words to
/// `0x2010_fc00..=0x2010_fcb0`. The reference vendor body is
/// `libphy.a[phy_i2c.o]::phy_i2c_master_cmd_mem_init`, size `0x5be`; its only
/// two ROM callees are the finite encoder at `0x2f82_a81a` and one-store
/// command-memory writer at `0x2f82_a824`.
///
/// Safety: this temporary C ABI boundary requires exclusive cold-PHY
/// ownership. In particular, no other owner may mutate `phy_param` or command
/// memory until the function returns.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn wifi_strict_phy_i2c_master_cmd_mem_init() {
    unsafe extern "C" {
        static mut phy_param: [u8; PHY_PARAM_LEN];
    }

    let parameter = &*core::ptr::addr_of!(phy_param);
    let dynamic_values = master_dynamic_values(parameter);
    let mut index = 0;
    let mut dynamic_cursor = 0;
    while index != PHY_I2C_MASTER_COMMAND_COUNT {
        let (block, register, fixed_value) = PHY_I2C_MASTER_TEMPLATE[index];
        let value = if dynamic_cursor != PHY_I2C_MASTER_DYNAMIC_INDICES.len()
            && *PHY_I2C_MASTER_DYNAMIC_INDICES.get_unchecked(dynamic_cursor) == index
        {
            // The preceding comparison proves `dynamic_cursor < 19`. Keep
            // this explicit so the final cold-init leaf cannot retain even
            // an unreachable panic call (and therefore no indirect `jalr`).
            let value = *dynamic_values.get_unchecked(dynamic_cursor);
            dynamic_cursor += 1;
            value
        } else {
            fixed_value
        };
        let destination = (PHY_I2C_MASTER_COMMAND_MEMORY_ADDRESS
            + index * core::mem::size_of::<u32>()) as *mut u32;
        destination.write_volatile(encode_master_command(block, register, value));
        index += 1;
    }
}

/// Publish one complete-register PHY-I2C read without waiting for completion.
///
/// Unlike the ROM read leaf, this function also rejects an already-busy host
/// before publishing the command. This is a deliberate fail-fast ownership
/// check, not a claim that the ROM performed the same pre-command check.
///
/// Safety: the caller must exclusively own the radio PHY-I2C host and keep
/// that ownership until [`try_finish_read`] succeeds.
#[cfg(target_arch = "riscv32")]
pub unsafe fn try_start_read(address: PhyI2cAddress) -> Result<(), PhyI2cError> {
    let host_config = PHY_I2C_HOST_CONFIG_ADDRESS as *mut u32;
    host_config.write_volatile(with_phy_i2c_host_config(host_config.read_volatile()));

    let command = command_register_address(address.host()) as *mut u32;
    if command_is_busy(command.read_volatile()) {
        return Err(PhyI2cError::Busy);
    }

    (PHY_I2C_READ_MASK_ADDRESS as *mut u32).write_volatile(!(address.read_mask() as u32));
    command.write_volatile(encode_read(address));
    Ok(())
}

/// Observe one previously published PHY-I2C read exactly once.
///
/// The caller may invoke this once after an independently delivered hardware
/// or timer completion edge. `Busy` is then an incomplete/timeout result; it
/// must not be converted into a self-waking retry loop. This function never
/// loops, delays, or schedules itself.
///
/// Safety: `address` must name the in-flight command started by
/// [`try_start_read`] under the same exclusive radio ownership.
#[cfg(target_arch = "riscv32")]
pub unsafe fn try_finish_read(address: PhyI2cAddress) -> Result<u8, PhyI2cError> {
    let command = (command_register_address(address.host()) as *const u32).read_volatile();
    if command_is_busy(command) {
        Err(PhyI2cError::Busy)
    } else {
        Ok(read_result(command))
    }
}

/// Publish one complete-register PHY-I2C write after observing the
/// pre-command busy state once. It never waits or loops on that state and
/// leaves post-command completion to [`try_finish_write`].
///
/// Safety: the caller must exclusively own the radio PHY-I2C host and keep
/// that ownership until [`try_finish_write`] succeeds.
#[cfg(target_arch = "riscv32")]
pub unsafe fn try_start_write(address: PhyI2cAddress, value: u8) -> Result<(), PhyI2cError> {
    let host_config = PHY_I2C_HOST_CONFIG_ADDRESS as *mut u32;
    host_config.write_volatile(with_phy_i2c_host_config(host_config.read_volatile()));

    let command = command_register_address(address.host()) as *mut u32;
    if command_is_busy(command.read_volatile()) {
        return Err(PhyI2cError::Busy);
    }
    command.write_volatile(encode_write(address, value));
    Ok(())
}

/// Observe one previously published PHY-I2C write exactly once.
///
/// The caller may invoke this once after an independently delivered hardware
/// or timer completion edge. `Busy` is an incomplete/timeout result and must
/// not be converted into a self-waking retry loop.
///
/// Safety: `address` must name the in-flight command started by
/// [`try_start_write`] under the same exclusive radio ownership.
#[cfg(target_arch = "riscv32")]
pub unsafe fn try_finish_write(address: PhyI2cAddress) -> Result<(), PhyI2cError> {
    let command = (command_register_address(address.host()) as *const u32).read_volatile();
    if command_is_busy(command) {
        Err(PhyI2cError::Busy)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BiasRegAction {
    Write { address: PhyI2cAddress, value: u8 },
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BiasRegCompletion {
    WriteCompleted { address: PhyI2cAddress },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BiasRegTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

/// Event-driven replacement plan for
/// `libphy.a[phy_i2c.o]::phy_bias_reg_set`.
///
/// The complete 48-byte vendor body ignores its argument and performs two
/// synchronous `phy_i2c_writeReg` calls. This transition retains the exact
/// `(block, register, value)` order but requires a separate completion edge
/// for each write. It owns no timer, waker, allocation, or hidden state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BiasRegTransition {
    step: u8,
}

impl BiasRegTransition {
    pub const fn new(_requested_state: bool) -> Self {
        Self { step: 0 }
    }

    pub const fn action(self) -> BiasRegAction {
        match self.step {
            0 => BiasRegAction::Write {
                address: PhyI2cAddress {
                    block: 0x6a,
                    register: 0,
                },
                value: 0xaf,
            },
            1 => BiasRegAction::Write {
                address: PhyI2cAddress {
                    block: 0x6a,
                    register: 1,
                },
                value: 0x7f,
            },
            _ => BiasRegAction::Complete,
        }
    }

    pub fn advance(&mut self, completion: BiasRegCompletion) -> Result<(), BiasRegTransitionError> {
        let BiasRegCompletion::WriteCompleted { address } = completion;
        match self.action() {
            BiasRegAction::Write {
                address: expected, ..
            } if address == expected => {
                self.step += 1;
                Ok(())
            }
            BiasRegAction::Write { .. } => Err(BiasRegTransitionError::WrongCompletion),
            BiasRegAction::Complete => Err(BiasRegTransitionError::AlreadyComplete),
        }
    }
}

/// Execute the finite register prefix which precedes the vendor
/// `ets_delay_us(100)` call in `phy_open_i2c_xpd_new(true)`.
///
/// This leaf deliberately stops before the delay. Unknown register-field
/// meanings are not inferred: it reproduces the complete pinned
/// `libphy.a[phy_reg.o]` load/mask/store sequence at offsets `0x2e..0x4e`.
///
/// Safety: the caller must exclusively own cold PHY initialization and the
/// MODEM_LPCON register block.
#[cfg(target_arch = "riscv32")]
pub unsafe fn configure_open_i2c_pre_delay() {
    let clock = MODEM_LPCON_CLK_CONF_ADDRESS as *mut u32;
    clock.write_volatile(clock.read_volatile() & 0x0000_ffff);

    let i2c_clock = MODEM_LPCON_I2C_MST_CLK_CONF_ADDRESS as *mut u32;
    i2c_clock.write_volatile(i2c_clock.read_volatile() & 0xefff_ffff);
}

/// Execute the finite common register suffix of `phy_open_i2c_xpd_new`.
///
/// The bit-31 clear/set edge is preserved when bit 30 was initially clear;
/// reducing the sequence to one final OR would lose an instruction-evidenced
/// hardware transition. This function never delays, waits, loops or calls.
///
/// Safety: the caller must exclusively own cold PHY initialization and the
/// MODEM_LPCON register block.
#[cfg(target_arch = "riscv32")]
pub unsafe fn configure_open_i2c_power_and_pulse() {
    let clock = MODEM_LPCON_CLK_CONF_ADDRESS as *mut u32;
    clock.write_volatile(clock.read_volatile() | 0xffff_0000);

    let i2c_clock = MODEM_LPCON_I2C_MST_CLK_CONF_ADDRESS as *mut u32;
    i2c_clock.write_volatile(i2c_clock.read_volatile() | 0x1000_0000);

    let control = MODEM_LPCON_I2C_MST_DATE_ADDRESS as *mut u32;
    if control.read_volatile() & (1 << 30) == 0 {
        control.write_volatile(control.read_volatile() | (1 << 30));
        control.write_volatile(control.read_volatile() & !(1 << 31));
        control.write_volatile(control.read_volatile() | (1 << 31));
    }
    if control.read_volatile() & (1 << 31) == 0 {
        control.write_volatile(control.read_volatile() | (1 << 31));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenI2cXpdOutcome {
    Stable,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenI2cXpdAction {
    ConfigurePreDelay,
    DelayMicros(u32),
    ConfigurePowerAndPulse,
    CheckSdmDeadline { maximum_cycles: u32 },
    ReadSdmSample { address: PhyI2cAddress },
    Complete(OpenI2cXpdOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenI2cXpdCompletion {
    PreDelayConfigured,
    DelayElapsed,
    PowerAndPulseConfigured,
    DeadlineObserved { expired: bool },
    SdmSample(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenI2cXpdTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenI2cXpdStep {
    PreDelayConfiguration,
    Delay,
    PowerAndPulseConfiguration,
    DeadlineCheck,
    SdmSample,
    Complete(OpenI2cXpdOutcome),
}

/// Event-driven replacement plan for `phy_open_i2c_xpd_new` and ROM
/// `phy_wait_i2c_sdm_stable`.
///
/// The vendor path contains one synchronous 100-microsecond delay and then a
/// cycle-counter/I2C polling loop. Here the delay, deadline observation and
/// every I2C sample are explicit completions delivered by the outer async
/// radio owner. A mismatching SDM value returns to `CheckSdmDeadline`; it does
/// not self-wake or read again from `poll`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenI2cXpdTransition {
    step: OpenI2cXpdStep,
    samples: u16,
}

impl OpenI2cXpdTransition {
    pub const fn new(with_pre_delay: bool) -> Self {
        Self {
            step: if with_pre_delay {
                OpenI2cXpdStep::PreDelayConfiguration
            } else {
                OpenI2cXpdStep::PowerAndPulseConfiguration
            },
            samples: 0,
        }
    }

    pub const fn action(self) -> OpenI2cXpdAction {
        const SDM_SAMPLE: PhyI2cAddress = PhyI2cAddress {
            block: 0x63,
            register: 0,
        };

        match self.step {
            OpenI2cXpdStep::PreDelayConfiguration => OpenI2cXpdAction::ConfigurePreDelay,
            OpenI2cXpdStep::Delay => OpenI2cXpdAction::DelayMicros(100),
            OpenI2cXpdStep::PowerAndPulseConfiguration => OpenI2cXpdAction::ConfigurePowerAndPulse,
            OpenI2cXpdStep::DeadlineCheck => OpenI2cXpdAction::CheckSdmDeadline {
                maximum_cycles: PHY_I2C_SDM_DEADLINE_CYCLES,
            },
            OpenI2cXpdStep::SdmSample => OpenI2cXpdAction::ReadSdmSample {
                address: SDM_SAMPLE,
            },
            OpenI2cXpdStep::Complete(outcome) => OpenI2cXpdAction::Complete(outcome),
        }
    }

    pub const fn samples(self) -> u16 {
        self.samples
    }

    pub fn advance(
        &mut self,
        completion: OpenI2cXpdCompletion,
    ) -> Result<(), OpenI2cXpdTransitionError> {
        self.step = match (self.step, completion) {
            (OpenI2cXpdStep::PreDelayConfiguration, OpenI2cXpdCompletion::PreDelayConfigured) => {
                OpenI2cXpdStep::Delay
            }
            (OpenI2cXpdStep::Delay, OpenI2cXpdCompletion::DelayElapsed) => {
                OpenI2cXpdStep::PowerAndPulseConfiguration
            }
            (
                OpenI2cXpdStep::PowerAndPulseConfiguration,
                OpenI2cXpdCompletion::PowerAndPulseConfigured,
            ) => OpenI2cXpdStep::DeadlineCheck,
            (
                OpenI2cXpdStep::DeadlineCheck,
                OpenI2cXpdCompletion::DeadlineObserved { expired: true },
            ) => OpenI2cXpdStep::Complete(OpenI2cXpdOutcome::TimedOut),
            (
                OpenI2cXpdStep::DeadlineCheck,
                OpenI2cXpdCompletion::DeadlineObserved { expired: false },
            ) => OpenI2cXpdStep::SdmSample,
            (OpenI2cXpdStep::SdmSample, OpenI2cXpdCompletion::SdmSample(value)) => {
                self.samples = self.samples.saturating_add(1);
                if value == PHY_I2C_SDM_STABLE_VALUE {
                    OpenI2cXpdStep::Complete(OpenI2cXpdOutcome::Stable)
                } else {
                    OpenI2cXpdStep::DeadlineCheck
                }
            }
            (OpenI2cXpdStep::Complete(_), _) => {
                return Err(OpenI2cXpdTransitionError::AlreadyComplete);
            }
            _ => return Err(OpenI2cXpdTransitionError::WrongCompletion),
        };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum I2cBbpllOutcome {
    Enabled { register_snapshot: u8 },
    Restored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum I2cBbpllAction {
    ReadMaskedByte { address: PhyI2cAddress },
    WriteByte { address: PhyI2cAddress, value: u8 },
    ReadSnapshot { address: PhyI2cAddress },
    Complete(I2cBbpllOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum I2cBbpllCompletion {
    I2cReadCompleted { address: PhyI2cAddress, value: u8 },
    I2cWriteCompleted { address: PhyI2cAddress },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum I2cBbpllTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum I2cBbpllStep {
    ReadMaskedByte,
    WriteEnabledByte(u8),
    ReadSnapshot,
    WriteRestoredByte(u8),
    Complete(I2cBbpllOutcome),
}

/// Owned replacement for complete rev0 ROM `phy_i2c_bbpll_set`.
///
/// Enabling performs a masked read/modify/write of bits 3:2 in PHY-I2C
/// register `(0x66, 4)`, reads the resulting byte again, and returns that byte
/// as explicit Rust-owned state. ROM stored it through the mutable
/// `phy_param` indirection at offset `0x4a`. Restoring accepts that byte as an
/// input instead of reading global C state. Every I2C edge is an external
/// completion; the transition never polls or retries itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct I2cBbpllTransition {
    step: I2cBbpllStep,
}

impl I2cBbpllTransition {
    const ADDRESS: PhyI2cAddress = PhyI2cAddress {
        block: 0x66,
        register: 4,
    };

    pub const fn enable() -> Self {
        Self {
            step: I2cBbpllStep::ReadMaskedByte,
        }
    }

    pub const fn restore(register_snapshot: u8) -> Self {
        Self {
            step: I2cBbpllStep::WriteRestoredByte(register_snapshot),
        }
    }

    pub const fn action(self) -> I2cBbpllAction {
        match self.step {
            I2cBbpllStep::ReadMaskedByte => I2cBbpllAction::ReadMaskedByte {
                address: Self::ADDRESS,
            },
            I2cBbpllStep::WriteEnabledByte(value) | I2cBbpllStep::WriteRestoredByte(value) => {
                I2cBbpllAction::WriteByte {
                    address: Self::ADDRESS,
                    value,
                }
            }
            I2cBbpllStep::ReadSnapshot => I2cBbpllAction::ReadSnapshot {
                address: Self::ADDRESS,
            },
            I2cBbpllStep::Complete(outcome) => I2cBbpllAction::Complete(outcome),
        }
    }

    pub fn advance(
        &mut self,
        completion: I2cBbpllCompletion,
    ) -> Result<(), I2cBbpllTransitionError> {
        self.step = match (self.step, completion) {
            (
                I2cBbpllStep::ReadMaskedByte,
                I2cBbpllCompletion::I2cReadCompleted { address, value },
            ) if address == Self::ADDRESS => I2cBbpllStep::WriteEnabledByte(value & !0x0c),
            (
                I2cBbpllStep::WriteEnabledByte(_),
                I2cBbpllCompletion::I2cWriteCompleted { address },
            ) if address == Self::ADDRESS => I2cBbpllStep::ReadSnapshot,
            (
                I2cBbpllStep::ReadSnapshot,
                I2cBbpllCompletion::I2cReadCompleted { address, value },
            ) if address == Self::ADDRESS => I2cBbpllStep::Complete(I2cBbpllOutcome::Enabled {
                register_snapshot: value,
            }),
            (
                I2cBbpllStep::WriteRestoredByte(_),
                I2cBbpllCompletion::I2cWriteCompleted { address },
            ) if address == Self::ADDRESS => I2cBbpllStep::Complete(I2cBbpllOutcome::Restored),
            (I2cBbpllStep::Complete(_), _) => {
                return Err(I2cBbpllTransitionError::AlreadyComplete);
            }
            _ => return Err(I2cBbpllTransitionError::WrongCompletion),
        };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdcRateAction {
    ReadI2c { address: PhyI2cAddress },
    WriteI2c { address: PhyI2cAddress, value: u8 },
    ConfigureMmio { rate: u32 },
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdcRateCompletion {
    I2cReadCompleted { address: PhyI2cAddress, value: u8 },
    I2cWriteCompleted { address: PhyI2cAddress },
    MmioConfigured,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdcRateTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdcRateStep {
    ReadI2c,
    WriteI2c(u8),
    ConfigureMmio,
    Complete,
}

/// Event-driven replacement for complete rev0 ROM `phy_adc_rate_set`.
///
/// ROM uses `phy_i2c_writeReg_Mask(0x66, 0, 4, 3, 2, !rate * 2)`,
/// whose nested read and write both busy-wait. Rust owns those as two
/// separately completed PHY-I2C transactions, then emits the finite two-write
/// MMIO suffix. No action polls or repeats itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdcRateTransition {
    step: AdcRateStep,
    rate: bool,
}

impl AdcRateTransition {
    const ADDRESS: PhyI2cAddress = PhyI2cAddress {
        block: 0x66,
        register: 4,
    };

    pub const fn new(rate: bool) -> Self {
        Self {
            step: AdcRateStep::ReadI2c,
            rate,
        }
    }

    pub const fn action(self) -> AdcRateAction {
        match self.step {
            AdcRateStep::ReadI2c => AdcRateAction::ReadI2c {
                address: Self::ADDRESS,
            },
            AdcRateStep::WriteI2c(value) => AdcRateAction::WriteI2c {
                address: Self::ADDRESS,
                value,
            },
            AdcRateStep::ConfigureMmio => AdcRateAction::ConfigureMmio {
                rate: self.rate as u32,
            },
            AdcRateStep::Complete => AdcRateAction::Complete,
        }
    }

    pub fn advance(&mut self, completion: AdcRateCompletion) -> Result<(), AdcRateTransitionError> {
        self.step = match (self.step, completion) {
            (AdcRateStep::ReadI2c, AdcRateCompletion::I2cReadCompleted { address, value })
                if address == Self::ADDRESS =>
            {
                let field = if self.rate { 0 } else { 0x08 };
                AdcRateStep::WriteI2c((value & !0x0c) | field)
            }
            (AdcRateStep::WriteI2c(_), AdcRateCompletion::I2cWriteCompleted { address })
                if address == Self::ADDRESS =>
            {
                AdcRateStep::ConfigureMmio
            }
            (AdcRateStep::ConfigureMmio, AdcRateCompletion::MmioConfigured) => {
                AdcRateStep::Complete
            }
            (AdcRateStep::Complete, _) => return Err(AdcRateTransitionError::AlreadyComplete),
            _ => return Err(AdcRateTransitionError::WrongCompletion),
        };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyRfInitPrefixOutcome {
    ReadyForFrontEndRegisterInit { bbpll_register_snapshot: u8 },
    SdmTimedOut,
    PbusForceTestTimedOut(PhyPbusForceTest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyRfInitPrefixAction {
    ConfigureFeBbClock,
    ConfigureBbpllCalibration { enabled: bool },
    Bias(BiasRegAction),
    OpenI2cXpd(OpenI2cXpdAction),
    PbusClear(PhyPbusClearAction),
    ConfigureI2cClockSelection { selection: u32 },
    I2cBbpll(I2cBbpllAction),
    AdcRate(AdcRateAction),
    ConfigureI2cMasterRegisters,
    ConfigurePowerDetectorRegisters,
    DelayMicros(u32),
    Complete(PhyRfInitPrefixOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyRfInitPrefixCompletion {
    FeBbClockConfigured,
    BbpllCalibrationConfigured,
    Bias(BiasRegCompletion),
    OpenI2cXpd(OpenI2cXpdCompletion),
    PbusClear(PhyPbusClearCompletion),
    I2cClockSelectionConfigured,
    I2cBbpll(I2cBbpllCompletion),
    AdcRate(AdcRateCompletion),
    I2cMasterRegistersConfigured,
    PowerDetectorRegistersConfigured,
    DelayElapsed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyRfInitPrefixTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhyRfInitPrefixStep {
    FeBbClock,
    BbpllCalibration,
    Bias(BiasRegTransition),
    OpenI2cXpd(OpenI2cXpdTransition),
    PostI2cDelay,
    PbusClear(PhyPbusClearTransition),
    I2cClockSelection,
    I2cBbpll(I2cBbpllTransition),
    AdcRate {
        transition: AdcRateTransition,
        bbpll_register_snapshot: u8,
    },
    I2cMasterRegisters {
        bbpll_register_snapshot: u8,
    },
    PowerDetectorRegisters {
        bbpll_register_snapshot: u8,
    },
    Complete(PhyRfInitPrefixOutcome),
}

/// Event-driven composition of operations one through eleven in the complete
/// pinned `libphy.a[phy_init.o]::phy_rf_init` body.
///
/// The two MMIO leaves are finite actions. Both bias writes and every SDM
/// sample require an external PHY-I2C completion. The 100- and 10-microsecond
/// intervals are separate executor timer edges. No transition is caused by
/// polling this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyRfInitPrefixTransition {
    step: PhyRfInitPrefixStep,
}

impl PhyRfInitPrefixTransition {
    pub const fn new() -> Self {
        Self {
            step: PhyRfInitPrefixStep::FeBbClock,
        }
    }

    pub const fn action(self) -> PhyRfInitPrefixAction {
        match self.step {
            PhyRfInitPrefixStep::FeBbClock => PhyRfInitPrefixAction::ConfigureFeBbClock,
            PhyRfInitPrefixStep::BbpllCalibration => {
                PhyRfInitPrefixAction::ConfigureBbpllCalibration { enabled: true }
            }
            PhyRfInitPrefixStep::Bias(transition) => match transition.action() {
                BiasRegAction::Complete => {
                    PhyRfInitPrefixAction::OpenI2cXpd(OpenI2cXpdAction::ConfigurePreDelay)
                }
                action => PhyRfInitPrefixAction::Bias(action),
            },
            PhyRfInitPrefixStep::OpenI2cXpd(transition) => match transition.action() {
                OpenI2cXpdAction::Complete(OpenI2cXpdOutcome::Stable) => {
                    PhyRfInitPrefixAction::DelayMicros(10)
                }
                OpenI2cXpdAction::Complete(OpenI2cXpdOutcome::TimedOut) => {
                    PhyRfInitPrefixAction::Complete(PhyRfInitPrefixOutcome::SdmTimedOut)
                }
                action => PhyRfInitPrefixAction::OpenI2cXpd(action),
            },
            PhyRfInitPrefixStep::PostI2cDelay => PhyRfInitPrefixAction::DelayMicros(10),
            PhyRfInitPrefixStep::PbusClear(transition) => match transition.action() {
                PhyPbusClearAction::Complete(PhyPbusClearOutcome::Cleared) => {
                    PhyRfInitPrefixAction::ConfigureI2cClockSelection { selection: 8 }
                }
                PhyPbusClearAction::Complete(PhyPbusClearOutcome::ForceTestTimedOut(
                    transaction,
                )) => PhyRfInitPrefixAction::Complete(
                    PhyRfInitPrefixOutcome::PbusForceTestTimedOut(transaction),
                ),
                action => PhyRfInitPrefixAction::PbusClear(action),
            },
            PhyRfInitPrefixStep::I2cClockSelection => {
                PhyRfInitPrefixAction::ConfigureI2cClockSelection { selection: 8 }
            }
            PhyRfInitPrefixStep::I2cBbpll(transition) => {
                PhyRfInitPrefixAction::I2cBbpll(transition.action())
            }
            PhyRfInitPrefixStep::AdcRate { transition, .. } => match transition.action() {
                AdcRateAction::Complete => PhyRfInitPrefixAction::ConfigureI2cMasterRegisters,
                action => PhyRfInitPrefixAction::AdcRate(action),
            },
            PhyRfInitPrefixStep::I2cMasterRegisters { .. } => {
                PhyRfInitPrefixAction::ConfigureI2cMasterRegisters
            }
            PhyRfInitPrefixStep::PowerDetectorRegisters { .. } => {
                PhyRfInitPrefixAction::ConfigurePowerDetectorRegisters
            }
            PhyRfInitPrefixStep::Complete(outcome) => PhyRfInitPrefixAction::Complete(outcome),
        }
    }

    pub fn advance(
        &mut self,
        completion: PhyRfInitPrefixCompletion,
    ) -> Result<(), PhyRfInitPrefixTransitionError> {
        self.step = match (self.step, completion) {
            (PhyRfInitPrefixStep::FeBbClock, PhyRfInitPrefixCompletion::FeBbClockConfigured) => {
                PhyRfInitPrefixStep::BbpllCalibration
            }
            (
                PhyRfInitPrefixStep::BbpllCalibration,
                PhyRfInitPrefixCompletion::BbpllCalibrationConfigured,
            ) => PhyRfInitPrefixStep::Bias(BiasRegTransition::new(true)),
            (
                PhyRfInitPrefixStep::Bias(mut transition),
                PhyRfInitPrefixCompletion::Bias(completion),
            ) => {
                transition
                    .advance(completion)
                    .map_err(|_| PhyRfInitPrefixTransitionError::WrongCompletion)?;
                if transition.action() == BiasRegAction::Complete {
                    PhyRfInitPrefixStep::OpenI2cXpd(OpenI2cXpdTransition::new(true))
                } else {
                    PhyRfInitPrefixStep::Bias(transition)
                }
            }
            (
                PhyRfInitPrefixStep::OpenI2cXpd(mut transition),
                PhyRfInitPrefixCompletion::OpenI2cXpd(completion),
            ) => {
                transition
                    .advance(completion)
                    .map_err(|_| PhyRfInitPrefixTransitionError::WrongCompletion)?;
                match transition.action() {
                    OpenI2cXpdAction::Complete(OpenI2cXpdOutcome::Stable) => {
                        PhyRfInitPrefixStep::PostI2cDelay
                    }
                    OpenI2cXpdAction::Complete(OpenI2cXpdOutcome::TimedOut) => {
                        PhyRfInitPrefixStep::Complete(PhyRfInitPrefixOutcome::SdmTimedOut)
                    }
                    _ => PhyRfInitPrefixStep::OpenI2cXpd(transition),
                }
            }
            (PhyRfInitPrefixStep::PostI2cDelay, PhyRfInitPrefixCompletion::DelayElapsed) => {
                PhyRfInitPrefixStep::PbusClear(PhyPbusClearTransition::new())
            }
            (
                PhyRfInitPrefixStep::PbusClear(mut transition),
                PhyRfInitPrefixCompletion::PbusClear(completion),
            ) => {
                transition
                    .advance(completion)
                    .map_err(|_| PhyRfInitPrefixTransitionError::WrongCompletion)?;
                match transition.action() {
                    PhyPbusClearAction::Complete(PhyPbusClearOutcome::Cleared) => {
                        PhyRfInitPrefixStep::I2cClockSelection
                    }
                    PhyPbusClearAction::Complete(PhyPbusClearOutcome::ForceTestTimedOut(
                        transaction,
                    )) => PhyRfInitPrefixStep::Complete(
                        PhyRfInitPrefixOutcome::PbusForceTestTimedOut(transaction),
                    ),
                    _ => PhyRfInitPrefixStep::PbusClear(transition),
                }
            }
            (
                PhyRfInitPrefixStep::I2cClockSelection,
                PhyRfInitPrefixCompletion::I2cClockSelectionConfigured,
            ) => PhyRfInitPrefixStep::I2cBbpll(I2cBbpllTransition::enable()),
            (
                PhyRfInitPrefixStep::I2cBbpll(mut transition),
                PhyRfInitPrefixCompletion::I2cBbpll(completion),
            ) => {
                transition
                    .advance(completion)
                    .map_err(|_| PhyRfInitPrefixTransitionError::WrongCompletion)?;
                match transition.action() {
                    I2cBbpllAction::Complete(I2cBbpllOutcome::Enabled { register_snapshot }) => {
                        PhyRfInitPrefixStep::AdcRate {
                            transition: AdcRateTransition::new(true),
                            bbpll_register_snapshot: register_snapshot,
                        }
                    }
                    I2cBbpllAction::Complete(I2cBbpllOutcome::Restored) => {
                        return Err(PhyRfInitPrefixTransitionError::WrongCompletion);
                    }
                    _ => PhyRfInitPrefixStep::I2cBbpll(transition),
                }
            }
            (
                PhyRfInitPrefixStep::AdcRate {
                    mut transition,
                    bbpll_register_snapshot,
                },
                PhyRfInitPrefixCompletion::AdcRate(completion),
            ) => {
                transition
                    .advance(completion)
                    .map_err(|_| PhyRfInitPrefixTransitionError::WrongCompletion)?;
                if transition.action() == AdcRateAction::Complete {
                    PhyRfInitPrefixStep::I2cMasterRegisters {
                        bbpll_register_snapshot,
                    }
                } else {
                    PhyRfInitPrefixStep::AdcRate {
                        transition,
                        bbpll_register_snapshot,
                    }
                }
            }
            (
                PhyRfInitPrefixStep::I2cMasterRegisters {
                    bbpll_register_snapshot,
                },
                PhyRfInitPrefixCompletion::I2cMasterRegistersConfigured,
            ) => PhyRfInitPrefixStep::PowerDetectorRegisters {
                bbpll_register_snapshot,
            },
            (
                PhyRfInitPrefixStep::PowerDetectorRegisters {
                    bbpll_register_snapshot,
                },
                PhyRfInitPrefixCompletion::PowerDetectorRegistersConfigured,
            ) => PhyRfInitPrefixStep::Complete(
                PhyRfInitPrefixOutcome::ReadyForFrontEndRegisterInit {
                    bbpll_register_snapshot,
                },
            ),
            (PhyRfInitPrefixStep::Complete(_), _) => {
                return Err(PhyRfInitPrefixTransitionError::AlreadyComplete);
            }
            _ => return Err(PhyRfInitPrefixTransitionError::WrongCompletion),
        };
        Ok(())
    }
}

impl Default for PhyRfInitPrefixTransition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RcCalibrationAction {
    WriteMasked {
        address: PhyI2cAddress,
        high_bit: u8,
        low_bit: u8,
        value: u8,
    },
    DelayMicros(u32),
    ReadMasked {
        address: PhyI2cAddress,
        high_bit: u8,
        low_bit: u8,
    },
    ApplyResult(u8),
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RcCalibrationCompletion {
    Write,
    Delay,
    Read(u8),
    Applied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RcCalibrationTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

/// Exact finite action plan recovered from ROM `phy_get_rc_dout`.
///
/// The owner executes each I2C action through a non-blocking transaction and
/// implements `DelayMicros(100)` with its Rust async timer. No action advances
/// merely because the future was polled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RcCalibrationTransition {
    step: u8,
    result: u8,
}

impl RcCalibrationTransition {
    pub const fn new() -> Self {
        Self { step: 0, result: 0 }
    }

    pub const fn action(self) -> RcCalibrationAction {
        const BLOCK_61_REG_8: PhyI2cAddress = PhyI2cAddress {
            block: 0x61,
            register: 8,
        };
        const BLOCK_6B_REG_13: PhyI2cAddress = PhyI2cAddress {
            block: 0x6b,
            register: 0x13,
        };
        const BLOCK_6B_REG_14: PhyI2cAddress = PhyI2cAddress {
            block: 0x6b,
            register: 0x14,
        };

        match self.step {
            0 => RcCalibrationAction::WriteMasked {
                address: BLOCK_61_REG_8,
                high_bit: 2,
                low_bit: 2,
                value: 1,
            },
            1 => RcCalibrationAction::WriteMasked {
                address: BLOCK_6B_REG_13,
                high_bit: 0,
                low_bit: 0,
                value: 0,
            },
            2 => RcCalibrationAction::WriteMasked {
                address: BLOCK_6B_REG_13,
                high_bit: 1,
                low_bit: 1,
                value: 0,
            },
            3 => RcCalibrationAction::WriteMasked {
                address: BLOCK_6B_REG_13,
                high_bit: 1,
                low_bit: 1,
                value: 1,
            },
            4 => RcCalibrationAction::DelayMicros(100),
            5 => RcCalibrationAction::ReadMasked {
                address: BLOCK_6B_REG_14,
                high_bit: 5,
                low_bit: 0,
            },
            6 => RcCalibrationAction::WriteMasked {
                address: BLOCK_61_REG_8,
                high_bit: 2,
                low_bit: 2,
                value: 0,
            },
            7 => RcCalibrationAction::WriteMasked {
                address: BLOCK_6B_REG_13,
                high_bit: 0,
                low_bit: 0,
                value: 0,
            },
            8 => RcCalibrationAction::ApplyResult(self.result),
            _ => RcCalibrationAction::Complete,
        }
    }

    pub fn advance(
        &mut self,
        completion: RcCalibrationCompletion,
    ) -> Result<(), RcCalibrationTransitionError> {
        let matches = matches!(
            (self.action(), completion),
            (
                RcCalibrationAction::WriteMasked { .. },
                RcCalibrationCompletion::Write
            ) | (
                RcCalibrationAction::DelayMicros(_),
                RcCalibrationCompletion::Delay
            ) | (
                RcCalibrationAction::ReadMasked { .. },
                RcCalibrationCompletion::Read(_)
            ) | (
                RcCalibrationAction::ApplyResult(_),
                RcCalibrationCompletion::Applied
            )
        );
        if !matches {
            return if self.action() == RcCalibrationAction::Complete {
                Err(RcCalibrationTransitionError::AlreadyComplete)
            } else {
                Err(RcCalibrationTransitionError::WrongCompletion)
            };
        }
        if let RcCalibrationCompletion::Read(value) = completion {
            self.result = value;
        }
        self.step += 1;
        Ok(())
    }
}

impl Default for RcCalibrationTransition {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        command_is_busy, command_register_address, encode_read, encode_write, master_command,
        read_result, with_phy_i2c_host_config, AdcRateAction, AdcRateCompletion, AdcRateTransition,
        AdcRateTransitionError, BiasRegAction, BiasRegCompletion, BiasRegTransition,
        BiasRegTransitionError, I2cBbpllAction, I2cBbpllCompletion, I2cBbpllOutcome,
        I2cBbpllTransition, I2cBbpllTransitionError, OpenI2cXpdAction, OpenI2cXpdCompletion,
        OpenI2cXpdOutcome, OpenI2cXpdTransition, OpenI2cXpdTransitionError, PhyI2cAddress,
        PhyRfInitPrefixAction, PhyRfInitPrefixCompletion, PhyRfInitPrefixOutcome,
        PhyRfInitPrefixTransition, PhyRfInitPrefixTransitionError, RcCalibrationAction,
        RcCalibrationCompletion, RcCalibrationTransition, RcCalibrationTransitionError,
        PHY_I2C_MASTER_COMMAND_COUNT,
    };
    use crate::phy_param::PHY_PARAM_LEN;
    use crate::phy_pbus::{PhyPbusClearAction, PhyPbusClearCompletion, PhyPbusForceTest};

    #[test]
    fn recovered_block_table_selects_exact_hosts_and_read_masks() {
        let expected = [
            (0x61, 1, 0x100),
            (0x62, 1, 0x020),
            (0x63, 1, 0x010),
            (0x64, 0, 0x000),
            (0x65, 0, 0x000),
            (0x66, 0, 0x080),
            (0x67, 1, 0x004),
            (0x68, 0, 0x000),
            (0x69, 0, 0x200),
            (0x6a, 1, 0x040),
            (0x6b, 1, 0x008),
            (0x6c, 0, 0x000),
            (0x6d, 0, 0x400),
        ];
        for (block, host, mask) in expected {
            let address = PhyI2cAddress::new(block, 0x12).unwrap();
            assert_eq!(address.host(), host);
            assert_eq!(address.read_mask(), mask);
        }
        assert!(PhyI2cAddress::new(0x60, 0).is_none());
        assert!(PhyI2cAddress::new(0x6e, 0).is_none());
    }

    #[test]
    fn command_words_match_complete_rom_leaf_encoding() {
        let address = PhyI2cAddress::new(0x6b, 0x14).unwrap();
        assert_eq!(command_register_address(address.host()), 0x2010_f804);
        assert_eq!(encode_read(address), 0x4000_146b);
        assert_eq!(encode_write(address, 0xa5), 0x50a5_146b);
        assert!(!command_is_busy(0x50a5_146b));
        assert!(command_is_busy(0x52a5_146b));
        assert_eq!(read_result(0x403c_146b), 0x3c);
        assert_eq!(with_phy_i2c_host_config(0xffff_ffff), 0xffff_fa0f);
        assert_eq!(with_phy_i2c_host_config(0), 0x1a00);
    }

    #[test]
    fn master_command_table_matches_complete_vendor_body() {
        let mut parameter = [0_u8; PHY_PARAM_LEN];
        parameter[0x18e] = 0x55;
        parameter[0xe9] = 0x12;
        parameter[0xea] = 0x34;
        parameter[0xed] = 0x20;
        parameter[0xee] = 0xfe;
        parameter[0xf0] = 0x9a;

        let expected = [
            (0x67, 0x02, 0x07),
            (0x6b, 0x01, 0x01),
            (0x6b, 0x02, 0x73),
            (0x6b, 0x03, 0xba),
            (0x6b, 0x04, 0x88),
            (0x6b, 0x05, 0x01),
            (0x6b, 0x06, 0x11),
            (0x6b, 0x07, 0xfd),
            (0x6b, 0x08, 0xbb),
            (0x6b, 0x09, 0x02),
            (0x6b, 0x0a, 0x08),
            (0x6b, 0x0b, 0x04),
            (0x6b, 0x0c, 0xa7),
            (0x6b, 0x0d, 0x7a),
            (0x6b, 0x0e, 0xf4),
            (0x6b, 0x0f, 0x81),
            (0x62, 0x00, 0x68),
            (0x62, 0x04, 0xa8),
            (0x62, 0x0b, 0x44),
            (0x62, 0x0d, 0x0a),
            (0x62, 0x0f, 0x55),
            (0x62, 0x15, 0x08),
            (0x66, 0x02, 0x70),
            (0x67, 0x02, 0x27),
            (0x67, 0x04, 0x12),
            (0x67, 0x05, 0x12),
            (0x67, 0x06, 0x34),
            (0x67, 0x07, 0x34),
            (0x67, 0x0c, 0x12),
            (0x67, 0x0d, 0x12),
            (0x67, 0x0e, 0x34),
            (0x67, 0x0f, 0x34),
            (0x67, 0x14, 0x26),
            (0x67, 0x15, 0x26),
            (0x67, 0x16, 0x1e),
            (0x67, 0x17, 0x20),
            (0x67, 0x18, 0x00),
            (0x67, 0x19, 0x00),
            (0x67, 0x1c, 0x9a),
            (0x67, 0x1d, 0x9a),
            (0x67, 0x1e, 0xda),
            (0x67, 0x1f, 0x9a),
            (0x63, 0x06, 0x00),
            (0x6a, 0x00, 0xaf),
            (0x6a, 0x01, 0x7f),
        ];
        assert_eq!(expected.len(), PHY_I2C_MASTER_COMMAND_COUNT);
        for (index, (block, register, value)) in expected.into_iter().enumerate() {
            assert_eq!(
                master_command(index, &parameter),
                (block as u32) | ((register as u32) << 8) | ((value as u32) << 16),
                "master command {index}"
            );
        }
    }

    #[test]
    fn rc_calibration_plan_has_only_explicit_async_edges() {
        let mut transition = RcCalibrationTransition::new();
        for _ in 0..4 {
            assert!(matches!(
                transition.action(),
                RcCalibrationAction::WriteMasked { .. }
            ));
            transition.advance(RcCalibrationCompletion::Write).unwrap();
        }
        assert_eq!(transition.action(), RcCalibrationAction::DelayMicros(100));
        assert_eq!(
            transition.advance(RcCalibrationCompletion::Write),
            Err(RcCalibrationTransitionError::WrongCompletion)
        );
        transition.advance(RcCalibrationCompletion::Delay).unwrap();
        assert!(matches!(
            transition.action(),
            RcCalibrationAction::ReadMasked {
                high_bit: 5,
                low_bit: 0,
                ..
            }
        ));
        transition
            .advance(RcCalibrationCompletion::Read(0x2d))
            .unwrap();
        transition.advance(RcCalibrationCompletion::Write).unwrap();
        transition.advance(RcCalibrationCompletion::Write).unwrap();
        assert_eq!(transition.action(), RcCalibrationAction::ApplyResult(0x2d));
        transition
            .advance(RcCalibrationCompletion::Applied)
            .unwrap();
        assert_eq!(transition.action(), RcCalibrationAction::Complete);
        assert_eq!(
            transition.advance(RcCalibrationCompletion::Applied),
            Err(RcCalibrationTransitionError::AlreadyComplete)
        );
    }

    #[test]
    fn bias_register_plan_requires_two_ordered_i2c_completions() {
        let first = PhyI2cAddress::new(0x6a, 0).unwrap();
        let second = PhyI2cAddress::new(0x6a, 1).unwrap();
        let mut transition = BiasRegTransition::new(true);

        assert_eq!(
            transition.action(),
            BiasRegAction::Write {
                address: first,
                value: 0xaf
            }
        );
        assert_eq!(
            transition.advance(BiasRegCompletion::WriteCompleted { address: second }),
            Err(BiasRegTransitionError::WrongCompletion)
        );
        transition
            .advance(BiasRegCompletion::WriteCompleted { address: first })
            .unwrap();
        assert_eq!(
            transition.action(),
            BiasRegAction::Write {
                address: second,
                value: 0x7f
            }
        );
        transition
            .advance(BiasRegCompletion::WriteCompleted { address: second })
            .unwrap();
        assert_eq!(transition.action(), BiasRegAction::Complete);
        assert_eq!(
            transition.advance(BiasRegCompletion::WriteCompleted { address: second }),
            Err(BiasRegTransitionError::AlreadyComplete)
        );
    }

    #[test]
    fn bias_register_argument_is_instruction_proven_unused() {
        assert_eq!(BiasRegTransition::new(false), BiasRegTransition::new(true));
    }

    #[test]
    fn adc_rate_owns_masked_i2c_read_write_and_mmio_edges() {
        let address = PhyI2cAddress::new(0x66, 4).unwrap();
        let mut high_rate = AdcRateTransition::new(true);
        assert_eq!(high_rate.action(), AdcRateAction::ReadI2c { address });
        assert_eq!(
            high_rate.advance(AdcRateCompletion::I2cWriteCompleted { address }),
            Err(AdcRateTransitionError::WrongCompletion)
        );
        high_rate
            .advance(AdcRateCompletion::I2cReadCompleted {
                address,
                value: 0xaf,
            })
            .unwrap();
        assert_eq!(
            high_rate.action(),
            AdcRateAction::WriteI2c {
                address,
                value: 0xa3,
            }
        );
        high_rate
            .advance(AdcRateCompletion::I2cWriteCompleted { address })
            .unwrap();
        assert_eq!(high_rate.action(), AdcRateAction::ConfigureMmio { rate: 1 });
        high_rate
            .advance(AdcRateCompletion::MmioConfigured)
            .unwrap();
        assert_eq!(high_rate.action(), AdcRateAction::Complete);

        let mut low_rate = AdcRateTransition::new(false);
        low_rate
            .advance(AdcRateCompletion::I2cReadCompleted {
                address,
                value: 0xa3,
            })
            .unwrap();
        assert_eq!(
            low_rate.action(),
            AdcRateAction::WriteI2c {
                address,
                value: 0xab,
            }
        );
    }

    #[test]
    fn i2c_bbpll_moves_rom_phy_param_snapshot_into_owned_state() {
        let address = PhyI2cAddress::new(0x66, 4).unwrap();
        let mut enable = I2cBbpllTransition::enable();
        assert_eq!(enable.action(), I2cBbpllAction::ReadMaskedByte { address });
        assert_eq!(
            enable.advance(I2cBbpllCompletion::I2cWriteCompleted { address }),
            Err(I2cBbpllTransitionError::WrongCompletion)
        );
        enable
            .advance(I2cBbpllCompletion::I2cReadCompleted {
                address,
                value: 0xaf,
            })
            .unwrap();
        assert_eq!(
            enable.action(),
            I2cBbpllAction::WriteByte {
                address,
                value: 0xa3,
            }
        );
        enable
            .advance(I2cBbpllCompletion::I2cWriteCompleted { address })
            .unwrap();
        assert_eq!(enable.action(), I2cBbpllAction::ReadSnapshot { address });
        enable
            .advance(I2cBbpllCompletion::I2cReadCompleted {
                address,
                value: 0xa3,
            })
            .unwrap();
        assert_eq!(
            enable.action(),
            I2cBbpllAction::Complete(I2cBbpllOutcome::Enabled {
                register_snapshot: 0xa3,
            })
        );

        let mut restore = I2cBbpllTransition::restore(0xa3);
        assert_eq!(
            restore.action(),
            I2cBbpllAction::WriteByte {
                address,
                value: 0xa3,
            }
        );
        restore
            .advance(I2cBbpllCompletion::I2cWriteCompleted { address })
            .unwrap();
        assert_eq!(
            restore.action(),
            I2cBbpllAction::Complete(I2cBbpllOutcome::Restored)
        );
    }

    #[test]
    fn rf_init_prefix_composes_mmio_i2c_and_timer_edges_in_vendor_order() {
        let bias_zero = PhyI2cAddress::new(0x6a, 0).unwrap();
        let bias_one = PhyI2cAddress::new(0x6a, 1).unwrap();
        let mut transition = PhyRfInitPrefixTransition::new();

        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::ConfigureFeBbClock
        );
        assert_eq!(
            transition.advance(PhyRfInitPrefixCompletion::BbpllCalibrationConfigured),
            Err(PhyRfInitPrefixTransitionError::WrongCompletion)
        );
        transition
            .advance(PhyRfInitPrefixCompletion::FeBbClockConfigured)
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::ConfigureBbpllCalibration { enabled: true }
        );
        transition
            .advance(PhyRfInitPrefixCompletion::BbpllCalibrationConfigured)
            .unwrap();

        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::Bias(BiasRegAction::Write {
                address: bias_zero,
                value: 0xaf
            })
        );
        transition
            .advance(PhyRfInitPrefixCompletion::Bias(
                BiasRegCompletion::WriteCompleted { address: bias_zero },
            ))
            .unwrap();
        transition
            .advance(PhyRfInitPrefixCompletion::Bias(
                BiasRegCompletion::WriteCompleted { address: bias_one },
            ))
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::OpenI2cXpd(OpenI2cXpdAction::ConfigurePreDelay)
        );

        transition
            .advance(PhyRfInitPrefixCompletion::OpenI2cXpd(
                OpenI2cXpdCompletion::PreDelayConfigured,
            ))
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::OpenI2cXpd(OpenI2cXpdAction::DelayMicros(100))
        );
        transition
            .advance(PhyRfInitPrefixCompletion::OpenI2cXpd(
                OpenI2cXpdCompletion::DelayElapsed,
            ))
            .unwrap();
        transition
            .advance(PhyRfInitPrefixCompletion::OpenI2cXpd(
                OpenI2cXpdCompletion::PowerAndPulseConfigured,
            ))
            .unwrap();
        transition
            .advance(PhyRfInitPrefixCompletion::OpenI2cXpd(
                OpenI2cXpdCompletion::DeadlineObserved { expired: false },
            ))
            .unwrap();
        transition
            .advance(PhyRfInitPrefixCompletion::OpenI2cXpd(
                OpenI2cXpdCompletion::SdmSample(0x5b),
            ))
            .unwrap();

        assert_eq!(transition.action(), PhyRfInitPrefixAction::DelayMicros(10));
        transition
            .advance(PhyRfInitPrefixCompletion::DelayElapsed)
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ConfigureDebugMode)
        );
        transition
            .advance(PhyRfInitPrefixCompletion::PbusClear(
                PhyPbusClearCompletion::DebugModeConfigured,
            ))
            .unwrap();
        for transaction in [
            PhyPbusForceTest::new(4, 1, 0),
            PhyPbusForceTest::new(4, 2, 0),
            PhyPbusForceTest::new(5, 1, 0),
            PhyPbusForceTest::new(5, 2, 0),
            PhyPbusForceTest::new(0, 1, 0),
            PhyPbusForceTest::new(0, 2, 0),
            PhyPbusForceTest::new(1, 1, 0),
            PhyPbusForceTest::new(1, 2, 0),
            PhyPbusForceTest::new(2, 1, 0x100),
            PhyPbusForceTest::new(3, 1, 0x100),
            PhyPbusForceTest::new(2, 2, 0x100),
            PhyPbusForceTest::new(3, 2, 0x100),
        ] {
            transition
                .advance(PhyRfInitPrefixCompletion::PbusClear(
                    PhyPbusClearCompletion::ForceTestCompleted(transaction),
                ))
                .unwrap();
        }
        transition
            .advance(PhyRfInitPrefixCompletion::PbusClear(
                PhyPbusClearCompletion::WorkModeConfigured {
                    settle_required: false,
                },
            ))
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::ConfigureI2cClockSelection { selection: 8 }
        );
        transition
            .advance(PhyRfInitPrefixCompletion::I2cClockSelectionConfigured)
            .unwrap();
        let bbpll_address = PhyI2cAddress::new(0x66, 4).unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::I2cBbpll(I2cBbpllAction::ReadMaskedByte {
                address: bbpll_address
            })
        );
        transition
            .advance(PhyRfInitPrefixCompletion::I2cBbpll(
                I2cBbpllCompletion::I2cReadCompleted {
                    address: bbpll_address,
                    value: 0xaf,
                },
            ))
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::I2cBbpll(I2cBbpllAction::WriteByte {
                address: bbpll_address,
                value: 0xa3,
            })
        );
        transition
            .advance(PhyRfInitPrefixCompletion::I2cBbpll(
                I2cBbpllCompletion::I2cWriteCompleted {
                    address: bbpll_address,
                },
            ))
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::I2cBbpll(I2cBbpllAction::ReadSnapshot {
                address: bbpll_address
            })
        );
        transition
            .advance(PhyRfInitPrefixCompletion::I2cBbpll(
                I2cBbpllCompletion::I2cReadCompleted {
                    address: bbpll_address,
                    value: 0xa3,
                },
            ))
            .unwrap();
        let adc_address = PhyI2cAddress::new(0x66, 4).unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::AdcRate(AdcRateAction::ReadI2c {
                address: adc_address
            })
        );
        transition
            .advance(PhyRfInitPrefixCompletion::AdcRate(
                AdcRateCompletion::I2cReadCompleted {
                    address: adc_address,
                    value: 0xff,
                },
            ))
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::AdcRate(AdcRateAction::WriteI2c {
                address: adc_address,
                value: 0xf3,
            })
        );
        transition
            .advance(PhyRfInitPrefixCompletion::AdcRate(
                AdcRateCompletion::I2cWriteCompleted {
                    address: adc_address,
                },
            ))
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::AdcRate(AdcRateAction::ConfigureMmio { rate: 1 })
        );
        transition
            .advance(PhyRfInitPrefixCompletion::AdcRate(
                AdcRateCompletion::MmioConfigured,
            ))
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::ConfigureI2cMasterRegisters
        );
        transition
            .advance(PhyRfInitPrefixCompletion::I2cMasterRegistersConfigured)
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::ConfigurePowerDetectorRegisters
        );
        transition
            .advance(PhyRfInitPrefixCompletion::PowerDetectorRegistersConfigured)
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::Complete(PhyRfInitPrefixOutcome::ReadyForFrontEndRegisterInit {
                bbpll_register_snapshot: 0xa3,
            })
        );
    }

    #[test]
    fn rf_init_prefix_propagates_sdm_timeout_without_running_post_delay() {
        let bias_zero = PhyI2cAddress::new(0x6a, 0).unwrap();
        let bias_one = PhyI2cAddress::new(0x6a, 1).unwrap();
        let mut transition = PhyRfInitPrefixTransition::new();
        transition
            .advance(PhyRfInitPrefixCompletion::FeBbClockConfigured)
            .unwrap();
        transition
            .advance(PhyRfInitPrefixCompletion::BbpllCalibrationConfigured)
            .unwrap();
        transition
            .advance(PhyRfInitPrefixCompletion::Bias(
                BiasRegCompletion::WriteCompleted { address: bias_zero },
            ))
            .unwrap();
        transition
            .advance(PhyRfInitPrefixCompletion::Bias(
                BiasRegCompletion::WriteCompleted { address: bias_one },
            ))
            .unwrap();
        transition
            .advance(PhyRfInitPrefixCompletion::OpenI2cXpd(
                OpenI2cXpdCompletion::PreDelayConfigured,
            ))
            .unwrap();
        transition
            .advance(PhyRfInitPrefixCompletion::OpenI2cXpd(
                OpenI2cXpdCompletion::DelayElapsed,
            ))
            .unwrap();
        transition
            .advance(PhyRfInitPrefixCompletion::OpenI2cXpd(
                OpenI2cXpdCompletion::PowerAndPulseConfigured,
            ))
            .unwrap();
        transition
            .advance(PhyRfInitPrefixCompletion::OpenI2cXpd(
                OpenI2cXpdCompletion::DeadlineObserved { expired: true },
            ))
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRfInitPrefixAction::Complete(PhyRfInitPrefixOutcome::SdmTimedOut)
        );
        assert_eq!(
            transition.advance(PhyRfInitPrefixCompletion::DelayElapsed),
            Err(PhyRfInitPrefixTransitionError::AlreadyComplete)
        );
    }

    #[test]
    fn open_i2c_xpd_delayed_path_requires_explicit_async_completions() {
        let mut transition = OpenI2cXpdTransition::new(true);
        assert_eq!(transition.action(), OpenI2cXpdAction::ConfigurePreDelay);
        assert_eq!(
            transition.advance(OpenI2cXpdCompletion::DelayElapsed),
            Err(OpenI2cXpdTransitionError::WrongCompletion)
        );
        transition
            .advance(OpenI2cXpdCompletion::PreDelayConfigured)
            .unwrap();
        assert_eq!(transition.action(), OpenI2cXpdAction::DelayMicros(100));
        transition
            .advance(OpenI2cXpdCompletion::DelayElapsed)
            .unwrap();
        assert_eq!(
            transition.action(),
            OpenI2cXpdAction::ConfigurePowerAndPulse
        );
        transition
            .advance(OpenI2cXpdCompletion::PowerAndPulseConfigured)
            .unwrap();
        assert_eq!(
            transition.action(),
            OpenI2cXpdAction::CheckSdmDeadline {
                maximum_cycles: 9_999
            }
        );
    }

    #[test]
    fn open_i2c_xpd_samples_only_after_deadline_and_i2c_edges() {
        let mut transition = OpenI2cXpdTransition::new(false);
        transition
            .advance(OpenI2cXpdCompletion::PowerAndPulseConfigured)
            .unwrap();
        transition
            .advance(OpenI2cXpdCompletion::DeadlineObserved { expired: false })
            .unwrap();
        assert_eq!(
            transition.action(),
            OpenI2cXpdAction::ReadSdmSample {
                address: PhyI2cAddress::new(0x63, 0).unwrap()
            }
        );

        transition
            .advance(OpenI2cXpdCompletion::SdmSample(0x42))
            .unwrap();
        assert_eq!(transition.samples(), 1);
        assert!(matches!(
            transition.action(),
            OpenI2cXpdAction::CheckSdmDeadline { .. }
        ));

        transition
            .advance(OpenI2cXpdCompletion::DeadlineObserved { expired: false })
            .unwrap();
        transition
            .advance(OpenI2cXpdCompletion::SdmSample(0x5b))
            .unwrap();
        assert_eq!(
            transition.action(),
            OpenI2cXpdAction::Complete(OpenI2cXpdOutcome::Stable)
        );
        assert_eq!(transition.samples(), 2);
        assert_eq!(
            transition.advance(OpenI2cXpdCompletion::SdmSample(0x5b)),
            Err(OpenI2cXpdTransitionError::AlreadyComplete)
        );
    }

    #[test]
    fn open_i2c_xpd_deadline_is_a_terminal_outcome() {
        let mut transition = OpenI2cXpdTransition::new(false);
        transition
            .advance(OpenI2cXpdCompletion::PowerAndPulseConfigured)
            .unwrap();
        transition
            .advance(OpenI2cXpdCompletion::DeadlineObserved { expired: true })
            .unwrap();
        assert_eq!(
            transition.action(),
            OpenI2cXpdAction::Complete(OpenI2cXpdOutcome::TimedOut)
        );
        assert_eq!(transition.samples(), 0);
    }
}
