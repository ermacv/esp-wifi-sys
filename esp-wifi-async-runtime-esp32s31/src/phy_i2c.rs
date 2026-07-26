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

const PHY_I2C_HOST_CONFIG_ADDRESS: usize = 0x2010_f820;
const PHY_I2C_READ_MASK_ADDRESS: usize = 0x2010_f81c;
const PHY_I2C_COMMAND_BASE_ADDRESS: usize = 0x2010_f800;
const PHY_I2C_BUSY: u32 = 1 << 25;
const PHY_I2C_READ: u32 = 1 << 30;
const PHY_I2C_WRITE: u32 = 1 << 28 | 1 << 30;

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
        command_is_busy, command_register_address, encode_read, encode_write, read_result,
        with_phy_i2c_host_config, PhyI2cAddress, RcCalibrationAction, RcCalibrationCompletion,
        RcCalibrationTransition, RcCalibrationTransitionError,
    };

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
}
