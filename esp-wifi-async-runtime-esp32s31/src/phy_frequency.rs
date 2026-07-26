//! Rust-owned ESP32-S31 cold frequency-table generation.
//!
//! The pinned reference is `libphy.a[phy_hw_freq.o]::phy_get_rf_freq_init`,
//! size `0x1d8`, and the rev0 ROM leaves `phy_get_data_sat`,
//! `phy_get_freq_mem_param`, `phy_freq_i2c_mem_write`, and
//! `phy_wr_rf_freq_mem`. The vendor parent materializes one three-word record
//! at a time for 85 frequencies beginning at `0x960`.
//!
//! Rust retains only the interpolation scalars and the current entry/word
//! indices. It never allocates or stores the complete 1,020-byte table in
//! SRAM. Every hardware-memory publication is an identity-bound finite MMIO
//! action completed by the caller.

use crate::phy_rfpll::calculate_rfpll_sdm;

pub const PHY_FREQUENCY_TABLE_ENTRY_COUNT: u8 = 85;
pub const PHY_FREQUENCY_TABLE_FIRST_CODE: u16 = 0x960;
const PHY_FREQUENCY_MEMORY_BASE: u16 = 0x12;
const PHY_FREQUENCY_MEMORY_ENTRY_STRIDE: u16 = 7;
const PHY_FREQUENCY_MEMORY_WORD_STRIDE: u16 = 3;
const PHY_FREQUENCY_MEMORY_MODE: u8 = 7;
const CAP_INTERPOLATION_DIVISOR: i32 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyFrequencyTableParameters {
    /// Explicit replacement for `phy_param[0x4f]`.
    pub crystal_selector: u8,
    /// Explicit replacement for `phy_param[0x19f]`.
    pub middle_xtal_duty: u8,
    /// Explicit replacement for `phy_param[0x1a0]`.
    pub outer_xtal_duty: u8,
    /// Upper five bits read once from PHY-I2C block `0x63`, register `6`.
    pub sdm_register_six_upper: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyFrequencyMemoryRecord {
    words: [u32; 3],
}

impl PhyFrequencyMemoryRecord {
    pub const fn words(self) -> [u32; 3] {
        self.words
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyFrequencyTableRequest {
    pub parameters: PhyFrequencyTableParameters,
    pub low_frequency_cap: u16,
    pub high_frequency_cap: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyFrequencyTableOutcome {
    pub entries_written: u8,
    pub low_frequency_cap: u16,
    pub high_frequency_cap: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyFrequencyTableAction {
    WriteMemory {
        entry_index: u8,
        word_index: u8,
        address: u16,
        value: u32,
        mode: u8,
    },
    Complete(PhyFrequencyTableOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyFrequencyTableCompletion {
    pub entry_index: u8,
    pub word_index: u8,
    pub address: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyFrequencyTableTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

/// Exact stateless body of pinned `libphy.a[phy_rx_cal.o]::phy_get_xtal_duty`.
pub const fn phy_frequency_xtal_duty(
    frequency_code: u16,
    middle_xtal_duty: u8,
    outer_xtal_duty: u8,
) -> u8 {
    if frequency_code <= 0x967 {
        17
    } else if frequency_code.wrapping_sub(0x975) <= 38 {
        middle_xtal_duty
    } else {
        outer_xtal_duty
    }
}

const fn interpolated_cap(low: u16, high: u16, index: u8) -> u16 {
    let low = low as i16 as i32;
    let delta = (high as i16 as i32).wrapping_sub(low);
    let interpolated =
        low.wrapping_add(delta.wrapping_mul(index as i32) / CAP_INTERPOLATION_DIVISOR);
    if interpolated < 0 {
        0
    } else if interpolated > 0x1ff {
        0x1ff
    } else {
        interpolated as u16
    }
}

/// Reproduce one packed three-word `phy_wr_rf_freq_mem` input record.
pub const fn phy_frequency_memory_record(
    request: PhyFrequencyTableRequest,
    index: u8,
) -> PhyFrequencyMemoryRecord {
    let frequency_code = PHY_FREQUENCY_TABLE_FIRST_CODE.wrapping_add(index as u16);
    let sdm = calculate_rfpll_sdm(frequency_code, request.parameters.crystal_selector, 0).bytes();
    let cap = interpolated_cap(request.low_frequency_cap, request.high_frequency_cap, index);
    let cap_high = 0xbf | (((cap >> 8) as u8 & 1) << 6);
    let sdm_low = sdm[0] | (request.parameters.sdm_register_six_upper & 0xf8);
    let xtal_duty = phy_frequency_xtal_duty(
        frequency_code,
        request.parameters.middle_xtal_duty,
        request.parameters.outer_xtal_duty,
    );

    PhyFrequencyMemoryRecord {
        words: [
            cap as u8 as u32 | ((cap_high as u32) << 8) | ((sdm_low as u32) << 16),
            sdm[1] as u32 | ((sdm[2] as u32) << 8) | ((sdm[3] as u32) << 16),
            xtal_duty as u32,
        ],
    }
}

/// Caller-driven 85-entry frequency-memory publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyFrequencyTableTransition {
    request: PhyFrequencyTableRequest,
    entry_index: u8,
    word_index: u8,
}

impl PhyFrequencyTableTransition {
    pub const fn new(request: PhyFrequencyTableRequest) -> Self {
        Self {
            request,
            entry_index: 0,
            word_index: 0,
        }
    }

    const fn address(self) -> u16 {
        PHY_FREQUENCY_MEMORY_BASE
            .wrapping_add((self.entry_index as u16).wrapping_mul(PHY_FREQUENCY_MEMORY_ENTRY_STRIDE))
            .wrapping_add((self.word_index as u16).wrapping_mul(PHY_FREQUENCY_MEMORY_WORD_STRIDE))
    }

    pub const fn action(self) -> PhyFrequencyTableAction {
        if self.entry_index == PHY_FREQUENCY_TABLE_ENTRY_COUNT {
            PhyFrequencyTableAction::Complete(PhyFrequencyTableOutcome {
                entries_written: self.entry_index,
                low_frequency_cap: self.request.low_frequency_cap,
                high_frequency_cap: self.request.high_frequency_cap,
            })
        } else {
            let record = phy_frequency_memory_record(self.request, self.entry_index);
            PhyFrequencyTableAction::WriteMemory {
                entry_index: self.entry_index,
                word_index: self.word_index,
                address: self.address(),
                value: record.words[self.word_index as usize],
                mode: PHY_FREQUENCY_MEMORY_MODE,
            }
        }
    }

    pub fn advance(
        &mut self,
        completion: PhyFrequencyTableCompletion,
    ) -> Result<(), PhyFrequencyTableTransitionError> {
        let PhyFrequencyTableAction::WriteMemory {
            entry_index,
            word_index,
            address,
            ..
        } = self.action()
        else {
            return Err(PhyFrequencyTableTransitionError::AlreadyComplete);
        };
        if completion.entry_index != entry_index
            || completion.word_index != word_index
            || completion.address != address
        {
            return Err(PhyFrequencyTableTransitionError::WrongCompletion);
        }

        if self.word_index == 2 {
            self.word_index = 0;
            self.entry_index += 1;
        } else {
            self.word_index += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        phy_frequency_memory_record, phy_frequency_xtal_duty, PhyFrequencyTableAction,
        PhyFrequencyTableCompletion, PhyFrequencyTableParameters, PhyFrequencyTableRequest,
        PhyFrequencyTableTransition, PhyFrequencyTableTransitionError,
        PHY_FREQUENCY_TABLE_ENTRY_COUNT,
    };

    const REQUEST: PhyFrequencyTableRequest = PhyFrequencyTableRequest {
        parameters: PhyFrequencyTableParameters {
            crystal_selector: 0x31,
            middle_xtal_duty: 0x2a,
            outer_xtal_duty: 0x35,
            sdm_register_six_upper: 0xa8,
        },
        low_frequency_cap: 0x0c8,
        high_frequency_cap: 0x118,
    };

    #[test]
    fn crystal_duty_preserves_both_unsigned_vendor_boundaries() {
        assert_eq!(phy_frequency_xtal_duty(0x967, 0x2a, 0x35), 17);
        assert_eq!(phy_frequency_xtal_duty(0x968, 0x2a, 0x35), 0x35);
        assert_eq!(phy_frequency_xtal_duty(0x974, 0x2a, 0x35), 0x35);
        assert_eq!(phy_frequency_xtal_duty(0x975, 0x2a, 0x35), 0x2a);
        assert_eq!(phy_frequency_xtal_duty(0x99b, 0x2a, 0x35), 0x2a);
        assert_eq!(phy_frequency_xtal_duty(0x99c, 0x2a, 0x35), 0x35);
    }

    #[test]
    fn record_packs_cap_sdm_and_duty_without_a_backing_table() {
        assert_eq!(
            phy_frequency_memory_record(REQUEST, 0).words(),
            [0x00a8_bfc8, 0x0030_0000, 17]
        );
        assert_eq!(
            phy_frequency_memory_record(REQUEST, 64).words(),
            [0x00a9_ff18, 0x0032_2222, 0x35]
        );
        assert_eq!(
            phy_frequency_memory_record(REQUEST, 84).words(),
            [0x00ae_ff31, 0x0032_cccc, 0x35]
        );
    }

    #[test]
    fn transition_publishes_exactly_three_words_for_all_85_entries() {
        let mut transition = PhyFrequencyTableTransition::new(REQUEST);
        let mut writes = 0;
        loop {
            match transition.action() {
                PhyFrequencyTableAction::WriteMemory {
                    entry_index,
                    word_index,
                    address,
                    mode,
                    ..
                } => {
                    assert_eq!(mode, 7);
                    assert_eq!(
                        address,
                        0x12 + u16::from(entry_index) * 7 + u16::from(word_index) * 3
                    );
                    transition
                        .advance(PhyFrequencyTableCompletion {
                            entry_index,
                            word_index,
                            address,
                        })
                        .unwrap();
                    writes += 1;
                }
                PhyFrequencyTableAction::Complete(outcome) => {
                    assert_eq!(outcome.entries_written, PHY_FREQUENCY_TABLE_ENTRY_COUNT);
                    break;
                }
            }
        }
        assert_eq!(writes, usize::from(PHY_FREQUENCY_TABLE_ENTRY_COUNT) * 3);
        assert_eq!(
            transition.advance(PhyFrequencyTableCompletion {
                entry_index: 0,
                word_index: 0,
                address: 0x12,
            }),
            Err(PhyFrequencyTableTransitionError::AlreadyComplete)
        );
    }

    #[test]
    fn transition_rejects_out_of_order_memory_completion() {
        let mut transition = PhyFrequencyTableTransition::new(REQUEST);
        assert_eq!(
            transition.advance(PhyFrequencyTableCompletion {
                entry_index: 0,
                word_index: 1,
                address: 0x15,
            }),
            Err(PhyFrequencyTableTransitionError::WrongCompletion)
        );
    }
}
