//! Event-driven ESP32-S31 crystal-duty search.
//!
//! Reference: complete `libphy.a[phy_rx_cal.o]::phy_xtal_duty_cal`, size
//! `0x392`. The pinned cold caller always passes `debug = 0`, so both vendor
//! `phy_printf` branches are dead and are intentionally absent here.

use crate::phy_i2c::PhyI2cAddress;

const FIRST_CANDIDATE: u8 = 0x20;
const LAST_CANDIDATE: u8 = 0x3e;
const INITIAL_SAMPLE_COUNT: u8 = 4;
const SIGNAL_POWER_SHIFT: u8 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutySampleKind {
    Initial(u8),
    FirstReplacement(u8),
    SecondReplacement(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutySearchAction {
    WriteCandidate(u8),
    DelayMicros(u32),
    MeasureSignalPower {
        candidate: u8,
        shift: u8,
        kind: XtalDutySampleKind,
    },
    Complete(XtalDutySearchOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutySearchCompletion {
    CandidateWritten(u8),
    DelayElapsed {
        candidate: u8,
    },
    SignalPowerMeasured {
        candidate: u8,
        kind: XtalDutySampleKind,
        value: i64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutySearchTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XtalDutySearchOutcome {
    pub best_candidate: u8,
    pub best_filtered_power: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XtalDutySearchStep {
    WriteCandidate {
        candidate: u8,
    },
    Delay {
        candidate: u8,
    },
    InitialSamples {
        candidate: u8,
        samples: [i64; INITIAL_SAMPLE_COUNT as usize],
        count: u8,
    },
    Review {
        candidate: u8,
        samples: [i64; INITIAL_SAMPLE_COUNT as usize],
        lower: i64,
        upper: i64,
        index: u8,
        filtered_sum: i64,
    },
    FirstReplacement {
        candidate: u8,
        samples: [i64; INITIAL_SAMPLE_COUNT as usize],
        lower: i64,
        upper: i64,
        index: u8,
        filtered_sum: i64,
    },
    SecondReplacement {
        candidate: u8,
        samples: [i64; INITIAL_SAMPLE_COUNT as usize],
        lower: i64,
        upper: i64,
        index: u8,
        filtered_sum: i64,
    },
    Complete(XtalDutySearchOutcome),
}

/// Fixed-size translation of the vendor crystal-duty candidate search.
///
/// The transition owns all samples. It can request at most six measurements
/// for each of the 31 candidates and cannot advance from `poll`: every
/// hardware measurement and 20-microsecond interval requires an explicit
/// external completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XtalDutySearchTransition {
    step: XtalDutySearchStep,
    best_candidate: u8,
    best_filtered_power: i64,
    has_best: bool,
}

impl XtalDutySearchTransition {
    pub const fn new() -> Self {
        Self {
            step: XtalDutySearchStep::WriteCandidate {
                candidate: FIRST_CANDIDATE,
            },
            best_candidate: FIRST_CANDIDATE,
            best_filtered_power: 0,
            has_best: false,
        }
    }

    pub const fn action(self) -> XtalDutySearchAction {
        match self.step {
            XtalDutySearchStep::WriteCandidate { candidate } => {
                XtalDutySearchAction::WriteCandidate(candidate)
            }
            XtalDutySearchStep::Delay { .. } => XtalDutySearchAction::DelayMicros(20),
            XtalDutySearchStep::InitialSamples {
                candidate, count, ..
            } => XtalDutySearchAction::MeasureSignalPower {
                candidate,
                shift: SIGNAL_POWER_SHIFT,
                kind: XtalDutySampleKind::Initial(count),
            },
            XtalDutySearchStep::Review {
                candidate, index, ..
            }
            | XtalDutySearchStep::FirstReplacement {
                candidate, index, ..
            } => XtalDutySearchAction::MeasureSignalPower {
                candidate,
                shift: SIGNAL_POWER_SHIFT,
                kind: XtalDutySampleKind::FirstReplacement(index),
            },
            XtalDutySearchStep::SecondReplacement {
                candidate, index, ..
            } => XtalDutySearchAction::MeasureSignalPower {
                candidate,
                shift: SIGNAL_POWER_SHIFT,
                kind: XtalDutySampleKind::SecondReplacement(index),
            },
            XtalDutySearchStep::Complete(outcome) => XtalDutySearchAction::Complete(outcome),
        }
    }

    fn outlier(value: i64, lower: i64, upper: i64) -> bool {
        value < lower || value > upper
    }

    fn finish_candidate(&mut self, candidate: u8, filtered_sum: i64) {
        let filtered_power = filtered_sum / i64::from(INITIAL_SAMPLE_COUNT);
        if !self.has_best || filtered_power < self.best_filtered_power {
            self.has_best = true;
            self.best_candidate = candidate;
            self.best_filtered_power = filtered_power;
        }
        self.step = if candidate == LAST_CANDIDATE {
            XtalDutySearchStep::Complete(XtalDutySearchOutcome {
                best_candidate: self.best_candidate,
                best_filtered_power: self.best_filtered_power,
            })
        } else {
            XtalDutySearchStep::WriteCandidate {
                candidate: candidate + 1,
            }
        };
    }

    fn normalize_review(&mut self) {
        loop {
            let XtalDutySearchStep::Review {
                candidate,
                samples,
                lower,
                upper,
                index,
                filtered_sum,
            } = self.step
            else {
                return;
            };
            if index == INITIAL_SAMPLE_COUNT {
                self.finish_candidate(candidate, filtered_sum);
                return;
            }
            let sample = samples[index as usize];
            if Self::outlier(sample, lower, upper) {
                self.step = XtalDutySearchStep::FirstReplacement {
                    candidate,
                    samples,
                    lower,
                    upper,
                    index,
                    filtered_sum,
                };
                return;
            }
            self.step = XtalDutySearchStep::Review {
                candidate,
                samples,
                lower,
                upper,
                index: index + 1,
                filtered_sum: filtered_sum.wrapping_add(sample),
            };
        }
    }

    pub fn advance(
        &mut self,
        completion: XtalDutySearchCompletion,
    ) -> Result<(), XtalDutySearchTransitionError> {
        self.step = match (self.step, completion) {
            (
                XtalDutySearchStep::WriteCandidate { candidate },
                XtalDutySearchCompletion::CandidateWritten(completed),
            ) if candidate == completed => XtalDutySearchStep::Delay { candidate },
            (
                XtalDutySearchStep::Delay { candidate },
                XtalDutySearchCompletion::DelayElapsed {
                    candidate: completed,
                },
            ) if candidate == completed => XtalDutySearchStep::InitialSamples {
                candidate,
                samples: [0; INITIAL_SAMPLE_COUNT as usize],
                count: 0,
            },
            (
                XtalDutySearchStep::InitialSamples {
                    candidate,
                    mut samples,
                    count,
                },
                XtalDutySearchCompletion::SignalPowerMeasured {
                    candidate: completed,
                    kind: XtalDutySampleKind::Initial(completed_count),
                    value,
                },
            ) if candidate == completed && count == completed_count => {
                samples[count as usize] = value;
                if count + 1 != INITIAL_SAMPLE_COUNT {
                    XtalDutySearchStep::InitialSamples {
                        candidate,
                        samples,
                        count: count + 1,
                    }
                } else {
                    let sum = samples
                        .into_iter()
                        .fold(0_i64, |sum, sample| sum.wrapping_add(sample));
                    let mean = sum / i64::from(INITIAL_SAMPLE_COUNT);
                    XtalDutySearchStep::Review {
                        candidate,
                        samples,
                        lower: mean.wrapping_mul(2) / 3,
                        upper: mean.wrapping_mul(3) / 2,
                        index: 0,
                        filtered_sum: 0,
                    }
                }
            }
            (
                XtalDutySearchStep::FirstReplacement {
                    candidate,
                    samples,
                    lower,
                    upper,
                    index,
                    filtered_sum,
                },
                XtalDutySearchCompletion::SignalPowerMeasured {
                    candidate: completed,
                    kind: XtalDutySampleKind::FirstReplacement(completed_index),
                    value,
                },
            ) if candidate == completed && index == completed_index => {
                if Self::outlier(value, lower, upper) {
                    XtalDutySearchStep::SecondReplacement {
                        candidate,
                        samples,
                        lower,
                        upper,
                        index,
                        filtered_sum,
                    }
                } else {
                    XtalDutySearchStep::Review {
                        candidate,
                        samples,
                        lower,
                        upper,
                        index: index + 1,
                        filtered_sum: filtered_sum.wrapping_add(value),
                    }
                }
            }
            (
                XtalDutySearchStep::SecondReplacement {
                    candidate,
                    samples,
                    lower,
                    upper,
                    index,
                    filtered_sum,
                },
                XtalDutySearchCompletion::SignalPowerMeasured {
                    candidate: completed,
                    kind: XtalDutySampleKind::SecondReplacement(completed_index),
                    value,
                },
            ) if candidate == completed && index == completed_index => XtalDutySearchStep::Review {
                candidate,
                samples,
                lower,
                upper,
                index: index + 1,
                filtered_sum: filtered_sum.wrapping_add(value),
            },
            (XtalDutySearchStep::Complete(_), _) => {
                return Err(XtalDutySearchTransitionError::AlreadyComplete);
            }
            _ => return Err(XtalDutySearchTransitionError::WrongCompletion),
        };
        self.normalize_review();
        Ok(())
    }
}

impl Default for XtalDutySearchTransition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XtalDutyCalibrationParameters {
    /// `phy_param[0x4f]`, passed to the RFPLL frequency calculation.
    pub rf_frequency_offset_base: u8,
    /// Byte two of the parameter image published through the rev0 ROM
    /// `phy_param_rom` pointer cell at `0x2f07_fc40`.
    ///
    /// ROM `phy_pbus_xpd_rx_on` forwards this value to PBus selector zero,
    /// path two. Its electrical meaning is not yet evidenced, so the name
    /// deliberately describes the observed use rather than guessing.
    pub pbus_rx_path_value: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XtalDutyPassOutcome {
    pub frequency_code: u16,
    pub best_candidate: u8,
    pub best_filtered_power: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyPassAction {
    WriteMasked {
        address: PhyI2cAddress,
        high_bit: u8,
        low_bit: u8,
        value: u8,
    },
    WriteByte {
        address: PhyI2cAddress,
        value: u8,
    },
    /// Hardware preparation recovered from the finite pre-search portion of
    /// `phy_xtal_duty_cal`.
    ///
    /// This action is intentionally explicit and not a vendor-call permit.
    /// Its adapter must be decomposed into Rust MMIO/PBus/RX-DCO transitions.
    PrepareHardware {
        frequency_code: u16,
        rf_frequency_offset_base: u8,
        pbus_rx_path_value: u8,
    },
    Search(XtalDutySearchAction),
    /// Restore tone, RX/TX clocks, PBus RX power and work mode.
    ///
    /// As with `PrepareHardware`, completion means a Rust-owned transition
    /// finished; it must never call the synchronous vendor parent.
    RestoreHardware {
        frequency_code: u16,
    },
    Complete(XtalDutyPassOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyPassCompletion {
    MaskedWrite {
        address: PhyI2cAddress,
    },
    ByteWrite {
        address: PhyI2cAddress,
    },
    HardwarePrepared {
        frequency_code: u16,
        rf_frequency_offset_base: u8,
        pbus_rx_path_value: u8,
    },
    Search(XtalDutySearchCompletion),
    HardwareRestored {
        frequency_code: u16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyPassTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XtalDutyPassStep {
    DisablePath,
    WriteInitialDuty,
    PrepareHardware,
    Search(XtalDutySearchTransition),
    RestoreInitialDuty(XtalDutySearchOutcome),
    RestoreHardware(XtalDutySearchOutcome),
    Complete(XtalDutyPassOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XtalDutyPassTransition {
    frequency_code: u16,
    initial_duty: u8,
    parameter: XtalDutyCalibrationParameters,
    step: XtalDutyPassStep,
}

impl XtalDutyPassTransition {
    const CONTROL_ADDRESS: PhyI2cAddress = PhyI2cAddress::new_internal(0x61, 7);
    const DUTY_ADDRESS: PhyI2cAddress = PhyI2cAddress::new_internal(0x61, 0x0a);

    pub const fn new(
        frequency_code: u16,
        initial_duty: u8,
        parameter: XtalDutyCalibrationParameters,
    ) -> Self {
        Self {
            frequency_code,
            initial_duty,
            parameter,
            step: XtalDutyPassStep::DisablePath,
        }
    }

    pub const fn action(self) -> XtalDutyPassAction {
        match self.step {
            XtalDutyPassStep::DisablePath => XtalDutyPassAction::WriteMasked {
                address: Self::CONTROL_ADDRESS,
                high_bit: 5,
                low_bit: 5,
                value: 0,
            },
            XtalDutyPassStep::WriteInitialDuty => XtalDutyPassAction::WriteByte {
                address: Self::DUTY_ADDRESS,
                value: self.initial_duty,
            },
            XtalDutyPassStep::PrepareHardware => XtalDutyPassAction::PrepareHardware {
                frequency_code: self.frequency_code,
                rf_frequency_offset_base: self.parameter.rf_frequency_offset_base,
                pbus_rx_path_value: self.parameter.pbus_rx_path_value,
            },
            XtalDutyPassStep::Search(transition) => XtalDutyPassAction::Search(transition.action()),
            XtalDutyPassStep::RestoreInitialDuty(_) => XtalDutyPassAction::WriteByte {
                address: Self::DUTY_ADDRESS,
                value: self.initial_duty,
            },
            XtalDutyPassStep::RestoreHardware(_) => XtalDutyPassAction::RestoreHardware {
                frequency_code: self.frequency_code,
            },
            XtalDutyPassStep::Complete(outcome) => XtalDutyPassAction::Complete(outcome),
        }
    }

    pub fn advance(
        &mut self,
        completion: XtalDutyPassCompletion,
    ) -> Result<(), XtalDutyPassTransitionError> {
        self.step =
            match (self.step, completion) {
                (
                    XtalDutyPassStep::DisablePath,
                    XtalDutyPassCompletion::MaskedWrite { address },
                ) if address == Self::CONTROL_ADDRESS => XtalDutyPassStep::WriteInitialDuty,
                (
                    XtalDutyPassStep::WriteInitialDuty,
                    XtalDutyPassCompletion::ByteWrite { address },
                ) if address == Self::DUTY_ADDRESS => XtalDutyPassStep::PrepareHardware,
                (
                    XtalDutyPassStep::PrepareHardware,
                    XtalDutyPassCompletion::HardwarePrepared {
                        frequency_code,
                        rf_frequency_offset_base,
                        pbus_rx_path_value,
                    },
                ) if frequency_code == self.frequency_code
                    && rf_frequency_offset_base == self.parameter.rf_frequency_offset_base
                    && pbus_rx_path_value == self.parameter.pbus_rx_path_value =>
                {
                    XtalDutyPassStep::Search(XtalDutySearchTransition::new())
                }
                (
                    XtalDutyPassStep::Search(mut transition),
                    XtalDutyPassCompletion::Search(completion),
                ) => {
                    transition
                        .advance(completion)
                        .map_err(|_| XtalDutyPassTransitionError::WrongCompletion)?;
                    match transition.action() {
                        XtalDutySearchAction::Complete(outcome) => {
                            XtalDutyPassStep::RestoreInitialDuty(outcome)
                        }
                        _ => XtalDutyPassStep::Search(transition),
                    }
                }
                (
                    XtalDutyPassStep::RestoreInitialDuty(outcome),
                    XtalDutyPassCompletion::ByteWrite { address },
                ) if address == Self::DUTY_ADDRESS => XtalDutyPassStep::RestoreHardware(outcome),
                (
                    XtalDutyPassStep::RestoreHardware(outcome),
                    XtalDutyPassCompletion::HardwareRestored { frequency_code },
                ) if frequency_code == self.frequency_code => {
                    XtalDutyPassStep::Complete(XtalDutyPassOutcome {
                        frequency_code: self.frequency_code,
                        best_candidate: outcome.best_candidate,
                        best_filtered_power: outcome.best_filtered_power,
                    })
                }
                (XtalDutyPassStep::Complete(_), _) => {
                    return Err(XtalDutyPassTransitionError::AlreadyComplete);
                }
                _ => return Err(XtalDutyPassTransitionError::WrongCompletion),
            };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XtalDutyCalibrationOutcome {
    pub initial_duty: u8,
    pub low_frequency: XtalDutyPassOutcome,
    pub high_frequency: XtalDutyPassOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyCalibrationAction {
    ReadInitialDuty {
        address: PhyI2cAddress,
        high_bit: u8,
        low_bit: u8,
    },
    DisableCalibrationPath {
        address: PhyI2cAddress,
        high_bit: u8,
        low_bit: u8,
        value: u8,
    },
    Pass(XtalDutyPassAction),
    Complete(XtalDutyCalibrationOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyCalibrationCompletion {
    InitialDutyRead { address: PhyI2cAddress, value: u8 },
    CalibrationPathDisabled { address: PhyI2cAddress },
    Pass(XtalDutyPassCompletion),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyCalibrationTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XtalDutyCalibrationStep {
    ReadInitialDuty,
    DisableCalibrationPath {
        initial_duty: u8,
    },
    LowFrequencyPass(XtalDutyPassTransition),
    HighFrequencyPass {
        transition: XtalDutyPassTransition,
        low_frequency: XtalDutyPassOutcome,
        initial_duty: u8,
    },
    Complete(XtalDutyCalibrationOutcome),
}

/// Complete wrapper order for pinned `phy_xtal_duty_cal_init(0)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XtalDutyCalibrationTransition {
    parameter: XtalDutyCalibrationParameters,
    step: XtalDutyCalibrationStep,
}

impl XtalDutyCalibrationTransition {
    const INITIAL_DUTY_ADDRESS: PhyI2cAddress = PhyI2cAddress::new_internal(0x61, 9);
    const CONTROL_ADDRESS: PhyI2cAddress = PhyI2cAddress::new_internal(0x61, 7);

    pub const fn new(parameter: XtalDutyCalibrationParameters) -> Self {
        Self {
            parameter,
            step: XtalDutyCalibrationStep::ReadInitialDuty,
        }
    }

    pub const fn action(self) -> XtalDutyCalibrationAction {
        match self.step {
            XtalDutyCalibrationStep::ReadInitialDuty => {
                XtalDutyCalibrationAction::ReadInitialDuty {
                    address: Self::INITIAL_DUTY_ADDRESS,
                    high_bit: 5,
                    low_bit: 0,
                }
            }
            XtalDutyCalibrationStep::DisableCalibrationPath { .. } => {
                XtalDutyCalibrationAction::DisableCalibrationPath {
                    address: Self::CONTROL_ADDRESS,
                    high_bit: 5,
                    low_bit: 5,
                    value: 0,
                }
            }
            XtalDutyCalibrationStep::LowFrequencyPass(transition)
            | XtalDutyCalibrationStep::HighFrequencyPass { transition, .. } => {
                XtalDutyCalibrationAction::Pass(transition.action())
            }
            XtalDutyCalibrationStep::Complete(outcome) => {
                XtalDutyCalibrationAction::Complete(outcome)
            }
        }
    }

    pub fn advance(
        &mut self,
        completion: XtalDutyCalibrationCompletion,
    ) -> Result<(), XtalDutyCalibrationTransitionError> {
        self.step = match (self.step, completion) {
            (
                XtalDutyCalibrationStep::ReadInitialDuty,
                XtalDutyCalibrationCompletion::InitialDutyRead { address, value },
            ) if address == Self::INITIAL_DUTY_ADDRESS => {
                XtalDutyCalibrationStep::DisableCalibrationPath {
                    initial_duty: value,
                }
            }
            (
                XtalDutyCalibrationStep::DisableCalibrationPath { initial_duty },
                XtalDutyCalibrationCompletion::CalibrationPathDisabled { address },
            ) if address == Self::CONTROL_ADDRESS => XtalDutyCalibrationStep::LowFrequencyPass(
                XtalDutyPassTransition::new(0x988, initial_duty, self.parameter),
            ),
            (
                XtalDutyCalibrationStep::LowFrequencyPass(mut transition),
                XtalDutyCalibrationCompletion::Pass(completion),
            ) => {
                transition
                    .advance(completion)
                    .map_err(|_| XtalDutyCalibrationTransitionError::WrongCompletion)?;
                match transition.action() {
                    XtalDutyPassAction::Complete(low_frequency) => {
                        XtalDutyCalibrationStep::HighFrequencyPass {
                            transition: XtalDutyPassTransition::new(
                                0x9b0,
                                transition.initial_duty,
                                self.parameter,
                            ),
                            low_frequency,
                            initial_duty: transition.initial_duty,
                        }
                    }
                    _ => XtalDutyCalibrationStep::LowFrequencyPass(transition),
                }
            }
            (
                XtalDutyCalibrationStep::HighFrequencyPass {
                    mut transition,
                    low_frequency,
                    initial_duty,
                },
                XtalDutyCalibrationCompletion::Pass(completion),
            ) => {
                transition
                    .advance(completion)
                    .map_err(|_| XtalDutyCalibrationTransitionError::WrongCompletion)?;
                match transition.action() {
                    XtalDutyPassAction::Complete(high_frequency) => {
                        XtalDutyCalibrationStep::Complete(XtalDutyCalibrationOutcome {
                            initial_duty,
                            low_frequency,
                            high_frequency,
                        })
                    }
                    _ => XtalDutyCalibrationStep::HighFrequencyPass {
                        transition,
                        low_frequency,
                        initial_duty,
                    },
                }
            }
            (XtalDutyCalibrationStep::Complete(_), _) => {
                return Err(XtalDutyCalibrationTransitionError::AlreadyComplete);
            }
            _ => return Err(XtalDutyCalibrationTransitionError::WrongCompletion),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PhyI2cAddress, XtalDutyCalibrationAction, XtalDutyCalibrationCompletion,
        XtalDutyCalibrationOutcome, XtalDutyCalibrationParameters, XtalDutyCalibrationTransition,
        XtalDutyPassAction, XtalDutyPassCompletion, XtalDutyPassOutcome, XtalDutyPassTransition,
        XtalDutyPassTransitionError, XtalDutySampleKind, XtalDutySearchAction,
        XtalDutySearchCompletion, XtalDutySearchOutcome, XtalDutySearchTransition,
        XtalDutySearchTransitionError,
    };

    fn drive_pass(
        transition: &mut XtalDutyCalibrationTransition,
        expected_frequency_code: u16,
        initial_duty: u8,
    ) {
        let mut current_candidate = None;
        loop {
            match transition.action() {
                XtalDutyCalibrationAction::Pass(XtalDutyPassAction::WriteMasked {
                    address,
                    high_bit: 5,
                    low_bit: 5,
                    value: 0,
                }) => {
                    assert_eq!((address.block(), address.register()), (0x61, 7));
                    transition
                        .advance(XtalDutyCalibrationCompletion::Pass(
                            XtalDutyPassCompletion::MaskedWrite { address },
                        ))
                        .unwrap();
                }
                XtalDutyCalibrationAction::Pass(XtalDutyPassAction::WriteByte {
                    address,
                    value,
                }) => {
                    assert_eq!((address.block(), address.register()), (0x61, 0x0a));
                    assert_eq!(value, initial_duty);
                    transition
                        .advance(XtalDutyCalibrationCompletion::Pass(
                            XtalDutyPassCompletion::ByteWrite { address },
                        ))
                        .unwrap();
                }
                XtalDutyCalibrationAction::Pass(XtalDutyPassAction::PrepareHardware {
                    frequency_code,
                    rf_frequency_offset_base,
                    pbus_rx_path_value,
                }) => {
                    assert_eq!(frequency_code, expected_frequency_code);
                    assert_eq!(rf_frequency_offset_base, 0x31);
                    assert_eq!(pbus_rx_path_value, 0x42);
                    transition
                        .advance(XtalDutyCalibrationCompletion::Pass(
                            XtalDutyPassCompletion::HardwarePrepared {
                                frequency_code,
                                rf_frequency_offset_base,
                                pbus_rx_path_value,
                            },
                        ))
                        .unwrap();
                }
                XtalDutyCalibrationAction::Pass(XtalDutyPassAction::Search(
                    XtalDutySearchAction::WriteCandidate(candidate),
                )) => {
                    current_candidate = Some(candidate);
                    transition
                        .advance(XtalDutyCalibrationCompletion::Pass(
                            XtalDutyPassCompletion::Search(
                                XtalDutySearchCompletion::CandidateWritten(candidate),
                            ),
                        ))
                        .unwrap();
                }
                XtalDutyCalibrationAction::Pass(XtalDutyPassAction::Search(
                    XtalDutySearchAction::DelayMicros(20),
                )) => {
                    let candidate = current_candidate.unwrap();
                    transition
                        .advance(XtalDutyCalibrationCompletion::Pass(
                            XtalDutyPassCompletion::Search(
                                XtalDutySearchCompletion::DelayElapsed { candidate },
                            ),
                        ))
                        .unwrap();
                }
                XtalDutyCalibrationAction::Pass(XtalDutyPassAction::Search(
                    XtalDutySearchAction::MeasureSignalPower {
                        candidate,
                        shift: 12,
                        kind,
                    },
                )) => {
                    transition
                        .advance(XtalDutyCalibrationCompletion::Pass(
                            XtalDutyPassCompletion::Search(
                                XtalDutySearchCompletion::SignalPowerMeasured {
                                    candidate,
                                    kind,
                                    value: i64::from(0x80 - candidate),
                                },
                            ),
                        ))
                        .unwrap();
                }
                XtalDutyCalibrationAction::Pass(XtalDutyPassAction::RestoreHardware {
                    frequency_code,
                }) => {
                    transition
                        .advance(XtalDutyCalibrationCompletion::Pass(
                            XtalDutyPassCompletion::HardwareRestored { frequency_code },
                        ))
                        .unwrap();
                    break;
                }
                action => panic!("unexpected pass action: {action:?}"),
            }
        }
    }

    #[test]
    fn evaluates_all_31_candidates_only_after_timer_and_measurement_edges() {
        let mut transition = XtalDutySearchTransition::new();
        let mut writes = 0;
        let mut delays = 0;
        let mut measurements = 0;
        loop {
            match transition.action() {
                XtalDutySearchAction::WriteCandidate(candidate) => {
                    writes += 1;
                    transition
                        .advance(XtalDutySearchCompletion::CandidateWritten(candidate))
                        .unwrap();
                }
                XtalDutySearchAction::DelayMicros(20) => {
                    delays += 1;
                    let candidate = 0x20 + delays - 1;
                    transition
                        .advance(XtalDutySearchCompletion::DelayElapsed { candidate })
                        .unwrap();
                }
                XtalDutySearchAction::MeasureSignalPower {
                    candidate,
                    shift: 12,
                    kind,
                } => {
                    measurements += 1;
                    transition
                        .advance(XtalDutySearchCompletion::SignalPowerMeasured {
                            candidate,
                            kind,
                            value: i64::from(0x80 - candidate),
                        })
                        .unwrap();
                }
                XtalDutySearchAction::Complete(outcome) => {
                    assert_eq!(
                        outcome,
                        XtalDutySearchOutcome {
                            best_candidate: 0x3e,
                            best_filtered_power: 0x42,
                        }
                    );
                    break;
                }
                action => panic!("unexpected action: {action:?}"),
            }
        }
        assert_eq!(writes, 31);
        assert_eq!(delays, 31);
        assert_eq!(measurements, 31 * 4);
    }

    #[test]
    fn each_outlier_uses_at_most_two_identity_bound_replacements() {
        let mut transition = XtalDutySearchTransition::new();
        transition
            .advance(XtalDutySearchCompletion::CandidateWritten(0x20))
            .unwrap();
        transition
            .advance(XtalDutySearchCompletion::DelayElapsed { candidate: 0x20 })
            .unwrap();
        for (index, value) in [1, 100, 100, 100].into_iter().enumerate() {
            transition
                .advance(XtalDutySearchCompletion::SignalPowerMeasured {
                    candidate: 0x20,
                    kind: XtalDutySampleKind::Initial(index as u8),
                    value,
                })
                .unwrap();
        }
        assert_eq!(
            transition.action(),
            XtalDutySearchAction::MeasureSignalPower {
                candidate: 0x20,
                shift: 12,
                kind: XtalDutySampleKind::FirstReplacement(0),
            }
        );
        assert_eq!(
            transition.advance(XtalDutySearchCompletion::SignalPowerMeasured {
                candidate: 0x21,
                kind: XtalDutySampleKind::FirstReplacement(0),
                value: 200,
            }),
            Err(XtalDutySearchTransitionError::WrongCompletion)
        );
        transition
            .advance(XtalDutySearchCompletion::SignalPowerMeasured {
                candidate: 0x20,
                kind: XtalDutySampleKind::FirstReplacement(0),
                value: 200,
            })
            .unwrap();
        assert_eq!(
            transition.action(),
            XtalDutySearchAction::MeasureSignalPower {
                candidate: 0x20,
                shift: 12,
                kind: XtalDutySampleKind::SecondReplacement(0),
            }
        );
        transition
            .advance(XtalDutySearchCompletion::SignalPowerMeasured {
                candidate: 0x20,
                kind: XtalDutySampleKind::SecondReplacement(0),
                value: 60,
            })
            .unwrap();
        assert_eq!(
            transition.action(),
            XtalDutySearchAction::WriteCandidate(0x21)
        );
    }

    #[test]
    fn pass_rejects_wrong_address_and_stale_parameter_completion() {
        let parameter = XtalDutyCalibrationParameters {
            rf_frequency_offset_base: 0x31,
            pbus_rx_path_value: 0x42,
        };
        let mut transition = XtalDutyPassTransition::new(0x988, 0x2a, parameter);
        let XtalDutyPassAction::WriteMasked { address, .. } = transition.action() else {
            panic!("expected path-disable write");
        };
        assert_eq!(
            transition.advance(XtalDutyPassCompletion::MaskedWrite {
                address: PhyI2cAddress::new(0x62, 7).unwrap(),
            }),
            Err(XtalDutyPassTransitionError::WrongCompletion)
        );
        transition
            .advance(XtalDutyPassCompletion::MaskedWrite { address })
            .unwrap();

        let XtalDutyPassAction::WriteByte { address, .. } = transition.action() else {
            panic!("expected initial-duty write");
        };
        transition
            .advance(XtalDutyPassCompletion::ByteWrite { address })
            .unwrap();
        assert_eq!(
            transition.advance(XtalDutyPassCompletion::HardwarePrepared {
                frequency_code: 0x988,
                rf_frequency_offset_base: 0x31,
                pbus_rx_path_value: 0x41,
            }),
            Err(XtalDutyPassTransitionError::WrongCompletion)
        );
        assert_eq!(
            transition.action(),
            XtalDutyPassAction::PrepareHardware {
                frequency_code: 0x988,
                rf_frequency_offset_base: 0x31,
                pbus_rx_path_value: 0x42,
            }
        );
    }

    #[test]
    fn wrapper_orders_both_frequency_passes_without_hidden_progress() {
        let initial_duty = 0x2a;
        let mut transition = XtalDutyCalibrationTransition::new(XtalDutyCalibrationParameters {
            rf_frequency_offset_base: 0x31,
            pbus_rx_path_value: 0x42,
        });

        let XtalDutyCalibrationAction::ReadInitialDuty {
            address,
            high_bit: 5,
            low_bit: 0,
        } = transition.action()
        else {
            panic!("expected the initial duty read");
        };
        assert_eq!((address.block(), address.register()), (0x61, 9));
        transition
            .advance(XtalDutyCalibrationCompletion::InitialDutyRead {
                address,
                value: initial_duty,
            })
            .unwrap();

        let XtalDutyCalibrationAction::DisableCalibrationPath {
            address,
            high_bit: 5,
            low_bit: 5,
            value: 0,
        } = transition.action()
        else {
            panic!("expected the calibration-path write");
        };
        assert_eq!((address.block(), address.register()), (0x61, 7));
        transition
            .advance(XtalDutyCalibrationCompletion::CalibrationPathDisabled { address })
            .unwrap();

        drive_pass(&mut transition, 0x988, initial_duty);
        drive_pass(&mut transition, 0x9b0, initial_duty);

        assert_eq!(
            transition.action(),
            XtalDutyCalibrationAction::Complete(XtalDutyCalibrationOutcome {
                initial_duty,
                low_frequency: XtalDutyPassOutcome {
                    frequency_code: 0x988,
                    best_candidate: 0x3e,
                    best_filtered_power: 0x42,
                },
                high_frequency: XtalDutyPassOutcome {
                    frequency_code: 0x9b0,
                    best_candidate: 0x3e,
                    best_filtered_power: 0x42,
                },
            })
        );
    }
}
