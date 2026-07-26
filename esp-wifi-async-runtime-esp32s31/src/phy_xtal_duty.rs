//! Event-driven ESP32-S31 crystal-duty search.
//!
//! Reference: complete `libphy.a[phy_rx_cal.o]::phy_xtal_duty_cal`, size
//! `0x392`. The pinned cold caller always passes `debug = 0`, so both vendor
//! `phy_printf` branches are dead and are intentionally absent here.

use crate::{
    phy_i2c::PhyI2cAddress,
    phy_pbus::PhyPbusForceTest,
    phy_rx_dco::{
        PhyRxDcoAction, PhyRxDcoCompletion, PhyRxDcoFailure, PhyRxDcoOutcome,
        PhyRxDcoRequest, PhyRxDcoTransition, RX_DCO_CONTROL_ADDRESS,
        RX_DCO_CONTROL_FIELD_MASK,
    },
};

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

const fn prepare_pbus_transaction(index: u8, pbus_rx_path_value: u8) -> PhyPbusForceTest {
    match index {
        0 => PhyPbusForceTest::new(4, 1, 0),
        1 => PhyPbusForceTest::new(4, 2, 1),
        2 => PhyPbusForceTest::new(5, 1, 0),
        3 => PhyPbusForceTest::new(0, 1, 0x40),
        4 => PhyPbusForceTest::new(0, 2, pbus_rx_path_value as u16),
        5 => PhyPbusForceTest::new(1, 1, 0x189),
        6 => PhyPbusForceTest::new(1, 2, 0xf0),
        7 => PhyPbusForceTest::new(0, 1, 0x43),
        8 => PhyPbusForceTest::new(1, 1, 0x38),
        _ => PhyPbusForceTest::new(1, 1, 0x189),
    }
}

const fn restore_pbus_transaction(index: u8) -> PhyPbusForceTest {
    match index {
        0 => PhyPbusForceTest::new(0, 1, 0),
        1 => PhyPbusForceTest::new(1, 1, 0),
        _ => PhyPbusForceTest::new(1, 2, 0),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyHardwareFailure {
    PbusForceTestTimedOut(PhyPbusForceTest),
    RxDco(PhyRxDcoFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyPrepareAction {
    /// Temporary boundary for `phy_set_rf_freq_offset`. Its three observed
    /// inputs are explicit; the synchronous vendor parent is not permitted.
    ProgramRfFrequency {
        rf_frequency_offset_base: u8,
        frequency_code: u16,
        mode: u8,
    },
    /// Temporary boundary for `phy_start_tx_tone_step_new(1, 0x80, 0, 0, 0, 0)`.
    ConfigureCalibrationTone {
        enabled: bool,
        selector: u8,
        step: u8,
    },
    ConfigureRxClock {
        enabled: bool,
    },
    ConfigureTxClock {
        enabled: bool,
    },
    ConfigurePbusDebugMode,
    ForcePbus(PhyPbusForceTest),
    /// Read the register once, preserve bits 23:22 in Rust, and clear them in
    /// the same serialized radio-owner operation.
    MaskRxDcoControl {
        address: usize,
        clear_mask: u32,
    },
    /// Complete Rust-owned RX-DCO loop. Its remaining IQ-estimator child is
    /// visible through `PhyRxDcoAction::MeasureDcIq`.
    RxDco(PhyRxDcoAction),
    RestoreRxDcoControl {
        address: usize,
        field_mask: u32,
        saved_field: u32,
    },
    Complete(PhyRxDcoOutcome),
    Failed(XtalDutyHardwareFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyPrepareCompletion {
    RfFrequencyProgrammed {
        rf_frequency_offset_base: u8,
        frequency_code: u16,
        mode: u8,
    },
    CalibrationToneConfigured {
        enabled: bool,
        selector: u8,
        step: u8,
    },
    RxClockConfigured {
        enabled: bool,
    },
    TxClockConfigured {
        enabled: bool,
    },
    PbusDebugModeConfigured,
    PbusForceCompleted(PhyPbusForceTest),
    PbusForceTimedOut(PhyPbusForceTest),
    RxDcoControlMasked {
        address: usize,
        saved_field: u32,
    },
    RxDco(PhyRxDcoCompletion),
    RxDcoControlRestored {
        address: usize,
        saved_field: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyPrepareTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XtalDutyPrepareStep {
    ProgramRfFrequency,
    StartTone,
    EnableRxClock,
    EnableTxClock,
    PbusDebugMode,
    PbusForce(u8),
    MaskRxDcoControl,
    RxDco {
        saved_field: u32,
        transition: PhyRxDcoTransition,
    },
    RestoreRxDcoControl {
        saved_field: u32,
        outcome: PhyRxDcoOutcome,
    },
    RestoreRxDcoControlAfterFailure {
        saved_field: u32,
        failure: PhyRxDcoFailure,
    },
    Complete(PhyRxDcoOutcome),
    Failed(XtalDutyHardwareFailure),
}

/// Exact finite preparation order before the crystal-duty candidate search.
///
/// PBus commands are individual externally completed operations. Nothing in
/// this transition retries a busy register, polls, delays, allocates, or
/// invokes a callback. RFPLL, tone and RX-DCO remain named child boundaries
/// until their own register/timer transitions are complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XtalDutyPrepareTransition {
    frequency_code: u16,
    parameter: XtalDutyCalibrationParameters,
    step: XtalDutyPrepareStep,
}

impl XtalDutyPrepareTransition {
    pub const fn new(
        frequency_code: u16,
        parameter: XtalDutyCalibrationParameters,
    ) -> Self {
        Self {
            frequency_code,
            parameter,
            step: XtalDutyPrepareStep::ProgramRfFrequency,
        }
    }

    pub const fn action(self) -> XtalDutyPrepareAction {
        match self.step {
            XtalDutyPrepareStep::ProgramRfFrequency => {
                XtalDutyPrepareAction::ProgramRfFrequency {
                    rf_frequency_offset_base: self.parameter.rf_frequency_offset_base,
                    frequency_code: self.frequency_code.wrapping_sub(5),
                    mode: 0,
                }
            }
            XtalDutyPrepareStep::StartTone => {
                XtalDutyPrepareAction::ConfigureCalibrationTone {
                    enabled: true,
                    selector: 0x80,
                    step: 0,
                }
            }
            XtalDutyPrepareStep::EnableRxClock => {
                XtalDutyPrepareAction::ConfigureRxClock { enabled: true }
            }
            XtalDutyPrepareStep::EnableTxClock => {
                XtalDutyPrepareAction::ConfigureTxClock { enabled: true }
            }
            XtalDutyPrepareStep::PbusDebugMode => {
                XtalDutyPrepareAction::ConfigurePbusDebugMode
            }
            XtalDutyPrepareStep::PbusForce(index) => XtalDutyPrepareAction::ForcePbus(
                prepare_pbus_transaction(index, self.parameter.pbus_rx_path_value),
            ),
            XtalDutyPrepareStep::MaskRxDcoControl => {
                XtalDutyPrepareAction::MaskRxDcoControl {
                    address: RX_DCO_CONTROL_ADDRESS,
                    clear_mask: RX_DCO_CONTROL_FIELD_MASK,
                }
            }
            XtalDutyPrepareStep::RxDco { transition, .. } => {
                XtalDutyPrepareAction::RxDco(transition.action())
            }
            XtalDutyPrepareStep::RestoreRxDcoControl { saved_field, .. }
            | XtalDutyPrepareStep::RestoreRxDcoControlAfterFailure {
                saved_field, ..
            } => {
                XtalDutyPrepareAction::RestoreRxDcoControl {
                    address: RX_DCO_CONTROL_ADDRESS,
                    field_mask: RX_DCO_CONTROL_FIELD_MASK,
                    saved_field,
                }
            }
            XtalDutyPrepareStep::Complete(outcome) => {
                XtalDutyPrepareAction::Complete(outcome)
            }
            XtalDutyPrepareStep::Failed(failure) => XtalDutyPrepareAction::Failed(failure),
        }
    }

    pub fn advance(
        &mut self,
        completion: XtalDutyPrepareCompletion,
    ) -> Result<(), XtalDutyPrepareTransitionError> {
        self.step = match (self.step, completion) {
            (
                XtalDutyPrepareStep::ProgramRfFrequency,
                XtalDutyPrepareCompletion::RfFrequencyProgrammed {
                    rf_frequency_offset_base,
                    frequency_code,
                    mode: 0,
                },
            ) if rf_frequency_offset_base == self.parameter.rf_frequency_offset_base
                && frequency_code == self.frequency_code.wrapping_sub(5) =>
            {
                XtalDutyPrepareStep::StartTone
            }
            (
                XtalDutyPrepareStep::StartTone,
                XtalDutyPrepareCompletion::CalibrationToneConfigured {
                    enabled: true,
                    selector: 0x80,
                    step: 0,
                },
            ) => XtalDutyPrepareStep::EnableRxClock,
            (
                XtalDutyPrepareStep::EnableRxClock,
                XtalDutyPrepareCompletion::RxClockConfigured { enabled: true },
            ) => XtalDutyPrepareStep::EnableTxClock,
            (
                XtalDutyPrepareStep::EnableTxClock,
                XtalDutyPrepareCompletion::TxClockConfigured { enabled: true },
            ) => XtalDutyPrepareStep::PbusDebugMode,
            (
                XtalDutyPrepareStep::PbusDebugMode,
                XtalDutyPrepareCompletion::PbusDebugModeConfigured,
            ) => XtalDutyPrepareStep::PbusForce(0),
            (
                XtalDutyPrepareStep::PbusForce(index),
                XtalDutyPrepareCompletion::PbusForceCompleted(transaction),
            ) if transaction
                == prepare_pbus_transaction(index, self.parameter.pbus_rx_path_value) =>
            {
                if index == 9 {
                    XtalDutyPrepareStep::MaskRxDcoControl
                } else {
                    XtalDutyPrepareStep::PbusForce(index + 1)
                }
            }
            (
                XtalDutyPrepareStep::PbusForce(index),
                XtalDutyPrepareCompletion::PbusForceTimedOut(transaction),
            ) if transaction
                == prepare_pbus_transaction(index, self.parameter.pbus_rx_path_value) =>
            {
                XtalDutyPrepareStep::Failed(XtalDutyHardwareFailure::PbusForceTestTimedOut(
                    transaction,
                ))
            }
            (
                XtalDutyPrepareStep::MaskRxDcoControl,
                XtalDutyPrepareCompletion::RxDcoControlMasked {
                    address: RX_DCO_CONTROL_ADDRESS,
                    saved_field,
                },
            ) if saved_field & !RX_DCO_CONTROL_FIELD_MASK == 0 => {
                XtalDutyPrepareStep::RxDco {
                    saved_field,
                    transition: PhyRxDcoTransition::new(PhyRxDcoRequest::XTAL_DUTY),
                }
            }
            (
                XtalDutyPrepareStep::RxDco {
                    saved_field,
                    mut transition,
                },
                XtalDutyPrepareCompletion::RxDco(completion),
            ) => {
                transition
                    .advance(completion)
                    .map_err(|_| XtalDutyPrepareTransitionError::WrongCompletion)?;
                match transition.action() {
                    PhyRxDcoAction::Complete(outcome) => {
                        XtalDutyPrepareStep::RestoreRxDcoControl {
                            saved_field,
                            outcome,
                        }
                    }
                    PhyRxDcoAction::Failed(failure) => {
                        XtalDutyPrepareStep::RestoreRxDcoControlAfterFailure {
                            saved_field,
                            failure,
                        }
                    }
                    _ => XtalDutyPrepareStep::RxDco {
                        saved_field,
                        transition,
                    },
                }
            }
            (
                XtalDutyPrepareStep::RestoreRxDcoControl {
                    saved_field,
                    outcome,
                },
                XtalDutyPrepareCompletion::RxDcoControlRestored {
                    address: RX_DCO_CONTROL_ADDRESS,
                    saved_field: completed_field,
                },
            ) if saved_field == completed_field => XtalDutyPrepareStep::Complete(outcome),
            (
                XtalDutyPrepareStep::RestoreRxDcoControlAfterFailure {
                    saved_field,
                    failure,
                },
                XtalDutyPrepareCompletion::RxDcoControlRestored {
                    address: RX_DCO_CONTROL_ADDRESS,
                    saved_field: completed_field,
                },
            ) if saved_field == completed_field => {
                XtalDutyPrepareStep::Failed(XtalDutyHardwareFailure::RxDco(failure))
            }
            (XtalDutyPrepareStep::Complete(_), _) | (XtalDutyPrepareStep::Failed(_), _) => {
                return Err(XtalDutyPrepareTransitionError::AlreadyComplete);
            }
            _ => return Err(XtalDutyPrepareTransitionError::WrongCompletion),
        };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyRestoreAction {
    /// Temporary boundary for `phy_start_tx_tone_step_new(0, 0x80, 0x28, 0, 0, 0)`.
    ConfigureCalibrationTone {
        enabled: bool,
        selector: u8,
        step: u8,
    },
    ConfigureRxClock {
        enabled: bool,
    },
    ConfigureTxClock {
        enabled: bool,
    },
    ForcePbus(PhyPbusForceTest),
    ConfigurePbusWorkMode,
    DelayMicros(u32),
    ConfigurePbusWorkModePulse,
    ClearPbusWorkModePulse,
    Complete,
    Failed(XtalDutyHardwareFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyRestoreCompletion {
    CalibrationToneConfigured {
        enabled: bool,
        selector: u8,
        step: u8,
    },
    RxClockConfigured {
        enabled: bool,
    },
    TxClockConfigured {
        enabled: bool,
    },
    PbusForceCompleted(PhyPbusForceTest),
    PbusForceTimedOut(PhyPbusForceTest),
    PbusWorkModeConfigured {
        settle_required: bool,
    },
    DelayElapsed {
        micros: u32,
    },
    PbusWorkModePulseConfigured,
    PbusWorkModePulseCleared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XtalDutyRestoreTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XtalDutyRestoreStep {
    StopTone,
    DisableRxClock,
    DisableTxClock,
    PbusForce(u8),
    WorkMode,
    SettleDelay,
    WorkModePulse,
    PulseDelay,
    ClearWorkModePulse,
    Complete,
    Failed(XtalDutyHardwareFailure),
}

/// Exact finite restoration tail of one crystal-duty pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XtalDutyRestoreTransition {
    step: XtalDutyRestoreStep,
}

impl XtalDutyRestoreTransition {
    pub const fn new() -> Self {
        Self {
            step: XtalDutyRestoreStep::StopTone,
        }
    }

    pub const fn action(self) -> XtalDutyRestoreAction {
        match self.step {
            XtalDutyRestoreStep::StopTone => {
                XtalDutyRestoreAction::ConfigureCalibrationTone {
                    enabled: false,
                    selector: 0x80,
                    step: 0x28,
                }
            }
            XtalDutyRestoreStep::DisableRxClock => {
                XtalDutyRestoreAction::ConfigureRxClock { enabled: false }
            }
            XtalDutyRestoreStep::DisableTxClock => {
                XtalDutyRestoreAction::ConfigureTxClock { enabled: false }
            }
            XtalDutyRestoreStep::PbusForce(index) => {
                XtalDutyRestoreAction::ForcePbus(restore_pbus_transaction(index))
            }
            XtalDutyRestoreStep::WorkMode => XtalDutyRestoreAction::ConfigurePbusWorkMode,
            XtalDutyRestoreStep::SettleDelay => XtalDutyRestoreAction::DelayMicros(1),
            XtalDutyRestoreStep::WorkModePulse => {
                XtalDutyRestoreAction::ConfigurePbusWorkModePulse
            }
            XtalDutyRestoreStep::PulseDelay => XtalDutyRestoreAction::DelayMicros(2),
            XtalDutyRestoreStep::ClearWorkModePulse => {
                XtalDutyRestoreAction::ClearPbusWorkModePulse
            }
            XtalDutyRestoreStep::Complete => XtalDutyRestoreAction::Complete,
            XtalDutyRestoreStep::Failed(failure) => XtalDutyRestoreAction::Failed(failure),
        }
    }

    pub fn advance(
        &mut self,
        completion: XtalDutyRestoreCompletion,
    ) -> Result<(), XtalDutyRestoreTransitionError> {
        self.step = match (self.step, completion) {
            (
                XtalDutyRestoreStep::StopTone,
                XtalDutyRestoreCompletion::CalibrationToneConfigured {
                    enabled: false,
                    selector: 0x80,
                    step: 0x28,
                },
            ) => XtalDutyRestoreStep::DisableRxClock,
            (
                XtalDutyRestoreStep::DisableRxClock,
                XtalDutyRestoreCompletion::RxClockConfigured { enabled: false },
            ) => XtalDutyRestoreStep::DisableTxClock,
            (
                XtalDutyRestoreStep::DisableTxClock,
                XtalDutyRestoreCompletion::TxClockConfigured { enabled: false },
            ) => XtalDutyRestoreStep::PbusForce(0),
            (
                XtalDutyRestoreStep::PbusForce(index),
                XtalDutyRestoreCompletion::PbusForceCompleted(transaction),
            ) if transaction == restore_pbus_transaction(index) => {
                if index == 2 {
                    XtalDutyRestoreStep::WorkMode
                } else {
                    XtalDutyRestoreStep::PbusForce(index + 1)
                }
            }
            (
                XtalDutyRestoreStep::PbusForce(index),
                XtalDutyRestoreCompletion::PbusForceTimedOut(transaction),
            ) if transaction == restore_pbus_transaction(index) => {
                XtalDutyRestoreStep::Failed(XtalDutyHardwareFailure::PbusForceTestTimedOut(
                    transaction,
                ))
            }
            (
                XtalDutyRestoreStep::WorkMode,
                XtalDutyRestoreCompletion::PbusWorkModeConfigured {
                    settle_required: false,
                },
            ) => XtalDutyRestoreStep::Complete,
            (
                XtalDutyRestoreStep::WorkMode,
                XtalDutyRestoreCompletion::PbusWorkModeConfigured {
                    settle_required: true,
                },
            ) => XtalDutyRestoreStep::SettleDelay,
            (
                XtalDutyRestoreStep::SettleDelay,
                XtalDutyRestoreCompletion::DelayElapsed { micros: 1 },
            ) => XtalDutyRestoreStep::WorkModePulse,
            (
                XtalDutyRestoreStep::WorkModePulse,
                XtalDutyRestoreCompletion::PbusWorkModePulseConfigured,
            ) => XtalDutyRestoreStep::PulseDelay,
            (
                XtalDutyRestoreStep::PulseDelay,
                XtalDutyRestoreCompletion::DelayElapsed { micros: 2 },
            ) => XtalDutyRestoreStep::ClearWorkModePulse,
            (
                XtalDutyRestoreStep::ClearWorkModePulse,
                XtalDutyRestoreCompletion::PbusWorkModePulseCleared,
            ) => XtalDutyRestoreStep::Complete,
            (XtalDutyRestoreStep::Complete, _) | (XtalDutyRestoreStep::Failed(_), _) => {
                return Err(XtalDutyRestoreTransitionError::AlreadyComplete);
            }
            _ => return Err(XtalDutyRestoreTransitionError::WrongCompletion),
        };
        Ok(())
    }
}

impl Default for XtalDutyRestoreTransition {
    fn default() -> Self {
        Self::new()
    }
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
    Prepare(XtalDutyPrepareAction),
    Search(XtalDutySearchAction),
    Restore(XtalDutyRestoreAction),
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
    Prepare(XtalDutyPrepareCompletion),
    Search(XtalDutySearchCompletion),
    Restore(XtalDutyRestoreCompletion),
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
    Prepare(XtalDutyPrepareTransition),
    Search(XtalDutySearchTransition),
    RestoreInitialDuty(XtalDutySearchOutcome),
    Restore {
        transition: XtalDutyRestoreTransition,
        search: XtalDutySearchOutcome,
    },
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
            XtalDutyPassStep::Prepare(transition) => {
                XtalDutyPassAction::Prepare(transition.action())
            }
            XtalDutyPassStep::Search(transition) => XtalDutyPassAction::Search(transition.action()),
            XtalDutyPassStep::RestoreInitialDuty(_) => XtalDutyPassAction::WriteByte {
                address: Self::DUTY_ADDRESS,
                value: self.initial_duty,
            },
            XtalDutyPassStep::Restore { transition, .. } => {
                XtalDutyPassAction::Restore(transition.action())
            }
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
                ) if address == Self::DUTY_ADDRESS => XtalDutyPassStep::Prepare(
                    XtalDutyPrepareTransition::new(self.frequency_code, self.parameter),
                ),
                (
                    XtalDutyPassStep::Prepare(mut transition),
                    XtalDutyPassCompletion::Prepare(completion),
                ) => {
                    transition
                        .advance(completion)
                        .map_err(|_| XtalDutyPassTransitionError::WrongCompletion)?;
                    match transition.action() {
                        XtalDutyPrepareAction::Complete(_) => {
                            XtalDutyPassStep::Search(XtalDutySearchTransition::new())
                        }
                        _ => XtalDutyPassStep::Prepare(transition),
                    }
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
                ) if address == Self::DUTY_ADDRESS => XtalDutyPassStep::Restore {
                    transition: XtalDutyRestoreTransition::new(),
                    search: outcome,
                },
                (
                    XtalDutyPassStep::Restore {
                        mut transition,
                        search,
                    },
                    XtalDutyPassCompletion::Restore(completion),
                ) => {
                    transition
                        .advance(completion)
                        .map_err(|_| XtalDutyPassTransitionError::WrongCompletion)?;
                    match transition.action() {
                        XtalDutyRestoreAction::Complete => {
                            XtalDutyPassStep::Complete(XtalDutyPassOutcome {
                                frequency_code: self.frequency_code,
                                best_candidate: search.best_candidate,
                                best_filtered_power: search.best_filtered_power,
                            })
                        }
                        _ => XtalDutyPassStep::Restore { transition, search },
                    }
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
        XtalDutyHardwareFailure, XtalDutyPassTransitionError, XtalDutyPrepareAction,
        XtalDutyPrepareCompletion, XtalDutyPrepareTransition, XtalDutyRestoreAction,
        XtalDutyRestoreCompletion, XtalDutyRestoreTransition, XtalDutySampleKind,
        XtalDutySearchAction, XtalDutySearchCompletion, XtalDutySearchOutcome,
        XtalDutySearchTransition, XtalDutySearchTransitionError,
    };
    use crate::phy_pbus::PhyPbusForceTest;
    use crate::phy_rx_dco::{
        PhyDcIqEstimate, PhyRxDcoAction, PhyRxDcoCompletion,
        RX_DCO_CONTROL_ADDRESS, RX_DCO_CONTROL_FIELD_MASK,
    };

    fn complete_rx_dco_action(action: PhyRxDcoAction) -> PhyRxDcoCompletion {
        match action {
            PhyRxDcoAction::MaskRxDcoControl { address, .. } => {
                PhyRxDcoCompletion::RxDcoControlMasked {
                    address,
                    saved_field: 0,
                }
            }
            PhyRxDcoAction::ReadPbus { selector, path } => PhyRxDcoCompletion::PbusRead {
                selector,
                path,
                value: 0,
            },
            PhyRxDcoAction::ForcePbus(transaction) => {
                PhyRxDcoCompletion::PbusForceCompleted(transaction)
            }
            PhyRxDcoAction::DelayMicros { iteration, micros } => {
                PhyRxDcoCompletion::DelayElapsed { iteration, micros }
            }
            PhyRxDcoAction::MeasureDcIq(request) => PhyRxDcoCompletion::DcIqMeasured {
                request,
                estimate: PhyDcIqEstimate { i: 0, q: 0 },
            },
            PhyRxDcoAction::RestoreRxDcoControl {
                address,
                saved_field,
                ..
            } => PhyRxDcoCompletion::RxDcoControlRestored {
                address,
                saved_field,
            },
            action => panic!("unexpected terminal RX-DCO action: {action:?}"),
        }
    }

    fn complete_prepare_action(action: XtalDutyPrepareAction) -> XtalDutyPrepareCompletion {
        match action {
            XtalDutyPrepareAction::ProgramRfFrequency {
                rf_frequency_offset_base,
                frequency_code,
                mode,
            } => XtalDutyPrepareCompletion::RfFrequencyProgrammed {
                rf_frequency_offset_base,
                frequency_code,
                mode,
            },
            XtalDutyPrepareAction::ConfigureCalibrationTone {
                enabled,
                selector,
                step,
            } => XtalDutyPrepareCompletion::CalibrationToneConfigured {
                enabled,
                selector,
                step,
            },
            XtalDutyPrepareAction::ConfigureRxClock { enabled } => {
                XtalDutyPrepareCompletion::RxClockConfigured { enabled }
            }
            XtalDutyPrepareAction::ConfigureTxClock { enabled } => {
                XtalDutyPrepareCompletion::TxClockConfigured { enabled }
            }
            XtalDutyPrepareAction::ConfigurePbusDebugMode => {
                XtalDutyPrepareCompletion::PbusDebugModeConfigured
            }
            XtalDutyPrepareAction::ForcePbus(transaction) => {
                XtalDutyPrepareCompletion::PbusForceCompleted(transaction)
            }
            XtalDutyPrepareAction::MaskRxDcoControl { address, .. } => {
                XtalDutyPrepareCompletion::RxDcoControlMasked {
                    address,
                    saved_field: 0x0080_0000,
                }
            }
            XtalDutyPrepareAction::RxDco(action) => {
                XtalDutyPrepareCompletion::RxDco(complete_rx_dco_action(action))
            }
            XtalDutyPrepareAction::RestoreRxDcoControl {
                address,
                saved_field,
                ..
            } => XtalDutyPrepareCompletion::RxDcoControlRestored {
                address,
                saved_field,
            },
            action => panic!("unexpected terminal preparation action: {action:?}"),
        }
    }

    fn complete_restore_action(action: XtalDutyRestoreAction) -> XtalDutyRestoreCompletion {
        match action {
            XtalDutyRestoreAction::ConfigureCalibrationTone {
                enabled,
                selector,
                step,
            } => XtalDutyRestoreCompletion::CalibrationToneConfigured {
                enabled,
                selector,
                step,
            },
            XtalDutyRestoreAction::ConfigureRxClock { enabled } => {
                XtalDutyRestoreCompletion::RxClockConfigured { enabled }
            }
            XtalDutyRestoreAction::ConfigureTxClock { enabled } => {
                XtalDutyRestoreCompletion::TxClockConfigured { enabled }
            }
            XtalDutyRestoreAction::ForcePbus(transaction) => {
                XtalDutyRestoreCompletion::PbusForceCompleted(transaction)
            }
            XtalDutyRestoreAction::ConfigurePbusWorkMode => {
                XtalDutyRestoreCompletion::PbusWorkModeConfigured {
                    settle_required: false,
                }
            }
            action => panic!("unexpected restoration action: {action:?}"),
        }
    }

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
                XtalDutyCalibrationAction::Pass(XtalDutyPassAction::Prepare(action)) => {
                    if let XtalDutyPrepareAction::ProgramRfFrequency {
                        rf_frequency_offset_base,
                        frequency_code,
                        mode: 0,
                    } = action
                    {
                        assert_eq!(frequency_code, expected_frequency_code - 5);
                        assert_eq!(rf_frequency_offset_base, 0x31);
                    }
                    transition
                        .advance(XtalDutyCalibrationCompletion::Pass(
                            XtalDutyPassCompletion::Prepare(complete_prepare_action(action)),
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
                XtalDutyCalibrationAction::Pass(XtalDutyPassAction::Restore(action)) => {
                    let pass_complete =
                        matches!(action, XtalDutyRestoreAction::ConfigurePbusWorkMode);
                    transition
                        .advance(XtalDutyCalibrationCompletion::Pass(
                            XtalDutyPassCompletion::Restore(complete_restore_action(action)),
                        ))
                        .unwrap();
                    if pass_complete {
                        break;
                    }
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
    fn preparation_exposes_all_ten_pbus_commands_and_owned_rx_dco_field() {
        let parameter = XtalDutyCalibrationParameters {
            rf_frequency_offset_base: 0x31,
            pbus_rx_path_value: 0x42,
        };
        let mut transition = XtalDutyPrepareTransition::new(0x988, parameter);

        for expected in [
            XtalDutyPrepareAction::ProgramRfFrequency {
                rf_frequency_offset_base: 0x31,
                frequency_code: 0x983,
                mode: 0,
            },
            XtalDutyPrepareAction::ConfigureCalibrationTone {
                enabled: true,
                selector: 0x80,
                step: 0,
            },
            XtalDutyPrepareAction::ConfigureRxClock { enabled: true },
            XtalDutyPrepareAction::ConfigureTxClock { enabled: true },
            XtalDutyPrepareAction::ConfigurePbusDebugMode,
        ] {
            assert_eq!(transition.action(), expected);
            transition
                .advance(complete_prepare_action(expected))
                .unwrap();
        }

        let expected_pbus = [
            PhyPbusForceTest::new(4, 1, 0),
            PhyPbusForceTest::new(4, 2, 1),
            PhyPbusForceTest::new(5, 1, 0),
            PhyPbusForceTest::new(0, 1, 0x40),
            PhyPbusForceTest::new(0, 2, 0x42),
            PhyPbusForceTest::new(1, 1, 0x189),
            PhyPbusForceTest::new(1, 2, 0xf0),
            PhyPbusForceTest::new(0, 1, 0x43),
            PhyPbusForceTest::new(1, 1, 0x38),
            PhyPbusForceTest::new(1, 1, 0x189),
        ];
        for transaction in expected_pbus {
            assert_eq!(
                transition.action(),
                XtalDutyPrepareAction::ForcePbus(transaction)
            );
            transition
                .advance(XtalDutyPrepareCompletion::PbusForceCompleted(
                    transaction,
                ))
                .unwrap();
        }

        assert_eq!(
            transition.action(),
            XtalDutyPrepareAction::MaskRxDcoControl {
                address: 0x2010_0434,
                clear_mask: 0x00c0_0000,
            }
        );
        transition
            .advance(XtalDutyPrepareCompletion::RxDcoControlMasked {
                address: 0x2010_0434,
                saved_field: 0x0080_0000,
            })
            .unwrap();
        assert_eq!(
            transition.action(),
            XtalDutyPrepareAction::RxDco(PhyRxDcoAction::MaskRxDcoControl {
                address: RX_DCO_CONTROL_ADDRESS,
                clear_mask: RX_DCO_CONTROL_FIELD_MASK,
            })
        );
        while let XtalDutyPrepareAction::RxDco(action) = transition.action() {
            transition
                .advance(XtalDutyPrepareCompletion::RxDco(
                    complete_rx_dco_action(action),
                ))
                .unwrap();
        }
        let outcome = crate::phy_rx_dco::PhyRxDcoOutcome {
            configuration: [0x0100_0100; 2],
            iterations: 1,
            converged: true,
            last_estimate: PhyDcIqEstimate { i: 0, q: 0 },
        };
        assert_eq!(
            transition.action(),
            XtalDutyPrepareAction::RestoreRxDcoControl {
                address: 0x2010_0434,
                field_mask: 0x00c0_0000,
                saved_field: 0x0080_0000,
            }
        );
        transition
            .advance(XtalDutyPrepareCompletion::RxDcoControlRestored {
                address: 0x2010_0434,
                saved_field: 0x0080_0000,
            })
            .unwrap();
        assert_eq!(
            transition.action(),
            XtalDutyPrepareAction::Complete(outcome)
        );
    }

    #[test]
    fn restoration_requires_external_pbus_and_timer_completions() {
        let mut transition = XtalDutyRestoreTransition::new();
        for expected in [
            XtalDutyRestoreAction::ConfigureCalibrationTone {
                enabled: false,
                selector: 0x80,
                step: 0x28,
            },
            XtalDutyRestoreAction::ConfigureRxClock { enabled: false },
            XtalDutyRestoreAction::ConfigureTxClock { enabled: false },
        ] {
            assert_eq!(transition.action(), expected);
            transition
                .advance(complete_restore_action(expected))
                .unwrap();
        }

        for transaction in [
            PhyPbusForceTest::new(0, 1, 0),
            PhyPbusForceTest::new(1, 1, 0),
            PhyPbusForceTest::new(1, 2, 0),
        ] {
            assert_eq!(
                transition.action(),
                XtalDutyRestoreAction::ForcePbus(transaction)
            );
            transition
                .advance(XtalDutyRestoreCompletion::PbusForceCompleted(
                    transaction,
                ))
                .unwrap();
        }

        assert_eq!(
            transition.action(),
            XtalDutyRestoreAction::ConfigurePbusWorkMode
        );
        transition
            .advance(XtalDutyRestoreCompletion::PbusWorkModeConfigured {
                settle_required: true,
            })
            .unwrap();
        assert_eq!(
            transition.action(),
            XtalDutyRestoreAction::DelayMicros(1)
        );
        assert!(transition
            .advance(XtalDutyRestoreCompletion::DelayElapsed { micros: 2 })
            .is_err());
        transition
            .advance(XtalDutyRestoreCompletion::DelayElapsed { micros: 1 })
            .unwrap();
        assert_eq!(
            transition.action(),
            XtalDutyRestoreAction::ConfigurePbusWorkModePulse
        );
        transition
            .advance(XtalDutyRestoreCompletion::PbusWorkModePulseConfigured)
            .unwrap();
        assert_eq!(
            transition.action(),
            XtalDutyRestoreAction::DelayMicros(2)
        );
        transition
            .advance(XtalDutyRestoreCompletion::DelayElapsed { micros: 2 })
            .unwrap();
        assert_eq!(
            transition.action(),
            XtalDutyRestoreAction::ClearPbusWorkModePulse
        );
        transition
            .advance(XtalDutyRestoreCompletion::PbusWorkModePulseCleared)
            .unwrap();
        assert_eq!(transition.action(), XtalDutyRestoreAction::Complete);

        let mut timed_out = XtalDutyRestoreTransition::new();
        for _ in 0..3 {
            let action = timed_out.action();
            timed_out
                .advance(complete_restore_action(action))
                .unwrap();
        }
        let XtalDutyRestoreAction::ForcePbus(transaction) = timed_out.action() else {
            panic!("expected first restore PBus command");
        };
        timed_out
            .advance(XtalDutyRestoreCompletion::PbusForceTimedOut(transaction))
            .unwrap();
        assert_eq!(
            timed_out.action(),
            XtalDutyRestoreAction::Failed(
                XtalDutyHardwareFailure::PbusForceTestTimedOut(transaction)
            )
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
            transition.advance(XtalDutyPassCompletion::Prepare(
                XtalDutyPrepareCompletion::RfFrequencyProgrammed {
                frequency_code: 0x983,
                rf_frequency_offset_base: 0x31,
                mode: 1,
            })),
            Err(XtalDutyPassTransitionError::WrongCompletion)
        );
        assert_eq!(
            transition.action(),
            XtalDutyPassAction::Prepare(XtalDutyPrepareAction::ProgramRfFrequency {
                frequency_code: 0x983,
                rf_frequency_offset_base: 0x31,
                mode: 0,
            })
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
