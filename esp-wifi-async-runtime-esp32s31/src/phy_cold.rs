//! Explicit single-owner state for ESP32-S31 PHY cold initialization.
//!
//! `libphy.a[phy_init.o]` defines a 508-byte mutable `phy_param` object and
//! passes its address through the rev0 ROM ABI.  The Rust cold path must not
//! reproduce that hidden ownership model.  This module owns the complete
//! parameter image as an ordinary Rust value and supplies only typed snapshots
//! to the event-driven `phy_rf_init` transition.
//!
//! The initial image below is the complete `.data.phy_param` section from the
//! pinned `libphy.a` (SHA-256
//! `51497819736295c9b33d6775495dade4c6fb39db887edfe095608c670d9ae223`).
//! The extracted 508-byte section has SHA-256
//! `d8b4dbeeedcfb2cbaa6a00d2a7c84bc8c9ad5bbf54a2ff6bc30dee7f3b46ed83`.
//! Keeping the sparse nonzero bytes here avoids retaining the vendor object
//! merely to obtain its initial data.

use crate::{
    phy_frequency::{
        PhyChannelFrequencyInitAction, PhyChannelFrequencyInitCompletion,
        PhyChannelFrequencyInitControl, PhyFrequencyI2cAction, PhyFrequencyI2cCompletion,
        PhyFrequencyTableAction, PhyFrequencyTableCompletion,
    },
    phy_i2c::{
        AdcRateAction, AdcRateCompletion, BiasRegAction, BiasRegCompletion, FilterDcapAction,
        FilterDcapCompletion, FilterDcapParameters, I2cBbpllAction, I2cBbpllCompletion,
        I2cInit1Action, I2cInit1Completion, MaskedI2cWriteAction, MaskedI2cWriteCompletion,
        OpenI2cXpdAction, OpenI2cXpdCompletion, PhyI2cAddress, PhyI2cError, PhyRfInitPrefixAction,
        PhyRfInitPrefixCompletion, PhyRfInitPrefixOutcome, PhyRfInitPrefixTransition,
        PhyRfInitPrefixTransitionError, RcCalibrationAction, RcCalibrationCompletion,
        RcCalibrationSetAction, RcCalibrationSetCompletion, RfpllChargePumpAction,
        RfpllChargePumpCompletion, Sar2InitAction, Sar2InitCompletion,
    },
    phy_param::{
        apply_init_data, apply_rc_calibration_result, calibration_record_check_or_write,
        xtal_parameter_code, PHY_CALIBRATION_PAYLOAD_OFFSET, PHY_CALIBRATION_PREFIX_LEN,
        PHY_INIT_DATA_LEN, PHY_PARAM_LEN,
    },
    phy_pbus::{PhyPbusClearAction, PhyPbusClearCompletion, PhyPbusForceTest},
    phy_rx_dco::{PhyRxDcoAction, PhyRxDcoCompletion},
    phy_xtal_duty::{
        XtalDutyCalibrationAction, XtalDutyCalibrationCompletion, XtalDutyCalibrationParameters,
        XtalDutyPassAction, XtalDutyPassCompletion, XtalDutyPrepareAction,
        XtalDutyPrepareCompletion, XtalDutyRestoreAction, XtalDutyRestoreCompletion,
    },
};

pub const PHY_COLD_PARAMETER_LEN: usize = PHY_PARAM_LEN;
pub const PHY_COLD_INIT_PROFILE_LEN: usize = PHY_INIT_DATA_LEN;
pub const PHY_COLD_CALIBRATION_RECORD_LEN: usize = PHY_CALIBRATION_PREFIX_LEN;

const fn initial_parameter_image() -> [u8; PHY_PARAM_LEN] {
    let mut parameter = [0; PHY_PARAM_LEN];

    parameter[0x002] = 0xbf;
    parameter[0x003] = 0x20;
    parameter[0x006] = 0x54;
    parameter[0x00b] = 0x01;
    parameter[0x00e] = 0x60;
    parameter[0x00f] = 0x01;
    parameter[0x012] = 0x1f;
    parameter[0x013] = 0x16;
    parameter[0x014] = 0x01;
    parameter[0x015] = 0x40;
    parameter[0x016] = 0x02;
    parameter[0x018] = 0x50;
    parameter[0x024] = 0x30;
    parameter[0x1ab] = 0x01;
    parameter[0x1af] = 0x01;

    parameter
}

/// Complete fixed-size calibration record used by `register_chipv7_phy`.
///
/// Bytes 0..12 are the version and eFuse identity, bytes 12..520 are the
/// parameter payload, and bytes 520..524 contain the one's-complement
/// checksum.  It is separate from [`PhyColdState`] because callers may keep a
/// retained calibration record while constructing a fresh radio owner.
#[repr(C, align(4))]
pub struct PhyCalibrationRecord {
    bytes: [u8; PHY_CALIBRATION_PREFIX_LEN],
}

impl PhyCalibrationRecord {
    pub const fn new() -> Self {
        Self {
            bytes: [0; PHY_CALIBRATION_PREFIX_LEN],
        }
    }

    pub const fn from_bytes(bytes: [u8; PHY_CALIBRATION_PREFIX_LEN]) -> Self {
        Self { bytes }
    }

    pub const fn bytes(&self) -> &[u8; PHY_CALIBRATION_PREFIX_LEN] {
        &self.bytes
    }

    pub fn refresh_header_and_checksum(&mut self, version: u32, mac_sys0: u32, mac_sys1: u32) {
        let result =
            calibration_record_check_or_write(&mut self.bytes, false, version, mac_sys0, mac_sys1);
        debug_assert_eq!(result, 0);
    }

    /// Refresh the identity fields and compare the stored checksum.
    ///
    /// The identity refresh before comparison matches the pinned vendor body;
    /// this method performs no MMIO itself, so the eFuse words are explicit
    /// inputs owned by the outer cold-init executor.
    pub fn checksum_matches(&mut self, version: u32, mac_sys0: u32, mac_sys1: u32) -> bool {
        calibration_record_check_or_write(&mut self.bytes, true, version, mac_sys0, mac_sys1) == 0
    }
}

impl Default for PhyCalibrationRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique Rust owner of all parameter state used by PHY cold initialization.
///
/// The type deliberately is neither `Copy` nor `Clone`.  Moving it transfers
/// ownership; duplicating the live radio state is not a supported operation.
/// Alignment matches `.data.phy_param` in the pinned archive and permits a
/// later direct ABI publication without changing the representation.
#[repr(C, align(4))]
pub struct PhyColdState {
    parameter: [u8; PHY_PARAM_LEN],
}

impl PhyColdState {
    pub const fn new() -> Self {
        Self {
            parameter: initial_parameter_image(),
        }
    }

    pub const fn from_parameter_image(parameter: [u8; PHY_PARAM_LEN]) -> Self {
        Self { parameter }
    }

    pub const fn parameter_image(&self) -> &[u8; PHY_PARAM_LEN] {
        &self.parameter
    }

    /// Apply the exact 71-byte mapping from the 128-byte S31 init profile.
    pub fn apply_init_profile(&mut self, init: &[u8; PHY_INIT_DATA_LEN]) {
        apply_init_data(&mut self.parameter, init);
    }

    pub fn backup_into(&self, calibration: &mut PhyCalibrationRecord) {
        let mut index = 0;
        while index != PHY_PARAM_LEN {
            calibration.bytes[PHY_CALIBRATION_PAYLOAD_OFFSET + index] = self.parameter[index];
            index += 1;
        }
    }

    pub fn recover_from(&mut self, calibration: &PhyCalibrationRecord) {
        let mut index = 0;
        while index != PHY_PARAM_LEN {
            self.parameter[index] = calibration.bytes[PHY_CALIBRATION_PAYLOAD_OFFSET + index];
            index += 1;
        }
    }

    pub const fn rc_calibration_complete(&self) -> bool {
        self.parameter[0xa6] & 0x80 != 0
    }

    pub fn apply_rc_calibration(&mut self, result: u8) {
        apply_rc_calibration_result(&mut self.parameter, result);
    }

    pub const fn filter_dcap_parameters(&self) -> FilterDcapParameters {
        FilterDcapParameters::new(
            self.parameter[0xe9],
            self.parameter[0xea],
            self.parameter[0xed],
            self.parameter[0xee],
            self.parameter[0xf0],
        )
    }

    pub const fn xtal_duty_parameters(&self) -> XtalDutyCalibrationParameters {
        XtalDutyCalibrationParameters {
            rf_frequency_offset_base: self.parameter[0x4f],
            pbus_rx_path_value: self.parameter[0x002],
        }
    }

    pub const fn channel_frequency_control(&self) -> PhyChannelFrequencyInitControl {
        PhyChannelFrequencyInitControl {
            frequency_register_parameter_override: self.parameter[0x193] != 0,
            frequency_table_initialized: self.parameter[0xa4] & 0x20 != 0,
            front_end_parameter_bit: self.parameter[0x1af] != 0,
        }
    }

    pub fn set_xtal_frequency_mhz(&mut self, frequency_mhz: u32) {
        self.parameter[0x4f] = xtal_parameter_code(frequency_mhz);
    }

    fn synchronize_success(&mut self, outcome: PhyRfInitPrefixOutcome) {
        let PhyRfInitPrefixOutcome::ChannelFrequencyInitialized {
            bbpll_register_snapshot,
            parameter,
            xtal_duty,
            channel_frequency,
            ..
        } = outcome
        else {
            return;
        };

        self.parameter[0x4a] = bbpll_register_snapshot;
        self.parameter[0x18e] = parameter.parameter_18e();
        self.parameter[0x19e] = xtal_duty.initial_duty;
        self.parameter[0x19f] = xtal_duty.low_frequency.best_candidate;
        self.parameter[0x1a0] = xtal_duty.high_frequency.best_candidate;
        if channel_frequency.table_is_initialized {
            self.parameter[0xa4] |= 0x20;
        } else {
            self.parameter[0xa4] &= !0x20;
        }
    }
}

impl Default for PhyColdState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdI2cRequest {
    ReadByte {
        address: PhyI2cAddress,
    },
    ReadMasked {
        address: PhyI2cAddress,
        high_bit: u8,
        low_bit: u8,
    },
    WriteByte {
        address: PhyI2cAddress,
        value: u8,
    },
    WriteMasked {
        address: PhyI2cAddress,
        high_bit: u8,
        low_bit: u8,
        value: u8,
    },
}

impl PhyColdI2cRequest {
    pub const fn read_byte(address: PhyI2cAddress) -> Self {
        Self::ReadByte { address }
    }

    pub const fn read_masked(address: PhyI2cAddress, high_bit: u8, low_bit: u8) -> Option<Self> {
        if high_bit < 8 && low_bit <= high_bit {
            Some(Self::ReadMasked {
                address,
                high_bit,
                low_bit,
            })
        } else {
            None
        }
    }

    pub const fn write_byte(address: PhyI2cAddress, value: u8) -> Self {
        Self::WriteByte { address, value }
    }

    pub const fn write_masked(
        address: PhyI2cAddress,
        high_bit: u8,
        low_bit: u8,
        value: u8,
    ) -> Option<Self> {
        if high_bit < 8 && low_bit <= high_bit {
            Some(Self::WriteMasked {
                address,
                high_bit,
                low_bit,
                value,
            })
        } else {
            None
        }
    }

    const fn address(self) -> PhyI2cAddress {
        match self {
            Self::ReadByte { address }
            | Self::ReadMasked { address, .. }
            | Self::WriteByte { address, .. }
            | Self::WriteMasked { address, .. } => address,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdI2cAction {
    StartRead { address: PhyI2cAddress },
    AwaitReadCompletionEdge { address: PhyI2cAddress },
    StartWrite { address: PhyI2cAddress, value: u8 },
    AwaitWriteCompletionEdge { address: PhyI2cAddress },
    Complete(PhyColdI2cOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdI2cOutcome {
    Read { address: PhyI2cAddress, value: u8 },
    Written { address: PhyI2cAddress },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdI2cObservation {
    /// The externally delivered edge arrived before the peripheral completed.
    ///
    /// The transaction remains unchanged and does not arrange another wake.
    /// Only a new hardware edge or an outer deadline may call the observation
    /// method again.
    StillPending,
    EdgeConsumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdI2cError {
    BusyAtStart,
    WrongEdge,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhyColdI2cPhase {
    StartRead,
    AwaitRead,
    StartWrite(u8),
    AwaitWrite,
    Complete(PhyColdI2cOutcome),
}

/// One nonblocking PHY-I2C transaction, including masked read/modify/write.
///
/// Start and completion are different states.  Observing `Busy` after an
/// externally delivered edge leaves the state at `Await*` and returns
/// [`PhyColdI2cObservation::StillPending`]; it does not spin, retry, register a
/// waker, or request an executor poll.  A separate owner must provide either a
/// later hardware edge or a deadline.
#[derive(Debug, Eq, PartialEq)]
pub struct PhyColdI2cTransaction {
    request: PhyColdI2cRequest,
    phase: PhyColdI2cPhase,
}

impl PhyColdI2cTransaction {
    pub const fn new(request: PhyColdI2cRequest) -> Self {
        let phase = match request {
            PhyColdI2cRequest::ReadByte { .. }
            | PhyColdI2cRequest::ReadMasked { .. }
            | PhyColdI2cRequest::WriteMasked { .. } => PhyColdI2cPhase::StartRead,
            PhyColdI2cRequest::WriteByte { value, .. } => PhyColdI2cPhase::StartWrite(value),
        };
        Self { request, phase }
    }

    pub const fn action(&self) -> PhyColdI2cAction {
        let address = self.request.address();
        match self.phase {
            PhyColdI2cPhase::StartRead => PhyColdI2cAction::StartRead { address },
            PhyColdI2cPhase::AwaitRead => PhyColdI2cAction::AwaitReadCompletionEdge { address },
            PhyColdI2cPhase::StartWrite(value) => PhyColdI2cAction::StartWrite { address, value },
            PhyColdI2cPhase::AwaitWrite => PhyColdI2cAction::AwaitWriteCompletionEdge { address },
            PhyColdI2cPhase::Complete(outcome) => PhyColdI2cAction::Complete(outcome),
        }
    }

    pub fn read_started(&mut self) -> Result<(), PhyColdI2cError> {
        if self.phase != PhyColdI2cPhase::StartRead {
            return Err(self.phase_error());
        }
        self.phase = PhyColdI2cPhase::AwaitRead;
        Ok(())
    }

    pub fn write_started(&mut self) -> Result<(), PhyColdI2cError> {
        if !matches!(self.phase, PhyColdI2cPhase::StartWrite(_)) {
            return Err(self.phase_error());
        }
        self.phase = PhyColdI2cPhase::AwaitWrite;
        Ok(())
    }

    pub fn observe_read_result(
        &mut self,
        result: Result<u8, PhyI2cError>,
    ) -> Result<PhyColdI2cObservation, PhyColdI2cError> {
        if self.phase != PhyColdI2cPhase::AwaitRead {
            return Err(self.phase_error());
        }
        let value = match result {
            Ok(value) => value,
            Err(PhyI2cError::Busy) => return Ok(PhyColdI2cObservation::StillPending),
        };

        let address = self.request.address();
        self.phase = match self.request {
            PhyColdI2cRequest::ReadByte { .. } => {
                PhyColdI2cPhase::Complete(PhyColdI2cOutcome::Read { address, value })
            }
            PhyColdI2cRequest::ReadMasked {
                high_bit, low_bit, ..
            } => PhyColdI2cPhase::Complete(PhyColdI2cOutcome::Read {
                address,
                value: extract_field(value, high_bit, low_bit),
            }),
            PhyColdI2cRequest::WriteMasked {
                high_bit,
                low_bit,
                value: field_value,
                ..
            } => PhyColdI2cPhase::StartWrite(replace_field(value, high_bit, low_bit, field_value)),
            PhyColdI2cRequest::WriteByte { .. } => return Err(PhyColdI2cError::WrongEdge),
        };
        Ok(PhyColdI2cObservation::EdgeConsumed)
    }

    pub fn observe_write_result(
        &mut self,
        result: Result<(), PhyI2cError>,
    ) -> Result<PhyColdI2cObservation, PhyColdI2cError> {
        if self.phase != PhyColdI2cPhase::AwaitWrite {
            return Err(self.phase_error());
        }
        match result {
            Ok(()) => {
                self.phase = PhyColdI2cPhase::Complete(PhyColdI2cOutcome::Written {
                    address: self.request.address(),
                });
                Ok(PhyColdI2cObservation::EdgeConsumed)
            }
            Err(PhyI2cError::Busy) => Ok(PhyColdI2cObservation::StillPending),
        }
    }

    #[cfg(target_arch = "riscv32")]
    pub unsafe fn start_target(&mut self) -> Result<(), PhyColdI2cError> {
        match self.action() {
            PhyColdI2cAction::StartRead { address } => {
                crate::phy_i2c::try_start_read(address)
                    .map_err(|PhyI2cError::Busy| PhyColdI2cError::BusyAtStart)?;
                self.read_started()
            }
            PhyColdI2cAction::StartWrite { address, value } => {
                crate::phy_i2c::try_start_write(address, value)
                    .map_err(|PhyI2cError::Busy| PhyColdI2cError::BusyAtStart)?;
                self.write_started()
            }
            PhyColdI2cAction::Complete(_) => Err(PhyColdI2cError::AlreadyComplete),
            _ => Err(PhyColdI2cError::WrongEdge),
        }
    }

    /// Consume exactly one independently delivered target completion edge.
    #[cfg(target_arch = "riscv32")]
    pub unsafe fn observe_target_edge(&mut self) -> Result<PhyColdI2cObservation, PhyColdI2cError> {
        match self.action() {
            PhyColdI2cAction::AwaitReadCompletionEdge { address } => {
                self.observe_read_result(crate::phy_i2c::try_finish_read(address))
            }
            PhyColdI2cAction::AwaitWriteCompletionEdge { address } => {
                self.observe_write_result(crate::phy_i2c::try_finish_write(address))
            }
            PhyColdI2cAction::Complete(_) => Err(PhyColdI2cError::AlreadyComplete),
            _ => Err(PhyColdI2cError::WrongEdge),
        }
    }

    const fn phase_error(&self) -> PhyColdI2cError {
        if matches!(self.phase, PhyColdI2cPhase::Complete(_)) {
            PhyColdI2cError::AlreadyComplete
        } else {
            PhyColdI2cError::WrongEdge
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdLoweringError {
    UnsupportedAction,
    IncompleteTransaction,
    UnexpectedOutcome,
}

/// Identity-bound lowering of one RF-init action to one PHY-I2C transaction.
///
/// The original action remains part of the binding until the transaction is
/// complete. This prevents a completion from being reused for a later action
/// which happens to address the same PHY-I2C register.
#[derive(Debug, Eq, PartialEq)]
pub struct PhyColdI2cBinding {
    outer_action: PhyRfInitPrefixAction,
    transaction: PhyColdI2cTransaction,
}

impl PhyColdI2cBinding {
    pub fn new(outer_action: PhyRfInitPrefixAction) -> Result<Self, PhyColdLoweringError> {
        let request = lower_prefix_i2c_request(outer_action)
            .ok_or(PhyColdLoweringError::UnsupportedAction)?;
        Ok(Self {
            outer_action,
            transaction: PhyColdI2cTransaction::new(request),
        })
    }

    pub const fn outer_action(&self) -> PhyRfInitPrefixAction {
        self.outer_action
    }

    pub const fn action(&self) -> PhyColdI2cAction {
        self.transaction.action()
    }

    pub fn read_started(&mut self) -> Result<(), PhyColdI2cError> {
        self.transaction.read_started()
    }

    pub fn write_started(&mut self) -> Result<(), PhyColdI2cError> {
        self.transaction.write_started()
    }

    pub fn observe_read_result(
        &mut self,
        result: Result<u8, PhyI2cError>,
    ) -> Result<PhyColdI2cObservation, PhyColdI2cError> {
        self.transaction.observe_read_result(result)
    }

    pub fn observe_write_result(
        &mut self,
        result: Result<(), PhyI2cError>,
    ) -> Result<PhyColdI2cObservation, PhyColdI2cError> {
        self.transaction.observe_write_result(result)
    }

    #[cfg(target_arch = "riscv32")]
    pub unsafe fn start_target(&mut self) -> Result<(), PhyColdI2cError> {
        self.transaction.start_target()
    }

    #[cfg(target_arch = "riscv32")]
    pub unsafe fn observe_target_edge(&mut self) -> Result<PhyColdI2cObservation, PhyColdI2cError> {
        self.transaction.observe_target_edge()
    }

    pub fn into_completion(self) -> Result<PhyRfInitPrefixCompletion, PhyColdLoweringError> {
        let PhyColdI2cAction::Complete(outcome) = self.transaction.action() else {
            return Err(PhyColdLoweringError::IncompleteTransaction);
        };
        lower_prefix_i2c_completion(self.outer_action, outcome)
            .ok_or(PhyColdLoweringError::UnexpectedOutcome)
    }
}

fn checked_masked_read(
    address: PhyI2cAddress,
    high_bit: u8,
    low_bit: u8,
) -> Option<PhyColdI2cRequest> {
    PhyColdI2cRequest::read_masked(address, high_bit, low_bit)
}

fn checked_masked_write(
    address: PhyI2cAddress,
    high_bit: u8,
    low_bit: u8,
    value: u8,
) -> Option<PhyColdI2cRequest> {
    PhyColdI2cRequest::write_masked(address, high_bit, low_bit, value)
}

fn lower_prefix_i2c_request(action: PhyRfInitPrefixAction) -> Option<PhyColdI2cRequest> {
    match action {
        PhyRfInitPrefixAction::Bias(BiasRegAction::Write { address, value })
        | PhyRfInitPrefixAction::FilterDcap(FilterDcapAction::Write { address, value })
        | PhyRfInitPrefixAction::I2cInit1(I2cInit1Action::Write { address, value })
        | PhyRfInitPrefixAction::Sar2Init(Sar2InitAction::WriteByte { address, value })
        | PhyRfInitPrefixAction::I2cBbpll(I2cBbpllAction::WriteByte { address, value })
        | PhyRfInitPrefixAction::AdcRate(AdcRateAction::WriteI2c { address, value })
        | PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::WriteByte {
            address,
            value,
        }) => Some(PhyColdI2cRequest::write_byte(address, value)),
        PhyRfInitPrefixAction::OpenI2cXpd(OpenI2cXpdAction::ReadSdmSample { address })
        | PhyRfInitPrefixAction::ReadParameter18e { address }
        | PhyRfInitPrefixAction::I2cBbpll(I2cBbpllAction::ReadMaskedByte { address })
        | PhyRfInitPrefixAction::I2cBbpll(I2cBbpllAction::ReadSnapshot { address })
        | PhyRfInitPrefixAction::AdcRate(AdcRateAction::ReadI2c { address })
        | PhyRfInitPrefixAction::RfpllChargePump(RfpllChargePumpAction::ReadByte { address })
        | PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::ReadByte {
            address,
        })
        | PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::I2c(
            PhyFrequencyI2cAction::ReadByte { address },
        )) => Some(PhyColdI2cRequest::read_byte(address)),
        PhyRfInitPrefixAction::RcCalibrationSet(RcCalibrationSetAction::MaskedWrite(
            MaskedI2cWriteAction::ReadByte { address },
        )) => Some(PhyColdI2cRequest::read_byte(address)),
        PhyRfInitPrefixAction::RcCalibrationSet(RcCalibrationSetAction::MaskedWrite(
            MaskedI2cWriteAction::WriteByte { address, value },
        )) => Some(PhyColdI2cRequest::write_byte(address, value)),
        PhyRfInitPrefixAction::RcCalibration(RcCalibrationAction::WriteMasked {
            address,
            high_bit,
            low_bit,
            value,
        })
        | PhyRfInitPrefixAction::RfpllChargePump(RfpllChargePumpAction::WriteMasked {
            address,
            high_bit,
            low_bit,
            value,
        })
        | PhyRfInitPrefixAction::Sar2Init(Sar2InitAction::WriteMasked {
            address,
            high_bit,
            low_bit,
            value,
        })
        | PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::WriteMasked {
            address,
            high_bit,
            low_bit,
            value,
        })
        | PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::I2c(
            PhyFrequencyI2cAction::WriteMasked {
                address,
                high_bit,
                low_bit,
                value,
            },
        )) => checked_masked_write(address, high_bit, low_bit, value),
        PhyRfInitPrefixAction::RcCalibration(RcCalibrationAction::ReadMasked {
            address,
            high_bit,
            low_bit,
        })
        | PhyRfInitPrefixAction::RfpllChargePump(RfpllChargePumpAction::ReadMasked {
            address,
            high_bit,
            low_bit,
        })
        | PhyRfInitPrefixAction::ReadMasked69 {
            address,
            high_bit,
            low_bit,
        } => checked_masked_read(address, high_bit, low_bit),
        _ => None,
    }
}

fn lower_prefix_i2c_completion(
    action: PhyRfInitPrefixAction,
    outcome: PhyColdI2cOutcome,
) -> Option<PhyRfInitPrefixCompletion> {
    match (action, outcome) {
        (
            PhyRfInitPrefixAction::Bias(BiasRegAction::Write { address, .. }),
            PhyColdI2cOutcome::Written { address: completed },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::Bias(
            BiasRegCompletion::WriteCompleted { address },
        )),
        (
            PhyRfInitPrefixAction::OpenI2cXpd(OpenI2cXpdAction::ReadSdmSample { address }),
            PhyColdI2cOutcome::Read {
                address: completed,
                value,
            },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::OpenI2cXpd(
            OpenI2cXpdCompletion::SdmSample(value),
        )),
        (
            PhyRfInitPrefixAction::I2cBbpll(
                I2cBbpllAction::ReadMaskedByte { address }
                | I2cBbpllAction::ReadSnapshot { address },
            ),
            PhyColdI2cOutcome::Read {
                address: completed,
                value,
            },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::I2cBbpll(
            I2cBbpllCompletion::I2cReadCompleted { address, value },
        )),
        (
            PhyRfInitPrefixAction::I2cBbpll(I2cBbpllAction::WriteByte { address, .. }),
            PhyColdI2cOutcome::Written { address: completed },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::I2cBbpll(
            I2cBbpllCompletion::I2cWriteCompleted { address },
        )),
        (
            PhyRfInitPrefixAction::AdcRate(AdcRateAction::ReadI2c { address }),
            PhyColdI2cOutcome::Read {
                address: completed,
                value,
            },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::AdcRate(
            AdcRateCompletion::I2cReadCompleted { address, value },
        )),
        (
            PhyRfInitPrefixAction::AdcRate(AdcRateAction::WriteI2c { address, .. }),
            PhyColdI2cOutcome::Written { address: completed },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::AdcRate(
            AdcRateCompletion::I2cWriteCompleted { address },
        )),
        (
            PhyRfInitPrefixAction::RcCalibrationSet(RcCalibrationSetAction::MaskedWrite(
                MaskedI2cWriteAction::ReadByte { address },
            )),
            PhyColdI2cOutcome::Read {
                address: completed,
                value,
            },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::RcCalibrationSet(
            RcCalibrationSetCompletion::MaskedWrite(MaskedI2cWriteCompletion::I2cReadCompleted {
                address,
                value,
            }),
        )),
        (
            PhyRfInitPrefixAction::RcCalibrationSet(RcCalibrationSetAction::MaskedWrite(
                MaskedI2cWriteAction::WriteByte { address, .. },
            )),
            PhyColdI2cOutcome::Written { address: completed },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::RcCalibrationSet(
            RcCalibrationSetCompletion::MaskedWrite(MaskedI2cWriteCompletion::I2cWriteCompleted {
                address,
            }),
        )),
        (
            PhyRfInitPrefixAction::RcCalibration(RcCalibrationAction::WriteMasked { .. }),
            PhyColdI2cOutcome::Written { .. },
        ) => Some(PhyRfInitPrefixCompletion::RcCalibration(
            RcCalibrationCompletion::Write,
        )),
        (
            PhyRfInitPrefixAction::RcCalibration(RcCalibrationAction::ReadMasked { .. }),
            PhyColdI2cOutcome::Read { value, .. },
        ) => Some(PhyRfInitPrefixCompletion::RcCalibration(
            RcCalibrationCompletion::Read(value),
        )),
        (
            PhyRfInitPrefixAction::FilterDcap(FilterDcapAction::Write { address, .. }),
            PhyColdI2cOutcome::Written { address: completed },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::FilterDcap(
            FilterDcapCompletion::WriteCompleted { address },
        )),
        (
            PhyRfInitPrefixAction::ReadParameter18e { address },
            PhyColdI2cOutcome::Read {
                address: completed,
                value,
            },
        ) if address == completed => {
            Some(PhyRfInitPrefixCompletion::Parameter18eRead { address, value })
        }
        (
            PhyRfInitPrefixAction::I2cInit1(I2cInit1Action::Write { address, .. }),
            PhyColdI2cOutcome::Written { address: completed },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::I2cInit1(
            I2cInit1Completion::WriteCompleted { address },
        )),
        (
            PhyRfInitPrefixAction::RfpllChargePump(RfpllChargePumpAction::WriteMasked { .. }),
            PhyColdI2cOutcome::Written { .. },
        ) => Some(PhyRfInitPrefixCompletion::RfpllChargePump(
            RfpllChargePumpCompletion::Write,
        )),
        (
            PhyRfInitPrefixAction::RfpllChargePump(RfpllChargePumpAction::ReadMasked { .. }),
            PhyColdI2cOutcome::Read { value, .. },
        ) => Some(PhyRfInitPrefixCompletion::RfpllChargePump(
            RfpllChargePumpCompletion::ReadMasked(value),
        )),
        (
            PhyRfInitPrefixAction::RfpllChargePump(RfpllChargePumpAction::ReadByte { address }),
            PhyColdI2cOutcome::Read {
                address: completed,
                value,
            },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::RfpllChargePump(
            RfpllChargePumpCompletion::ReadByte { address, value },
        )),
        (PhyRfInitPrefixAction::ReadMasked69 { .. }, PhyColdI2cOutcome::Read { value, .. }) => {
            Some(PhyRfInitPrefixCompletion::Masked69Read(value))
        }
        (
            PhyRfInitPrefixAction::Sar2Init(Sar2InitAction::WriteMasked { .. }),
            PhyColdI2cOutcome::Written { .. },
        ) => Some(PhyRfInitPrefixCompletion::Sar2Init(
            Sar2InitCompletion::MaskedWrite,
        )),
        (
            PhyRfInitPrefixAction::Sar2Init(Sar2InitAction::WriteByte { address, .. }),
            PhyColdI2cOutcome::Written { address: completed },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::Sar2Init(
            Sar2InitCompletion::ByteWrite { address },
        )),
        (
            PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::WriteMasked {
                address,
                high_bit,
                low_bit,
                ..
            }),
            PhyColdI2cOutcome::Written { address: completed },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::ChannelFrequency(
            PhyChannelFrequencyInitCompletion::MaskedWrite {
                address,
                high_bit,
                low_bit,
            },
        )),
        (
            PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::WriteByte {
                address,
                ..
            }),
            PhyColdI2cOutcome::Written { address: completed },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::ChannelFrequency(
            PhyChannelFrequencyInitCompletion::ByteWrite { address },
        )),
        (
            PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::ReadByte {
                address,
            }),
            PhyColdI2cOutcome::Read {
                address: completed,
                value,
            },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::ChannelFrequency(
            PhyChannelFrequencyInitCompletion::ByteRead { address, value },
        )),
        (
            PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::I2c(
                PhyFrequencyI2cAction::WriteMasked {
                    address,
                    high_bit,
                    low_bit,
                    ..
                },
            )),
            PhyColdI2cOutcome::Written { address: completed },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::ChannelFrequency(
            PhyChannelFrequencyInitCompletion::I2c(PhyFrequencyI2cCompletion::MaskedWrite {
                address,
                high_bit,
                low_bit,
            }),
        )),
        (
            PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::I2c(
                PhyFrequencyI2cAction::ReadByte { address },
            )),
            PhyColdI2cOutcome::Read {
                address: completed,
                value,
            },
        ) if address == completed => Some(PhyRfInitPrefixCompletion::ChannelFrequency(
            PhyChannelFrequencyInitCompletion::I2c(PhyFrequencyI2cCompletion::ByteRead {
                address,
                value,
            }),
        )),
        _ => None,
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PhyColdMmioBinding {
    outer_action: PhyRfInitPrefixAction,
}

impl PhyColdMmioBinding {
    pub fn new(outer_action: PhyRfInitPrefixAction) -> Result<Self, PhyColdLoweringError> {
        if lower_prefix_mmio_completion(outer_action).is_none() {
            return Err(PhyColdLoweringError::UnsupportedAction);
        }
        Ok(Self { outer_action })
    }

    pub const fn outer_action(&self) -> PhyRfInitPrefixAction {
        self.outer_action
    }

    pub fn into_completion(self) -> Result<PhyRfInitPrefixCompletion, PhyColdLoweringError> {
        lower_prefix_mmio_completion(self.outer_action)
            .ok_or(PhyColdLoweringError::UnsupportedAction)
    }

    /// Execute exactly one finite target MMIO transaction and consume its
    /// identity token.
    #[cfg(target_arch = "riscv32")]
    pub unsafe fn execute_target(self) -> Result<PhyRfInitPrefixCompletion, PhyColdLoweringError> {
        match self.outer_action {
            PhyRfInitPrefixAction::ConfigureFeBbClock => {
                crate::radio_hal::wifi_strict_phy_open_fe_bb_clk()
            }
            PhyRfInitPrefixAction::ConfigureBbpllCalibration { enabled } => {
                crate::radio_hal::wifi_strict_phy_bbpll_cal(enabled as u32)
            }
            PhyRfInitPrefixAction::OpenI2cXpd(OpenI2cXpdAction::ConfigurePreDelay) => {
                crate::phy_i2c::configure_open_i2c_pre_delay()
            }
            PhyRfInitPrefixAction::OpenI2cXpd(OpenI2cXpdAction::ConfigurePowerAndPulse) => {
                crate::phy_i2c::configure_open_i2c_power_and_pulse()
            }
            PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ConfigureDebugMode) => {
                crate::radio_hal::configure_phy_pbus_debug_mode()
            }
            PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ConfigureWorkModePulse) => {
                crate::radio_hal::configure_phy_pbus_work_mode_pulse()
            }
            PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ClearWorkModePulse) => {
                crate::radio_hal::clear_phy_pbus_work_mode_pulse()
            }
            PhyRfInitPrefixAction::ConfigureI2cClockSelection { selection } => {
                crate::radio_hal::configure_phy_i2c_clock_selection(selection)
            }
            PhyRfInitPrefixAction::AdcRate(AdcRateAction::ConfigureMmio { rate }) => {
                crate::radio_hal::configure_phy_adc_rate(rate)
            }
            PhyRfInitPrefixAction::ConfigureI2cMasterRegisters => {
                crate::radio_hal::configure_phy_i2c_master_registers()
            }
            PhyRfInitPrefixAction::ConfigurePowerDetectorRegisters => {
                crate::radio_hal::configure_phy_power_detector_registers()
            }
            PhyRfInitPrefixAction::ConfigureFrontEndRegisters => {
                crate::radio_hal::configure_phy_front_end_registers()
            }
            PhyRfInitPrefixAction::ConfigureTemperatureSensorRead => {
                crate::radio_hal::configure_phy_temperature_sensor_read()
            }
            PhyRfInitPrefixAction::ConfigureTxPowerControlBackground => {
                crate::radio_hal::configure_phy_tx_power_control_background()
            }
            PhyRfInitPrefixAction::ConfigureI2cMasterCommandMemory { parameter } => {
                crate::phy_i2c::configure_i2c_master_command_memory(parameter)
            }
            PhyRfInitPrefixAction::ConfigureFrontEndRegisterUpdate => {
                crate::radio_hal::configure_phy_front_end_update()
            }
            PhyRfInitPrefixAction::ChannelFrequency(
                PhyChannelFrequencyInitAction::ConfigureFrequencyRegisters { parameter_override },
            ) => crate::radio_hal::configure_phy_frequency_registers(parameter_override),
            PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::Table(
                PhyFrequencyTableAction::WriteMemory {
                    address,
                    value,
                    mode,
                    ..
                },
            ))
            | PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::I2c(
                PhyFrequencyI2cAction::WriteMemory {
                    address,
                    value,
                    mode,
                    ..
                },
            )) => crate::radio_hal::write_phy_frequency_memory(address, value, mode),
            PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::I2c(
                PhyFrequencyI2cAction::ConfigureNumberAddresses(image),
            )) => crate::radio_hal::configure_phy_frequency_i2c_number_addresses(
                image.control_field,
                image.words,
            ),
            _ => return Err(PhyColdLoweringError::UnsupportedAction),
        }
        self.into_completion()
    }
}

fn lower_prefix_mmio_completion(
    action: PhyRfInitPrefixAction,
) -> Option<PhyRfInitPrefixCompletion> {
    match action {
        PhyRfInitPrefixAction::ConfigureFeBbClock => {
            Some(PhyRfInitPrefixCompletion::FeBbClockConfigured)
        }
        PhyRfInitPrefixAction::ConfigureBbpllCalibration { .. } => {
            Some(PhyRfInitPrefixCompletion::BbpllCalibrationConfigured)
        }
        PhyRfInitPrefixAction::OpenI2cXpd(OpenI2cXpdAction::ConfigurePreDelay) => Some(
            PhyRfInitPrefixCompletion::OpenI2cXpd(OpenI2cXpdCompletion::PreDelayConfigured),
        ),
        PhyRfInitPrefixAction::OpenI2cXpd(OpenI2cXpdAction::ConfigurePowerAndPulse) => Some(
            PhyRfInitPrefixCompletion::OpenI2cXpd(OpenI2cXpdCompletion::PowerAndPulseConfigured),
        ),
        PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ConfigureDebugMode) => Some(
            PhyRfInitPrefixCompletion::PbusClear(PhyPbusClearCompletion::DebugModeConfigured),
        ),
        PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ConfigureWorkModePulse) => Some(
            PhyRfInitPrefixCompletion::PbusClear(PhyPbusClearCompletion::WorkModePulseConfigured),
        ),
        PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ClearWorkModePulse) => Some(
            PhyRfInitPrefixCompletion::PbusClear(PhyPbusClearCompletion::WorkModePulseCleared),
        ),
        PhyRfInitPrefixAction::ConfigureI2cClockSelection { .. } => {
            Some(PhyRfInitPrefixCompletion::I2cClockSelectionConfigured)
        }
        PhyRfInitPrefixAction::AdcRate(AdcRateAction::ConfigureMmio { .. }) => Some(
            PhyRfInitPrefixCompletion::AdcRate(AdcRateCompletion::MmioConfigured),
        ),
        PhyRfInitPrefixAction::ConfigureI2cMasterRegisters => {
            Some(PhyRfInitPrefixCompletion::I2cMasterRegistersConfigured)
        }
        PhyRfInitPrefixAction::ConfigurePowerDetectorRegisters => {
            Some(PhyRfInitPrefixCompletion::PowerDetectorRegistersConfigured)
        }
        PhyRfInitPrefixAction::ConfigureFrontEndRegisters => {
            Some(PhyRfInitPrefixCompletion::FrontEndRegistersConfigured)
        }
        PhyRfInitPrefixAction::ConfigureTemperatureSensorRead => {
            Some(PhyRfInitPrefixCompletion::TemperatureSensorReadConfigured)
        }
        PhyRfInitPrefixAction::ConfigureTxPowerControlBackground => {
            Some(PhyRfInitPrefixCompletion::TxPowerControlBackgroundConfigured)
        }
        PhyRfInitPrefixAction::ConfigureI2cMasterCommandMemory { .. } => {
            Some(PhyRfInitPrefixCompletion::I2cMasterCommandMemoryConfigured)
        }
        PhyRfInitPrefixAction::ConfigureFrontEndRegisterUpdate => {
            Some(PhyRfInitPrefixCompletion::FrontEndRegisterUpdateConfigured)
        }
        PhyRfInitPrefixAction::ChannelFrequency(
            PhyChannelFrequencyInitAction::ConfigureFrequencyRegisters { parameter_override },
        ) => Some(PhyRfInitPrefixCompletion::ChannelFrequency(
            PhyChannelFrequencyInitCompletion::FrequencyRegistersConfigured { parameter_override },
        )),
        PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::Table(
            PhyFrequencyTableAction::WriteMemory {
                entry_index,
                word_index,
                address,
                ..
            },
        )) => Some(PhyRfInitPrefixCompletion::ChannelFrequency(
            PhyChannelFrequencyInitCompletion::Table(PhyFrequencyTableCompletion {
                entry_index,
                word_index,
                address,
            }),
        )),
        PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::I2c(
            PhyFrequencyI2cAction::WriteMemory {
                descriptor_index,
                copy_index,
                address,
                ..
            },
        )) => Some(PhyRfInitPrefixCompletion::ChannelFrequency(
            PhyChannelFrequencyInitCompletion::I2c(PhyFrequencyI2cCompletion::MemoryWrite {
                descriptor_index,
                copy_index,
                address,
            }),
        )),
        PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::I2c(
            PhyFrequencyI2cAction::ConfigureNumberAddresses(image),
        )) => Some(PhyRfInitPrefixCompletion::ChannelFrequency(
            PhyChannelFrequencyInitCompletion::I2c(
                PhyFrequencyI2cCompletion::NumberAddressesConfigured(image),
            ),
        )),
        _ => None,
    }
}

/// One timer edge belonging to one exact RF-init action.
///
/// The value owns no timer implementation and cannot wake itself. The outer
/// Rust executor arms its timer from [`micros`](Self::micros), then consumes
/// this binding only when that timer reports expiry.
#[derive(Debug, Eq, PartialEq)]
pub struct PhyColdTimerBinding {
    outer_action: PhyRfInitPrefixAction,
    micros: u32,
}

impl PhyColdTimerBinding {
    pub fn new(outer_action: PhyRfInitPrefixAction) -> Result<Self, PhyColdLoweringError> {
        let micros = match outer_action {
            PhyRfInitPrefixAction::DelayMicros(micros)
            | PhyRfInitPrefixAction::OpenI2cXpd(OpenI2cXpdAction::DelayMicros(micros))
            | PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::DelayMicros(micros))
            | PhyRfInitPrefixAction::RcCalibration(RcCalibrationAction::DelayMicros(micros))
            | PhyRfInitPrefixAction::RfpllChargePump(RfpllChargePumpAction::DelayMicros(micros)) => {
                micros
            }
            _ => return Err(PhyColdLoweringError::UnsupportedAction),
        };
        Ok(Self {
            outer_action,
            micros,
        })
    }

    pub const fn outer_action(&self) -> PhyRfInitPrefixAction {
        self.outer_action
    }

    pub const fn micros(&self) -> u32 {
        self.micros
    }

    pub fn into_elapsed_completion(
        self,
    ) -> Result<PhyRfInitPrefixCompletion, PhyColdLoweringError> {
        match self.outer_action {
            PhyRfInitPrefixAction::DelayMicros(_) => Ok(PhyRfInitPrefixCompletion::DelayElapsed),
            PhyRfInitPrefixAction::OpenI2cXpd(OpenI2cXpdAction::DelayMicros(_)) => Ok(
                PhyRfInitPrefixCompletion::OpenI2cXpd(OpenI2cXpdCompletion::DelayElapsed),
            ),
            PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::DelayMicros(_)) => Ok(
                PhyRfInitPrefixCompletion::PbusClear(PhyPbusClearCompletion::DelayElapsed),
            ),
            PhyRfInitPrefixAction::RcCalibration(RcCalibrationAction::DelayMicros(_)) => Ok(
                PhyRfInitPrefixCompletion::RcCalibration(RcCalibrationCompletion::Delay),
            ),
            PhyRfInitPrefixAction::RfpllChargePump(RfpllChargePumpAction::DelayMicros(_)) => Ok(
                PhyRfInitPrefixCompletion::RfpllChargePump(RfpllChargePumpCompletion::Delay),
            ),
            _ => Err(PhyColdLoweringError::UnsupportedAction),
        }
    }
}

/// Exactly one lowered external operation owned by the cold-init executor.
///
/// Unsupported nested actions are rejected during construction; there is no
/// generic vendor callback or synchronous fallback variant.
#[derive(Debug, Eq, PartialEq)]
pub enum PhyColdExternalBinding {
    I2c(PhyColdI2cBinding),
    Mmio(PhyColdMmioBinding),
    Observation(PhyColdObservationBinding),
    Pbus(PhyColdPbusBinding),
    Timer(PhyColdTimerBinding),
}

impl PhyColdExternalBinding {
    pub fn lower(action: PhyRfInitPrefixAction) -> Result<Self, PhyColdLoweringError> {
        if let Ok(binding) = PhyColdI2cBinding::new(action) {
            return Ok(Self::I2c(binding));
        }
        if let Ok(binding) = PhyColdMmioBinding::new(action) {
            return Ok(Self::Mmio(binding));
        }
        if let Ok(binding) = PhyColdPbusBinding::new(action) {
            return Ok(Self::Pbus(binding));
        }
        if let Ok(binding) = PhyColdObservationBinding::new(action) {
            return Ok(Self::Observation(binding));
        }
        if let Ok(binding) = PhyColdTimerBinding::new(action) {
            return Ok(Self::Timer(binding));
        }
        Err(PhyColdLoweringError::UnsupportedAction)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdObservationRequest {
    ConfigurePbusWorkMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdObservationResult {
    PbusWorkMode { settle_required: bool },
}

/// One finite MMIO operation whose sampled value is part of the completion.
///
/// This is separate from [`PhyColdMmioBinding`] so a dynamic register sample
/// cannot be fabricated by constructing a fixed completion. Consuming the
/// binding returns the observation to exactly the parent action that requested
/// it.
#[derive(Debug, Eq, PartialEq)]
pub struct PhyColdObservationBinding {
    outer_action: PhyRfInitPrefixAction,
    request: PhyColdObservationRequest,
}

impl PhyColdObservationBinding {
    pub fn new(outer_action: PhyRfInitPrefixAction) -> Result<Self, PhyColdLoweringError> {
        let request = match outer_action {
            PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ConfigureWorkMode)
            | PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
                XtalDutyPassAction::Restore(XtalDutyRestoreAction::ConfigurePbusWorkMode),
            )) => PhyColdObservationRequest::ConfigurePbusWorkMode,
            _ => return Err(PhyColdLoweringError::UnsupportedAction),
        };
        Ok(Self {
            outer_action,
            request,
        })
    }

    pub const fn outer_action(&self) -> PhyRfInitPrefixAction {
        self.outer_action
    }

    pub const fn request(&self) -> PhyColdObservationRequest {
        self.request
    }

    pub fn into_completion(
        self,
        result: PhyColdObservationResult,
    ) -> Result<PhyRfInitPrefixCompletion, PhyColdLoweringError> {
        match (self.outer_action, result) {
            (
                PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ConfigureWorkMode),
                PhyColdObservationResult::PbusWorkMode { settle_required },
            ) => Ok(PhyRfInitPrefixCompletion::PbusClear(
                PhyPbusClearCompletion::WorkModeConfigured { settle_required },
            )),
            (
                PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
                    XtalDutyPassAction::Restore(XtalDutyRestoreAction::ConfigurePbusWorkMode),
                )),
                PhyColdObservationResult::PbusWorkMode { settle_required },
            ) => Ok(PhyRfInitPrefixCompletion::XtalDuty(
                XtalDutyCalibrationCompletion::Pass(XtalDutyPassCompletion::Restore(
                    XtalDutyRestoreCompletion::PbusWorkModeConfigured { settle_required },
                )),
            )),
            _ => Err(PhyColdLoweringError::UnexpectedOutcome),
        }
    }

    #[cfg(target_arch = "riscv32")]
    pub unsafe fn execute_target(self) -> Result<PhyRfInitPrefixCompletion, PhyColdLoweringError> {
        match self.request {
            PhyColdObservationRequest::ConfigurePbusWorkMode => {
                let settle_required = crate::radio_hal::configure_phy_pbus_work_mode();
                self.into_completion(PhyColdObservationResult::PbusWorkMode { settle_required })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdPbusAction {
    Start(PhyPbusForceTest),
    AwaitCompletionEdge(PhyPbusForceTest),
    Complete(PhyPbusForceTest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdPbusObservation {
    StillPending,
    EdgeConsumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdPbusHardwareResult {
    Busy,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdPbusError {
    BusyAtStart,
    WrongEdge,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhyColdPbusPhase {
    Start,
    AwaitCompletionEdge,
    Complete,
}

/// One uniquely owned PBus command and its independently delivered edge.
///
/// `Busy` after an observation preserves `AwaitCompletionEdge`; the binding
/// does not retry, poll, or arrange another wake. An outer deadline may
/// instead consume the binding through [`into_timeout_completion`].
#[derive(Debug, Eq, PartialEq)]
pub struct PhyColdPbusBinding {
    outer_action: PhyRfInitPrefixAction,
    transaction: PhyPbusForceTest,
    phase: PhyColdPbusPhase,
}

impl PhyColdPbusBinding {
    pub fn new(outer_action: PhyRfInitPrefixAction) -> Result<Self, PhyColdLoweringError> {
        let transaction = match outer_action {
            PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ForceTest(transaction)) => {
                transaction
            }
            PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
                XtalDutyPassAction::Prepare(XtalDutyPrepareAction::ForcePbus(transaction)),
            ))
            | PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
                XtalDutyPassAction::Prepare(XtalDutyPrepareAction::RxDco(
                    PhyRxDcoAction::ForcePbus(transaction),
                )),
            ))
            | PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
                XtalDutyPassAction::Restore(XtalDutyRestoreAction::ForcePbus(transaction)),
            )) => transaction,
            _ => return Err(PhyColdLoweringError::UnsupportedAction),
        };
        Ok(Self {
            outer_action,
            transaction,
            phase: PhyColdPbusPhase::Start,
        })
    }

    pub const fn outer_action(&self) -> PhyRfInitPrefixAction {
        self.outer_action
    }

    pub const fn action(&self) -> PhyColdPbusAction {
        match self.phase {
            PhyColdPbusPhase::Start => PhyColdPbusAction::Start(self.transaction),
            PhyColdPbusPhase::AwaitCompletionEdge => {
                PhyColdPbusAction::AwaitCompletionEdge(self.transaction)
            }
            PhyColdPbusPhase::Complete => PhyColdPbusAction::Complete(self.transaction),
        }
    }

    pub fn started(&mut self) -> Result<(), PhyColdPbusError> {
        match self.phase {
            PhyColdPbusPhase::Start => {
                self.phase = PhyColdPbusPhase::AwaitCompletionEdge;
                Ok(())
            }
            PhyColdPbusPhase::AwaitCompletionEdge => Err(PhyColdPbusError::WrongEdge),
            PhyColdPbusPhase::Complete => Err(PhyColdPbusError::AlreadyComplete),
        }
    }

    pub fn observe_result(
        &mut self,
        result: PhyColdPbusHardwareResult,
    ) -> Result<PhyColdPbusObservation, PhyColdPbusError> {
        match self.phase {
            PhyColdPbusPhase::AwaitCompletionEdge
                if result == PhyColdPbusHardwareResult::Completed =>
            {
                self.phase = PhyColdPbusPhase::Complete;
                Ok(PhyColdPbusObservation::EdgeConsumed)
            }
            PhyColdPbusPhase::AwaitCompletionEdge => Ok(PhyColdPbusObservation::StillPending),
            PhyColdPbusPhase::Start => Err(PhyColdPbusError::WrongEdge),
            PhyColdPbusPhase::Complete => Err(PhyColdPbusError::AlreadyComplete),
        }
    }

    #[cfg(target_arch = "riscv32")]
    pub unsafe fn start_target(&mut self) -> Result<(), PhyColdPbusError> {
        if self.phase != PhyColdPbusPhase::Start {
            return Err(if self.phase == PhyColdPbusPhase::Complete {
                PhyColdPbusError::AlreadyComplete
            } else {
                PhyColdPbusError::WrongEdge
            });
        }
        crate::radio_hal::try_start_phy_pbus_force_test(self.transaction)
            .map_err(|crate::radio_hal::PhyPbusError::Busy| PhyColdPbusError::BusyAtStart)?;
        self.started()
    }

    #[cfg(target_arch = "riscv32")]
    pub unsafe fn observe_target_edge(
        &mut self,
    ) -> Result<PhyColdPbusObservation, PhyColdPbusError> {
        if self.phase != PhyColdPbusPhase::AwaitCompletionEdge {
            return Err(if self.phase == PhyColdPbusPhase::Complete {
                PhyColdPbusError::AlreadyComplete
            } else {
                PhyColdPbusError::WrongEdge
            });
        }
        match crate::radio_hal::try_finish_phy_pbus_force_test() {
            Ok(()) => self.observe_result(PhyColdPbusHardwareResult::Completed),
            Err(crate::radio_hal::PhyPbusError::Busy) => {
                self.observe_result(PhyColdPbusHardwareResult::Busy)
            }
        }
    }

    pub fn into_completion(self) -> Result<PhyRfInitPrefixCompletion, PhyColdLoweringError> {
        if self.phase != PhyColdPbusPhase::Complete {
            return Err(PhyColdLoweringError::IncompleteTransaction);
        }
        match self.outer_action {
            PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ForceTest(transaction))
                if transaction == self.transaction =>
            {
                Ok(PhyRfInitPrefixCompletion::PbusClear(
                    PhyPbusClearCompletion::ForceTestCompleted(transaction),
                ))
            }
            PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
                XtalDutyPassAction::Prepare(XtalDutyPrepareAction::ForcePbus(transaction)),
            )) if transaction == self.transaction => Ok(PhyRfInitPrefixCompletion::XtalDuty(
                XtalDutyCalibrationCompletion::Pass(XtalDutyPassCompletion::Prepare(
                    XtalDutyPrepareCompletion::PbusForceCompleted(transaction),
                )),
            )),
            PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
                XtalDutyPassAction::Prepare(XtalDutyPrepareAction::RxDco(
                    PhyRxDcoAction::ForcePbus(transaction),
                )),
            )) if transaction == self.transaction => Ok(PhyRfInitPrefixCompletion::XtalDuty(
                XtalDutyCalibrationCompletion::Pass(XtalDutyPassCompletion::Prepare(
                    XtalDutyPrepareCompletion::RxDco(PhyRxDcoCompletion::PbusForceCompleted(
                        transaction,
                    )),
                )),
            )),
            PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
                XtalDutyPassAction::Restore(XtalDutyRestoreAction::ForcePbus(transaction)),
            )) if transaction == self.transaction => Ok(PhyRfInitPrefixCompletion::XtalDuty(
                XtalDutyCalibrationCompletion::Pass(XtalDutyPassCompletion::Restore(
                    XtalDutyRestoreCompletion::PbusForceCompleted(transaction),
                )),
            )),
            _ => Err(PhyColdLoweringError::UnexpectedOutcome),
        }
    }

    pub fn into_timeout_completion(
        self,
    ) -> Result<PhyRfInitPrefixCompletion, PhyColdLoweringError> {
        if self.phase != PhyColdPbusPhase::AwaitCompletionEdge {
            return Err(PhyColdLoweringError::IncompleteTransaction);
        }
        match self.outer_action {
            PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ForceTest(transaction))
                if transaction == self.transaction =>
            {
                Ok(PhyRfInitPrefixCompletion::PbusClear(
                    PhyPbusClearCompletion::ForceTestTimedOut(transaction),
                ))
            }
            PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
                XtalDutyPassAction::Prepare(XtalDutyPrepareAction::ForcePbus(transaction)),
            )) if transaction == self.transaction => Ok(PhyRfInitPrefixCompletion::XtalDuty(
                XtalDutyCalibrationCompletion::Pass(XtalDutyPassCompletion::Prepare(
                    XtalDutyPrepareCompletion::PbusForceTimedOut(transaction),
                )),
            )),
            PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
                XtalDutyPassAction::Prepare(XtalDutyPrepareAction::RxDco(
                    PhyRxDcoAction::ForcePbus(transaction),
                )),
            )) if transaction == self.transaction => Ok(PhyRfInitPrefixCompletion::XtalDuty(
                XtalDutyCalibrationCompletion::Pass(XtalDutyPassCompletion::Prepare(
                    XtalDutyPrepareCompletion::RxDco(PhyRxDcoCompletion::PbusForceTimedOut(
                        transaction,
                    )),
                )),
            )),
            PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
                XtalDutyPassAction::Restore(XtalDutyRestoreAction::ForcePbus(transaction)),
            )) if transaction == self.transaction => Ok(PhyRfInitPrefixCompletion::XtalDuty(
                XtalDutyCalibrationCompletion::Pass(XtalDutyPassCompletion::Restore(
                    XtalDutyRestoreCompletion::PbusForceTimedOut(transaction),
                )),
            )),
            _ => Err(PhyColdLoweringError::UnexpectedOutcome),
        }
    }
}

const fn field_mask(high_bit: u8, low_bit: u8) -> u8 {
    let width = high_bit - low_bit + 1;
    ((((1_u16 << width) - 1) << low_bit) & 0xff) as u8
}

const fn extract_field(value: u8, high_bit: u8, low_bit: u8) -> u8 {
    (value & field_mask(high_bit, low_bit)) >> low_bit
}

const fn replace_field(value: u8, high_bit: u8, low_bit: u8, field_value: u8) -> u8 {
    let mask = field_mask(high_bit, low_bit);
    (value & !mask) | ((field_value << low_bit) & mask)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdLocalStep {
    /// One finite state-only action was applied.  The caller may consume
    /// another bounded action in the same executor dispatch or yield.
    StateAdvanced,
    /// Hardware, timer, or observation work must be completed externally.
    External(PhyRfInitPrefixAction),
    Complete(PhyRfInitPrefixOutcome),
}

/// Error from the single-owner composition around `phy_rf_init`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyColdTransitionError {
    WrongCompletion,
    AlreadyComplete,
}

impl From<PhyRfInitPrefixTransitionError> for PhyColdTransitionError {
    fn from(error: PhyRfInitPrefixTransitionError) -> Self {
        match error {
            PhyRfInitPrefixTransitionError::WrongCompletion => Self::WrongCompletion,
            PhyRfInitPrefixTransitionError::AlreadyComplete => Self::AlreadyComplete,
        }
    }
}

/// `phy_rf_init` transition and its only mutable software-state owner.
///
/// [`step_local`](Self::step_local) performs at most one finite state action.
/// It never loops, polls hardware, creates a waker, or retries a busy
/// transaction.  All non-local actions are returned verbatim to the target
/// executor and require one identity-bound external completion.
pub struct PhyRfColdInit {
    state: PhyColdState,
    transition: PhyRfInitPrefixTransition,
}

impl PhyRfColdInit {
    pub const fn new(state: PhyColdState) -> Self {
        Self {
            state,
            transition: PhyRfInitPrefixTransition::new(),
        }
    }

    pub const fn state(&self) -> &PhyColdState {
        &self.state
    }

    pub const fn action(&self) -> PhyRfInitPrefixAction {
        self.transition.action()
    }

    pub fn step_local(&mut self) -> Result<PhyColdLocalStep, PhyColdTransitionError> {
        let action = self.transition.action();
        let completion = match action {
            PhyRfInitPrefixAction::InspectRcCalibrationState => {
                PhyRfInitPrefixCompletion::RcCalibrationStateInspected {
                    already_complete: self.state.rc_calibration_complete(),
                }
            }
            PhyRfInitPrefixAction::RcCalibration(RcCalibrationAction::ApplyResult(result)) => {
                self.state.apply_rc_calibration(result);
                PhyRfInitPrefixCompletion::RcCalibration(RcCalibrationCompletion::Applied)
            }
            PhyRfInitPrefixAction::CaptureFilterDcapParameters => {
                PhyRfInitPrefixCompletion::FilterDcapParametersCaptured(
                    self.state.filter_dcap_parameters(),
                )
            }
            PhyRfInitPrefixAction::CaptureXtalDutyParameters => {
                PhyRfInitPrefixCompletion::XtalDutyParametersCaptured(
                    self.state.xtal_duty_parameters(),
                )
            }
            PhyRfInitPrefixAction::CaptureChannelFrequencyControl => {
                PhyRfInitPrefixCompletion::ChannelFrequencyControlCaptured(
                    self.state.channel_frequency_control(),
                )
            }
            PhyRfInitPrefixAction::Complete(outcome) => {
                self.state.synchronize_success(outcome);
                return Ok(PhyColdLocalStep::Complete(outcome));
            }
            external => return Ok(PhyColdLocalStep::External(external)),
        };

        self.transition.advance(completion)?;
        Ok(PhyColdLocalStep::StateAdvanced)
    }

    pub fn advance_external(
        &mut self,
        completion: PhyRfInitPrefixCompletion,
    ) -> Result<(), PhyColdTransitionError> {
        self.transition.advance(completion)?;
        if let PhyRfInitPrefixAction::Complete(outcome) = self.transition.action() {
            self.state.synchronize_success(outcome);
        }
        Ok(())
    }

    pub fn into_state(self) -> PhyColdState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::{
        initial_parameter_image, PhyCalibrationRecord, PhyColdExternalBinding, PhyColdI2cAction,
        PhyColdI2cBinding, PhyColdI2cObservation, PhyColdI2cOutcome, PhyColdI2cRequest,
        PhyColdI2cTransaction, PhyColdLoweringError, PhyColdMmioBinding, PhyColdObservationBinding,
        PhyColdObservationRequest, PhyColdObservationResult, PhyColdPbusAction, PhyColdPbusBinding,
        PhyColdPbusHardwareResult, PhyColdPbusObservation, PhyColdState, PhyColdTimerBinding,
        PHY_COLD_PARAMETER_LEN,
    };
    use crate::phy_frequency::{PhyChannelFrequencyInitAction, PhyChannelFrequencyInitCompletion};
    use crate::phy_i2c::{
        BiasRegAction, BiasRegCompletion, PhyI2cAddress, PhyI2cError, PhyRfInitPrefixAction,
        PhyRfInitPrefixCompletion, RcCalibrationAction, RcCalibrationCompletion,
    };
    use crate::phy_pbus::{PhyPbusClearAction, PhyPbusClearCompletion, PhyPbusForceTest};
    use crate::phy_rx_dco::{PhyRxDcoAction, PhyRxDcoCompletion};
    use crate::phy_xtal_duty::{
        XtalDutyCalibrationAction, XtalDutyCalibrationCompletion, XtalDutyPassAction,
        XtalDutyPassCompletion, XtalDutyPrepareAction, XtalDutyPrepareCompletion,
        XtalDutyRestoreAction, XtalDutyRestoreCompletion,
    };

    #[test]
    fn baseline_matches_the_complete_sparse_vendor_data_image() {
        let image = initial_parameter_image();
        assert_eq!(image.len(), 508);
        let nonzero: std::vec::Vec<_> = image
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, value)| *value != 0)
            .collect();
        assert_eq!(
            nonzero,
            [
                (0x002, 0xbf),
                (0x003, 0x20),
                (0x006, 0x54),
                (0x00b, 0x01),
                (0x00e, 0x60),
                (0x00f, 0x01),
                (0x012, 0x1f),
                (0x013, 0x16),
                (0x014, 0x01),
                (0x015, 0x40),
                (0x016, 0x02),
                (0x018, 0x50),
                (0x024, 0x30),
                (0x1ab, 0x01),
                (0x1af, 0x01),
            ]
        );
    }

    #[test]
    fn state_is_aligned_unique_storage_with_the_exact_abi_size() {
        assert_eq!(PHY_COLD_PARAMETER_LEN, 0x1fc);
        assert_eq!(core::mem::size_of::<PhyColdState>(), 0x1fc);
        assert_eq!(core::mem::align_of::<PhyColdState>(), 4);
        assert!(!core::mem::needs_drop::<PhyColdState>());
    }

    #[test]
    fn typed_views_replace_every_parameter_read_in_the_rf_prefix() {
        let state = PhyColdState::new();
        assert!(!state.rc_calibration_complete());
        assert_eq!(
            state.xtal_duty_parameters(),
            crate::phy_xtal_duty::XtalDutyCalibrationParameters {
                rf_frequency_offset_base: 0,
                pbus_rx_path_value: 0xbf,
            }
        );
        assert_eq!(
            state.channel_frequency_control(),
            crate::phy_frequency::PhyChannelFrequencyInitControl {
                frequency_register_parameter_override: false,
                frequency_table_initialized: false,
                front_end_parameter_bit: true,
            }
        );
    }

    #[test]
    fn init_calibration_and_backup_are_owned_by_one_state_value() {
        let mut state = PhyColdState::new();
        let mut init = [0; super::PHY_COLD_INIT_PROFILE_LEN];
        let mut index = 0;
        while index != init.len() {
            init[index] = index as u8;
            index += 1;
        }
        state.apply_init_profile(&init);
        state.apply_rc_calibration(45);

        let expected = *state.parameter_image();
        let mut record = PhyCalibrationRecord::new();
        state.backup_into(&mut record);

        let mut restored = PhyColdState::new();
        restored.recover_from(&record);
        assert_eq!(restored.parameter_image(), &expected);
        assert!(restored.rc_calibration_complete());
    }

    #[test]
    fn calibration_record_checksum_has_fixed_owned_storage() {
        let state = PhyColdState::new();
        let mut record = PhyCalibrationRecord::new();
        state.backup_into(&mut record);
        record.refresh_header_and_checksum(0x1234_5678, 0xa1b2_c3d4, 0xe5f6_0718);
        assert!(record.checksum_matches(0x1234_5678, 0xa1b2_c3d4, 0xe5f6_0718));

        let mut bytes = *record.bytes();
        bytes[0x40] ^= 0x80;
        let mut corrupted = PhyCalibrationRecord::from_bytes(bytes);
        assert!(!corrupted.checksum_matches(0x1234_5678, 0xa1b2_c3d4, 0xe5f6_0718));

        // Keep the state live until after the record checks so the test also
        // proves no shared global backing was used.
        assert_eq!(state.parameter_image()[0x002], 0xbf);
    }

    #[test]
    fn busy_observation_preserves_await_state_without_self_progress() {
        let address = PhyI2cAddress::new(0x66, 4).unwrap();
        let mut transaction = PhyColdI2cTransaction::new(PhyColdI2cRequest::read_byte(address));
        assert_eq!(
            transaction.action(),
            PhyColdI2cAction::StartRead { address }
        );
        transaction.read_started().unwrap();
        let awaiting = PhyColdI2cAction::AwaitReadCompletionEdge { address };
        assert_eq!(transaction.action(), awaiting);

        assert_eq!(
            transaction.observe_read_result(Err(PhyI2cError::Busy)),
            Ok(PhyColdI2cObservation::StillPending)
        );
        assert_eq!(transaction.action(), awaiting);

        assert_eq!(
            transaction.observe_read_result(Ok(0xa5)),
            Ok(PhyColdI2cObservation::EdgeConsumed)
        );
        assert_eq!(
            transaction.action(),
            PhyColdI2cAction::Complete(PhyColdI2cOutcome::Read {
                address,
                value: 0xa5,
            })
        );
    }

    #[test]
    fn masked_write_needs_two_distinct_external_edges() {
        let address = PhyI2cAddress::new(0x6b, 0x13).unwrap();
        let request = PhyColdI2cRequest::write_masked(address, 5, 2, 9).unwrap();
        let mut transaction = PhyColdI2cTransaction::new(request);

        transaction.read_started().unwrap();
        transaction.observe_read_result(Ok(0xc3)).unwrap();
        assert_eq!(
            transaction.action(),
            PhyColdI2cAction::StartWrite {
                address,
                value: 0xe7,
            }
        );

        transaction.write_started().unwrap();
        assert_eq!(
            transaction.observe_write_result(Err(PhyI2cError::Busy)),
            Ok(PhyColdI2cObservation::StillPending)
        );
        assert_eq!(
            transaction.action(),
            PhyColdI2cAction::AwaitWriteCompletionEdge { address }
        );
        transaction.observe_write_result(Ok(())).unwrap();
        assert_eq!(
            transaction.action(),
            PhyColdI2cAction::Complete(PhyColdI2cOutcome::Written { address })
        );
    }

    #[test]
    fn masked_read_returns_only_the_requested_field() {
        let address = PhyI2cAddress::new(0x62, 0x0e).unwrap();
        let request = PhyColdI2cRequest::read_masked(address, 4, 1).unwrap();
        let mut transaction = PhyColdI2cTransaction::new(request);
        transaction.read_started().unwrap();
        transaction.observe_read_result(Ok(0xb6)).unwrap();
        assert_eq!(
            transaction.action(),
            PhyColdI2cAction::Complete(PhyColdI2cOutcome::Read {
                address,
                value: 0x0b,
            })
        );
    }

    #[test]
    fn binding_retains_the_exact_outer_action_until_completion() {
        let address = PhyI2cAddress::new(0x6a, 0).unwrap();
        let outer_action = PhyRfInitPrefixAction::Bias(BiasRegAction::Write {
            address,
            value: 0xaf,
        });
        let mut binding = PhyColdI2cBinding::new(outer_action).unwrap();
        assert_eq!(binding.outer_action(), outer_action);
        assert_eq!(
            binding.action(),
            PhyColdI2cAction::StartWrite {
                address,
                value: 0xaf,
            }
        );

        binding.write_started().unwrap();
        assert_eq!(
            binding.observe_write_result(Ok(())),
            Ok(PhyColdI2cObservation::EdgeConsumed)
        );
        assert_eq!(
            binding.into_completion(),
            Ok(PhyRfInitPrefixCompletion::Bias(
                BiasRegCompletion::WriteCompleted { address }
            ))
        );
    }

    #[test]
    fn masked_outer_write_is_two_edges_but_one_identity_bound_completion() {
        let address = PhyI2cAddress::new(0x67, 3).unwrap();
        let outer_action = PhyRfInitPrefixAction::RcCalibration(RcCalibrationAction::WriteMasked {
            address,
            high_bit: 6,
            low_bit: 4,
            value: 5,
        });
        let mut binding = PhyColdI2cBinding::new(outer_action).unwrap();

        binding.read_started().unwrap();
        binding.observe_read_result(Ok(0x83)).unwrap();
        assert_eq!(
            binding.action(),
            PhyColdI2cAction::StartWrite {
                address,
                value: 0xd3,
            }
        );
        binding.write_started().unwrap();
        assert_eq!(
            binding.observe_write_result(Err(PhyI2cError::Busy)),
            Ok(PhyColdI2cObservation::StillPending)
        );
        assert_eq!(
            binding.action(),
            PhyColdI2cAction::AwaitWriteCompletionEdge { address }
        );

        binding.observe_write_result(Ok(())).unwrap();
        assert_eq!(
            binding.into_completion(),
            Ok(PhyRfInitPrefixCompletion::RcCalibration(
                RcCalibrationCompletion::Write
            ))
        );
    }

    #[test]
    fn non_i2c_outer_action_is_rejected_instead_of_becoming_a_fallback() {
        assert_eq!(
            PhyColdI2cBinding::new(PhyRfInitPrefixAction::ConfigureFeBbClock),
            Err(PhyColdLoweringError::UnsupportedAction)
        );
    }

    #[test]
    fn finite_mmio_binding_preserves_dynamic_frequency_identity() {
        let outer_action = PhyRfInitPrefixAction::ChannelFrequency(
            PhyChannelFrequencyInitAction::ConfigureFrequencyRegisters {
                parameter_override: true,
            },
        );
        let binding = PhyColdMmioBinding::new(outer_action).unwrap();
        assert_eq!(binding.outer_action(), outer_action);
        assert_eq!(
            binding.into_completion(),
            Ok(PhyRfInitPrefixCompletion::ChannelFrequency(
                PhyChannelFrequencyInitCompletion::FrequencyRegistersConfigured {
                    parameter_override: true,
                }
            ))
        );

        assert_eq!(
            PhyColdMmioBinding::new(PhyRfInitPrefixAction::DelayMicros(10)),
            Err(PhyColdLoweringError::UnsupportedAction)
        );
    }

    #[test]
    fn timer_binding_consumes_one_exact_delay_edge() {
        let outer_action =
            PhyRfInitPrefixAction::RcCalibration(RcCalibrationAction::DelayMicros(100));
        let binding = PhyColdTimerBinding::new(outer_action).unwrap();
        assert_eq!(binding.outer_action(), outer_action);
        assert_eq!(binding.micros(), 100);
        assert_eq!(
            binding.into_elapsed_completion(),
            Ok(PhyRfInitPrefixCompletion::RcCalibration(
                RcCalibrationCompletion::Delay
            ))
        );

        assert_eq!(
            PhyColdTimerBinding::new(PhyRfInitPrefixAction::ConfigureFeBbClock),
            Err(PhyColdLoweringError::UnsupportedAction)
        );
    }

    #[test]
    fn pbus_busy_result_preserves_one_owned_awaiting_edge() {
        let transaction = PhyPbusForceTest::new(4, 1, 0);
        let outer_action =
            PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ForceTest(transaction));
        let mut binding = PhyColdPbusBinding::new(outer_action).unwrap();
        assert_eq!(binding.action(), PhyColdPbusAction::Start(transaction));

        binding.started().unwrap();
        let awaiting = PhyColdPbusAction::AwaitCompletionEdge(transaction);
        assert_eq!(binding.action(), awaiting);
        assert_eq!(
            binding.observe_result(PhyColdPbusHardwareResult::Busy),
            Ok(PhyColdPbusObservation::StillPending)
        );
        assert_eq!(binding.action(), awaiting);

        assert_eq!(
            binding.observe_result(PhyColdPbusHardwareResult::Completed),
            Ok(PhyColdPbusObservation::EdgeConsumed)
        );
        assert_eq!(binding.action(), PhyColdPbusAction::Complete(transaction));
        assert_eq!(
            binding.into_completion(),
            Ok(PhyRfInitPrefixCompletion::PbusClear(
                PhyPbusClearCompletion::ForceTestCompleted(transaction)
            ))
        );
    }

    #[test]
    fn pbus_timeout_consumes_the_exact_awaiting_transaction() {
        let transaction = PhyPbusForceTest::new(3, 2, 0x100);
        let outer_action =
            PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ForceTest(transaction));
        let mut binding = PhyColdPbusBinding::new(outer_action).unwrap();
        binding.started().unwrap();
        assert_eq!(
            binding.into_timeout_completion(),
            Ok(PhyRfInitPrefixCompletion::PbusClear(
                PhyPbusClearCompletion::ForceTestTimedOut(transaction)
            ))
        );
    }

    #[test]
    fn nested_xtal_pbus_edges_return_to_the_exact_parent_transition() {
        let prepare_transaction = PhyPbusForceTest::new(0, 2, 0x42);
        let prepare_action = PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
            XtalDutyPassAction::Prepare(XtalDutyPrepareAction::ForcePbus(prepare_transaction)),
        ));
        let mut prepare = PhyColdPbusBinding::new(prepare_action).unwrap();
        prepare.started().unwrap();
        prepare
            .observe_result(PhyColdPbusHardwareResult::Completed)
            .unwrap();
        assert_eq!(
            prepare.into_completion(),
            Ok(PhyRfInitPrefixCompletion::XtalDuty(
                XtalDutyCalibrationCompletion::Pass(XtalDutyPassCompletion::Prepare(
                    XtalDutyPrepareCompletion::PbusForceCompleted(prepare_transaction)
                ))
            ))
        );

        let rx_dco_transaction = PhyPbusForceTest::new(3, 1, 0x1ff);
        let rx_dco_action = PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
            XtalDutyPassAction::Prepare(XtalDutyPrepareAction::RxDco(PhyRxDcoAction::ForcePbus(
                rx_dco_transaction,
            ))),
        ));
        let mut rx_dco = PhyColdPbusBinding::new(rx_dco_action).unwrap();
        rx_dco.started().unwrap();
        assert_eq!(
            rx_dco.into_timeout_completion(),
            Ok(PhyRfInitPrefixCompletion::XtalDuty(
                XtalDutyCalibrationCompletion::Pass(XtalDutyPassCompletion::Prepare(
                    XtalDutyPrepareCompletion::RxDco(PhyRxDcoCompletion::PbusForceTimedOut(
                        rx_dco_transaction
                    ))
                ))
            ))
        );

        let restore_transaction = PhyPbusForceTest::new(1, 2, 0);
        let restore_action = PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
            XtalDutyPassAction::Restore(XtalDutyRestoreAction::ForcePbus(restore_transaction)),
        ));
        let mut restore = PhyColdPbusBinding::new(restore_action).unwrap();
        restore.started().unwrap();
        restore
            .observe_result(PhyColdPbusHardwareResult::Completed)
            .unwrap();
        assert_eq!(
            restore.into_completion(),
            Ok(PhyRfInitPrefixCompletion::XtalDuty(
                XtalDutyCalibrationCompletion::Pass(XtalDutyPassCompletion::Restore(
                    XtalDutyRestoreCompletion::PbusForceCompleted(restore_transaction)
                ))
            ))
        );
    }

    #[test]
    fn sampled_pbus_work_mode_is_bound_to_its_exact_parent() {
        let clear_action = PhyRfInitPrefixAction::PbusClear(PhyPbusClearAction::ConfigureWorkMode);
        let clear = PhyColdObservationBinding::new(clear_action).unwrap();
        assert_eq!(clear.outer_action(), clear_action);
        assert_eq!(
            clear.request(),
            PhyColdObservationRequest::ConfigurePbusWorkMode
        );
        assert_eq!(
            clear.into_completion(PhyColdObservationResult::PbusWorkMode {
                settle_required: true,
            }),
            Ok(PhyRfInitPrefixCompletion::PbusClear(
                PhyPbusClearCompletion::WorkModeConfigured {
                    settle_required: true
                }
            ))
        );

        let restore_action = PhyRfInitPrefixAction::XtalDuty(XtalDutyCalibrationAction::Pass(
            XtalDutyPassAction::Restore(XtalDutyRestoreAction::ConfigurePbusWorkMode),
        ));
        let restore = PhyColdObservationBinding::new(restore_action).unwrap();
        assert_eq!(
            restore.into_completion(PhyColdObservationResult::PbusWorkMode {
                settle_required: false,
            }),
            Ok(PhyRfInitPrefixCompletion::XtalDuty(
                XtalDutyCalibrationCompletion::Pass(XtalDutyPassCompletion::Restore(
                    XtalDutyRestoreCompletion::PbusWorkModeConfigured {
                        settle_required: false
                    }
                ))
            ))
        );
    }

    #[test]
    fn external_lowering_has_no_vendor_or_synchronous_fallback_variant() {
        assert!(matches!(
            PhyColdExternalBinding::lower(PhyRfInitPrefixAction::DelayMicros(10)),
            Ok(PhyColdExternalBinding::Timer(_))
        ));
        assert!(matches!(
            PhyColdExternalBinding::lower(PhyRfInitPrefixAction::ConfigureFrontEndRegisters),
            Ok(PhyColdExternalBinding::Mmio(_))
        ));

        let address = PhyI2cAddress::new(0x62, 1).unwrap();
        assert!(matches!(
            PhyColdExternalBinding::lower(PhyRfInitPrefixAction::ReadParameter18e { address }),
            Ok(PhyColdExternalBinding::I2c(_))
        ));
        let transaction = PhyPbusForceTest::new(4, 1, 0);
        assert!(matches!(
            PhyColdExternalBinding::lower(PhyRfInitPrefixAction::PbusClear(
                PhyPbusClearAction::ForceTest(transaction)
            )),
            Ok(PhyColdExternalBinding::Pbus(_))
        ));
        assert!(matches!(
            PhyColdExternalBinding::lower(PhyRfInitPrefixAction::PbusClear(
                PhyPbusClearAction::ConfigureWorkMode
            )),
            Ok(PhyColdExternalBinding::Observation(_))
        ));
        assert_eq!(
            PhyColdExternalBinding::lower(PhyRfInitPrefixAction::CaptureFilterDcapParameters),
            Err(PhyColdLoweringError::UnsupportedAction)
        );
    }

    #[test]
    fn channel_frequency_i2c_completion_keeps_its_field_identity() {
        let address = PhyI2cAddress::new(0x63, 6).unwrap();
        let outer_action =
            PhyRfInitPrefixAction::ChannelFrequency(PhyChannelFrequencyInitAction::WriteMasked {
                address,
                high_bit: 7,
                low_bit: 3,
                value: 0x12,
            });
        let mut binding = PhyColdI2cBinding::new(outer_action).unwrap();
        binding.read_started().unwrap();
        binding.observe_read_result(Ok(0x05)).unwrap();
        binding.write_started().unwrap();
        binding.observe_write_result(Ok(())).unwrap();
        assert_eq!(
            binding.into_completion(),
            Ok(PhyRfInitPrefixCompletion::ChannelFrequency(
                PhyChannelFrequencyInitCompletion::MaskedWrite {
                    address,
                    high_bit: 7,
                    low_bit: 3,
                }
            ))
        );
    }
}
