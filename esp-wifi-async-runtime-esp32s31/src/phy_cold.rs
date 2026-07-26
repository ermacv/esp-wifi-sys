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
    phy_frequency::PhyChannelFrequencyInitControl,
    phy_i2c::{
        FilterDcapParameters, PhyI2cAddress, PhyI2cError, PhyRfInitPrefixAction,
        PhyRfInitPrefixCompletion, PhyRfInitPrefixOutcome, PhyRfInitPrefixTransition,
        PhyRfInitPrefixTransitionError, RcCalibrationAction, RcCalibrationCompletion,
    },
    phy_param::{
        apply_init_data, apply_rc_calibration_result, calibration_record_check_or_write,
        xtal_parameter_code, PHY_CALIBRATION_PAYLOAD_OFFSET, PHY_CALIBRATION_PREFIX_LEN,
        PHY_INIT_DATA_LEN, PHY_PARAM_LEN,
    },
    phy_xtal_duty::XtalDutyCalibrationParameters,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    pub const fn action(self) -> PhyColdI2cAction {
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

    const fn phase_error(self) -> PhyColdI2cError {
        if matches!(self.phase, PhyColdI2cPhase::Complete(_)) {
            PhyColdI2cError::AlreadyComplete
        } else {
            PhyColdI2cError::WrongEdge
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
        initial_parameter_image, PhyCalibrationRecord, PhyColdI2cAction, PhyColdI2cObservation,
        PhyColdI2cOutcome, PhyColdI2cRequest, PhyColdI2cTransaction, PhyColdState,
        PHY_COLD_PARAMETER_LEN,
    };
    use crate::phy_i2c::{PhyI2cAddress, PhyI2cError};

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
}
