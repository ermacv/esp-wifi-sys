//! Rust-owned transmit rate-control state.
//!
//! The vendor ABI still passes a stable 0x98-byte record pointer while the
//! surrounding rate-selection code is being migrated.  The storage type below
//! makes that ownership explicit.  Runtime policy is represented separately
//! by [`RateControlState`], so retry accounting and schedule transitions are
//! safe value operations rather than mutations performed by ROM through an
//! untyped pointer.

pub(crate) const RATE_CONTROL_RECORD_SIZE: usize = 0x98;
pub(crate) const RATE_SCHEDULE_RECORD_SIZE: usize = 12;

/// Stable backing for one temporary vendor-compatible rate-control record.
///
/// Unknown fields remain opaque until their readers and writers are migrated.
/// Code outside the target adapter must not interpret `bytes` by offset.
#[repr(C, align(4))]
pub(crate) struct RateControlRecord {
    bytes: [u8; RATE_CONTROL_RECORD_SIZE],
}

impl RateControlRecord {
    pub(crate) const fn zeroed() -> Self {
        Self {
            bytes: [0; RATE_CONTROL_RECORD_SIZE],
        }
    }
}

/// Instruction-evidenced fields of one 12-byte rate schedule record.
///
/// The remaining bytes select the actual PHY rate and retry sequence.  They
/// stay in the compatibility projection for now; only the mutable schedule
/// state used by TX completion is owned here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RateScheduleState {
    pub retry_limit: u8,
    pub index: u8,
    pub adaptive: u8,
}

/// Safe state mutated by the recovered `rcTxUpdatePer` transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RateControlState {
    pub retry_pressure: u8,
    pub weighted_retries: u32,
    pub transmissions: u32,
    pub completed: u32,
    pub reevaluate_after_us: u32,
    pub retry_state_1d: u8,
    pub retry_state_1e: u8,
    pub maximum_schedule_index: u8,
    pub current_schedule: RateScheduleState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScheduleSelection {
    Unchanged,
    AdvanceCurrentByOne,
    LegacyIndex(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TxPerUpdate {
    pub schedule: ScheduleSelection,
}

impl RateControlState {
    const COUNTER_RESCALE_LIMIT: u32 = 0x0200_0000;
    const REEVALUATE_AFTER_US: u32 = 500_000;

    /// Apply the complete scalar state transition from the pinned
    /// `libpp.a[trc.o]::rcTxUpdatePer` body.
    ///
    /// Arithmetic intentionally follows the RISC-V body: the per-result
    /// penalty is truncated to a byte before it is accumulated, retry pressure
    /// is a wrapping byte, and large counters are halved together.
    pub(crate) fn update_tx_per(&mut self, retries: u32) -> TxPerUpdate {
        let penalty = if u32::from(self.current_schedule.retry_limit) < retries {
            self.current_schedule.retry_limit.wrapping_add(2)
        } else {
            retries.wrapping_add(1) as u8
        };

        if self.transmissions.wrapping_add(1) >= Self::COUNTER_RESCALE_LIMIT {
            self.transmissions >>= 1;
            self.weighted_retries >>= 1;
        }
        self.transmissions = self.transmissions.wrapping_add(1);
        self.weighted_retries = self.weighted_retries.wrapping_add(u32::from(penalty));

        match retries {
            0..=2 => self.retry_pressure = 0,
            3..=4 => {}
            5..=7 => self.retry_pressure = self.retry_pressure.wrapping_add(1),
            _ => self.retry_pressure = self.retry_pressure.wrapping_add(2),
        }

        if self.retry_pressure <= 6 {
            return TxPerUpdate {
                schedule: ScheduleSelection::Unchanged,
            };
        }

        // Exact scalar part of `rcClearCurSched`.
        self.current_schedule.adaptive = 0;
        self.reevaluate_after_us = Self::REEVALUATE_AFTER_US;
        self.transmissions = 0;
        self.weighted_retries = 0;
        self.completed = 0;
        self.retry_state_1d = 0;
        self.retry_state_1e = 0;
        self.retry_pressure = 0;

        let next_index = u16::from(self.current_schedule.index) + 1;
        let schedule = if u16::from(self.maximum_schedule_index) < next_index {
            ScheduleSelection::LegacyIndex(self.maximum_schedule_index)
        } else {
            ScheduleSelection::AdvanceCurrentByOne
        };
        TxPerUpdate { schedule }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BeamformingReportRate {
    pub mode: u8,
    pub rate: u16,
    pub dcm: bool,
    pub ersu: bool,
    pub ersu_ack: bool,
}

/// Safe policy recovered from `trc_set_bf_report_rate`.
pub(crate) const fn beamforming_report_rate(
    filtered_ack_snr: u8,
    quarter_noise_floor: i32,
    he_feature_8f: bool,
    he_feature_90: bool,
) -> BeamformingReportRate {
    let metric = filtered_ack_snr.wrapping_sub(quarter_noise_floor as u8) as i8;
    if metric > 13 {
        BeamformingReportRate {
            mode: 1,
            rate: 16,
            dcm: false,
            ersu: false,
            ersu_ack: false,
        }
    } else if he_feature_8f && he_feature_90 {
        BeamformingReportRate {
            mode: 2,
            rate: 16,
            dcm: true,
            ersu: true,
            ersu_ack: true,
        }
    } else {
        BeamformingReportRate {
            mode: 0,
            rate: 11,
            dcm: false,
            ersu: false,
            ersu_ack: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> RateControlState {
        RateControlState {
            retry_pressure: 4,
            weighted_retries: 10,
            transmissions: 20,
            completed: 30,
            reevaluate_after_us: 1,
            retry_state_1d: 2,
            retry_state_1e: 3,
            maximum_schedule_index: 5,
            current_schedule: RateScheduleState {
                retry_limit: 7,
                index: 2,
                adaptive: 1,
            },
        }
    }

    #[test]
    fn retry_bands_match_the_pinned_transition() {
        let mut low = state();
        assert_eq!(low.update_tx_per(2).schedule, ScheduleSelection::Unchanged);
        assert_eq!(low.retry_pressure, 0);
        assert_eq!(low.transmissions, 21);
        assert_eq!(low.weighted_retries, 13);

        let mut middle = state();
        middle.update_tx_per(4);
        assert_eq!(middle.retry_pressure, 4);

        let mut high = state();
        high.update_tx_per(6);
        assert_eq!(high.retry_pressure, 5);

        let mut very_high = state();
        very_high.update_tx_per(8);
        assert_eq!(very_high.retry_pressure, 6);
        // retry_limit < retries selects retry_limit + 2, not retries + 1.
        assert_eq!(very_high.weighted_retries, 19);
    }

    #[test]
    fn large_counters_are_rescaled_before_accumulation() {
        let mut value = state();
        value.transmissions = 0x01ff_ffff;
        value.weighted_retries = 100;
        value.update_tx_per(0);
        assert_eq!(value.transmissions, 0x0100_0000);
        assert_eq!(value.weighted_retries, 51);
    }

    #[test]
    fn pressure_threshold_clears_state_and_advances_schedule() {
        let mut value = state();
        value.retry_pressure = 6;
        let update = value.update_tx_per(5);
        assert_eq!(update.schedule, ScheduleSelection::AdvanceCurrentByOne);
        assert_eq!(value.retry_pressure, 0);
        assert_eq!(value.weighted_retries, 0);
        assert_eq!(value.transmissions, 0);
        assert_eq!(value.completed, 0);
        assert_eq!(value.reevaluate_after_us, 500_000);
        assert_eq!(value.retry_state_1d, 0);
        assert_eq!(value.retry_state_1e, 0);
        assert_eq!(value.current_schedule.adaptive, 0);
    }

    #[test]
    fn last_schedule_falls_back_to_the_legacy_table() {
        let mut value = state();
        value.retry_pressure = 6;
        value.maximum_schedule_index = 2;
        value.current_schedule.index = 2;
        assert_eq!(
            value.update_tx_per(5).schedule,
            ScheduleSelection::LegacyIndex(2)
        );
    }

    #[test]
    fn byte_pressure_wrap_is_preserved() {
        let mut value = state();
        value.retry_pressure = 0xff;
        value.update_tx_per(8);
        assert_eq!(value.retry_pressure, 1);
    }

    #[test]
    fn beamforming_policy_has_three_exact_modes() {
        assert_eq!(
            beamforming_report_rate(40, 20, true, true),
            BeamformingReportRate {
                mode: 1,
                rate: 16,
                dcm: false,
                ersu: false,
                ersu_ack: false,
            }
        );
        assert_eq!(
            beamforming_report_rate(20, 20, true, true),
            BeamformingReportRate {
                mode: 2,
                rate: 16,
                dcm: true,
                ersu: true,
                ersu_ack: true,
            }
        );
        assert_eq!(
            beamforming_report_rate(20, 20, true, false),
            BeamformingReportRate {
                mode: 0,
                rate: 11,
                dcm: false,
                ersu: false,
                ersu_ack: false,
            }
        );
    }
}
