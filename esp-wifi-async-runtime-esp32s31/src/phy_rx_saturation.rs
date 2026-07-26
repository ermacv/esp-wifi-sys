//! Event-driven replacement plan for `phy_check_rx_sat`.
//!
//! The pinned archive body performs eleven PBus commands, calls
//! `ets_delay_us(5)`, then reads `0x2010_08d0[21:20]` exactly 100 times.
//! Copying that loop would reintroduce CPU polling. This transition instead
//! requires one externally completed capture window. Its eventual target
//! binding must be interrupt, DMA, or timer-sampler driven; an executor-side
//! register loop is explicitly not a valid completion source.

use crate::phy_pbus::PhyPbusForceTest;

pub const PHY_RX_SATURATION_DELAY_MICROS: u32 = 5;
pub const PHY_RX_SATURATION_SAMPLE_COUNT: u8 = 100;
pub const PHY_RX_SATURATION_STATUS_ADDRESS: usize = 0x2010_08d0;
pub const PHY_RX_SATURATION_STATUS_MASK: u32 = 0x0030_0000;

const PHY_RX_SATURATION_PBUS_COUNT: u8 = 11;

const fn pbus_transaction(index: u8, parameter_002: u8) -> PhyPbusForceTest {
    match index {
        0 => PhyPbusForceTest::new(4, 1, 0),
        1 => PhyPbusForceTest::new(4, 2, 1),
        2 => PhyPbusForceTest::new(5, 1, 0),
        3 => PhyPbusForceTest::new(0, 1, 0x40),
        4 => PhyPbusForceTest::new(0, 2, parameter_002 as u16),
        5 => PhyPbusForceTest::new(1, 1, 0x189),
        6 => PhyPbusForceTest::new(1, 2, 0),
        7 => PhyPbusForceTest::new(2, 1, 0x100),
        8 => PhyPbusForceTest::new(3, 1, 0x100),
        9 => PhyPbusForceTest::new(2, 2, 0x100),
        _ => PhyPbusForceTest::new(3, 2, 0x100),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyRxSaturationOutcome {
    Measured { saturated_samples: u8, samples: u8 },
    PbusTimedOut(PhyPbusForceTest),
    CaptureTimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyRxSaturationAction {
    ConfigureDebugMode,
    ForcePbus(PhyPbusForceTest),
    DelayMicros {
        micros: u32,
    },
    AwaitCaptureCompletion {
        address: usize,
        activity_mask: u32,
        samples: u8,
    },
    ConfigureWorkMode,
    Complete(PhyRxSaturationOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyRxSaturationCompletion {
    DebugModeConfigured,
    PbusCompleted(PhyPbusForceTest),
    PbusTimedOut(PhyPbusForceTest),
    DelayElapsed {
        micros: u32,
    },
    CaptureCompleted {
        address: usize,
        samples: u8,
        saturated_samples: u8,
    },
    CaptureTimedOut,
    WorkModeConfigured,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhyRxSaturationTransitionError {
    WrongCompletion,
    InvalidCapture,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhyRxSaturationStep {
    DebugMode,
    Pbus { index: u8 },
    Delay,
    Capture,
    WorkMode(PhyRxSaturationOutcome),
    Complete(PhyRxSaturationOutcome),
}

/// Caller-driven `phy_check_rx_sat` state machine with no polling operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyRxSaturationTransition {
    parameter_002: u8,
    step: PhyRxSaturationStep,
}

impl PhyRxSaturationTransition {
    pub const fn new(parameter_002: u8) -> Self {
        Self {
            parameter_002,
            step: PhyRxSaturationStep::DebugMode,
        }
    }

    pub const fn action(self) -> PhyRxSaturationAction {
        match self.step {
            PhyRxSaturationStep::DebugMode => PhyRxSaturationAction::ConfigureDebugMode,
            PhyRxSaturationStep::Pbus { index } => {
                PhyRxSaturationAction::ForcePbus(pbus_transaction(index, self.parameter_002))
            }
            PhyRxSaturationStep::Delay => PhyRxSaturationAction::DelayMicros {
                micros: PHY_RX_SATURATION_DELAY_MICROS,
            },
            PhyRxSaturationStep::Capture => PhyRxSaturationAction::AwaitCaptureCompletion {
                address: PHY_RX_SATURATION_STATUS_ADDRESS,
                activity_mask: PHY_RX_SATURATION_STATUS_MASK,
                samples: PHY_RX_SATURATION_SAMPLE_COUNT,
            },
            PhyRxSaturationStep::WorkMode(_) => PhyRxSaturationAction::ConfigureWorkMode,
            PhyRxSaturationStep::Complete(outcome) => PhyRxSaturationAction::Complete(outcome),
        }
    }

    pub fn advance(
        &mut self,
        completion: PhyRxSaturationCompletion,
    ) -> Result<(), PhyRxSaturationTransitionError> {
        self.step = match (self.step, completion) {
            (PhyRxSaturationStep::DebugMode, PhyRxSaturationCompletion::DebugModeConfigured) => {
                PhyRxSaturationStep::Pbus { index: 0 }
            }
            (
                PhyRxSaturationStep::Pbus { index },
                PhyRxSaturationCompletion::PbusCompleted(completed),
            ) if completed == pbus_transaction(index, self.parameter_002) => {
                let next = index + 1;
                if next == PHY_RX_SATURATION_PBUS_COUNT {
                    PhyRxSaturationStep::Delay
                } else {
                    PhyRxSaturationStep::Pbus { index: next }
                }
            }
            (
                PhyRxSaturationStep::Pbus { index },
                PhyRxSaturationCompletion::PbusTimedOut(completed),
            ) if completed == pbus_transaction(index, self.parameter_002) => {
                PhyRxSaturationStep::WorkMode(PhyRxSaturationOutcome::PbusTimedOut(completed))
            }
            (
                PhyRxSaturationStep::Delay,
                PhyRxSaturationCompletion::DelayElapsed {
                    micros: PHY_RX_SATURATION_DELAY_MICROS,
                },
            ) => PhyRxSaturationStep::Capture,
            (
                PhyRxSaturationStep::Capture,
                PhyRxSaturationCompletion::CaptureCompleted {
                    address: PHY_RX_SATURATION_STATUS_ADDRESS,
                    samples: PHY_RX_SATURATION_SAMPLE_COUNT,
                    saturated_samples,
                },
            ) if saturated_samples <= PHY_RX_SATURATION_SAMPLE_COUNT => {
                PhyRxSaturationStep::WorkMode(PhyRxSaturationOutcome::Measured {
                    saturated_samples,
                    samples: PHY_RX_SATURATION_SAMPLE_COUNT,
                })
            }
            (PhyRxSaturationStep::Capture, PhyRxSaturationCompletion::CaptureCompleted { .. }) => {
                return Err(PhyRxSaturationTransitionError::InvalidCapture)
            }
            (PhyRxSaturationStep::Capture, PhyRxSaturationCompletion::CaptureTimedOut) => {
                PhyRxSaturationStep::WorkMode(PhyRxSaturationOutcome::CaptureTimedOut)
            }
            (
                PhyRxSaturationStep::WorkMode(outcome),
                PhyRxSaturationCompletion::WorkModeConfigured,
            ) => PhyRxSaturationStep::Complete(outcome),
            (PhyRxSaturationStep::Complete(_), _) => {
                return Err(PhyRxSaturationTransitionError::AlreadyComplete);
            }
            _ => return Err(PhyRxSaturationTransitionError::WrongCompletion),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PhyRxSaturationAction, PhyRxSaturationCompletion, PhyRxSaturationOutcome,
        PhyRxSaturationTransition, PhyRxSaturationTransitionError, PHY_RX_SATURATION_DELAY_MICROS,
        PHY_RX_SATURATION_SAMPLE_COUNT, PHY_RX_SATURATION_STATUS_ADDRESS,
        PHY_RX_SATURATION_STATUS_MASK,
    };
    use crate::phy_pbus::PhyPbusForceTest;

    #[test]
    fn transition_reproduces_all_pbus_commands_and_async_edges() {
        let expected = [
            PhyPbusForceTest::new(4, 1, 0),
            PhyPbusForceTest::new(4, 2, 1),
            PhyPbusForceTest::new(5, 1, 0),
            PhyPbusForceTest::new(0, 1, 0x40),
            PhyPbusForceTest::new(0, 2, 0xbf),
            PhyPbusForceTest::new(1, 1, 0x189),
            PhyPbusForceTest::new(1, 2, 0),
            PhyPbusForceTest::new(2, 1, 0x100),
            PhyPbusForceTest::new(3, 1, 0x100),
            PhyPbusForceTest::new(2, 2, 0x100),
            PhyPbusForceTest::new(3, 2, 0x100),
        ];
        let mut transition = PhyRxSaturationTransition::new(0xbf);
        assert_eq!(
            transition.action(),
            PhyRxSaturationAction::ConfigureDebugMode
        );
        transition
            .advance(PhyRxSaturationCompletion::DebugModeConfigured)
            .unwrap();
        for transaction in expected {
            assert_eq!(
                transition.action(),
                PhyRxSaturationAction::ForcePbus(transaction)
            );
            transition
                .advance(PhyRxSaturationCompletion::PbusCompleted(transaction))
                .unwrap();
        }
        assert_eq!(
            transition.action(),
            PhyRxSaturationAction::DelayMicros {
                micros: PHY_RX_SATURATION_DELAY_MICROS,
            }
        );
        transition
            .advance(PhyRxSaturationCompletion::DelayElapsed {
                micros: PHY_RX_SATURATION_DELAY_MICROS,
            })
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRxSaturationAction::AwaitCaptureCompletion {
                address: PHY_RX_SATURATION_STATUS_ADDRESS,
                activity_mask: PHY_RX_SATURATION_STATUS_MASK,
                samples: PHY_RX_SATURATION_SAMPLE_COUNT,
            }
        );
        transition
            .advance(PhyRxSaturationCompletion::CaptureCompleted {
                address: PHY_RX_SATURATION_STATUS_ADDRESS,
                samples: PHY_RX_SATURATION_SAMPLE_COUNT,
                saturated_samples: 7,
            })
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRxSaturationAction::ConfigureWorkMode
        );
        transition
            .advance(PhyRxSaturationCompletion::WorkModeConfigured)
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRxSaturationAction::Complete(PhyRxSaturationOutcome::Measured {
                saturated_samples: 7,
                samples: 100,
            })
        );
    }

    #[test]
    fn capture_rejects_wrong_identity_and_impossible_population() {
        let mut transition = PhyRxSaturationTransition::new(0);
        transition
            .advance(PhyRxSaturationCompletion::DebugModeConfigured)
            .unwrap();
        for transaction in [
            PhyPbusForceTest::new(4, 1, 0),
            PhyPbusForceTest::new(4, 2, 1),
            PhyPbusForceTest::new(5, 1, 0),
            PhyPbusForceTest::new(0, 1, 0x40),
            PhyPbusForceTest::new(0, 2, 0),
            PhyPbusForceTest::new(1, 1, 0x189),
            PhyPbusForceTest::new(1, 2, 0),
            PhyPbusForceTest::new(2, 1, 0x100),
            PhyPbusForceTest::new(3, 1, 0x100),
            PhyPbusForceTest::new(2, 2, 0x100),
            PhyPbusForceTest::new(3, 2, 0x100),
        ] {
            transition
                .advance(PhyRxSaturationCompletion::PbusCompleted(transaction))
                .unwrap();
        }
        transition
            .advance(PhyRxSaturationCompletion::DelayElapsed { micros: 5 })
            .unwrap();
        assert_eq!(
            transition.advance(PhyRxSaturationCompletion::CaptureCompleted {
                address: PHY_RX_SATURATION_STATUS_ADDRESS + 4,
                samples: 100,
                saturated_samples: 1,
            }),
            Err(PhyRxSaturationTransitionError::InvalidCapture)
        );
        assert_eq!(
            transition.advance(PhyRxSaturationCompletion::CaptureCompleted {
                address: PHY_RX_SATURATION_STATUS_ADDRESS,
                samples: 100,
                saturated_samples: 101,
            }),
            Err(PhyRxSaturationTransitionError::InvalidCapture)
        );
    }

    #[test]
    fn timeout_still_restores_work_mode_before_terminal_state() {
        let transaction = PhyPbusForceTest::new(4, 1, 0);
        let mut transition = PhyRxSaturationTransition::new(0);
        transition
            .advance(PhyRxSaturationCompletion::DebugModeConfigured)
            .unwrap();
        transition
            .advance(PhyRxSaturationCompletion::PbusTimedOut(transaction))
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRxSaturationAction::ConfigureWorkMode
        );
        transition
            .advance(PhyRxSaturationCompletion::WorkModeConfigured)
            .unwrap();
        assert_eq!(
            transition.action(),
            PhyRxSaturationAction::Complete(PhyRxSaturationOutcome::PbusTimedOut(transaction))
        );
    }
}
