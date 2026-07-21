//! Allocation-free TX BlockAck negotiation state.
//!
//! The stock `ieee80211_ampdu_request` allocates one vendor agreement object
//! per TID and arms an OS timer. This module owns the protocol state and its
//! deadline instead. A caller sends the returned action body through the
//! fixed management-frame pool and programs `TxBlockAckAlarm::deadline_us`
//! into a Rust async timer.

pub const BLOCK_ACK_CATEGORY: u8 = 3;
pub const ADDBA_REQUEST_ACTION: u8 = 0;
pub const ADDBA_RESPONSE_ACTION: u8 = 1;
pub const ADDBA_ACTION_BODY_LEN: usize = 9;
pub const TX_BLOCK_ACK_MAX_WINDOW: u16 = 32;
pub const TX_AMPDU_SLOT_CAPACITY: usize = TX_BLOCK_ACK_MAX_WINDOW as usize;

const BA_PARAMETER_AMSDU: u16 = 1;
const BA_PARAMETER_IMMEDIATE: u16 = 1 << 1;
const BA_PARAMETER_TID_SHIFT: u32 = 2;
const BA_PARAMETER_TID_MASK: u16 = 0x0f << BA_PARAMETER_TID_SHIFT;
const BA_PARAMETER_WINDOW_SHIFT: u32 = 6;
const BA_PARAMETER_WINDOW_MASK: u16 = 0x03ff << BA_PARAMETER_WINDOW_SHIFT;
const SEQUENCE_NUMBER_MASK: u16 = 0x0fff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxBlockAckError {
    InvalidTid(u8),
    InvalidWindow(u16),
    ZeroTimeout,
    DeadlineOverflow,
    MalformedResponse,
    UnexpectedResponse,
    DelayedPolicyUnsupported,
    WindowExceedsCapacity(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxBlockAckConfig {
    pub tid: u8,
    pub window: u16,
    pub timeout_tu: u16,
    pub negotiation_timeout_us: u32,
    pub amsdu: bool,
}

impl TxBlockAckConfig {
    pub const fn validate(self) -> Result<Self, TxBlockAckError> {
        if self.tid > 15 {
            return Err(TxBlockAckError::InvalidTid(self.tid));
        }
        if self.window == 0 || self.window > TX_BLOCK_ACK_MAX_WINDOW {
            return Err(TxBlockAckError::InvalidWindow(self.window));
        }
        if self.negotiation_timeout_us == 0 {
            return Err(TxBlockAckError::ZeroTimeout);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxBlockAckAlarm {
    pub generation: u32,
    pub deadline_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddbaRequest {
    pub generation: u32,
    pub dialog_token: u8,
    pub starting_sequence: u16,
    pub body: [u8; ADDBA_ACTION_BODY_LEN],
    pub alarm: TxBlockAckAlarm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationalTxBlockAck {
    pub tid: u8,
    pub window: u16,
    pub timeout_tu: u16,
    pub starting_sequence: u16,
    pub amsdu: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxBlockAckResponse {
    Operational(OperationalTxBlockAck),
    Rejected(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TxBlockAckPhase {
    Idle,
    Awaiting {
        dialog_token: u8,
        starting_sequence: u16,
    },
    Operational(OperationalTxBlockAck),
}

/// One statically owned TX BlockAck agreement for one QoS TID.
///
/// Every method performs a fixed number of loads/stores. Timer expiry is an
/// externally delivered edge; this type never reads time, sleeps, or retries.
pub struct TxBlockAckSession {
    config: TxBlockAckConfig,
    generation: u32,
    next_dialog_token: u8,
    phase: TxBlockAckPhase,
}

/// Opaque index of one statically owned TX frame.
///
/// The strict S31 data path has exactly 32 fixed TX slots. Keeping only their
/// indices here prevents the BlockAck state machine from owning raw pointers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxAmpduSlot(u8);

impl TxAmpduSlot {
    pub const fn new(index: u8) -> Option<Self> {
        if (index as usize) < TX_AMPDU_SLOT_CAPACITY {
            Some(Self(index))
        } else {
            None
        }
    }

    pub const fn index(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxAmpduMpdu {
    pub slot: TxAmpduSlot,
    pub sequence: u16,
}

/// BlockAck information read from the MAC completion registers.
///
/// Bit zero acknowledges `starting_sequence`, bit one the following sequence,
/// and so on. The S31 completion block exposes 64 bits even though strict mode
/// deliberately negotiates a window of at most 32 frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxBlockAckBitmap {
    pub starting_sequence: u16,
    pub bitmap: u64,
}

impl TxBlockAckBitmap {
    pub const fn new(starting_sequence: u16, bitmap: u64) -> Self {
        Self {
            starting_sequence: starting_sequence & SEQUENCE_NUMBER_MASK,
            bitmap,
        }
    }

    pub const fn acknowledges(self, sequence: u16) -> bool {
        let distance = sequence.wrapping_sub(self.starting_sequence) & SEQUENCE_NUMBER_MASK;
        distance < 64 && self.bitmap & (1_u64 << distance) != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxAmpduDisposition {
    Acknowledged,
    Retry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxAmpduCompletion {
    pub mpdu: TxAmpduMpdu,
    pub disposition: TxAmpduDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxAmpduBatchError {
    Busy,
    NotBuilding,
    Empty,
    InvalidWindow(u8),
    InvalidSlot(u8),
    DuplicateSlot(u8),
    Full,
}

#[derive(Clone, Copy)]
enum TxAmpduBatchPhase {
    Idle,
    Building,
    Completing(Option<TxBlockAckBitmap>),
}

/// One fixed TX A-MPDU batch owned by the Rust radio task.
///
/// `next_completion` returns at most one frame on every call. The executor can
/// therefore recycle or retry one MPDU and yield, instead of running the
/// vendor linked-list drains inside one PP event. There is no allocation,
/// clock read, retry loop, lock, or raw-pointer ownership in this type.
pub struct TxAmpduBatch {
    entries: [Option<TxAmpduMpdu>; TX_AMPDU_SLOT_CAPACITY],
    phase: TxAmpduBatchPhase,
    starting_sequence: u16,
    window: u8,
    count: u8,
    completion_index: u8,
    slot_mask: u32,
}

impl TxAmpduBatch {
    pub const fn new() -> Self {
        Self {
            entries: [None; TX_AMPDU_SLOT_CAPACITY],
            phase: TxAmpduBatchPhase::Idle,
            starting_sequence: 0,
            window: 0,
            count: 0,
            completion_index: 0,
            slot_mask: 0,
        }
    }

    pub fn begin(&mut self, starting_sequence: u16, window: u8) -> Result<(), TxAmpduBatchError> {
        if !matches!(self.phase, TxAmpduBatchPhase::Idle) {
            return Err(TxAmpduBatchError::Busy);
        }
        if window == 0 || usize::from(window) > TX_AMPDU_SLOT_CAPACITY {
            return Err(TxAmpduBatchError::InvalidWindow(window));
        }
        self.starting_sequence = starting_sequence & SEQUENCE_NUMBER_MASK;
        self.window = window;
        self.count = 0;
        self.completion_index = 0;
        self.slot_mask = 0;
        self.phase = TxAmpduBatchPhase::Building;
        Ok(())
    }

    /// Append one statically owned frame and assign its consecutive QoS
    /// sequence number. Duplicate slot ownership is rejected in O(1).
    pub fn push(&mut self, slot: u8) -> Result<TxAmpduMpdu, TxAmpduBatchError> {
        if !matches!(self.phase, TxAmpduBatchPhase::Building) {
            return Err(TxAmpduBatchError::NotBuilding);
        }
        let slot = TxAmpduSlot::new(slot).ok_or(TxAmpduBatchError::InvalidSlot(slot))?;
        let slot_bit = 1_u32 << slot.index();
        if self.slot_mask & slot_bit != 0 {
            return Err(TxAmpduBatchError::DuplicateSlot(slot.index()));
        }
        if self.count >= self.window {
            return Err(TxAmpduBatchError::Full);
        }

        let sequence =
            self.starting_sequence.wrapping_add(u16::from(self.count)) & SEQUENCE_NUMBER_MASK;
        let mpdu = TxAmpduMpdu { slot, sequence };
        self.entries[usize::from(self.count)] = Some(mpdu);
        self.count += 1;
        self.slot_mask |= slot_bit;
        Ok(mpdu)
    }

    pub fn complete_with_block_ack(
        &mut self,
        block_ack: TxBlockAckBitmap,
    ) -> Result<(), TxAmpduBatchError> {
        self.begin_completion(Some(block_ack))
    }

    /// Complete a hardware timeout/error edge. Every submitted MPDU is
    /// returned as `Retry`, one per `next_completion` call.
    pub fn complete_without_block_ack(&mut self) -> Result<(), TxAmpduBatchError> {
        self.begin_completion(None)
    }

    fn begin_completion(
        &mut self,
        block_ack: Option<TxBlockAckBitmap>,
    ) -> Result<(), TxAmpduBatchError> {
        if !matches!(self.phase, TxAmpduBatchPhase::Building) {
            return Err(TxAmpduBatchError::NotBuilding);
        }
        if self.count == 0 {
            return Err(TxAmpduBatchError::Empty);
        }
        self.completion_index = 0;
        self.phase = TxAmpduBatchPhase::Completing(block_ack);
        Ok(())
    }

    /// Consume exactly one completion result. Returning the last result also
    /// returns the batch to idle; no separate drain or cleanup loop exists.
    pub fn next_completion(&mut self) -> Option<TxAmpduCompletion> {
        let TxAmpduBatchPhase::Completing(block_ack) = self.phase else {
            return None;
        };
        if self.completion_index >= self.count {
            self.reset();
            return None;
        }

        let index = usize::from(self.completion_index);
        let mpdu = self.entries[index].take()?;
        self.completion_index += 1;
        self.slot_mask &= !(1_u32 << mpdu.slot.index());
        let disposition = if block_ack.is_some_and(|ack| ack.acknowledges(mpdu.sequence)) {
            TxAmpduDisposition::Acknowledged
        } else {
            TxAmpduDisposition::Retry
        };
        let completion = TxAmpduCompletion { mpdu, disposition };
        if self.completion_index == self.count {
            self.reset();
        }
        Some(completion)
    }

    pub const fn len(&self) -> usize {
        self.count as usize
    }

    pub const fn is_idle(&self) -> bool {
        matches!(self.phase, TxAmpduBatchPhase::Idle)
    }

    fn reset(&mut self) {
        self.phase = TxAmpduBatchPhase::Idle;
        self.window = 0;
        self.count = 0;
        self.completion_index = 0;
        self.slot_mask = 0;
    }
}

impl Default for TxAmpduBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl TxBlockAckSession {
    pub const fn new(config: TxBlockAckConfig) -> Result<Self, TxBlockAckError> {
        let config = match config.validate() {
            Ok(config) => config,
            Err(error) => return Err(error),
        };
        Ok(Self {
            config,
            generation: 0,
            next_dialog_token: 1,
            phase: TxBlockAckPhase::Idle,
        })
    }

    pub fn begin(
        &mut self,
        starting_sequence: u16,
        now_us: u64,
    ) -> Result<AddbaRequest, TxBlockAckError> {
        let deadline_us = now_us
            .checked_add(u64::from(self.config.negotiation_timeout_us))
            .ok_or(TxBlockAckError::DeadlineOverflow)?;
        self.generation = next_generation(self.generation);
        let dialog_token = self.next_dialog_token;
        self.next_dialog_token = next_dialog_token(dialog_token);
        let starting_sequence = starting_sequence & SEQUENCE_NUMBER_MASK;
        self.phase = TxBlockAckPhase::Awaiting {
            dialog_token,
            starting_sequence,
        };

        let parameters =
            encode_ba_parameters(self.config.tid, self.config.window, self.config.amsdu);
        let sequence_control = starting_sequence << 4;
        let mut body = [0_u8; ADDBA_ACTION_BODY_LEN];
        body[0] = BLOCK_ACK_CATEGORY;
        body[1] = ADDBA_REQUEST_ACTION;
        body[2] = dialog_token;
        body[3..5].copy_from_slice(&parameters.to_le_bytes());
        body[5..7].copy_from_slice(&self.config.timeout_tu.to_le_bytes());
        body[7..9].copy_from_slice(&sequence_control.to_le_bytes());

        let alarm = TxBlockAckAlarm {
            generation: self.generation,
            deadline_us,
        };
        Ok(AddbaRequest {
            generation: self.generation,
            dialog_token,
            starting_sequence,
            body,
            alarm,
        })
    }

    pub fn on_response(&mut self, body: &[u8]) -> Result<TxBlockAckResponse, TxBlockAckError> {
        if body.len() != ADDBA_ACTION_BODY_LEN
            || body[0] != BLOCK_ACK_CATEGORY
            || body[1] != ADDBA_RESPONSE_ACTION
        {
            return Err(TxBlockAckError::MalformedResponse);
        }
        let TxBlockAckPhase::Awaiting {
            dialog_token,
            starting_sequence,
        } = self.phase
        else {
            return Err(TxBlockAckError::UnexpectedResponse);
        };
        if body[2] != dialog_token {
            return Err(TxBlockAckError::UnexpectedResponse);
        }

        let status = u16::from_le_bytes([body[3], body[4]]);
        if status != 0 {
            self.phase = TxBlockAckPhase::Idle;
            self.generation = next_generation(self.generation);
            return Ok(TxBlockAckResponse::Rejected(status));
        }

        let parameters = u16::from_le_bytes([body[5], body[6]]);
        if parameters & BA_PARAMETER_IMMEDIATE == 0 {
            return Err(TxBlockAckError::DelayedPolicyUnsupported);
        }
        let tid = ((parameters & BA_PARAMETER_TID_MASK) >> BA_PARAMETER_TID_SHIFT) as u8;
        if tid != self.config.tid {
            return Err(TxBlockAckError::UnexpectedResponse);
        }
        let window = (parameters & BA_PARAMETER_WINDOW_MASK) >> BA_PARAMETER_WINDOW_SHIFT;
        if window == 0 || window > self.config.window || window > TX_BLOCK_ACK_MAX_WINDOW {
            return Err(TxBlockAckError::WindowExceedsCapacity(window));
        }
        let agreement = OperationalTxBlockAck {
            tid,
            window,
            timeout_tu: u16::from_le_bytes([body[7], body[8]]),
            starting_sequence,
            amsdu: self.config.amsdu && parameters & BA_PARAMETER_AMSDU != 0,
        };
        self.phase = TxBlockAckPhase::Operational(agreement);
        self.generation = next_generation(self.generation);
        Ok(TxBlockAckResponse::Operational(agreement))
    }

    /// Consume one exact async timer edge. Returns true only when it cancelled
    /// the currently outstanding negotiation.
    pub fn on_alarm(&mut self, alarm: TxBlockAckAlarm) -> bool {
        if alarm.generation != self.generation
            || !matches!(self.phase, TxBlockAckPhase::Awaiting { .. })
        {
            return false;
        }
        self.phase = TxBlockAckPhase::Idle;
        self.generation = next_generation(self.generation);
        true
    }

    pub fn stop(&mut self) {
        self.phase = TxBlockAckPhase::Idle;
        self.generation = next_generation(self.generation);
    }

    pub const fn operational(&self) -> Option<OperationalTxBlockAck> {
        match self.phase {
            TxBlockAckPhase::Operational(agreement) => Some(agreement),
            _ => None,
        }
    }

    pub const fn is_awaiting(&self) -> bool {
        matches!(self.phase, TxBlockAckPhase::Awaiting { .. })
    }
}

const fn encode_ba_parameters(tid: u8, window: u16, amsdu: bool) -> u16 {
    ((amsdu as u16) * BA_PARAMETER_AMSDU)
        | BA_PARAMETER_IMMEDIATE
        | ((tid as u16) << BA_PARAMETER_TID_SHIFT)
        | (window << BA_PARAMETER_WINDOW_SHIFT)
}

const fn next_generation(current: u32) -> u32 {
    let next = current.wrapping_add(1);
    if next == 0 {
        1
    } else {
        next
    }
}

const fn next_dialog_token(current: u8) -> u8 {
    let next = current.wrapping_add(1);
    if next == 0 {
        1
    } else {
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: TxBlockAckConfig = TxBlockAckConfig {
        tid: 7,
        window: 32,
        timeout_tu: 0,
        negotiation_timeout_us: 100_000,
        amsdu: true,
    };

    #[test]
    fn request_encoding_is_exact_and_bounded() {
        let mut session = TxBlockAckSession::new(CONFIG).unwrap();
        let request = session.begin(0x1abc, 50).unwrap();
        assert_eq!(request.starting_sequence, 0x0abc);
        assert_eq!(request.alarm.deadline_us, 100_050);
        assert_eq!(request.body, [3, 0, 1, 0x1f, 0x08, 0, 0, 0xc0, 0xab]);
    }

    #[test]
    fn matching_response_commits_only_the_static_window() {
        let mut session = TxBlockAckSession::new(CONFIG).unwrap();
        let request = session.begin(0x123, 0).unwrap();
        let response = [3, 1, request.dialog_token, 0, 0, 0x1f, 0x08, 0, 0];
        assert_eq!(
            session.on_response(&response),
            Ok(TxBlockAckResponse::Operational(OperationalTxBlockAck {
                tid: 7,
                window: 32,
                timeout_tu: 0,
                starting_sequence: 0x123,
                amsdu: true,
            }))
        );
        assert_eq!(
            session.operational(),
            Some(OperationalTxBlockAck {
                tid: 7,
                window: 32,
                timeout_tu: 0,
                starting_sequence: 0x123,
                amsdu: true,
            })
        );
        assert!(!session.on_alarm(request.alarm));
    }

    #[test]
    fn stale_alarm_cannot_cancel_a_new_generation() {
        let mut session = TxBlockAckSession::new(CONFIG).unwrap();
        let stale = session.begin(1, 0).unwrap().alarm;
        let current = session.begin(2, 10).unwrap().alarm;
        assert!(!session.on_alarm(stale));
        assert!(session.on_alarm(current));
        assert_eq!(session.operational(), None);
    }

    #[test]
    fn response_cannot_expand_the_static_capacity() {
        let mut session = TxBlockAckSession::new(CONFIG).unwrap();
        let request = session.begin(0, 0).unwrap();
        let parameters = encode_ba_parameters(7, 64, false).to_le_bytes();
        let response = [
            3,
            1,
            request.dialog_token,
            0,
            0,
            parameters[0],
            parameters[1],
            0,
            0,
        ];
        assert_eq!(
            session.on_response(&response),
            Err(TxBlockAckError::WindowExceedsCapacity(64))
        );
    }

    #[test]
    fn rejected_response_returns_to_idle_without_a_timer_retry() {
        let mut session = TxBlockAckSession::new(CONFIG).unwrap();
        let request = session.begin(0, 0).unwrap();
        let response = [3, 1, request.dialog_token, 37, 0, 0, 0, 0, 0];
        assert_eq!(
            session.on_response(&response),
            Ok(TxBlockAckResponse::Rejected(37))
        );
        assert_eq!(session.operational(), None);
        assert!(!session.on_alarm(request.alarm));
    }

    #[test]
    fn block_ack_bitmap_handles_sequence_wrap() {
        let ack = TxBlockAckBitmap::new(0x0ffe, 0b1101);
        assert!(ack.acknowledges(0x0ffe));
        assert!(!ack.acknowledges(0x0fff));
        assert!(ack.acknowledges(0));
        assert!(ack.acknowledges(1));
        assert!(!ack.acknowledges(2));
    }

    #[test]
    fn batch_returns_one_block_ack_result_per_step() {
        let mut batch = TxAmpduBatch::new();
        batch.begin(0x0ffe, 4).unwrap();
        for slot in 3..7 {
            batch.push(slot).unwrap();
        }
        batch
            .complete_with_block_ack(TxBlockAckBitmap::new(0x0ffe, 0b1101))
            .unwrap();

        for (slot, sequence, disposition) in [
            (3, 0x0ffe, TxAmpduDisposition::Acknowledged),
            (4, 0x0fff, TxAmpduDisposition::Retry),
            (5, 0, TxAmpduDisposition::Acknowledged),
            (6, 1, TxAmpduDisposition::Acknowledged),
        ] {
            assert_eq!(
                batch.next_completion(),
                Some(TxAmpduCompletion {
                    mpdu: TxAmpduMpdu {
                        slot: TxAmpduSlot::new(slot).unwrap(),
                        sequence,
                    },
                    disposition,
                })
            );
        }
        assert!(batch.is_idle());
        assert_eq!(batch.next_completion(), None);
    }

    #[test]
    fn missing_block_ack_retries_every_mpdu_without_a_drain() {
        let mut batch = TxAmpduBatch::new();
        batch.begin(9, 2).unwrap();
        batch.push(0).unwrap();
        batch.push(31).unwrap();
        batch.complete_without_block_ack().unwrap();
        assert_eq!(
            batch.next_completion().unwrap().disposition,
            TxAmpduDisposition::Retry
        );
        assert!(!batch.is_idle());
        assert_eq!(
            batch.next_completion().unwrap().disposition,
            TxAmpduDisposition::Retry
        );
        assert!(batch.is_idle());
    }

    #[test]
    fn batch_rejects_duplicate_static_slot_ownership() {
        let mut batch = TxAmpduBatch::new();
        batch.begin(0, 32).unwrap();
        batch.push(17).unwrap();
        assert_eq!(batch.push(17), Err(TxAmpduBatchError::DuplicateSlot(17)));
    }

    #[test]
    fn batch_never_exceeds_negotiated_or_static_window() {
        let mut batch = TxAmpduBatch::new();
        assert_eq!(batch.begin(0, 0), Err(TxAmpduBatchError::InvalidWindow(0)));
        assert_eq!(
            batch.begin(0, 33),
            Err(TxAmpduBatchError::InvalidWindow(33))
        );
        batch.begin(0, 1).unwrap();
        batch.push(0).unwrap();
        assert_eq!(batch.push(1), Err(TxAmpduBatchError::Full));
    }
}
