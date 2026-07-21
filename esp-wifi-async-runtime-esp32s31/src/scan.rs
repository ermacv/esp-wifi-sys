//! Allocation-free passive scanning on the strict ESP32-S31 radio owner.

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU32, AtomicU8, Ordering},
};

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
use crate::interrupt::InterruptSignal;

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub(crate) const SCAN_CHANNEL_EVENT: u32 = u32::MAX - 11;
pub const STRICT_SCAN_RECORD_CAPACITY: usize = 32;

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
const SESSION_IDLE: u8 = 0;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
const SESSION_ARMING: u8 = 1;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
const SESSION_ACTIVE: u8 = 2;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
const OP_IDLE: u8 = 0;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
const OP_QUEUED: u8 = 1;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
const OP_RUNNING: u8 = 2;

/// One bounded, owned observation from a beacon or probe response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictScanRecord {
    pub ssid: [u8; 32],
    pub ssid_len: u8,
    pub bssid: [u8; 6],
    pub channel: u8,
    pub rssi: i8,
    pub privacy: bool,
    pub rsn: bool,
    pub legacy_wpa: bool,
    pub information_elements_truncated: bool,
}

impl StrictScanRecord {
    pub const EMPTY: Self = Self {
        ssid: [0; 32],
        ssid_len: 0,
        bssid: [0; 6],
        channel: 0,
        rssi: i8::MIN,
        privacy: false,
        rsn: false,
        legacy_wpa: false,
        information_elements_truncated: false,
    };

    pub fn ssid_bytes(&self) -> &[u8] {
        &self.ssid[..usize::from(self.ssid_len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictScanSummary {
    pub records: usize,
    pub observed_frames: u32,
    pub dropped_unique_bss: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrictScanError {
    Busy,
    InvalidDwell,
    QueueFull,
    ChannelStart(i32),
    ChannelCompletion(u32),
}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
struct ScanTable(UnsafeCell<[StrictScanRecord; STRICT_SCAN_RECORD_CAPACITY]>);

// The table is written only by the radio-owner RX path while SESSION_ACTIVE.
// The initiating future copies it only after the last radio-owner completion.
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
unsafe impl Sync for ScanTable {}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
static TABLE: ScanTable = ScanTable(UnsafeCell::new(
    [StrictScanRecord::EMPTY; STRICT_SCAN_RECORD_CAPACITY],
));
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
static TABLE_LEN: AtomicU8 = AtomicU8::new(0);
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
static SESSION: AtomicU8 = AtomicU8::new(SESSION_IDLE);
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
static CURRENT_CHANNEL: AtomicU8 = AtomicU8::new(0);
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
static OBSERVED_FRAMES: AtomicU32 = AtomicU32::new(0);
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
static DROPPED_UNIQUE_BSS: AtomicU32 = AtomicU32::new(0);

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
static OP_STATE: AtomicU8 = AtomicU8::new(OP_IDLE);
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
static OP_CHANNEL: AtomicU8 = AtomicU8::new(0);
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
static OP_DWELL_MS: AtomicU32 = AtomicU32::new(0);
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
static OP_RESULT: AtomicU32 = AtomicU32::new(0);
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
static OP_SIGNAL: InterruptSignal = InterruptSignal::new();

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
unsafe extern "C" {
    static mut g_ic: u8;
    fn ic_set_mac(index: u32, address: *const u8);
    fn ic_set_rx_policy(index: u32, mode: u32, control: u32, management: u32);
    fn ic_set_rx_policy_ubssid_check(index: u32, enabled: u32);
    fn chm_start_op(
        channel: *const u8,
        first_dwell_ms: u32,
        final_dwell_ms: u32,
        start: Option<unsafe extern "C" fn(*mut core::ffi::c_void, u32)>,
        end: Option<unsafe extern "C" fn(*mut core::ffi::c_void, u32)>,
        context: *mut core::ffi::c_void,
    ) -> i32;
}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
struct SessionGuard;

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
impl SessionGuard {
    fn begin() -> Result<Self, StrictScanError> {
        if OP_STATE.load(Ordering::Acquire) != OP_IDLE {
            return Err(StrictScanError::Busy);
        }
        SESSION
            .compare_exchange(
                SESSION_IDLE,
                SESSION_ARMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| StrictScanError::Busy)?;
        unsafe { (*TABLE.0.get()).fill(StrictScanRecord::EMPTY) };
        TABLE_LEN.store(0, Ordering::Relaxed);
        CURRENT_CHANNEL.store(0, Ordering::Relaxed);
        OBSERVED_FRAMES.store(0, Ordering::Relaxed);
        DROPPED_UNIQUE_BSS.store(0, Ordering::Relaxed);
        SESSION.store(SESSION_ACTIVE, Ordering::Release);
        Ok(Self)
    }
}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
impl Drop for SessionGuard {
    fn drop(&mut self) {
        SESSION.store(SESSION_IDLE, Ordering::Release);
    }
}

/// Run a complete passive 2.4-GHz scan through the Rust-owned radio future.
///
/// The future has no polling timer of its own: every channel completion is
/// driven by the strict runtime's one-shot alarm and wakes this future once.
/// Results are copied into `output`; excess unique BSS entries are counted and
/// discarded immediately.
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub async fn passive_scan_2_4ghz(
    output: &mut [StrictScanRecord],
    dwell_ms: u32,
) -> Result<StrictScanSummary, StrictScanError> {
    if dwell_ms == 0 {
        return Err(StrictScanError::InvalidDwell);
    }
    let _guard = SessionGuard::begin()?;

    for channel in 1..=13 {
        run_channel(channel, dwell_ms).await?;
    }

    // Stop ingress before copying. The completion callback and RX observer run
    // on the same radio-owner stack, so no producer can still hold the table.
    SESSION.store(SESSION_ARMING, Ordering::Release);
    let available = usize::from(TABLE_LEN.load(Ordering::Acquire));
    let copied = available.min(output.len());
    let records = unsafe { &*TABLE.0.get() };
    output[..copied].copy_from_slice(&records[..copied]);
    Ok(StrictScanSummary {
        records: copied,
        observed_frames: OBSERVED_FRAMES.load(Ordering::Acquire),
        dropped_unique_bss: DROPPED_UNIQUE_BSS
            .load(Ordering::Acquire)
            .saturating_add((available - copied) as u32),
    })
}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
async fn run_channel(channel: u8, dwell_ms: u32) -> Result<(), StrictScanError> {
    OP_STATE
        .compare_exchange(OP_IDLE, OP_QUEUED, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| StrictScanError::Busy)?;
    OP_CHANNEL.store(channel, Ordering::Relaxed);
    OP_DWELL_MS.store(dwell_ms, Ordering::Relaxed);
    OP_RESULT.store(0, Ordering::Relaxed);
    CURRENT_CHANNEL.store(channel, Ordering::Release);
    let observed = OP_SIGNAL.generation();
    if !crate::adapter::enqueue_internal_event(crate::event::PpEvent {
        kind: SCAN_CHANNEL_EVENT,
        argument: core::ptr::null_mut(),
    }) {
        OP_STATE.store(OP_IDLE, Ordering::Release);
        return Err(StrictScanError::QueueFull);
    }
    OP_SIGNAL.wait_after(observed).await;
    match OP_RESULT.load(Ordering::Acquire) {
        0 => Ok(()),
        value if value & 0x8000_0000 != 0 => {
            Err(StrictScanError::ChannelStart((value & 0x7fff_ffff) as i32))
        }
        value => Err(StrictScanError::ChannelCompletion(value)),
    }
}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub(crate) unsafe fn dispatch_channel() {
    if OP_STATE
        .compare_exchange(OP_QUEUED, OP_RUNNING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        OP_RESULT.store(1, Ordering::Release);
        OP_STATE.store(OP_IDLE, Ordering::Release);
        OP_SIGNAL.notify_from_isr();
        return;
    }
    let channel = [OP_CHANNEL.load(Ordering::Acquire), 0];
    let dwell = OP_DWELL_MS.load(Ordering::Acquire);
    if channel[0] == 1 {
        enable_scan_rx_policy();
    }
    let result = chm_start_op(
        channel.as_ptr(),
        dwell,
        dwell,
        None,
        Some(channel_complete),
        core::ptr::null_mut(),
    );
    if result != 0 {
        restore_default_rx_policy();
        OP_RESULT.store(0x8000_0000 | result as u32, Ordering::Release);
        OP_STATE.store(OP_IDLE, Ordering::Release);
        OP_SIGNAL.notify_from_isr();
    }
}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub(crate) unsafe extern "C" fn channel_complete(_context: *mut core::ffi::c_void, result: u32) {
    if result != 0
        || OP_CHANNEL.load(Ordering::Acquire) == 13
        || SESSION.load(Ordering::Acquire) != SESSION_ACTIVE
    {
        restore_default_rx_policy();
    }
    OP_RESULT.store(result, Ordering::Release);
    OP_STATE.store(OP_IDLE, Ordering::Release);
    OP_SIGNAL.notify_from_isr();
}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
unsafe fn enable_scan_rx_policy() {
    // Exact policy-3 branch of the pinned `wifi_set_rx_policy` jump table.
    // Calling the three finite leaves directly removes the unproven indirect
    // dispatch while preserving management/control reception off-channel.
    ic_set_rx_policy(0, 2, 1, 1);
    ic_set_rx_policy_ubssid_check(0, 0);
    core::ptr::addr_of_mut!(g_ic).add(716).write(3);
}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
unsafe fn restore_default_rx_policy() {
    // Exact policy-0 branch. Both addresses belong to the pinned `g_ic`
    // object and the called leaves audit without heap, waits, or cycles.
    let ic = core::ptr::addr_of_mut!(g_ic);
    ic_set_mac(0, ic.add(0x21a));
    ic_set_mac(1, ic.add(0x214));
    ic_set_rx_policy(0, 0, 0, 0);
    ic_set_rx_policy(1, 0, 0, 0);
    ic_set_rx_policy_ubssid_check(0, 0);
    ic.add(716).write(0);
}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub(crate) fn observe_management(frame: &[u8], rssi: i8) {
    if SESSION.load(Ordering::Acquire) != SESSION_ACTIVE {
        return;
    }
    let fallback_channel = CURRENT_CHANNEL.load(Ordering::Acquire);
    let Some(record) = parse_management(frame, fallback_channel, rssi) else {
        return;
    };
    OBSERVED_FRAMES.fetch_add(1, Ordering::Relaxed);

    let length = usize::from(TABLE_LEN.load(Ordering::Acquire));
    let records = unsafe { &mut *TABLE.0.get() };
    for existing in &mut records[..length] {
        if existing.bssid == record.bssid {
            if record.rssi > existing.rssi || existing.ssid_len == 0 {
                *existing = record;
            }
            return;
        }
    }
    if length == STRICT_SCAN_RECORD_CAPACITY {
        DROPPED_UNIQUE_BSS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    records[length] = record;
    TABLE_LEN.store((length + 1) as u8, Ordering::Release);
}

#[cfg(any(test, all(target_arch = "riscv32", feature = "strict-no-wait")))]
fn parse_management(frame: &[u8], fallback_channel: u8, rssi: i8) -> Option<StrictScanRecord> {
    if frame.len() < 36 {
        return None;
    }
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    let subtype = (frame_control >> 4) & 0x0f;
    if frame_control & 0x000c != 0 || !matches!(subtype, 5 | 8) {
        return None;
    }

    let mut record = StrictScanRecord::EMPTY;
    record.bssid.copy_from_slice(&frame[16..22]);
    record.channel = fallback_channel;
    record.rssi = rssi;
    record.privacy = u16::from_le_bytes([frame[34], frame[35]]) & 0x0010 != 0;

    let mut offset = 36;
    while offset + 2 <= frame.len() {
        let id = frame[offset];
        let length = usize::from(frame[offset + 1]);
        offset += 2;
        let Some(end) = offset.checked_add(length) else {
            record.information_elements_truncated = true;
            break;
        };
        if end > frame.len() {
            // S31's RX metadata exposes a bounded management-frame prefix.
            // BSSID, capabilities, and all preceding complete IEs remain
            // trustworthy even when a long vendor/HE tail is truncated.
            record.information_elements_truncated = true;
            break;
        }
        let value = &frame[offset..end];
        match id {
            0 if length <= record.ssid.len() => {
                record.ssid[..length].copy_from_slice(value);
                record.ssid_len = length as u8;
            }
            3 if length == 1 => record.channel = value[0],
            48 => record.rsn = true,
            221 if length >= 4 && value[..4] == [0x00, 0x50, 0xf2, 0x01] => {
                record.legacy_wpa = true;
            }
            _ => {}
        }
        offset = end;
    }
    Some(record)
}

#[cfg(test)]
mod tests {
    use super::parse_management;

    #[test]
    fn parses_beacon_into_owned_bounded_record() {
        let mut frame = [0_u8; 64];
        frame[0] = 0x80;
        frame[16..22].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[34] = 0x10;
        frame[36..42].copy_from_slice(&[0, 4, b't', b'e', b's', b't']);
        frame[42..45].copy_from_slice(&[3, 1, 11]);
        frame[45..47].copy_from_slice(&[48, 0]);
        let record = parse_management(&frame[..47], 3, -42).unwrap();
        assert_eq!(record.ssid_bytes(), b"test");
        assert_eq!(record.bssid, [1, 2, 3, 4, 5, 6]);
        assert_eq!(record.channel, 11);
        assert_eq!(record.rssi, -42);
        assert!(record.privacy);
        assert!(record.rsn);
    }

    #[test]
    fn rejects_data_and_keeps_bounded_prefix_of_truncated_information_elements() {
        let mut frame = [0_u8; 40];
        frame[0] = 0x08;
        assert!(parse_management(&frame, 1, -1).is_none());
        frame[0] = 0x50;
        frame[36] = 0;
        frame[37] = 8;
        let record = parse_management(&frame, 1, -1).unwrap();
        assert!(record.information_elements_truncated);
    }
}
