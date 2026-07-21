//! Allocation-free asynchronous STA authentication boundary.
//!
//! The pinned blob's `ieee80211_send_mgmt` dispatcher reaches the complete
//! vendor STA state machine, including allocator, power-save, and retry
//! branches. This module instead owns open-system authentication and calls
//! only the finite management-buffer/TX leaves.

pub const OPEN_AUTH_DEFAULT_TIMEOUT_US: u32 = 500_000;
pub const OPEN_AUTH_DEFAULT_ATTEMPTS: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaAuthError {
    Busy,
    InvalidAccessPoint,
    QueueFull,
    InterfaceUnavailable,
    ManagementBufferUnavailable,
    TxRejected(i32),
    TimerUnavailable,
    Timeout,
    Status(u16),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StaAuthSnapshot {
    pub attempts: u32,
    pub submitted: u32,
    pub tx_done: u32,
    pub responses: u32,
    pub timeouts: u32,
    pub last_frame_control: u16,
    pub last_hardware_status: u8,
    pub last_descriptor_status: u32,
}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
mod target {
    use core::{
        cell::UnsafeCell,
        ffi::c_void,
        ptr,
        sync::atomic::{AtomicU32, AtomicU8, Ordering},
    };

    use super::*;
    use crate::{interrupt::InterruptSignal, scan::StrictScanRecord, timer::RawOsiTimer};

    pub(crate) const STA_AUTH_EVENT: u32 = u32::MAX - 12;

    const PHASE_IDLE: u8 = 0;
    const PHASE_ARMING: u8 = 1;
    const PHASE_WAITING: u8 = 2;
    const PHASE_COMPLETE: u8 = 3;

    const RESULT_PENDING: u32 = 0;
    const RESULT_OK: u32 = 1;
    const RESULT_TIMEOUT: u32 = 2;
    const RESULT_INTERFACE_UNAVAILABLE: u32 = 3;
    const RESULT_BUFFER_UNAVAILABLE: u32 = 4;
    const RESULT_TIMER_UNAVAILABLE: u32 = 5;
    const RESULT_TX_REJECTED: u32 = 0x4000_0000;
    const RESULT_STATUS: u32 = 0x8000_0000;

    const VENDOR_NODE_LEN: usize = 0x606;
    const AUTH_BODY_LEN: usize = 6;
    const MANAGEMENT_HEADER_LEN: u32 = 24;
    const AUTH_SUBTYPE: u8 = 0xb0;
    const AUTH_PTI: u32 = 6;
    const MANAGEMENT_RATE_POLICY: u32 = 7;

    #[derive(Clone, Copy)]
    struct AuthConfig {
        local: [u8; 6],
        bssid: [u8; 6],
        channel: u8,
        timeout_us: u32,
    }

    impl AuthConfig {
        const EMPTY: Self = Self {
            local: [0; 6],
            bssid: [0; 6],
            channel: 0,
            timeout_us: 0,
        };
    }

    struct ConfigCell(UnsafeCell<AuthConfig>);
    unsafe impl Sync for ConfigCell {}

    #[repr(C, align(4))]
    struct NodeCell(UnsafeCell<[u8; VENDOR_NODE_LEN]>);
    unsafe impl Sync for NodeCell {}

    struct TimerCell(UnsafeCell<RawOsiTimer>);
    unsafe impl Sync for TimerCell {}

    static CONFIG: ConfigCell = ConfigCell(UnsafeCell::new(AuthConfig::EMPTY));
    static NODE: NodeCell = NodeCell(UnsafeCell::new([0; VENDOR_NODE_LEN]));
    static TIMER: TimerCell = TimerCell(UnsafeCell::new(RawOsiTimer {
        next: ptr::null_mut(),
        expire: 0,
        period: 0,
        callback: None,
        argument: ptr::null_mut(),
    }));
    static PHASE: AtomicU8 = AtomicU8::new(PHASE_IDLE);
    static RESULT: AtomicU32 = AtomicU32::new(RESULT_PENDING);
    static SIGNAL: InterruptSignal = InterruptSignal::new();
    static ATTEMPTS: AtomicU32 = AtomicU32::new(0);
    static SUBMITTED: AtomicU32 = AtomicU32::new(0);
    static TX_DONE: AtomicU32 = AtomicU32::new(0);
    static RESPONSES: AtomicU32 = AtomicU32::new(0);
    static TIMEOUTS: AtomicU32 = AtomicU32::new(0);
    static LAST_FRAME_CONTROL: AtomicU32 = AtomicU32::new(0);
    static LAST_HARDWARE_STATUS: AtomicU32 = AtomicU32::new(0);
    static LAST_DESCRIPTOR_STATUS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" {
        static mut g_ic: u8;
        fn ieee80211_getmgtframe(
            body: *mut *mut u8,
            header_length: u32,
            body_length: u32,
        ) -> *mut u8;
        fn ieee80211_set_tx_desc(
            node: *mut u8,
            buffer: *mut u8,
            rate_policy: u32,
            tid: u32,
            flags: u32,
        );
        #[link_name = "ieee80211_set_tx_pti"]
        fn linked_ieee80211_set_tx_pti(buffer: *mut u8, packet_type: u32);
        #[link_name = "ieee80211_mgmt_output"]
        fn linked_ieee80211_mgmt_output(node: *mut u8, buffer: *mut u8, subtype: u8) -> i32;
    }

    fn decode_result(result: u32) -> Result<(), StaAuthError> {
        match result {
            RESULT_OK => Ok(()),
            RESULT_TIMEOUT => Err(StaAuthError::Timeout),
            RESULT_INTERFACE_UNAVAILABLE => Err(StaAuthError::InterfaceUnavailable),
            RESULT_BUFFER_UNAVAILABLE => Err(StaAuthError::ManagementBufferUnavailable),
            RESULT_TIMER_UNAVAILABLE => Err(StaAuthError::TimerUnavailable),
            value if value & RESULT_STATUS != 0 => Err(StaAuthError::Status(value as u16)),
            value if value & RESULT_TX_REJECTED != 0 => Err(StaAuthError::TxRejected(i32::from(
                (value & 0xffff) as u16 as i16,
            ))),
            value => Err(StaAuthError::TxRejected(value as i32)),
        }
    }

    fn complete(result: u32) {
        if PHASE
            .compare_exchange(
                PHASE_WAITING,
                PHASE_COMPLETE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            RESULT.store(result, Ordering::Release);
            SIGNAL.notify_from_isr();
        }
    }

    pub fn sta_auth_snapshot() -> StaAuthSnapshot {
        StaAuthSnapshot {
            attempts: ATTEMPTS.load(Ordering::Acquire),
            submitted: SUBMITTED.load(Ordering::Acquire),
            tx_done: TX_DONE.load(Ordering::Acquire),
            responses: RESPONSES.load(Ordering::Acquire),
            timeouts: TIMEOUTS.load(Ordering::Acquire),
            last_frame_control: LAST_FRAME_CONTROL.load(Ordering::Acquire) as u16,
            last_hardware_status: LAST_HARDWARE_STATUS.load(Ordering::Acquire) as u8,
            last_descriptor_status: LAST_DESCRIPTOR_STATUS.load(Ordering::Acquire),
        }
    }

    async fn authenticate_attempt(
        access_point: &StrictScanRecord,
        local: [u8; 6],
        timeout_us: u32,
    ) -> Result<(), StaAuthError> {
        PHASE
            .compare_exchange(
                PHASE_IDLE,
                PHASE_ARMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| StaAuthError::Busy)?;
        unsafe {
            CONFIG.0.get().write(AuthConfig {
                local,
                bssid: access_point.bssid,
                channel: access_point.channel,
                timeout_us,
            });
        }
        RESULT.store(RESULT_PENDING, Ordering::Relaxed);
        let observed = SIGNAL.generation();
        PHASE.store(PHASE_WAITING, Ordering::Release);
        if !crate::adapter::enqueue_internal_event(crate::event::PpEvent {
            kind: STA_AUTH_EVENT,
            argument: ptr::null_mut(),
        }) {
            PHASE.store(PHASE_IDLE, Ordering::Release);
            return Err(StaAuthError::QueueFull);
        }
        SIGNAL.wait_after(observed).await;
        let result = RESULT.load(Ordering::Acquire);
        PHASE.store(PHASE_IDLE, Ordering::Release);
        decode_result(result)
    }

    /// Authenticate with an AP using bounded async retries.
    ///
    /// Each timeout is a one-shot runtime timer. No retry polls state, delays a
    /// task, blocks an executor thread, or enters the vendor STA state machine.
    pub async fn authenticate_open(
        access_point: &StrictScanRecord,
        local: [u8; 6],
        timeout_us: u32,
        attempts: u8,
    ) -> Result<(), StaAuthError> {
        if !(1..=13).contains(&access_point.channel)
            || access_point.bssid == [0; 6]
            || local == [0; 6]
            || timeout_us == 0
            || attempts == 0
        {
            return Err(StaAuthError::InvalidAccessPoint);
        }
        let mut remaining = attempts;
        loop {
            match authenticate_attempt(access_point, local, timeout_us).await {
                Err(StaAuthError::Timeout) if remaining > 1 => remaining -= 1,
                result => return result,
            }
        }
    }

    unsafe fn initialize_static_node(config: AuthConfig) -> Option<*mut u8> {
        let ic = ptr::addr_of_mut!(g_ic);
        let interface = ic.add(0x10).cast::<*mut u8>().read();
        if interface.is_null() || interface.add(0x138).cast::<u32>().read() != 0 {
            return None;
        }
        let node = NODE.0.get().cast::<u8>();
        ptr::write_bytes(node, 0, VENDOR_NODE_LEN);
        node.cast::<*mut u8>().write(interface);
        ptr::copy_nonoverlapping(config.bssid.as_ptr(), node.add(4), 6);
        node.add(0xab).write(config.channel);
        node.add(0xac).write(0);
        node.add(0x134).write(4);

        interface.add(0xe4).cast::<*mut u8>().write(node);
        ptr::copy_nonoverlapping(config.bssid.as_ptr(), interface.add(0x9c), 6);
        ptr::copy_nonoverlapping(config.local.as_ptr(), ic.add(0x21a), 6);
        Some(node)
    }

    pub(crate) unsafe fn dispatch_auth_tx() {
        ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        if PHASE.load(Ordering::Acquire) != PHASE_WAITING
            || !crate::critical::on_strict_wifi_hart()
            || !crate::context::in_radio_context()
        {
            complete(RESULT_INTERFACE_UNAVAILABLE);
            return;
        }
        let config = CONFIG.0.get().read();
        let Some(node) = initialize_static_node(config) else {
            complete(RESULT_INTERFACE_UNAVAILABLE);
            return;
        };
        let mut body = ptr::null_mut();
        let buffer = ieee80211_getmgtframe(&mut body, MANAGEMENT_HEADER_LEN, AUTH_BODY_LEN as u32);
        if buffer.is_null() || body.is_null() {
            complete(RESULT_BUFFER_UNAVAILABLE);
            return;
        }
        // Open System algorithm, transaction 1, status success/reserved zero.
        body.cast::<u16>().write_unaligned(0);
        body.add(2).cast::<u16>().write_unaligned(1);
        body.add(4).cast::<u16>().write_unaligned(0);
        ieee80211_set_tx_desc(node, buffer, MANAGEMENT_RATE_POLICY, 0, 0);
        linked_ieee80211_set_tx_pti(buffer, AUTH_PTI);
        let tx = linked_ieee80211_mgmt_output(node, buffer, AUTH_SUBTYPE);
        if tx != 0 {
            complete(RESULT_TX_REJECTED | u32::from(tx as u16));
            return;
        }
        SUBMITTED.fetch_add(1, Ordering::Relaxed);
        if !crate::adapter::schedule_internal_timer(
            TIMER.0.get().cast(),
            auth_timeout,
            ptr::null_mut(),
            config.timeout_us,
        ) {
            complete(RESULT_TIMER_UNAVAILABLE);
        }
    }

    unsafe extern "C" fn auth_timeout(_argument: *mut c_void) {
        let _ = crate::adapter::cancel_internal_timer(TIMER.0.get().cast());
        TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        complete(RESULT_TIMEOUT);
    }

    pub(crate) fn management_tx_done(
        frame_control: u16,
        hardware_status: u8,
        descriptor_status: u32,
    ) {
        LAST_FRAME_CONTROL.store(u32::from(frame_control), Ordering::Relaxed);
        LAST_HARDWARE_STATUS.store(u32::from(hardware_status), Ordering::Relaxed);
        LAST_DESCRIPTOR_STATUS.store(descriptor_status, Ordering::Relaxed);
        TX_DONE.fetch_add(1, Ordering::Release);
    }

    pub(crate) fn observe_management(frame: &[u8]) {
        if PHASE.load(Ordering::Acquire) != PHASE_WAITING || frame.len() < 30 {
            return;
        }
        let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
        if frame_control & 0x00fc != 0x00b0 {
            return;
        }
        let config = unsafe { CONFIG.0.get().read() };
        if frame[4..10] != config.local
            || frame[10..16] != config.bssid
            || frame[16..22] != config.bssid
            || u16::from_le_bytes([frame[24], frame[25]]) != 0
            || u16::from_le_bytes([frame[26], frame[27]]) != 2
        {
            return;
        }
        let status = u16::from_le_bytes([frame[28], frame[29]]);
        RESPONSES.fetch_add(1, Ordering::Relaxed);
        unsafe {
            let _ = crate::adapter::cancel_internal_timer(TIMER.0.get().cast());
        }
        if status == 0 {
            complete(RESULT_OK);
        } else {
            complete(RESULT_STATUS | u32::from(status));
        }
    }
}

#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use target::authenticate_open;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use target::sta_auth_snapshot;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub(crate) use target::{dispatch_auth_tx, management_tx_done, observe_management, STA_AUTH_EVENT};

#[cfg(test)]
mod tests {
    #[test]
    fn open_auth_response_layout_is_unambiguous() {
        let mut frame = [0_u8; 30];
        frame[0] = 0xb0;
        frame[24..26].copy_from_slice(&0_u16.to_le_bytes());
        frame[26..28].copy_from_slice(&2_u16.to_le_bytes());
        frame[28..30].copy_from_slice(&17_u16.to_le_bytes());
        assert_eq!(frame[0] & 0xfc, 0xb0);
        assert_eq!(u16::from_le_bytes([frame[24], frame[25]]), 0);
        assert_eq!(u16::from_le_bytes([frame[26], frame[27]]), 2);
        assert_eq!(u16::from_le_bytes([frame[28], frame[29]]), 17);
    }
}
