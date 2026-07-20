//! Allocation-free STA EAPOL TX-completion bridge.

use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_arch = "riscv32")]
use core::sync::atomic::AtomicBool;

use crate::{
    channel::{BoundedChannel, Receive},
    wpa2::EapolKeyMessage,
};

#[cfg(any(test, target_arch = "riscv32"))]
use crate::wpa2::EapolKeyFrame;

pub const WPA2_STA_TX_DONE_CAPACITY: usize = 8;
#[cfg(any(test, target_arch = "riscv32"))]
const MAX_EAPOL_TX_FRAME: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Wpa2StaTxDone {
    pub message: EapolKeyMessage,
    pub replay_counter: u64,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wpa2TxDoneInstallError {
    AlreadyInstalled,
    NotInstalled,
    NotRadioOwner,
    PendingEvents,
}

static EVENTS: BoundedChannel<Wpa2StaTxDone, WPA2_STA_TX_DONE_CAPACITY> = BoundedChannel::new();
#[cfg(target_arch = "riscv32")]
static INSTALLED: AtomicBool = AtomicBool::new(false);
static REJECTED: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static HIL_COMPLETED_LENGTH: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static HIL_COMPLETED_HASH: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "hil-vendor-tx")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HilCompletedEapolSnapshot {
    pub length: usize,
    pub hash: u32,
}

#[cfg(feature = "hil-vendor-tx")]
pub fn hil_completed_eapol_snapshot() -> HilCompletedEapolSnapshot {
    HilCompletedEapolSnapshot {
        length: HIL_COMPLETED_LENGTH.load(Ordering::Acquire),
        hash: HIL_COMPLETED_HASH.load(Ordering::Acquire) as u32,
    }
}

pub fn try_receive_wpa2_sta_tx_done() -> Option<Wpa2StaTxDone> {
    EVENTS.try_receive()
}

pub fn receive_wpa2_sta_tx_done() -> Receive<'static, Wpa2StaTxDone, WPA2_STA_TX_DONE_CAPACITY> {
    EVENTS.receive()
}

pub fn rejected_wpa2_sta_tx_done() -> usize {
    REJECTED.load(Ordering::Acquire)
}

pub fn async_wpa2_sta_tx_done_installed() -> bool {
    #[cfg(target_arch = "riscv32")]
    {
        INSTALLED.load(Ordering::Acquire)
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        false
    }
}

#[cfg(any(test, target_arch = "riscv32"))]
fn ingest(frame: *const u8, length: usize, failed: bool) {
    if frame.is_null()
        || !(crate::wpa2::EAPOL_KEY_PACKET_LEN..=MAX_EAPOL_TX_FRAME).contains(&length)
    {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let bytes = unsafe { core::slice::from_raw_parts(frame, length) };
    #[cfg(feature = "hil-vendor-tx")]
    {
        let mut hash = 0x811c_9dc5_u32;
        for byte in bytes {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        HIL_COMPLETED_LENGTH.store(length, Ordering::Release);
        HIL_COMPLETED_HASH.store(hash as usize, Ordering::Release);
    }
    let Ok(key) = EapolKeyFrame::parse(bytes) else {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let message = key.message();
    if !matches!(
        message,
        EapolKeyMessage::PairwiseMessage2 | EapolKeyMessage::PairwiseMessage4
    ) {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if EVENTS
        .try_send(Wpa2StaTxDone {
            message,
            replay_counter: key.replay_counter(),
            failed,
        })
        .is_err()
    {
        REJECTED.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(target_arch = "riscv32")]
type EapolTxDoneCallback = unsafe extern "C" fn(*const u8, usize, bool);

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    fn esp_wifi_register_eapol_txdonecb_internal(callback: Option<EapolTxDoneCallback>);
    fn eapol_txcb(frame: *const u8, length: usize, failed: bool);
}

#[cfg(target_arch = "riscv32")]
#[no_mangle]
unsafe extern "C" fn __esp_wifi_async_wpa2_sta_txdone(
    frame: *const u8,
    length: usize,
    failed: bool,
) {
    ingest(frame, length, failed);
}

/// Replace the stock STA `eapol_txcb` state transition after Wi-Fi setup.
///
/// # Safety
/// Registration must be serialized with supplicant initialization and
/// deinitialization and must finish before the executor/radio IRQ is enabled.
/// The callback ABI and the stock restore symbol are pinned by the S31
/// analyzer.
#[cfg(target_arch = "riscv32")]
pub unsafe fn install_async_wpa2_sta_tx_done() -> Result<(), Wpa2TxDoneInstallError> {
    if !EVENTS.is_empty() {
        return Err(Wpa2TxDoneInstallError::PendingEvents);
    }
    if INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Wpa2TxDoneInstallError::AlreadyInstalled);
    }
    esp_wifi_register_eapol_txdonecb_internal(Some(__esp_wifi_async_wpa2_sta_txdone));
    Ok(())
}

/// Restore the pinned stock callback before supplicant teardown.
///
/// # Safety
/// The same serialization requirements as
/// [`install_async_wpa2_sta_tx_done`] apply. The restored callback is not
/// strict-safe and must not run before teardown takes exclusive ownership.
#[cfg(target_arch = "riscv32")]
pub unsafe fn uninstall_async_wpa2_sta_tx_done() -> Result<(), Wpa2TxDoneInstallError> {
    if !crate::context::in_radio_context() {
        return Err(Wpa2TxDoneInstallError::NotRadioOwner);
    }
    if INSTALLED
        .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Wpa2TxDoneInstallError::NotInstalled);
    }
    esp_wifi_register_eapol_txdonecb_internal(Some(eapol_txcb));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wpa2_frames::Wpa2TxFrame;

    #[test]
    fn callback_copies_only_valid_sta_handshake_metadata() {
        while try_receive_wpa2_sta_tx_done().is_some() {}
        let m2 = Wpa2TxFrame::<128>::message2(
            [1; 6],
            7,
            [2; 32],
            &crate::wpa2_frames::OwnedRsnIe::<2>::try_copy(&[0x30, 0]).unwrap(),
        )
        .unwrap();
        ingest(m2.as_bytes().as_ptr(), m2.as_bytes().len(), false);
        assert_eq!(
            try_receive_wpa2_sta_tx_done(),
            Some(Wpa2StaTxDone {
                message: EapolKeyMessage::PairwiseMessage2,
                replay_counter: 7,
                failed: false,
            })
        );

        let m1 = Wpa2TxFrame::<128>::message1([1; 6], 8, [3; 32]).unwrap();
        let rejected = rejected_wpa2_sta_tx_done();
        ingest(m1.as_bytes().as_ptr(), m1.as_bytes().len(), false);
        assert_eq!(rejected_wpa2_sta_tx_done(), rejected + 1);
        assert_eq!(try_receive_wpa2_sta_tx_done(), None);
    }
}
