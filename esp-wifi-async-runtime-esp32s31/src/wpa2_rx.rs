//! Static fail-fast WPA2-Personal EAPOL RX bridge for the pinned S31 ABI.

use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(any(test, target_arch = "riscv32"))]
use crate::wpa2::Wpa2Interface;
#[cfg(target_arch = "riscv32")]
use crate::wpa2::DEFAULT_EAPOL_FRAME_CAPACITY;
use crate::{
    channel::Receive,
    wpa2::{OwnedEapolFrame, Wpa2Ingress},
};

pub const WPA2_RX_CAPACITY: usize = 8;

static INGRESS: Wpa2Ingress<WPA2_RX_CAPACITY> = Wpa2Ingress::new();
static REJECTED: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "hil-vendor-tx")]
static STA_RAW_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static STA_ACCEPTED: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static AP_RAW_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "hil-vendor-tx")]
static AP_ACCEPTED: AtomicUsize = AtomicUsize::new(0);

/// Laboratory-only counters at the final supplicant/authenticator ingress.
#[cfg(feature = "hil-vendor-tx")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Wpa2RxDiagnosticSnapshot {
    pub sta_raw_attempts: usize,
    pub sta_accepted: usize,
    pub ap_raw_attempts: usize,
    pub ap_accepted: usize,
    pub rejected: usize,
}

#[cfg(feature = "hil-vendor-tx")]
pub fn wpa2_rx_diagnostic_snapshot() -> Wpa2RxDiagnosticSnapshot {
    Wpa2RxDiagnosticSnapshot {
        sta_raw_attempts: STA_RAW_ATTEMPTS.load(Ordering::Acquire),
        sta_accepted: STA_ACCEPTED.load(Ordering::Acquire),
        ap_raw_attempts: AP_RAW_ATTEMPTS.load(Ordering::Acquire),
        ap_accepted: AP_ACCEPTED.load(Ordering::Acquire),
        rejected: REJECTED.load(Ordering::Acquire),
    }
}

pub fn try_receive_wpa2_eapol() -> Option<OwnedEapolFrame> {
    INGRESS.try_receive()
}

pub fn receive_wpa2_eapol() -> Receive<'static, OwnedEapolFrame, WPA2_RX_CAPACITY> {
    INGRESS.receive()
}

pub fn rejected_wpa2_eapol() -> usize {
    REJECTED.load(Ordering::Acquire)
}

#[cfg(any(test, target_arch = "riscv32"))]
fn ingest(interface: Wpa2Interface, peer: [u8; 6], bytes: &[u8]) -> bool {
    if INGRESS.try_push(interface, peer, bytes).is_ok() {
        true
    } else {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Copy an unencrypted STA EAPOL-Key packet directly from an 802.11 data MPDU.
///
/// This boundary is used before the vendor net80211 protocol classifier. A
/// Rust-driven association does not populate the vendor supplicant/link state
/// which would otherwise select `sta_rx_eapol`, so relying on that callback
/// would leave a valid M1 in the raw RX path without waking the async consumer.
/// Recognized EAPOL traffic is always consumed, including malformed or
/// overflowed packets, and therefore can never fall through into `wpa2_task`.
#[cfg(any(test, target_arch = "riscv32"))]
pub(crate) fn ingest_sta_80211(frame: &[u8]) -> bool {
    const LLC_EAPOL: [u8; 8] = [0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e];

    if frame.len() < 24 {
        return false;
    }
    let frame_control = u16::from_le_bytes([frame[0], frame[1]]);
    let frame_type = (frame_control >> 2) & 3;
    let to_ds = frame_control & 0x0100 != 0;
    let from_ds = frame_control & 0x0200 != 0;
    if frame_type != 2 || to_ds || !from_ds || frame_control & 0x4000 != 0 {
        return false;
    }

    let qos = frame_control & 0x0080 != 0;
    let order = frame_control & 0x8000 != 0;
    let mut header_len = 24_usize;
    if qos {
        header_len += 2;
        if order {
            header_len += 4;
        }
    }
    let Some(llc_end) = header_len.checked_add(LLC_EAPOL.len()) else {
        return false;
    };
    if frame.get(header_len..llc_end) != Some(LLC_EAPOL.as_slice()) {
        return false;
    }

    // Once LLC identifies EAPOL, keep it out of the vendor supplicant even if
    // its own length fields are malformed. The bounded ingress accounts the
    // rejection and the caller recycles the PP packet immediately.
    #[cfg(feature = "hil-vendor-tx")]
    STA_RAW_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let Some(header) = frame.get(llc_end..llc_end + 4) else {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return true;
    };
    let body_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let Some(eapol_len) = 4_usize.checked_add(body_len) else {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return true;
    };
    let Some(bytes) = frame.get(llc_end..llc_end + eapol_len) else {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return true;
    };
    let mut peer = [0; 6];
    peer.copy_from_slice(&frame[10..16]);
    let _accepted = ingest(Wpa2Interface::Station, peer, bytes);
    #[cfg(feature = "hil-vendor-tx")]
    if _accepted {
        STA_ACCEPTED.fetch_add(1, Ordering::Release);
    }
    true
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    #[link_name = "sta_rx_eapol"]
    fn vendor_sta_packet_rx_eapol(
        interface: *mut core::ffi::c_void,
        node: *mut core::ffi::c_void,
        packet: *mut core::ffi::c_void,
    ) -> i32;
    #[link_name = "wpa_sm_rx_eapol"]
    fn vendor_sta_rx_eapol(src: *const u8, bytes: *const u8, length: usize) -> i32;
    #[link_name = "wpa_ap_rx_eapol"]
    fn vendor_ap_rx_eapol(
        hostap: *mut u8,
        station: *mut u8,
        bytes: *const u8,
        length: usize,
    ) -> i32;
}

#[cfg(target_arch = "riscv32")]
pub(crate) fn runtime_wpa2_rx_link_wrappers_active() -> bool {
    core::ptr::eq(
        vendor_sta_packet_rx_eapol as *const (),
        __wrap_sta_rx_eapol as *const (),
    ) && core::ptr::eq(
        vendor_sta_rx_eapol as *const (),
        __wrap_wpa_sm_rx_eapol as *const (),
    ) && core::ptr::eq(
        vendor_ap_rx_eapol as *const (),
        __wrap_wpa_ap_rx_eapol as *const (),
    )
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    fn __real_sta_rx_eapol(
        interface: *mut core::ffi::c_void,
        node: *mut core::ffi::c_void,
        packet: *mut core::ffi::c_void,
    ) -> i32;
}

/// Capture WPA2-Personal EAPOL directly at the net80211 STA callback.
///
/// The stock callback forwards the same payload through the allocating
/// `wpa2_task` queue before it reaches `wpa_sm_rx_eapol`. The pinned S31 ABI
/// stores the payload owner at packet offset four, its byte pointer at owner
/// offset four, the Ethernet length at packet offset 22, and bit 13 at packet
/// offset 36 selects an eight-byte prefix for the source-address view. The
/// EAPOL bytes themselves start at byte 14 exactly as in `sta_rx_eapol`.
///
/// A valid frame is copied into the fixed Rust channel and never enters the
/// vendor WPA task. Non-RSN/EAP traffic is delegated during initialization so
/// this replacement does not silently consume an unsupported protocol.
///
/// # Safety
/// The three arguments must obey the pinned vendor callback ABI.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn __wrap_sta_rx_eapol(
    interface: *mut core::ffi::c_void,
    node: *mut core::ffi::c_void,
    packet: *mut core::ffi::c_void,
) -> i32 {
    if packet.is_null() {
        return __real_sta_rx_eapol(interface, node, packet);
    }
    let packet = packet.cast::<u8>();
    let owner = packet.add(4).cast::<*const u8>().read_unaligned();
    if owner.is_null() {
        return __real_sta_rx_eapol(interface, node, packet.cast());
    }
    let frame = owner.add(4).cast::<*const u8>().read_unaligned();
    let ethernet_length = usize::from(packet.add(22).cast::<u16>().read_unaligned());
    if frame.is_null() || ethernet_length < 14 {
        return __real_sta_rx_eapol(interface, node, packet.cast());
    }
    let prefix = if packet.add(36).cast::<u16>().read_unaligned() & 0x2000 != 0 {
        8
    } else {
        0
    };
    let eapol_length = ethernet_length - 14;
    let result = ingest_raw(
        Wpa2Interface::Station,
        frame.add(prefix + 6),
        frame.add(14),
        eapol_length,
    );
    if result != 0 {
        crate::handoff::request_handoff_on_wpa2_ingress();
        return result;
    }
    __real_sta_rx_eapol(interface, node, packet.cast())
}

#[cfg(target_arch = "riscv32")]
unsafe fn ingest_raw(
    interface: Wpa2Interface,
    peer: *const u8,
    bytes: *const u8,
    length: usize,
) -> i32 {
    #[cfg(feature = "hil-vendor-tx")]
    match interface {
        Wpa2Interface::Station => {
            STA_RAW_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        }
        Wpa2Interface::AccessPoint => {
            AP_RAW_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        }
    }
    if peer.is_null()
        || bytes.is_null()
        || !(crate::wpa2::EAPOL_KEY_PACKET_LEN..=DEFAULT_EAPOL_FRAME_CAPACITY).contains(&length)
    {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return 0;
    }
    let mut owned_peer = [0; 6];
    owned_peer.copy_from_slice(core::slice::from_raw_parts(peer, 6));
    let bytes = core::slice::from_raw_parts(bytes, length);
    let accepted = ingest(interface, owned_peer, bytes);
    #[cfg(feature = "hil-vendor-tx")]
    if accepted {
        match interface {
            Wpa2Interface::Station => {
                STA_ACCEPTED.fetch_add(1, Ordering::Release);
            }
            Wpa2Interface::AccessPoint => {
                AP_ACCEPTED.fetch_add(1, Ordering::Release);
            }
        }
    }
    i32::from(accepted)
}

/// Replace the stock allocating STA supplicant ingress with one bounded copy.
///
/// # Safety
/// The pointers and length must describe the live buffers supplied by the
/// pinned S31 callback ABI. They are read only for the duration of this call.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn __wrap_wpa_sm_rx_eapol(
    src: *const u8,
    bytes: *const u8,
    length: usize,
) -> i32 {
    let result = ingest_raw(Wpa2Interface::Station, src, bytes, length);
    if result != 0 {
        crate::handoff::request_handoff_on_wpa2_ingress();
    }
    result
}

/// Replace the stock AP authenticator ingress with one bounded copy.
///
/// # Safety
/// `station` must point to the pinned S31 AP station object, while `bytes` and
/// `length` must describe its live EAPOL packet for the duration of this call.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn __wrap_wpa_ap_rx_eapol(
    _hostap: *mut u8,
    station: *mut u8,
    bytes: *const u8,
    length: usize,
) -> i32 {
    // The pinned 0x28-byte AP station object stores its six-byte address at
    // offset eight; `ap_get_sta` compares exactly this field.
    let peer = if station.is_null() {
        core::ptr::null()
    } else {
        station.add(8).cast_const()
    };
    let result = ingest_raw(Wpa2Interface::AccessPoint, peer, bytes, length);
    if result != 0 {
        crate::handoff::request_handoff_on_wpa2_ingress();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wpa2_frames::{OwnedRsnIe, Wpa2TxFrame};

    #[test]
    fn static_ingress_owns_sta_and_ap_frames() {
        while try_receive_wpa2_eapol().is_some() {}
        let m1 = Wpa2TxFrame::<128>::message1([1; 6], 7, [2; 32]).unwrap();
        assert!(ingest(Wpa2Interface::Station, [3; 6], m1.as_bytes()));
        let sta = try_receive_wpa2_eapol().unwrap();
        assert_eq!(sta.interface(), Wpa2Interface::Station);
        assert_eq!(sta.peer(), &[3; 6]);

        let rsn = OwnedRsnIe::<2>::try_copy(&[0x30, 0]).unwrap();
        let m2 = Wpa2TxFrame::<128>::message2([4; 6], 8, [5; 32], &rsn).unwrap();
        assert!(ingest(Wpa2Interface::AccessPoint, [6; 6], m2.as_bytes()));
        let ap = try_receive_wpa2_eapol().unwrap();
        assert_eq!(ap.interface(), Wpa2Interface::AccessPoint);
        assert_eq!(ap.peer(), &[6; 6]);
    }

    #[test]
    fn raw_sta_mpdu_enters_static_ingress_without_vendor_classifier() {
        while try_receive_wpa2_eapol().is_some() {}
        let eapol = Wpa2TxFrame::<128>::message1([1; 6], 9, [2; 32]).unwrap();
        let mut frame = [0_u8; 24 + 8 + 128];
        frame[..2].copy_from_slice(&0x0208_u16.to_le_bytes());
        frame[10..16].copy_from_slice(&[3; 6]);
        frame[24..32].copy_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e]);
        let length = 32 + eapol.as_bytes().len();
        frame[32..length].copy_from_slice(eapol.as_bytes());

        assert!(ingest_sta_80211(&frame[..length]));
        let received = try_receive_wpa2_eapol().unwrap();
        assert_eq!(received.peer(), &[3; 6]);
        assert_eq!(received.key_frame().replay_counter(), 9);
    }
}
