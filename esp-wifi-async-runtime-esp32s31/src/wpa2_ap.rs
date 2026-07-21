//! Static WPA2-Personal AP association boundary for the pinned S31 ABI.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    channel::{BoundedChannel, Receive},
    wpa2_frames::OwnedRsnIe,
};

pub const WPA2_AP_ASSOC_CAPACITY: usize = 8;

const RSN_ELEMENT_ID: u8 = 0x30;
const RSN_VERSION: u16 = 1;
const RSN_CAPABILITY_MFPR: u16 = 1 << 6;
const RSN_OUI: [u8; 3] = [0x00, 0x0f, 0xac];
const RSN_CIPHER_CCMP: u8 = 4;
const RSN_AKM_PSK: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wpa2ApRsnError {
    Malformed,
    CapacityExceeded,
    UnsupportedVersion,
    UnsupportedGroupCipher,
    UnsupportedPairwiseCipher,
    UnsupportedAkm,
    ManagementFrameProtectionRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Wpa2ApPeerEvent {
    Associated {
        peer: [u8; 6],
        rsn_ie: OwnedRsnIe,
        reassociation: bool,
    },
    Removed {
        peer: [u8; 6],
    },
}

static EVENTS: BoundedChannel<Wpa2ApPeerEvent, WPA2_AP_ASSOC_CAPACITY> = BoundedChannel::new();
static REJECTED: AtomicUsize = AtomicUsize::new(0);

fn read_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, Wpa2ApRsnError> {
    let value = bytes
        .get(*offset..*offset + 2)
        .ok_or(Wpa2ApRsnError::Malformed)?;
    *offset += 2;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_suite(bytes: &[u8], offset: &mut usize) -> Result<[u8; 4], Wpa2ApRsnError> {
    let suite = bytes
        .get(*offset..*offset + 4)
        .ok_or(Wpa2ApRsnError::Malformed)?;
    *offset += 4;
    Ok([suite[0], suite[1], suite[2], suite[3]])
}

fn supported_suite(suite: [u8; 4], selector: u8) -> bool {
    suite[..3] == RSN_OUI && suite[3] == selector
}

/// Validate the allocation-free WPA2-PSK/CCMP subset implemented by the Rust
/// state machine and return an owned association IE.
pub fn validate_wpa2_ap_rsn(bytes: &[u8]) -> Result<OwnedRsnIe, Wpa2ApRsnError> {
    let owned = OwnedRsnIe::try_copy(bytes).map_err(|error| match error {
        crate::wpa2_frames::Wpa2FrameError::CapacityExceeded => Wpa2ApRsnError::CapacityExceeded,
        _ => Wpa2ApRsnError::Malformed,
    })?;
    if bytes.first() != Some(&RSN_ELEMENT_ID) {
        return Err(Wpa2ApRsnError::Malformed);
    }

    let body = &bytes[2..];
    let mut offset = 0;
    if read_u16(body, &mut offset)? != RSN_VERSION {
        return Err(Wpa2ApRsnError::UnsupportedVersion);
    }
    if !supported_suite(read_suite(body, &mut offset)?, RSN_CIPHER_CCMP) {
        return Err(Wpa2ApRsnError::UnsupportedGroupCipher);
    }

    let pairwise_count = usize::from(read_u16(body, &mut offset)?);
    if pairwise_count == 0 {
        return Err(Wpa2ApRsnError::UnsupportedPairwiseCipher);
    }
    let mut pairwise_ccmp = false;
    for _ in 0..pairwise_count {
        pairwise_ccmp |= supported_suite(read_suite(body, &mut offset)?, RSN_CIPHER_CCMP);
    }
    if !pairwise_ccmp {
        return Err(Wpa2ApRsnError::UnsupportedPairwiseCipher);
    }

    let akm_count = usize::from(read_u16(body, &mut offset)?);
    if akm_count == 0 {
        return Err(Wpa2ApRsnError::UnsupportedAkm);
    }
    let mut psk = false;
    for _ in 0..akm_count {
        psk |= supported_suite(read_suite(body, &mut offset)?, RSN_AKM_PSK);
    }
    if !psk {
        return Err(Wpa2ApRsnError::UnsupportedAkm);
    }

    if offset < body.len() {
        let capabilities = read_u16(body, &mut offset)?;
        if capabilities & RSN_CAPABILITY_MFPR != 0 {
            return Err(Wpa2ApRsnError::ManagementFrameProtectionRequired);
        }
    }
    // PMKSA caching and group-management ciphers are outside this fixed
    // WPA2-only profile. Do not silently accept data the state machine will
    // not consume.
    if offset != body.len() {
        return Err(Wpa2ApRsnError::Malformed);
    }
    Ok(owned)
}

pub fn try_receive_wpa2_ap_event() -> Option<Wpa2ApPeerEvent> {
    EVENTS.try_receive()
}

pub fn receive_wpa2_ap_event() -> Receive<'static, Wpa2ApPeerEvent, WPA2_AP_ASSOC_CAPACITY> {
    EVENTS.receive()
}

pub fn rejected_wpa2_ap_events() -> usize {
    REJECTED.load(Ordering::Acquire)
}

#[cfg(target_arch = "riscv32")]
mod target {
    use core::{
        cell::UnsafeCell,
        ffi::c_void,
        mem, ptr,
        sync::atomic::{AtomicBool, Ordering},
    };

    use super::*;

    const WPA_AP_JOIN_OFFSET: usize = 0x24;
    const WPA_AP_REMOVE_OFFSET: usize = 0x28;
    const WPA_AP_INIT_OFFSET: usize = 0x1c;
    const WPA_AP_DEINIT_OFFSET: usize = 0x20;
    const WPA_AP_GET_RSN_OFFSET: usize = 0x2c;
    const WPA_AP_SPP_OFFSET: usize = 0x34;
    const PINNED_STATION_SIZE: usize = 0x28;
    const PINNED_STATION_MAC_OFFSET: usize = 8;
    const CCMP_DRIVER_SELECTOR: u8 = 4;
    const WLAN_STATUS_SUCCESS: u16 = 0;
    const WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA: u16 = 17;
    const WLAN_STATUS_INVALID_IE: u16 = 40;

    type InitCallback = unsafe extern "C" fn() -> *mut c_void;
    type DeinitCallback = unsafe extern "C" fn(*mut c_void) -> bool;
    type JoinCallback = unsafe extern "C" fn(*mut WpaStationJoinParam) -> bool;
    type RemoveCallback = unsafe extern "C" fn(*const u8) -> bool;
    type GetRsnCallback = unsafe extern "C" fn(*mut usize) -> *mut u8;
    type SppCallback = unsafe extern "C" fn(*mut c_void, *mut bool, *mut bool);

    #[repr(C)]
    struct WpaStationJoinParam {
        station: *mut *mut c_void,
        bssid: *const u8,
        wpa_ie: *const u8,
        rsnxe: *const u8,
        pmf_enable: *mut bool,
        pairwise_cipher: *mut u8,
        rsn_selection_ie: *mut u8,
        owe_dhie: *mut u8,
        subtype: i32,
        rsnxe_len: u16,
        wpa_ie_len: u8,
        owe_dh_len: u8,
    }

    #[repr(C, align(4))]
    struct PinnedStation {
        bytes: [u8; PINNED_STATION_SIZE],
    }

    struct PeerSlot {
        claimed: AtomicBool,
        station: UnsafeCell<PinnedStation>,
    }

    impl PeerSlot {
        const fn new() -> Self {
            Self {
                claimed: AtomicBool::new(false),
                station: UnsafeCell::new(PinnedStation {
                    bytes: [0; PINNED_STATION_SIZE],
                }),
            }
        }
    }

    unsafe impl Sync for PeerSlot {}

    struct ApRsnStorage(UnsafeCell<[u8; crate::wpa2_frames::WPA2_RSN_IE_CAPACITY]>);

    impl ApRsnStorage {
        const fn new() -> Self {
            Self(UnsafeCell::new(
                [0; crate::wpa2_frames::WPA2_RSN_IE_CAPACITY],
            ))
        }
    }

    unsafe impl Sync for ApRsnStorage {}

    struct StaticByte(UnsafeCell<u8>);

    unsafe impl Sync for StaticByte {}

    static PEERS: [PeerSlot; WPA2_AP_ASSOC_CAPACITY] =
        [const { PeerSlot::new() }; WPA2_AP_ASSOC_CAPACITY];
    static AP_RSN: ApRsnStorage = ApRsnStorage::new();
    static AP_RSN_LEN: AtomicUsize = AtomicUsize::new(0);
    static AP_CONTEXT: StaticByte = StaticByte(UnsafeCell::new(0));
    static CALLBACKS_INSTALLED: AtomicBool = AtomicBool::new(false);
    static REJECTED_MANAGEMENT_TX: AtomicUsize = AtomicUsize::new(0);
    static PTI_REJECTED_BUFFER: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" {
        static mut g_ic: u8;
        static mut wpa_cb: *mut c_void;
        fn hostap_init() -> *mut c_void;
        fn hostap_deinit(context: *mut c_void) -> bool;
        fn wpa_ap_remove(peer: *const u8) -> bool;
        fn wpa_ap_get_wpa_ie(length: *mut usize) -> *mut u8;
        fn wpa_ap_get_peer_spp_msg(station: *mut c_void, capable: *mut bool, required: *mut bool);
        fn __esp_hostap_sta_join(join: *mut WpaStationJoinParam) -> bool;
        fn __esp_hostap_sta_join_end();
        fn cnx_node_search(peer: *const u8) -> *mut u8;
        fn ieee80211_assoc_resp_construct(node: *mut u8, status: u8) -> *mut u8;
        fn ieee80211_set_tx_desc(
            node: *mut u8,
            buffer: *mut u8,
            rate_policy: u32,
            tid: u32,
            flags: u32,
        );
        #[link_name = "ieee80211_set_tx_pti"]
        fn linked_ieee80211_set_tx_pti(buffer: *mut u8, packet_type: u32);
        fn __real_ieee80211_set_tx_pti(buffer: *mut u8, packet_type: u32);
        static mut coex_pti_tab: [u8; 48];
        #[link_name = "ieee80211_mgmt_output"]
        fn linked_ieee80211_mgmt_output(node: *mut u8, buffer: *mut u8, subtype: u8) -> i32;
        fn __real_ieee80211_mgmt_output(node: *mut u8, buffer: *mut u8, subtype: u8) -> i32;
        fn chm_is_at_home_channel() -> bool;
        fn esf_buf_recycle(frame: *mut c_void);
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Wpa2ApInstallError {
        SupplicantNotInitialized,
        InvalidRsn(Wpa2ApRsnError),
        UnexpectedJoinSize(usize),
        UnexpectedInitCallback(usize),
        UnexpectedDeinitCallback(usize),
        UnexpectedJoinCallback(usize),
        UnexpectedRemoveCallback(usize),
        UnexpectedGetRsnCallback(usize),
        UnexpectedSppCallback(usize),
    }

    unsafe fn callback_slot<T>(callbacks: *mut c_void, offset: usize) -> *mut T {
        callbacks.cast::<u8>().add(offset).cast::<T>()
    }

    unsafe fn station_mac(slot: &PeerSlot) -> [u8; 6] {
        let mut peer = [0; 6];
        ptr::copy_nonoverlapping(
            slot.station
                .get()
                .cast::<u8>()
                .add(PINNED_STATION_MAC_OFFSET),
            peer.as_mut_ptr(),
            peer.len(),
        );
        peer
    }

    unsafe fn claim_peer(peer: [u8; 6]) -> Option<*mut c_void> {
        for slot in &PEERS {
            if slot.claimed.load(Ordering::Acquire) && station_mac(slot) == peer {
                return Some(slot.station.get().cast());
            }
        }
        for slot in &PEERS {
            if slot
                .claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                ptr::write_bytes(slot.station.get().cast::<u8>(), 0, PINNED_STATION_SIZE);
                ptr::copy_nonoverlapping(
                    peer.as_ptr(),
                    slot.station
                        .get()
                        .cast::<u8>()
                        .add(PINNED_STATION_MAC_OFFSET),
                    peer.len(),
                );
                return Some(slot.station.get().cast());
            }
        }
        None
    }

    unsafe fn release_peer(peer: &[u8; 6]) -> bool {
        for slot in &PEERS {
            if slot.claimed.load(Ordering::Acquire) && station_mac(slot) == *peer {
                ptr::write_bytes(slot.station.get().cast::<u8>(), 0, PINNED_STATION_SIZE);
                slot.claimed.store(false, Ordering::Release);
                return true;
            }
        }
        false
    }

    #[no_mangle]
    unsafe extern "C" fn __esp_wifi_async_wpa2_ap_init() -> *mut c_void {
        if AP_RSN_LEN.load(Ordering::Acquire) == 0 {
            ptr::null_mut()
        } else {
            AP_CONTEXT.0.get().cast()
        }
    }

    #[no_mangle]
    unsafe extern "C" fn __esp_wifi_async_wpa2_ap_deinit(context: *mut c_void) -> bool {
        if !ptr::eq(context, AP_CONTEXT.0.get().cast()) {
            return false;
        }
        for slot in &PEERS {
            ptr::write_bytes(slot.station.get().cast::<u8>(), 0, PINNED_STATION_SIZE);
            slot.claimed.store(false, Ordering::Release);
        }
        true
    }

    #[no_mangle]
    unsafe extern "C" fn __esp_wifi_async_wpa2_ap_get_rsn(length: *mut usize) -> *mut u8 {
        let rsn_length = AP_RSN_LEN.load(Ordering::Acquire);
        if length.is_null() || rsn_length == 0 {
            return ptr::null_mut();
        }
        length.write(rsn_length);
        AP_RSN.0.get().cast::<u8>()
    }

    unsafe fn send_association_response(peer: [u8; 6], subtype: i32, status: u16) -> bool {
        let Ok(subtype @ (0x10 | 0x30)) = u8::try_from(subtype) else {
            return false;
        };
        let Ok(status) = u8::try_from(status) else {
            return false;
        };
        let node = cnx_node_search(peer.as_ptr());
        if node.is_null() || node.cast::<*mut u8>().read().is_null() {
            return false;
        }
        // All register-indirect calls in the pinned constructor live in its
        // mesh-only branch. Recheck the live invariant at the call site so a
        // strict association response cannot enter that callback table.
        if ptr::addr_of_mut!(g_ic).add(0x74).cast::<usize>().read() != 0 {
            return false;
        }
        let buffer = ieee80211_assoc_resp_construct(node, status);
        if buffer.is_null() {
            return false;
        }
        if status != 0 {
            // Exact side effect of the pinned `ieee80211_send_mgmt` response
            // branch: clear the association-pending bit after an error.
            let flags = node.add(0x0c).cast::<u32>();
            flags.write(flags.read() & 0xfdff_ffff);
        }
        ieee80211_set_tx_desc(node, buffer, 7, 0, 0);
        linked_ieee80211_set_tx_pti(buffer, 6);
        linked_ieee80211_mgmt_output(node, buffer, subtype) == 0
    }

    pub(crate) fn management_link_wrappers_active() -> bool {
        ptr::eq(
            linked_ieee80211_mgmt_output as *const (),
            __wrap_ieee80211_mgmt_output as *const (),
        ) && ptr::eq(
            linked_ieee80211_set_tx_pti as *const (),
            __wrap_ieee80211_set_tx_pti as *const (),
        )
    }

    fn rejected_buffer_key(buffer: *mut u8) -> usize {
        if buffer.is_null() {
            1
        } else {
            buffer as usize
        }
    }

    fn record_management_tx_rejection(subtype: u8, argument: usize) {
        REJECTED_MANAGEMENT_TX.fetch_add(1, Ordering::Relaxed);
        crate::adapter::blocking_probe().record(
            crate::diagnostics::BlockingCall::ManagementTxRejected,
            u32::from(subtype),
            argument,
        );
    }

    unsafe fn reject_management_tx(subtype: u8, node: *mut u8, buffer: *mut u8) -> i32 {
        record_management_tx_rejection(subtype, node as usize);
        if !buffer.is_null() && crate::critical::on_strict_wifi_hart() {
            esf_buf_recycle(buffer.cast());
        }
        -1
    }

    /// Strict gate for the stock management-frame output routine.
    ///
    /// The accepted AP/STA subtypes take the ordinary fixed-channel branch.
    /// Mesh, NAN, power-save buffering, robust management, disconnect, and
    /// off-channel queuing are rejected before the vendor body is entered.
    ///
    /// # Safety
    ///
    /// `node` and `buffer` must be live objects from the pinned net80211 ABI,
    /// with ownership transferred according to `ieee80211_mgmt_output`.
    #[no_mangle]
    pub unsafe extern "C" fn __wrap_ieee80211_mgmt_output(
        node: *mut u8,
        buffer: *mut u8,
        subtype: u8,
    ) -> i32 {
        if !crate::critical::strict_wifi_hart_armed() {
            return __real_ieee80211_mgmt_output(node, buffer, subtype);
        }
        if PTI_REJECTED_BUFFER
            .compare_exchange(
                rejected_buffer_key(buffer),
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            if !buffer.is_null() && crate::critical::on_strict_wifi_hart() {
                esf_buf_recycle(buffer.cast());
            }
            return -1;
        }
        let subtype_allowed = matches!(subtype, 0x00 | 0x10 | 0x20 | 0x30 | 0x40 | 0x50 | 0xb0)
            || crate::sta_link::is_owned_action_management(buffer, subtype);
        if !crate::critical::on_strict_wifi_hart()
            || !crate::context::in_radio_context()
            || node.is_null()
            || buffer.is_null()
            || !subtype_allowed
            || ptr::addr_of_mut!(g_ic).add(0x74).cast::<usize>().read() != 0
            || !chm_is_at_home_channel()
        {
            return reject_management_tx(subtype, node, buffer);
        }
        let interface = node.cast::<*mut u8>().read();
        if interface.is_null() {
            return reject_management_tx(subtype, node, buffer);
        }
        let mode = interface.add(0x138).cast::<u32>().read();
        if mode > 1 {
            return reject_management_tx(subtype, node, buffer);
        }
        if mode == 1
            && (node.add(0x04).read() & 1 != 0
                || node.add(0x0c).cast::<u32>().read() & 0x10 != 0
                || node.add(0x2fe).read() != 0)
        {
            return reject_management_tx(subtype, node, buffer);
        }
        __real_ieee80211_mgmt_output(node, buffer, subtype)
    }

    /// Replace the OSI-table coexistence PTI call with its exact finite leaf.
    ///
    /// # Safety
    ///
    /// `buffer` must point to a live pinned ESF object with a writable TX
    /// descriptor at offset `0x34`.
    #[no_mangle]
    pub unsafe extern "C" fn __wrap_ieee80211_set_tx_pti(buffer: *mut u8, event: u32) {
        if !crate::critical::strict_wifi_hart_armed() {
            __real_ieee80211_set_tx_pti(buffer, event);
            return;
        }
        PTI_REJECTED_BUFFER.store(0, Ordering::Release);
        if !crate::critical::on_strict_wifi_hart() || buffer.is_null() {
            record_management_tx_rejection(event as u8, buffer as usize);
            PTI_REJECTED_BUFFER.store(rejected_buffer_key(buffer), Ordering::Release);
            return;
        }
        let descriptor = buffer.add(0x34).cast::<*mut u8>().read();
        if descriptor.is_null() {
            record_management_tx_rejection(event as u8, buffer as usize);
            PTI_REJECTED_BUFFER.store(rejected_buffer_key(buffer), Ordering::Release);
            return;
        }
        if event >= 48 {
            record_management_tx_rejection(event as u8, buffer as usize);
            PTI_REJECTED_BUFFER.store(rejected_buffer_key(buffer), Ordering::Release);
            return;
        }
        let event_index = event as usize;
        // Exact success branch of the pinned 0x1e-byte
        // `coex_core_pti_get`: one indexed byte read from its exported table.
        let pti = ptr::read_volatile(
            ptr::addr_of_mut!(coex_pti_tab)
                .cast::<u8>()
                .add(event_index),
        );
        descriptor.add(0x20).write(pti);
        descriptor.add(0x22).cast::<u16>().write(1);
    }

    #[no_mangle]
    unsafe extern "C" fn __esp_wifi_async_wpa2_ap_join(join: *mut WpaStationJoinParam) -> bool {
        if join.is_null() || !crate::context::in_radio_context() {
            REJECTED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let join = &mut *join;
        if join.station.is_null()
            || join.bssid.is_null()
            || join.wpa_ie.is_null()
            || join.pmf_enable.is_null()
            || join.pairwise_cipher.is_null()
            || !join.rsnxe.is_null()
            || join.rsnxe_len != 0
            || !join.rsn_selection_ie.is_null()
            || !join.owe_dhie.is_null()
            || join.owe_dh_len != 0
        {
            REJECTED.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let mut peer = [0; 6];
        peer.copy_from_slice(core::slice::from_raw_parts(join.bssid, 6));
        let rsn_bytes = core::slice::from_raw_parts(join.wpa_ie, usize::from(join.wpa_ie_len));
        let Ok(rsn_ie) = validate_wpa2_ap_rsn(rsn_bytes) else {
            let _ = send_association_response(peer, join.subtype, WLAN_STATUS_INVALID_IE);
            REJECTED.fetch_add(1, Ordering::Relaxed);
            return false;
        };

        if EVENTS.len() >= WPA2_AP_ASSOC_CAPACITY {
            let _ = send_association_response(
                peer,
                join.subtype,
                WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA,
            );
            REJECTED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let Some(station) = claim_peer(peer) else {
            let _ = send_association_response(
                peer,
                join.subtype,
                WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA,
            );
            REJECTED.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        if !send_association_response(peer, join.subtype, WLAN_STATUS_SUCCESS) {
            release_peer(&peer);
            REJECTED.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        join.station.write(station);
        join.pmf_enable.write(false);
        join.pairwise_cipher.write(CCMP_DRIVER_SELECTOR);
        let event = Wpa2ApPeerEvent::Associated {
            peer,
            rsn_ie,
            reassociation: join.subtype == 0x30,
        };
        if EVENTS.try_send(event).is_err() {
            // The callback is the sole producer in the serialized radio
            // context, so only violated integration assumptions reach here.
            release_peer(&peer);
            REJECTED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    #[no_mangle]
    unsafe extern "C" fn __esp_wifi_async_wpa2_ap_remove(peer: *const u8) -> bool {
        if peer.is_null() || !crate::context::in_radio_context() {
            REJECTED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let mut owned_peer = [0; 6];
        owned_peer.copy_from_slice(core::slice::from_raw_parts(peer, 6));
        let existed = release_peer(&owned_peer);
        if EVENTS
            .try_send(Wpa2ApPeerEvent::Removed { peer: owned_peer })
            .is_err()
        {
            REJECTED.fetch_add(1, Ordering::Relaxed);
        }
        existed
    }

    #[no_mangle]
    unsafe extern "C" fn __esp_wifi_async_wpa2_ap_get_peer_spp_msg(
        _station: *mut c_void,
        capable: *mut bool,
        required: *mut bool,
    ) {
        if !capable.is_null() {
            capable.write(false);
        }
        if !required.is_null() {
            required.write(false);
        }
    }

    /// Patch the three AP callbacks that otherwise own heap-backed station
    /// state. Install after `esp_supplicant_init`, before starting AP RX.
    ///
    /// The companion `ld/esp32s31-wpa2-ap-locals.x` fragment is required.
    ///
    /// # Safety
    /// The pinned audited S31 archives must be linked. Installation must be
    /// serialized with supplicant init/deinit and no AP station may exist yet.
    pub unsafe fn install_async_wpa2_ap_callbacks(rsn_ie: &[u8]) -> Result<(), Wpa2ApInstallError> {
        const _: () = assert!(mem::size_of::<WpaStationJoinParam>() == 0x28);

        let owned_rsn = validate_wpa2_ap_rsn(rsn_ie).map_err(Wpa2ApInstallError::InvalidRsn)?;

        let join_size = (__esp_hostap_sta_join_end as *const () as usize)
            .wrapping_sub(__esp_hostap_sta_join as *const () as usize);
        // The archive audit pins the 0x114-byte input section. The linker can
        // shrink its call pairs to a 0xf8-byte final flash image.
        if join_size != 0x114 && join_size != 0xf8 {
            return Err(Wpa2ApInstallError::UnexpectedJoinSize(join_size));
        }
        let callbacks = ptr::addr_of!(wpa_cb).read();
        if callbacks.is_null() {
            return Err(Wpa2ApInstallError::SupplicantNotInitialized);
        }

        let init = callback_slot::<InitCallback>(callbacks, WPA_AP_INIT_OFFSET);
        let deinit = callback_slot::<DeinitCallback>(callbacks, WPA_AP_DEINIT_OFFSET);
        let join = callback_slot::<JoinCallback>(callbacks, WPA_AP_JOIN_OFFSET);
        let remove = callback_slot::<RemoveCallback>(callbacks, WPA_AP_REMOVE_OFFSET);
        let get_rsn = callback_slot::<GetRsnCallback>(callbacks, WPA_AP_GET_RSN_OFFSET);
        let spp = callback_slot::<SppCallback>(callbacks, WPA_AP_SPP_OFFSET);
        let current_init = init.read() as usize;
        let current_deinit = deinit.read() as usize;
        let current_join = join.read() as usize;
        let current_remove = remove.read() as usize;
        let current_get_rsn = get_rsn.read() as usize;
        let current_spp = spp.read() as usize;
        if current_init != hostap_init as InitCallback as usize
            && current_init != __esp_wifi_async_wpa2_ap_init as InitCallback as usize
        {
            return Err(Wpa2ApInstallError::UnexpectedInitCallback(current_init));
        }
        if current_deinit != hostap_deinit as DeinitCallback as usize
            && current_deinit != __esp_wifi_async_wpa2_ap_deinit as DeinitCallback as usize
        {
            return Err(Wpa2ApInstallError::UnexpectedDeinitCallback(current_deinit));
        }
        if current_join != __esp_hostap_sta_join as JoinCallback as usize
            && current_join != __esp_wifi_async_wpa2_ap_join as JoinCallback as usize
        {
            return Err(Wpa2ApInstallError::UnexpectedJoinCallback(current_join));
        }
        if current_remove != wpa_ap_remove as RemoveCallback as usize
            && current_remove != __esp_wifi_async_wpa2_ap_remove as RemoveCallback as usize
        {
            return Err(Wpa2ApInstallError::UnexpectedRemoveCallback(current_remove));
        }
        if current_get_rsn != wpa_ap_get_wpa_ie as GetRsnCallback as usize
            && current_get_rsn != __esp_wifi_async_wpa2_ap_get_rsn as GetRsnCallback as usize
        {
            return Err(Wpa2ApInstallError::UnexpectedGetRsnCallback(
                current_get_rsn,
            ));
        }
        if current_spp != wpa_ap_get_peer_spp_msg as SppCallback as usize
            && current_spp != __esp_wifi_async_wpa2_ap_get_peer_spp_msg as SppCallback as usize
        {
            return Err(Wpa2ApInstallError::UnexpectedSppCallback(current_spp));
        }

        let rsn = owned_rsn.as_bytes();
        ptr::copy_nonoverlapping(rsn.as_ptr(), AP_RSN.0.get().cast::<u8>(), rsn.len());
        AP_RSN_LEN.store(rsn.len(), Ordering::Release);

        init.write(__esp_wifi_async_wpa2_ap_init);
        deinit.write(__esp_wifi_async_wpa2_ap_deinit);
        join.write(__esp_wifi_async_wpa2_ap_join);
        remove.write(__esp_wifi_async_wpa2_ap_remove);
        get_rsn.write(__esp_wifi_async_wpa2_ap_get_rsn);
        spp.write(__esp_wifi_async_wpa2_ap_get_peer_spp_msg);
        CALLBACKS_INSTALLED.store(true, Ordering::Release);
        Ok(())
    }

    pub fn async_wpa2_ap_callbacks_installed() -> bool {
        CALLBACKS_INSTALLED.load(Ordering::Acquire)
    }
}

#[cfg(target_arch = "riscv32")]
pub(crate) use target::management_link_wrappers_active;
#[cfg(target_arch = "riscv32")]
pub use target::{
    async_wpa2_ap_callbacks_installed, install_async_wpa2_ap_callbacks, Wpa2ApInstallError,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn rsn(pairwise: u8, akm: u8, capabilities: u16) -> [u8; 22] {
        let mut ie = [0_u8; 22];
        ie[0] = 0x30;
        ie[1] = 20;
        ie[2..4].copy_from_slice(&1_u16.to_le_bytes());
        ie[4..8].copy_from_slice(&[0x00, 0x0f, 0xac, 4]);
        ie[8..10].copy_from_slice(&1_u16.to_le_bytes());
        ie[10..14].copy_from_slice(&[0x00, 0x0f, 0xac, pairwise]);
        ie[14..16].copy_from_slice(&1_u16.to_le_bytes());
        ie[16..20].copy_from_slice(&[0x00, 0x0f, 0xac, akm]);
        ie[20..22].copy_from_slice(&capabilities.to_le_bytes());
        ie
    }

    #[test]
    fn accepts_wpa2_psk_ccmp() {
        let ie = rsn(4, 2, 0);
        assert_eq!(validate_wpa2_ap_rsn(&ie).unwrap().as_bytes(), &ie);
    }

    #[test]
    fn rejects_non_ccmp_non_psk_and_required_pmf() {
        assert_eq!(
            validate_wpa2_ap_rsn(&rsn(2, 2, 0)),
            Err(Wpa2ApRsnError::UnsupportedPairwiseCipher)
        );
        assert_eq!(
            validate_wpa2_ap_rsn(&rsn(4, 8, 0)),
            Err(Wpa2ApRsnError::UnsupportedAkm)
        );
        assert_eq!(
            validate_wpa2_ap_rsn(&rsn(4, 2, RSN_CAPABILITY_MFPR)),
            Err(Wpa2ApRsnError::ManagementFrameProtectionRequired)
        );
    }

    #[test]
    fn rejects_truncated_suite_lists() {
        let mut ie = rsn(4, 2, 0);
        ie[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(validate_wpa2_ap_rsn(&ie), Err(Wpa2ApRsnError::Malformed));
    }
}
