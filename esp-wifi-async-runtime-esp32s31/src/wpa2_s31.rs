//! Pinned ESP32-S31 static TX and CCMP backend.
//!
//! AP controlled-port state is owned by Rust because no independent
//! allocation-free authorization primitive is exported by the pinned blobs.

#![cfg_attr(not(any(test, target_arch = "riscv32")), allow(dead_code))]

use core::{
    cell::UnsafeCell,
    sync::atomic::{compiler_fence, AtomicBool, AtomicU8, Ordering},
};

use crate::wpa2_crypto::WPA2_TK_LEN;

const VENDOR_KEY_PREFIX_LEN: usize = 0xa8;
const VENDOR_KEY_OBJECT_LEN: usize = VENDOR_KEY_PREFIX_LEN + WPA2_TK_LEN;
const KEY_INDEX_OFFSET: usize = 0x00;
const RECEIVE_SEQUENCE_OFFSET: usize = 0x98;
const CIPHER_POINTER_OFFSET: usize = 0xa0;
const KEY_LENGTH_OFFSET: usize = 0xa4;
const KEY_BYTES_OFFSET: usize = 0xa8;
const STA_PAIRWISE_HARDWARE_INDEX: u8 = 4;
const STA_GROUP_HARDWARE_INDEX: u8 = 1;
const AP_GROUP_HARDWARE_INDEX_BASE: u8 = 8;
const MAX_WPA2_GTK_ID: u8 = 3;
#[cfg(target_arch = "riscv32")]
const MAX_VENDOR_KEY_INDEX: u8 = 24;

const fn group_hardware_index(interface: crate::wpa2::Wpa2Interface, key_id: u8) -> Option<u8> {
    if key_id > MAX_WPA2_GTK_ID {
        return None;
    }
    match interface {
        crate::wpa2::Wpa2Interface::Station => Some(STA_GROUP_HARDWARE_INDEX),
        crate::wpa2::Wpa2Interface::AccessPoint => Some(AP_GROUP_HARDWARE_INDEX_BASE + key_id),
    }
}

#[repr(C, align(4))]
struct VendorCcmpKeyObject {
    bytes: [u8; VENDOR_KEY_OBJECT_LEN],
}

impl VendorCcmpKeyObject {
    const fn new() -> Self {
        Self {
            bytes: [0; VENDOR_KEY_OBJECT_LEN],
        }
    }

    fn wipe(&mut self) {
        for byte in &mut self.bytes {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }

    fn initialize_like_wifi_init_key(&mut self) {
        self.bytes[..VENDOR_KEY_PREFIX_LEN].fill(0);
        self.bytes[8..0x98].fill(0xff);
    }
}

struct StaticVendorKeySlot {
    claimed: AtomicBool,
    hardware_index: AtomicU8,
    object: UnsafeCell<VendorCcmpKeyObject>,
}

impl StaticVendorKeySlot {
    const fn new() -> Self {
        Self {
            claimed: AtomicBool::new(false),
            hardware_index: AtomicU8::new(u8::MAX),
            object: UnsafeCell::new(VendorCcmpKeyObject::new()),
        }
    }
}

unsafe impl Sync for StaticVendorKeySlot {}

struct StaticAuthorizedPeers<const N: usize> {
    peers: [Option<[u8; 6]>; N],
}

impl<const N: usize> StaticAuthorizedPeers<N> {
    const fn new() -> Self {
        Self {
            peers: [const { None }; N],
        }
    }

    fn contains(&self, peer: &[u8; 6]) -> bool {
        self.peers
            .iter()
            .any(|candidate| candidate.as_ref() == Some(peer))
    }

    fn set(&mut self, peer: [u8; 6], authorized: bool) -> Result<(), ()> {
        if let Some(slot) = self
            .peers
            .iter_mut()
            .find(|candidate| candidate.as_ref() == Some(&peer))
        {
            if !authorized {
                *slot = None;
            }
            return Ok(());
        }
        if !authorized {
            return Ok(());
        }
        let Some(slot) = self.peers.iter_mut().find(|candidate| candidate.is_none()) else {
            return Err(());
        };
        *slot = Some(peer);
        Ok(())
    }
}

/// Stable-address storage referenced by the pinned net80211 key table.
pub struct S31StaticKeyStorage<const N: usize> {
    backend_taken: AtomicBool,
    slots: [StaticVendorKeySlot; N],
}

impl<const N: usize> S31StaticKeyStorage<N> {
    pub const fn new() -> Self {
        Self {
            backend_taken: AtomicBool::new(false),
            slots: [const { StaticVendorKeySlot::new() }; N],
        }
    }

    #[cfg(target_arch = "riscv32")]
    fn take_backend(&'static self) -> bool {
        self.backend_taken
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    #[cfg(any(test, target_arch = "riscv32"))]
    fn claim(&'static self, hardware_index: u8) -> Option<*mut VendorCcmpKeyObject> {
        for slot in &self.slots {
            if slot.claimed.load(Ordering::Acquire)
                && slot.hardware_index.load(Ordering::Acquire) == hardware_index
            {
                return Some(slot.object.get());
            }
        }
        for slot in &self.slots {
            if slot
                .claimed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                slot.hardware_index.store(hardware_index, Ordering::Release);
                return Some(slot.object.get());
            }
        }
        None
    }

    /// Wipe all slots after the Wi-Fi driver has been fully deinitialized.
    ///
    /// # Safety
    /// No vendor key-table pointer may reference this storage and no backend
    /// may be executing.
    pub unsafe fn reset_after_wifi_deinit(&'static self) {
        for slot in &self.slots {
            (*slot.object.get()).wipe();
            slot.hardware_index.store(u8::MAX, Ordering::Release);
            slot.claimed.store(false, Ordering::Release);
        }
        self.backend_taken.store(false, Ordering::Release);
    }
}

impl<const N: usize> Default for S31StaticKeyStorage<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S31Wpa2IoError {
    StorageAlreadyTaken,
    NotRadioOwner,
    StaTxDoneCallbackMissing,
    TxLengthOverflow,
    TxPeerNotFound(u32),
    TxPeerPowerSaveUnsupported,
    CachedTxRuntimeEnabled,
    StaticTxPoolExhausted,
    InvalidTxDescriptor,
    TxPostRejected(u32),
    VendorTxDiagnosticRejected(i32),
    TxBackendPoisoned,
    StaticKeySlotsFull,
    MissingApPeerHardwareIndex,
    InvalidGroupKeyId(u8),
    InvalidHardwareIndex(u8),
    ForeignSoftwareKeyPresent,
    MissingStaInterfaceState,
    UnexpectedStaPairwiseHardwareIndex,
    AuthorizationWithoutPairwiseKey,
    StaPeerUnauthorized,
    ApPeerUnauthorized,
    AuthorizationSlotsFull,
    InternalOwnershipMismatch,
}

#[cfg(all(target_arch = "riscv32", feature = "hil-vendor-tx"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HilStaPairwiseKeySnapshot {
    pub valid: bool,
    pub peer: [u8; 6],
    pub control: u16,
    pub key_matches: bool,
    pub crypto_gate: u16,
    pub node_hardware_index: u8,
    pub node_flags: u32,
    pub node_key_state: u8,
    pub station_privacy: u32,
    pub station_state: u8,
    pub global_connected: u8,
    pub global_auth_state: u8,
}

#[cfg(target_arch = "riscv32")]
mod target {
    use core::{ffi::c_void, ptr};

    use esp_wifi_sys_esp32s31::include::{
        wifi_interface_t_WIFI_IF_AP, wifi_interface_t_WIFI_IF_STA,
    };

    use super::*;
    use crate::{
        context::in_radio_context,
        data_rx::WifiDataInterface,
        data_tx::OwnedWifiDataTxFrame,
        wpa2::Wpa2Interface,
        wpa2_io::{
            StaticWpa2Keys, TryWpa2Io, Wpa2IoCommand, Wpa2IoFailure, Wpa2KeyInstall, Wpa2KeyKind,
        },
        wpa2_txdone::async_wpa2_sta_tx_done_installed,
    };

    const CCMP_ALGORITHM: u32 = 3;
    const PAIRWISE_KEY_INDEX: u32 = 0;
    const CRYPTO_KEY_TABLE_BASE: usize = 0x2010_5800;
    const CRYPTO_KEY_ENTRY_STRIDE: usize = 40;
    const CRYPTO_KEY_VALID_BITMAP: *mut u32 = 0x2010_4814 as *mut u32;
    const MAX_HARDWARE_KEY_BYTES: usize = 32;
    unsafe extern "C" {
        static ccmp: [u8; 24];
        static mut g_ic: u8;
        static mut g_sta_connected_flag: u8;
        #[cfg(feature = "hil-vendor-tx")]
        static mut gWpaSm: u8;

        #[link_name = "hal_crypto_set_key_entry"]
        fn linked_hal_crypto_set_key_entry(
            hardware_index: u32,
            key: *const u8,
            key_length: usize,
            metadata: *const u8,
        );

        fn cnx_node_search(peer: *const u8) -> *mut u8;
        fn ieee80211_search_node(interface: u32, frame: *const u8, error: *mut u32) -> *mut u8;
        fn esf_buf_alloc(frame: *const u8, kind: u32, length: u32) -> *mut u8;
        fn ieee80211_post_hmac_tx(buffer: *mut u8) -> u32;
        fn ic_del_key(hardware_index: u32);
        #[cfg(feature = "hil-vendor-tx")]
        fn ieee80211_output_do(
            interface: u32,
            frame: *const u8,
            length: u32,
            flags: u32,
            netstack_buffer: *mut c_void,
        ) -> i32;
        #[cfg(feature = "hil-vendor-tx")]
        fn wpa_ether_send(
            state: *mut c_void,
            destination: *const u8,
            protocol: u16,
            data: *mut u8,
            data_len: usize,
        ) -> i32;
        fn ic_set_key(
            interface: u32,
            algorithm: u32,
            key_index: u32,
            peer: *const u8,
            hardware_index: u32,
            key: *const u8,
            key_length: usize,
            enable: u32,
            spp: u32,
        );
    }

    pub(crate) fn runtime_key_link_wrapper_active() -> bool {
        core::ptr::eq(
            linked_hal_crypto_set_key_entry as *const (),
            __wrap_hal_crypto_set_key_entry as *const (),
        )
    }

    #[cfg(feature = "hil-vendor-tx")]
    pub fn hil_sta_pairwise_key_snapshot(
        expected_tk: &[u8; WPA2_TK_LEN],
    ) -> HilStaPairwiseKeySnapshot {
        unsafe {
            let entry = (CRYPTO_KEY_TABLE_BASE
                + usize::from(STA_PAIRWISE_HARDWARE_INDEX) * CRYPTO_KEY_ENTRY_STRIDE)
                as *const u8;
            let peer_low = entry.cast::<u32>().read_volatile().to_le_bytes();
            let peer_control = entry.add(4).cast::<u32>().read_volatile();
            let peer_high = peer_control.to_le_bytes();
            let mut peer = [0; 6];
            peer[..4].copy_from_slice(&peer_low);
            peer[4..].copy_from_slice(&peer_high[..2]);
            let mut key_matches = true;
            let mut index = 0;
            while index < expected_tk.len() {
                key_matches &= entry.add(8 + index).read_volatile() == expected_tk[index];
                index += 1;
            }
            let station = sta_interface_state();
            let node = sta_interface_node();
            HilStaPairwiseKeySnapshot {
                valid: CRYPTO_KEY_VALID_BITMAP.read_volatile()
                    & (1_u32 << STA_PAIRWISE_HARDWARE_INDEX)
                    != 0,
                peer,
                control: (peer_control >> 16) as u16,
                key_matches,
                crypto_gate: ptr::addr_of_mut!(g_ic)
                    .add(0x210)
                    .cast::<u16>()
                    .read_volatile(),
                node_hardware_index: if node.is_null() {
                    u8::MAX
                } else {
                    node.add(0x134).read_volatile()
                },
                node_flags: if node.is_null() {
                    0
                } else {
                    node.add(0x0c).cast::<u32>().read_volatile()
                },
                node_key_state: if node.is_null() {
                    u8::MAX
                } else {
                    node.add(0x24).read_volatile()
                },
                station_privacy: if station.is_null() {
                    0
                } else {
                    station.add(0xa4).cast::<u32>().read_volatile()
                },
                station_state: if station.is_null() {
                    u8::MAX
                } else {
                    station.add(0x140).read_volatile()
                },
                global_connected: ptr::addr_of_mut!(g_sta_connected_flag).read_volatile(),
                global_auth_state: ptr::addr_of_mut!(g_ic).add(0x274).read_volatile(),
            }
        }
    }

    unsafe fn software_key_slot(hardware_index: u8) -> Option<*mut *mut c_void> {
        if hardware_index > MAX_VENDOR_KEY_INDEX {
            return None;
        }
        Some(
            ptr::addr_of_mut!(g_ic)
                .add(0x148 + usize::from(hardware_index) * 4)
                .cast::<*mut c_void>(),
        )
    }

    unsafe fn ap_pairwise_hardware_index(peer: *const u8) -> u8 {
        let node = cnx_node_search(peer);
        if node.is_null() {
            0
        } else {
            node.add(0x134).read()
        }
    }

    unsafe fn peer_spp(interface: Wpa2Interface, peer: *const u8) -> u8 {
        let node = match interface {
            Wpa2Interface::AccessPoint => cnx_node_search(peer),
            Wpa2Interface::Station => {
                let interface = ptr::addr_of_mut!(g_ic).add(0x10).cast::<*mut u8>().read();
                if interface.is_null() {
                    return 0;
                }
                interface.add(0xe4).cast::<*mut u8>().read()
            }
        };
        if node.is_null() {
            0
        } else {
            node.add(0x2f8).read()
        }
    }

    unsafe fn sta_interface_state() -> *mut u8 {
        ptr::addr_of_mut!(g_ic).add(0x10).cast::<*mut u8>().read()
    }

    unsafe fn sta_interface_node() -> *mut u8 {
        let interface = sta_interface_state();
        if interface.is_null() {
            return ptr::null_mut();
        }
        interface.add(0xe4).cast::<*mut u8>().read()
    }

    unsafe fn read_metadata(metadata: *const u8, offset: usize) -> u32 {
        u32::from(metadata.add(offset).read())
    }

    unsafe fn write_key_word(
        destination: *mut u32,
        key: *const u8,
        key_length: usize,
        word: usize,
    ) {
        let offset = word * 4;
        if offset >= key_length {
            return;
        }
        let mut value = 0_u32;
        if offset < key_length {
            value |= u32::from(key.add(offset).read());
        }
        if offset + 1 < key_length {
            value |= u32::from(key.add(offset + 1).read()) << 8;
        }
        if offset + 2 < key_length {
            value |= u32::from(key.add(offset + 2).read()) << 16;
        }
        if offset + 3 < key_length {
            value |= u32::from(key.add(offset + 3).read()) << 24;
        }
        destination.add(word).write_volatile(value);
    }

    /// Allocation-free replacement for the pinned `0x1c2`-byte HAL leaf.
    ///
    /// The stock implementation allocates a temporary buffer solely when the
    /// key pointer is not word-aligned. This replacement programs the same
    /// fixed key-table MMIO a byte at a time and supports the complete hardware
    /// maximum of 32 key bytes, so neither pointer alignment nor a future
    /// caller can expose the allocator branch. The surrounding pinned
    /// `wDev_Insert_KeyEntry` still performs its bookkeeping and calls
    /// `hal_crypto_enable`.
    ///
    /// The final firmware must link with
    /// `-Wl,--wrap=hal_crypto_set_key_entry`.
    #[no_mangle]
    pub unsafe extern "C" fn __wrap_hal_crypto_set_key_entry(
        hardware_index: u32,
        key: *const u8,
        key_length: usize,
        metadata: *const u8,
    ) {
        if hardware_index > u32::from(MAX_VENDOR_KEY_INDEX)
            || key.is_null()
            || metadata.is_null()
            || key_length == 0
            || key_length > MAX_HARDWARE_KEY_BYTES
        {
            return;
        }

        let interface = read_metadata(metadata, 0);
        let algorithm = read_metadata(metadata, 1);
        let logical_key_index = read_metadata(metadata, 2);
        let peer_low = read_metadata(metadata, 3)
            | (read_metadata(metadata, 4) << 8)
            | (read_metadata(metadata, 5) << 16)
            | (read_metadata(metadata, 6) << 24);
        let peer_high = read_metadata(metadata, 7) | (read_metadata(metadata, 8) << 8);

        let cipher = if algorithm == 5 {
            0x0005_0000
        } else if algorithm == 9 {
            0x0014_0000
                | if key_length == MAX_HARDWARE_KEY_BYTES {
                    0x0400_0000
                } else {
                    0
                }
        } else {
            (algorithm & 7) << 18
        };
        let direction = if cipher & 0x001c_0000 == 0x0004_0000 {
            7
        } else if hardware_index <= 3 {
            6
        } else {
            7
        };
        let control = ((interface & 3) << 8)
            | (direction << 5)
            | (u32::from(logical_key_index != 3) << 11)
            | (logical_key_index << 14)
            | ((cipher >> 16) & 0x341f);

        let entry =
            (CRYPTO_KEY_TABLE_BASE + hardware_index as usize * CRYPTO_KEY_ENTRY_STRIDE) as *mut u32;
        entry.write_volatile(peer_low);
        entry.add(1).write_volatile(peer_high | (control << 16));
        let key_destination = entry.add(2);
        write_key_word(key_destination, key, key_length, 0);
        write_key_word(key_destination, key, key_length, 1);
        write_key_word(key_destination, key, key_length, 2);
        write_key_word(key_destination, key, key_length, 3);
        write_key_word(key_destination, key, key_length, 4);
        write_key_word(key_destination, key, key_length, 5);
        write_key_word(key_destination, key, key_length, 6);
        write_key_word(key_destination, key, key_length, 7);

        let valid = CRYPTO_KEY_VALID_BITMAP.read_volatile();
        CRYPTO_KEY_VALID_BITMAP.write_volatile(valid | (1_u32 << hardware_index));
    }

    pub struct S31StaticWpa2Io<const K: usize> {
        storage: &'static S31StaticKeyStorage<K>,
        keys: StaticWpa2Keys<K>,
        sta_authorized_peer: Option<[u8; 6]>,
        authorized_peers: StaticAuthorizedPeers<K>,
        tx_poisoned: bool,
        #[cfg(feature = "hil-vendor-tx")]
        vendor_tx_diagnostic: bool,
        #[cfg(feature = "hil-vendor-tx")]
        vendor_wpa_tx_diagnostic: bool,
    }

    impl<const K: usize> S31StaticWpa2Io<K> {
        /// Construct a backend after strict runtime preparation.
        ///
        /// # Safety
        /// `proof` must belong to the active driver. Controlled hardware key
        /// indices must contain no foreign heap object. The backend and static
        /// storage must remain exclusive until Wi-Fi deinitialization. No RX
        /// fragment assembled under an old key may be live when a key-install
        /// command is submitted; the stock fragment cleanup can call logging
        /// and is deliberately excluded from this strict backend.
        pub unsafe fn new(
            storage: &'static S31StaticKeyStorage<K>,
            _proof: &crate::policy::StrictRuntimeProof,
        ) -> Result<Self, S31Wpa2IoError> {
            if !storage.take_backend() {
                return Err(S31Wpa2IoError::StorageAlreadyTaken);
            }
            Ok(Self {
                storage,
                keys: StaticWpa2Keys::new(),
                sta_authorized_peer: None,
                authorized_peers: StaticAuthorizedPeers::new(),
                tx_poisoned: false,
                #[cfg(feature = "hil-vendor-tx")]
                vendor_tx_diagnostic: false,
                #[cfg(feature = "hil-vendor-tx")]
                vendor_wpa_tx_diagnostic: false,
            })
        }

        /// Route HIL frames through the stock `ieee80211_output_do` oracle.
        ///
        /// This intentionally reintroduces the vendor global-lock callbacks
        /// and is only for locating differences in the reconstructed TX leaf.
        #[cfg(feature = "hil-vendor-tx")]
        pub unsafe fn enable_vendor_tx_diagnostic(&mut self) {
            self.vendor_tx_diagnostic = true;
        }

        /// Route HIL EAPOL through the complete stock `wpa_ether_send` leaf.
        ///
        /// This is strictly a differential oracle: it reintroduces the stock
        /// global-lock TX wrapper and must never be enabled in production.
        #[cfg(feature = "hil-vendor-tx")]
        pub unsafe fn enable_vendor_wpa_tx_diagnostic(&mut self) {
            self.vendor_wpa_tx_diagnostic = true;
        }

        pub const fn keys(&self) -> &StaticWpa2Keys<K> {
            &self.keys
        }

        /// Controlled-port gate for Rust-owned AP data channels.
        ///
        /// EAPOL ingress is intentionally handled separately. Every ordinary
        /// AP data frame must be checked here immediately before enqueue or
        /// transmit, so a prior authorization cannot be retained as a stale
        /// capability after deauthorization.
        pub fn is_ap_peer_authorized(&self, peer: &[u8; 6]) -> bool {
            self.authorized_peers.contains(peer)
        }

        /// Controlled-port state for the single associated STA peer.
        pub fn is_sta_peer_authorized(&self) -> bool {
            self.sta_authorized_peer.is_some()
        }

        /// Submit one frame received from the fixed application TX channel.
        ///
        /// This performs one immediate static-pool attempt. AP traffic is
        /// checked against the current controlled-port table at the point of
        /// submission, so queueing a frame cannot retain stale authorization.
        pub fn try_transmit_wifi_data(
            &mut self,
            frame: &OwnedWifiDataTxFrame,
        ) -> Result<(), S31Wpa2IoError> {
            if !in_radio_context() {
                return Err(S31Wpa2IoError::NotRadioOwner);
            }
            let interface = match frame.interface() {
                WifiDataInterface::Station => Wpa2Interface::Station,
                WifiDataInterface::AccessPoint => Wpa2Interface::AccessPoint,
            };
            match interface {
                Wpa2Interface::Station if !self.is_sta_peer_authorized() => {
                    return Err(S31Wpa2IoError::StaPeerUnauthorized);
                }
                Wpa2Interface::AccessPoint if !self.is_ap_peer_authorized(frame.destination()) => {
                    return Err(S31Wpa2IoError::ApPeerUnauthorized);
                }
                _ => {}
            }
            self.submit_frame(interface, frame.as_bytes())
        }

        fn has_pairwise_key(&self, interface: Wpa2Interface, peer: &[u8; 6]) -> bool {
            (0..K).any(|index| {
                self.keys.get(index).is_some_and(|key| {
                    key.interface() == interface
                        && key.peer() == peer
                        && key.kind() == Wpa2KeyKind::Pairwise
                })
            })
        }

        fn set_peer_authorized(
            &mut self,
            interface: Wpa2Interface,
            peer: [u8; 6],
            authorized: bool,
        ) -> Result<(), S31Wpa2IoError> {
            if authorized && !self.has_pairwise_key(interface, &peer) {
                return Err(S31Wpa2IoError::AuthorizationWithoutPairwiseKey);
            }
            match interface {
                Wpa2Interface::Station => {
                    if authorized {
                        self.activate_sta_ptk()?;
                        self.sta_authorized_peer = Some(peer);
                    } else if self.sta_authorized_peer == Some(peer) {
                        self.sta_authorized_peer = None;
                    }
                    Ok(())
                }
                Wpa2Interface::AccessPoint => self
                    .authorized_peers
                    .set(peer, authorized)
                    .map_err(|()| S31Wpa2IoError::AuthorizationSlotsFull),
            }
        }

        #[inline(never)]
        fn activate_sta_ptk(&self) -> Result<(), S31Wpa2IoError> {
            let station = unsafe { sta_interface_state() };
            let node = unsafe { sta_interface_node() };
            if station.is_null() || node.is_null() {
                return Err(S31Wpa2IoError::MissingStaInterfaceState);
            }
            let hardware_index = unsafe { node.add(0x134).read() };
            if hardware_index != STA_PAIRWISE_HARDWARE_INDEX {
                return Err(S31Wpa2IoError::UnexpectedStaPairwiseHardwareIndex);
            }
            unsafe {
                // Finite state tail of the pinned PTK-ready and STA privacy
                // callbacks. It runs only after M4 TX completion; their
                // event/log side effects are deliberately omitted.
                let flags = node.add(0x0c).cast::<u32>();
                flags.write((flags.read() & 0xfdff_ffff) | 1);
                node.add(0x24).write(0);
                let privacy = station.add(0xa4).cast::<u32>();
                privacy.write(privacy.read() | 0x10);

                // Minimal finite connection-state commit recovered from
                // `cnx_auth_done`. Its omitted remainder enters NVS, event
                // posting, power-save and AMPDU control; ordinary STA data
                // paths consume only these state facts.
                ptr::addr_of_mut!(g_ic).add(0x274).write(1);
                ptr::addr_of_mut!(g_sta_connected_flag).write(1);
                station.add(0x140).write(5);
            }
            Ok(())
        }

        fn submit_eapol<const N: usize>(
            &mut self,
            frame: &crate::wpa2_frames::Wpa2EthernetFrame<N>,
        ) -> Result<(), S31Wpa2IoError> {
            self.submit_frame(frame.interface(), frame.as_bytes())
        }

        fn submit_frame(
            &mut self,
            frame_interface: Wpa2Interface,
            frame: &[u8],
        ) -> Result<(), S31Wpa2IoError> {
            if self.tx_poisoned {
                return Err(S31Wpa2IoError::TxBackendPoisoned);
            }
            let length =
                u32::try_from(frame.len()).map_err(|_| S31Wpa2IoError::TxLengthOverflow)?;
            let interface = match frame_interface {
                Wpa2Interface::Station => wifi_interface_t_WIFI_IF_STA,
                Wpa2Interface::AccessPoint => wifi_interface_t_WIFI_IF_AP,
            };

            #[cfg(feature = "hil-vendor-tx")]
            if self.vendor_wpa_tx_diagnostic && frame_interface == Wpa2Interface::Station {
                if frame.len() < 14 || frame.len() > crate::wpa2_frames::WPA2_TX_ETHERNET_CAPACITY {
                    return Err(S31Wpa2IoError::TxLengthOverflow);
                }
                let mut vendor_frame = [0_u8; crate::wpa2_frames::WPA2_TX_ETHERNET_CAPACITY];
                vendor_frame[..frame.len()].copy_from_slice(frame);
                let protocol = u16::from_be_bytes([vendor_frame[12], vendor_frame[13]]);
                let result = unsafe {
                    wpa_ether_send(
                        ptr::addr_of_mut!(gWpaSm).cast(),
                        vendor_frame.as_ptr(),
                        protocol,
                        vendor_frame.as_mut_ptr().add(14),
                        frame.len() - 14,
                    )
                };
                return if result == 0 {
                    Ok(())
                } else {
                    Err(S31Wpa2IoError::VendorTxDiagnosticRejected(result))
                };
            }

            #[cfg(feature = "hil-vendor-tx")]
            if self.vendor_tx_diagnostic {
                let result = unsafe {
                    ieee80211_output_do(interface, frame.as_ptr(), length, 0, ptr::null_mut())
                };
                return if result == 0 {
                    Ok(())
                } else {
                    Err(S31Wpa2IoError::VendorTxDiagnosticRejected(result))
                };
            }

            let mut peer_error = 0_u32;
            let node = unsafe { ieee80211_search_node(interface, frame.as_ptr(), &mut peer_error) };
            if node.is_null() {
                return Err(S31Wpa2IoError::TxPeerNotFound(peer_error));
            }
            if frame_interface == Wpa2Interface::AccessPoint {
                // The stock output wrapper branches into the AP power-save
                // queue when either field is set. Strict mode rejects that
                // branch instead of entering its separate scheduling graph.
                let sleeping = unsafe { node.add(0x2fe).read() != 0 };
                let flags = unsafe { node.add(0x0c).cast::<u32>().read() };
                if sleeping || flags & 0x10 != 0 {
                    return Err(S31Wpa2IoError::TxPeerPowerSaveUnsupported);
                }
            }
            if unsafe { core::ptr::addr_of_mut!(g_ic).add(0x258).read() } != 0 {
                return Err(S31Wpa2IoError::CachedTxRuntimeEnabled);
            }

            // Call the mandatory ESF wrapper directly. Kind 1 is the
            // initialized static TX free list; this bypasses the stock cache
            // selector and its optional netstack callback.
            let buffer = unsafe { esf_buf_alloc(frame.as_ptr(), 1, length) };
            if buffer.is_null() {
                return Err(S31Wpa2IoError::StaticTxPoolExhausted);
            }

            let descriptor = unsafe { buffer.add(0x34).cast::<*mut u8>().read() };
            if descriptor.is_null() {
                self.tx_poisoned = true;
                return Err(S31Wpa2IoError::InvalidTxDescriptor);
            }
            unsafe {
                let control = descriptor.add(0x10).cast::<u32>();
                control.write((control.read() & 0xfff3_ffff) | ((interface & 3) << 18));
                let flags = buffer.add(0x1c).cast::<u32>();
                // `ieee80211_output_do(..., flags = 0, netstack = 0)` clears
                // the entire upper halfword here, not only the by-reference
                // ownership bit. Retaining stale allocator metadata can make
                // a successfully completed EAPOL buffer take the wrong TX
                // treatment downstream.
                flags.write(flags.read() & 0x0000_ffff);
            }

            let result = unsafe { ieee80211_post_hmac_tx(buffer) };
            if result != 0 {
                // The leaf recycles on its ordinary rejection branches. If
                // pp_post itself rejects after list insertion, its ownership
                // cannot be recovered synchronously; poison the backend and
                // require Wi-Fi deinit instead of retrying or duplicating TX.
                self.tx_poisoned = true;
                return Err(S31Wpa2IoError::TxPostRejected(result));
            }
            Ok(())
        }

        fn logical_slot_for(&self, install: &Wpa2KeyInstall) -> Result<usize, S31Wpa2IoError> {
            if install.interface() == Wpa2Interface::Station
                && matches!(install.kind(), Wpa2KeyKind::Group { .. })
            {
                // This chip has one active STA GTK hardware slot. Rekeying
                // to another logical GTK id replaces the old owned secret.
                if let Some(index) = (0..K).find(|&index| {
                    self.keys.get(index).is_some_and(|old| {
                        old.interface() == Wpa2Interface::Station
                            && matches!(old.kind(), Wpa2KeyKind::Group { .. })
                    })
                }) {
                    return Ok(index);
                }
            }
            self.keys
                .slot_for(install)
                .map_err(|_| S31Wpa2IoError::StaticKeySlotsFull)
        }

        fn install_ccmp(
            &mut self,
            install: Wpa2KeyInstall,
        ) -> Result<(), (S31Wpa2IoError, Wpa2KeyInstall)> {
            let interface = install.interface();
            let peer = *install.peer();
            let kind = install.kind();
            let (hardware_index, key_index, spp, sta_gtk_node) = match kind {
                Wpa2KeyKind::Pairwise => {
                    let hardware_index = unsafe {
                        match interface {
                            Wpa2Interface::Station => STA_PAIRWISE_HARDWARE_INDEX,
                            Wpa2Interface::AccessPoint => ap_pairwise_hardware_index(peer.as_ptr()),
                        }
                    };
                    if interface == Wpa2Interface::AccessPoint && hardware_index == 0 {
                        return Err((S31Wpa2IoError::MissingApPeerHardwareIndex, install));
                    }
                    let spp = unsafe { peer_spp(interface, peer.as_ptr()) };
                    (
                        hardware_index,
                        PAIRWISE_KEY_INDEX,
                        u32::from(spp != 0),
                        None,
                    )
                }
                Wpa2KeyKind::Group { key_id, .. } => {
                    let Some(hardware_index) = group_hardware_index(interface, key_id) else {
                        return Err((S31Wpa2IoError::InvalidGroupKeyId(key_id), install));
                    };
                    let sta_gtk_node = if interface == Wpa2Interface::Station {
                        let node = unsafe { sta_interface_node() };
                        if node.is_null() {
                            return Err((S31Wpa2IoError::MissingStaInterfaceState, install));
                        }
                        Some(node)
                    } else {
                        None
                    };
                    (hardware_index, u32::from(key_id), 0, sta_gtk_node)
                }
            };
            if hardware_index > MAX_VENDOR_KEY_INDEX {
                return Err((
                    S31Wpa2IoError::InvalidHardwareIndex(hardware_index),
                    install,
                ));
            }
            let logical_index = match self.logical_slot_for(&install) {
                Ok(index) => index,
                Err(error) => return Err((error, install)),
            };
            let Some(object) = self.storage.claim(hardware_index) else {
                return Err((S31Wpa2IoError::StaticKeySlotsFull, install));
            };
            let software_key_slot = unsafe { software_key_slot(hardware_index) }.unwrap();
            let registered = unsafe { software_key_slot.read() };
            if !registered.is_null() && registered != object.cast::<c_void>() {
                return Err((S31Wpa2IoError::ForeignSoftwareKeyPresent, install));
            }
            let key = match self.keys.replace_at(logical_index, install) {
                Ok(key) => key,
                Err(install) => {
                    return Err((S31Wpa2IoError::InternalOwnershipMismatch, install));
                }
            };

            let interface_number = match interface {
                Wpa2Interface::Station => wifi_interface_t_WIFI_IF_STA,
                Wpa2Interface::AccessPoint => wifi_interface_t_WIFI_IF_AP,
            };
            unsafe {
                // Exact bounded hardware replacement prefix from the pinned
                // non-delete `ppInstallKey` branch. `ic_del_key` is a finite
                // bitmap update plus ten key-register clears; it has no loop,
                // lock, allocation, callback, or wait edge.
                ic_del_key(hardware_index.into());
                let crypto_enable = u32::from(
                    ptr::addr_of_mut!(g_ic)
                        .add(0x210)
                        .cast::<u16>()
                        .read_volatile()
                        == 0,
                );
                ic_set_key(
                    interface_number,
                    CCMP_ALGORITHM,
                    key_index,
                    peer.as_ptr(),
                    hardware_index.into(),
                    key.key().as_bytes().as_ptr(),
                    WPA2_TK_LEN,
                    crypto_enable,
                    spp,
                );

                let object = &mut *object;
                // Exact two bounded memset operations from the pinned
                // 0x30-byte `wifi_init_key`, performed in Rust-owned storage.
                object.initialize_like_wifi_init_key();
                object.bytes[KEY_INDEX_OFFSET..KEY_INDEX_OFFSET + 2]
                    .copy_from_slice(&(hardware_index as u16).to_le_bytes());
                object.bytes[RECEIVE_SEQUENCE_OFFSET..RECEIVE_SEQUENCE_OFFSET + 8]
                    .copy_from_slice(key.receive_sequence());
                object
                    .bytes
                    .as_mut_ptr()
                    .add(CIPHER_POINTER_OFFSET)
                    .cast::<*const u8>()
                    .write(core::ptr::addr_of!(ccmp).cast::<u8>());
                object.bytes[KEY_LENGTH_OFFSET..KEY_LENGTH_OFFSET + 4]
                    .copy_from_slice(&(WPA2_TK_LEN as u32).to_le_bytes());
                object.bytes[KEY_BYTES_OFFSET..].copy_from_slice(key.key().as_bytes());

                // Exact non-freeing branch of the pinned key-table setter.
                // The foreign-pointer case was rejected before any mutation.
                software_key_slot.write(object as *mut _ as *mut c_void);
                if let Wpa2KeyKind::Group { key_id, .. } = kind {
                    if let Some(station) = sta_gtk_node {
                        // ppInstallKey proves this exact metadata update for
                        // hardware indices zero and one. It is a finite pair
                        // of byte stores with no callback or lock.
                        station.add(0x135).write(hardware_index);
                        station
                            .add(0x137 + usize::from(key_id))
                            .write(hardware_index);
                    }
                }
            }
            Ok(())
        }
    }

    impl<const K: usize, const N: usize> TryWpa2Io<N> for S31StaticWpa2Io<K> {
        type Error = S31Wpa2IoError;

        fn try_execute(
            &mut self,
            command: Wpa2IoCommand<N>,
        ) -> Result<(), Wpa2IoFailure<Self::Error, N>> {
            if !in_radio_context() {
                return Err(Wpa2IoFailure {
                    error: S31Wpa2IoError::NotRadioOwner,
                    command,
                });
            }
            match command {
                Wpa2IoCommand::Transmit(frame) => {
                    if frame.interface() == Wpa2Interface::Station
                        && !async_wpa2_sta_tx_done_installed()
                    {
                        return Err(Wpa2IoFailure {
                            error: S31Wpa2IoError::StaTxDoneCallbackMissing,
                            command: Wpa2IoCommand::Transmit(frame),
                        });
                    }
                    if let Err(error) = self.submit_eapol(&frame) {
                        return Err(Wpa2IoFailure {
                            error,
                            command: Wpa2IoCommand::Transmit(frame),
                        });
                    }
                    Ok(())
                }
                Wpa2IoCommand::TransmitData(frame) => {
                    self.try_transmit_wifi_data(&frame)
                        .map_err(|error| Wpa2IoFailure {
                            error,
                            command: Wpa2IoCommand::TransmitData(frame),
                        })
                }
                Wpa2IoCommand::InstallKey(install) => {
                    self.install_ccmp(install)
                        .map_err(|(error, install)| Wpa2IoFailure {
                            error,
                            command: Wpa2IoCommand::InstallKey(install),
                        })
                }
                Wpa2IoCommand::SetPeerAuthorized {
                    interface,
                    peer,
                    authorized,
                } => self
                    .set_peer_authorized(interface, peer, authorized)
                    .map_err(|error| Wpa2IoFailure {
                        error,
                        command: Wpa2IoCommand::SetPeerAuthorized {
                            interface,
                            peer,
                            authorized,
                        },
                    }),
            }
        }
    }
}

#[cfg(all(target_arch = "riscv32", feature = "hil-vendor-tx"))]
pub use target::hil_sta_pairwise_key_snapshot;
#[cfg(target_arch = "riscv32")]
pub(crate) use target::runtime_key_link_wrapper_active;
#[cfg(target_arch = "riscv32")]
pub use target::S31StaticWpa2Io;

#[cfg(test)]
mod tests {
    use super::*;

    static STORAGE: S31StaticKeyStorage<1> = S31StaticKeyStorage::new();

    #[test]
    fn pinned_vendor_key_layout_is_exact_and_aligned() {
        assert_eq!(core::mem::size_of::<VendorCcmpKeyObject>(), 0xb8);
        assert_eq!(core::mem::align_of::<VendorCcmpKeyObject>(), 4);
        assert_eq!(KEY_INDEX_OFFSET, 0);
        assert_eq!(RECEIVE_SEQUENCE_OFFSET, 0x98);
        assert_eq!(CIPHER_POINTER_OFFSET, 0xa0);
        assert_eq!(KEY_LENGTH_OFFSET, 0xa4);
        assert_eq!(KEY_BYTES_OFFSET, 0xa8);
    }

    #[test]
    fn rust_key_initialization_matches_pinned_wifi_init_key() {
        let mut object = VendorCcmpKeyObject {
            bytes: [0x5a; VENDOR_KEY_OBJECT_LEN],
        };

        object.initialize_like_wifi_init_key();

        assert!(object.bytes[..8].iter().all(|byte| *byte == 0));
        assert!(object.bytes[8..0x98].iter().all(|byte| *byte == 0xff));
        assert!(object.bytes[0x98..0xa8].iter().all(|byte| *byte == 0));
        assert!(object.bytes[0xa8..].iter().all(|byte| *byte == 0x5a));
    }

    #[test]
    fn static_vendor_slot_has_stable_address_and_fixed_capacity() {
        let first = STORAGE.claim(4).unwrap();
        let same = STORAGE.claim(4).unwrap();
        assert_eq!(first, same);
        assert!(STORAGE.claim(5).is_none());
        assert_eq!(first.addr() & 3, 0);
    }

    #[test]
    fn group_hardware_slots_are_fixed_and_disjoint_from_sta_pairwise() {
        use crate::wpa2::Wpa2Interface;

        for key_id in 0..=MAX_WPA2_GTK_ID {
            assert_eq!(
                group_hardware_index(Wpa2Interface::Station, key_id),
                Some(STA_GROUP_HARDWARE_INDEX)
            );
            assert_eq!(
                group_hardware_index(Wpa2Interface::AccessPoint, key_id),
                Some(AP_GROUP_HARDWARE_INDEX_BASE + key_id)
            );
        }
        assert_ne!(STA_GROUP_HARDWARE_INDEX, STA_PAIRWISE_HARDWARE_INDEX);
        assert_eq!(group_hardware_index(Wpa2Interface::Station, 4), None);
    }

    #[test]
    fn authorization_table_is_fixed_and_deauthorization_is_idempotent() {
        let first = [1, 2, 3, 4, 5, 6];
        let second = [6, 5, 4, 3, 2, 1];
        let mut peers = StaticAuthorizedPeers::<1>::new();

        assert!(!peers.contains(&first));
        assert_eq!(peers.set(first, true), Ok(()));
        assert!(peers.contains(&first));
        assert_eq!(peers.set(second, true), Err(()));
        assert_eq!(peers.set(first, false), Ok(()));
        assert_eq!(peers.set(first, false), Ok(()));
        assert_eq!(peers.set(second, true), Ok(()));
        assert!(peers.contains(&second));
    }
}
