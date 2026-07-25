//! Explicit Rust registry for the vendor interface objects published in
//! `g_ic`.
//!
//! This is a transitional ownership boundary. Rust owns the registry and the
//! publication lifetime, while the interface objects themselves are still
//! fixed vendor-layout storage. A handle identifies one role; it does not
//! expose arbitrary `g_ic` fields or imply ownership of node tables.

use core::{
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[cfg(target_arch = "riscv32")]
const STA_INTERFACE_OFFSET: usize = 0x10;
#[cfg(target_arch = "riscv32")]
const AP_INTERFACE_OFFSET: usize = 0x14;
#[cfg(target_arch = "riscv32")]
const MESH_STATE_OFFSET: usize = 0x74;
#[cfg(target_arch = "riscv32")]
const PENDING_TX_HEAD_OFFSET: usize = 0x1ac;
#[cfg(target_arch = "riscv32")]
const CACHED_TX_ENABLED_OFFSET: usize = 0x258;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Net80211StateAdoptionError {
    MissingInterfaces,
    AliasedInterfaces,
    MisalignedStationInterface,
    MisalignedAccessPointInterface,
    MeshModeActive,
    PendingTxActive,
    CachedTxEnabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Net80211InterfaceRole {
    Station,
    AccessPoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Net80211InterfaceHandle {
    role: Net80211InterfaceRole,
    address: NonNull<u8>,
}

impl Net80211InterfaceHandle {
    pub fn role(self) -> Net80211InterfaceRole {
        self.role
    }

    pub fn as_ptr(self) -> *mut u8 {
        self.address.as_ptr()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Net80211InterfaceRegistrySnapshot {
    pub adopted: bool,
    pub station: Option<usize>,
    pub access_point: Option<usize>,
}

struct Net80211InterfaceRegistry {
    adopted: AtomicBool,
    station: AtomicUsize,
    access_point: AtomicUsize,
}

impl Net80211InterfaceRegistry {
    const fn new() -> Self {
        Self {
            adopted: AtomicBool::new(false),
            station: AtomicUsize::new(0),
            access_point: AtomicUsize::new(0),
        }
    }

    fn adopt(
        &self,
        station: usize,
        access_point: usize,
        mesh_state: usize,
        pending_tx_head: usize,
        cached_tx_enabled: bool,
    ) -> Result<(), Net80211StateAdoptionError> {
        if station == 0 && access_point == 0 {
            return Err(Net80211StateAdoptionError::MissingInterfaces);
        }
        if station != 0 && station == access_point {
            return Err(Net80211StateAdoptionError::AliasedInterfaces);
        }
        if station & (core::mem::align_of::<usize>() - 1) != 0 {
            return Err(Net80211StateAdoptionError::MisalignedStationInterface);
        }
        if access_point & (core::mem::align_of::<usize>() - 1) != 0 {
            return Err(Net80211StateAdoptionError::MisalignedAccessPointInterface);
        }
        if mesh_state != 0 {
            return Err(Net80211StateAdoptionError::MeshModeActive);
        }
        if pending_tx_head != 0 {
            return Err(Net80211StateAdoptionError::PendingTxActive);
        }
        if cached_tx_enabled {
            return Err(Net80211StateAdoptionError::CachedTxEnabled);
        }

        self.station.store(station, Ordering::Relaxed);
        self.access_point.store(access_point, Ordering::Relaxed);
        self.adopted.store(true, Ordering::Release);
        Ok(())
    }

    fn interface(&self, role: Net80211InterfaceRole) -> Option<Net80211InterfaceHandle> {
        if !self.adopted.load(Ordering::Acquire) {
            return None;
        }
        let address = match role {
            Net80211InterfaceRole::Station => self.station.load(Ordering::Acquire),
            Net80211InterfaceRole::AccessPoint => self.access_point.load(Ordering::Acquire),
        };
        NonNull::new(address as *mut u8).map(|address| Net80211InterfaceHandle { role, address })
    }

    fn snapshot(&self) -> Net80211InterfaceRegistrySnapshot {
        let adopted = self.adopted.load(Ordering::Acquire);
        Net80211InterfaceRegistrySnapshot {
            adopted,
            station: adopted
                .then(|| self.station.load(Ordering::Acquire))
                .filter(|address| *address != 0),
            access_point: adopted
                .then(|| self.access_point.load(Ordering::Acquire))
                .filter(|address| *address != 0),
        }
    }
}

#[link_section = ".critical.bss.wifi_strict.net80211_interfaces"]
static INTERFACES: Net80211InterfaceRegistry = Net80211InterfaceRegistry::new();

pub(crate) fn station_interface() -> Option<Net80211InterfaceHandle> {
    INTERFACES.interface(Net80211InterfaceRole::Station)
}

pub(crate) fn access_point_interface() -> Option<Net80211InterfaceHandle> {
    INTERFACES.interface(Net80211InterfaceRole::AccessPoint)
}

pub fn net80211_interface_registry_snapshot() -> Net80211InterfaceRegistrySnapshot {
    INTERFACES.snapshot()
}

/// The strict handoff accepts only ordinary STA/AP state with mesh and the
/// vendor cached-TX path disabled. No post-handoff API can change this policy.
pub(crate) fn ordinary_sta_ap_profile() -> bool {
    INTERFACES.adopted.load(Ordering::Acquire)
}

/// Check the vendor off-channel TX head which strict handoff requires to stay
/// empty until its compatibility consumer is removed.
#[cfg(target_arch = "riscv32")]
pub(crate) unsafe fn vendor_pending_tx_empty() -> bool {
    core::ptr::addr_of!(g_ic)
        .add(PENDING_TX_HEAD_OFFSET)
        .cast::<usize>()
        .read_volatile()
        == 0
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    static g_ic: u8;
}

/// Adopt only the two interface publications from initialized `g_ic`.
///
/// # Safety
/// Vendor initialization must be complete and no interface publication may
/// change concurrently. The fixed interface storage must outlive strict
/// runtime operation.
#[cfg(target_arch = "riscv32")]
pub(crate) unsafe fn adopt_vendor_interface_registry() -> Result<(), Net80211StateAdoptionError> {
    let state = core::ptr::addr_of!(g_ic);
    let station = state
        .add(STA_INTERFACE_OFFSET)
        .cast::<*mut u8>()
        .read_unaligned() as usize;
    let access_point = state
        .add(AP_INTERFACE_OFFSET)
        .cast::<*mut u8>()
        .read_unaligned() as usize;
    let mesh_state = state
        .add(MESH_STATE_OFFSET)
        .cast::<usize>()
        .read_unaligned();
    let pending_tx_head = state
        .add(PENDING_TX_HEAD_OFFSET)
        .cast::<usize>()
        .read_unaligned();
    let cached_tx_enabled = state.add(CACHED_TX_ENABLED_OFFSET).read() != 0;
    INTERFACES.adopt(
        station,
        access_point,
        mesh_state,
        pending_tx_head,
        cached_tx_enabled,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_is_role_checked_and_null_role_remains_absent() {
        let registry = Net80211InterfaceRegistry::new();
        registry.adopt(0x1000, 0, 0, 0, false).unwrap();

        let station = registry.interface(Net80211InterfaceRole::Station).unwrap();
        assert_eq!(station.role(), Net80211InterfaceRole::Station);
        assert_eq!(station.as_ptr() as usize, 0x1000);
        assert_eq!(registry.interface(Net80211InterfaceRole::AccessPoint), None);
    }

    #[test]
    fn invalid_publication_is_not_observable() {
        let registry = Net80211InterfaceRegistry::new();
        assert_eq!(
            registry.adopt(0, 0, 0, 0, false),
            Err(Net80211StateAdoptionError::MissingInterfaces)
        );
        assert!(!registry.snapshot().adopted);

        assert_eq!(
            registry.adopt(0x1001, 0, 0, 0, false),
            Err(Net80211StateAdoptionError::MisalignedStationInterface)
        );
        assert!(!registry.snapshot().adopted);

        assert_eq!(
            registry.adopt(0x1000, 0x1000, 0, 0, false),
            Err(Net80211StateAdoptionError::AliasedInterfaces)
        );
        assert!(!registry.snapshot().adopted);

        assert_eq!(
            registry.adopt(0x1000, 0, 0x2000, 0, false),
            Err(Net80211StateAdoptionError::MeshModeActive)
        );
        assert_eq!(
            registry.adopt(0x1000, 0, 0, 0x2000, false),
            Err(Net80211StateAdoptionError::PendingTxActive)
        );
        assert_eq!(
            registry.adopt(0x1000, 0, 0, 0, true),
            Err(Net80211StateAdoptionError::CachedTxEnabled)
        );
        assert!(!registry.snapshot().adopted);
    }
}
