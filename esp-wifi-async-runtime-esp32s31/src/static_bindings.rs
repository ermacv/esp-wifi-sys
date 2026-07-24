//! Fixed-storage vendor-state bindings used by ESP32-S31 ROM leaves.
//!
//! The pinned `net80211_data_ptr_init` and `wdev_data_init` bodies contain
//! only direct stores of archive-static addresses into ROM ABI cells. The
//! strict archive audit treats them as separate cold-init roots and proves
//! that they contain no allocation, wait, indirect call, or control-flow
//! cycle.

use core::ptr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticVendorBindingError {
    TxRxContext,
    WdevControl,
    Net80211Interface,
    ChannelManager,
}

/// Evidence that the four state objects used directly by strict runtime leaves
/// are backed by the pinned fixed archive storage.
pub struct StaticVendorBindings {
    _private: (),
}

unsafe extern "C" {
    fn net80211_data_ptr_init();
    fn wdev_data_init();

    static mut TxRxCxt: u8;
    static mut pTxRx: *mut u8;

    static mut wDevCtrl: u8;
    static mut wDevCtrl_ptr: *mut u8;

    static mut g_ic: u8;
    static mut g_ic_ptr: *mut u8;

    static mut gChmCxt: u8;
    static mut g_chm: *mut u8;
}

/// Run the two audited fixed-storage binding leaves.
///
/// This is intentionally narrower than vendor Wi-Fi initialization: it does
/// not initialize PHY/MAC hardware, allocate buffers, create a task, or start
/// radio processing. It only publishes addresses of already-linked static
/// objects through the S31 ROM ABI cells.
///
/// # Safety
///
/// The caller must serialize this with Wi-Fi initialization and ensure that no
/// ROM or vendor code reads the affected cells concurrently.
pub unsafe fn bind_static_vendor_state() -> Result<StaticVendorBindings, StaticVendorBindingError> {
    net80211_data_ptr_init();
    wdev_data_init();
    validate_static_vendor_bindings()
}

/// Validate the strict runtime's direct fixed-state dependencies without
/// changing any state.
///
/// # Safety
///
/// The bindings must not be concurrently modified by initialization or
/// teardown.
pub unsafe fn validate_static_vendor_bindings(
) -> Result<StaticVendorBindings, StaticVendorBindingError> {
    if ptr::addr_of!(pTxRx).read_volatile() != ptr::addr_of_mut!(TxRxCxt).cast::<u8>() {
        return Err(StaticVendorBindingError::TxRxContext);
    }
    if ptr::addr_of!(wDevCtrl_ptr).read_volatile() != ptr::addr_of_mut!(wDevCtrl).cast::<u8>() {
        return Err(StaticVendorBindingError::WdevControl);
    }
    if ptr::addr_of!(g_ic_ptr).read_volatile() != ptr::addr_of_mut!(g_ic).cast::<u8>() {
        return Err(StaticVendorBindingError::Net80211Interface);
    }
    if ptr::addr_of!(g_chm).read_volatile() != ptr::addr_of_mut!(gChmCxt).cast::<u8>() {
        return Err(StaticVendorBindingError::ChannelManager);
    }
    Ok(StaticVendorBindings { _private: () })
}
