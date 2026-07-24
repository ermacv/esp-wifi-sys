//! Strict publication boundary for the net80211 transmit queue.
//!
//! The pinned `ieee80211_post_hmac_tx` body has two independent jobs:
//! selecting the optional cached/NAN path from `g_ic`, and appending an ESF
//! object to `s_tx_cacheq` before posting PP event 5. Strict handoff already
//! proves that cached TX and NAN/mesh operation are unavailable. This module
//! keeps only the ordinary STA/AP append and event publication.

use core::{
    ffi::c_void,
    ptr::{self, NonNull},
};

const ESF_QUEUE_LINK_OFFSET: usize = 0x30;
const ESF_DESCRIPTOR_OFFSET: usize = 0x34;
const TX_DESCRIPTOR_CONTROL_OFFSET: usize = 0x10;
const TX_DESCRIPTOR_INTERFACE_SHIFT: u32 = 18;
const TX_DESCRIPTOR_INTERFACE_MASK: u32 = 0x3;

const POST_REJECTED: u32 = 0x3012;
const INVALID_STRICT_FRAME: u32 = 0x3002;
const NET80211_TX_EVENT: u32 = 5;

#[repr(C)]
struct VendorTailQueue {
    head: *mut u8,
    /// Address of the link field which receives the next queue element.
    tail_slot: *mut *mut u8,
}

unsafe extern "C" {
    static mut s_tx_cacheq: VendorTailQueue;
    fn ieee80211_post_hmac_tx(buffer: *mut u8) -> u32;
    fn __real_ieee80211_post_hmac_tx(buffer: *mut u8) -> u32;
    fn pp_post(kind: u32, argument: *mut c_void) -> i32;
    fn esf_buf_recycle(buffer: *mut c_void);
}

pub(crate) fn link_wrapper_active() -> bool {
    ptr::eq(
        ieee80211_post_hmac_tx as *const (),
        wifi_strict_ieee80211_post_hmac_tx as *const (),
    )
}

/// Verify the vendor mailbox is in its canonical empty state before the
/// strict executor can publish a frame.
pub(crate) unsafe fn vendor_mailbox_empty() -> bool {
    let queue = ptr::addr_of_mut!(s_tx_cacheq);
    (*queue).head.is_null()
        && ptr::eq(
            (*queue).tail_slot,
            ptr::addr_of_mut!((*queue).head).cast::<*mut u8>(),
        )
}

/// Replace the pinned cached/NAN selector with the strict ordinary STA/AP
/// publication path.
///
/// `s_tx_cacheq` remains a vendor-layout mailbox until event-5 consumption is
/// migrated. Publication and consumption execute as run-to-completion actions
/// on the one strict Wi-Fi hart, so no task can observe the link between these
/// stores. Interrupt handlers do not submit net80211 ESF objects.
///
/// # Safety
///
/// `buffer` must be either null or an outstanding ESF object owned by the
/// caller. On validation failure ownership is returned to the fixed ESF pool.
/// On success ownership moves to the net80211 TX queue.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn wifi_strict_ieee80211_post_hmac_tx(buffer: *mut u8) -> u32 {
    if !crate::critical::strict_wifi_hart_armed() {
        return __real_ieee80211_post_hmac_tx(buffer);
    }
    let Some(buffer) = NonNull::new(buffer) else {
        return INVALID_STRICT_FRAME;
    };
    if !crate::net80211_state::ordinary_sta_ap_profile() {
        esf_buf_recycle(buffer.as_ptr().cast());
        return INVALID_STRICT_FRAME;
    }

    let descriptor = buffer
        .as_ptr()
        .add(ESF_DESCRIPTOR_OFFSET)
        .cast::<*mut u8>()
        .read();
    let Some(descriptor) = NonNull::new(descriptor) else {
        esf_buf_recycle(buffer.as_ptr().cast());
        return INVALID_STRICT_FRAME;
    };
    let control = descriptor
        .as_ptr()
        .add(TX_DESCRIPTOR_CONTROL_OFFSET)
        .cast::<u32>()
        .read();
    let interface = (control >> TX_DESCRIPTOR_INTERFACE_SHIFT) & TX_DESCRIPTOR_INTERFACE_MASK;
    if interface > 1 {
        // The stock body performs an additional node lookup for interface 2.
        // Strict mode supports ordinary STA/AP only, so accepting NAN or the
        // reserved fourth selector would create ownership outside this queue.
        esf_buf_recycle(buffer.as_ptr().cast());
        return INVALID_STRICT_FRAME;
    }

    let queue = ptr::addr_of_mut!(s_tx_cacheq);
    let tail_slot = (*queue).tail_slot;
    if tail_slot.is_null() {
        esf_buf_recycle(buffer.as_ptr().cast());
        return INVALID_STRICT_FRAME;
    }

    let next = buffer.as_ptr().add(ESF_QUEUE_LINK_OFFSET).cast::<*mut u8>();
    next.write(ptr::null_mut());
    tail_slot.write(buffer.as_ptr());
    (*queue).tail_slot = next;

    if pp_post(NET80211_TX_EVENT, ptr::null_mut()) == 0 {
        0
    } else {
        // Match the pinned ABI: the frame is already queue-owned when event
        // publication fails. The caller must not recycle or retry it.
        POST_REJECTED
    }
}

const _: () = assert!(core::mem::size_of::<VendorTailQueue>() == 8);
