//! Strict publication boundary for the net80211 transmit queue.
//!
//! The pinned `ieee80211_post_hmac_tx` body has two independent jobs:
//! selecting the optional cached/NAN path from `g_ic`, and appending an ESF
//! object to `s_tx_cacheq` before posting PP event 5. Strict handoff already
//! proves that cached TX and NAN/mesh operation are unavailable. This module
//! replaces the shared input list with a Rust-owned intrusive queue and lends
//! one frame at a time to the remaining vendor output stage.

use core::{
    cell::UnsafeCell,
    ffi::c_void,
    ptr::{self, NonNull},
};

const ESF_QUEUE_LINK_OFFSET: usize = 0x30;
const ESF_DESCRIPTOR_OFFSET: usize = 0x34;
const TX_DESCRIPTOR_CONTROL_OFFSET: usize = 0x10;
const TX_DESCRIPTOR_INTERFACE_SHIFT: u32 = 18;
const TX_DESCRIPTOR_INTERFACE_MASK: u32 = 0x3;
const TX_DESCRIPTOR_RAW_FLAG: u32 = 0x0000_8000;
const TX_DESCRIPTOR_FIXED_RATE_FLAG: u32 = 0x0200_0000;
const ESF_DATA_OFFSET: usize = 0x04;
const ESF_PREFIX_FLAGS_OFFSET: usize = 0x24;
const ESF_PREFIX_PRESENT: u16 = 0x2000;
const NODE_INTERFACE_OFFSET: usize = 0x00;
const NODE_FLAGS_OFFSET: usize = 0x0c;
const NODE_WMM_ADMISSION_BASE: usize = 0x89;
const NODE_WMM_ADMISSION_STRIDE: usize = 7;
const NODE_SPECIAL_CLASSIFIER_OFFSET: usize = 0x2f4;
const NET80211_CLASSIFY_CALLBACK_SLOT: usize = 0x24 / core::mem::size_of::<usize>();

const POST_REJECTED: u32 = 0x3012;
const INVALID_STRICT_FRAME: u32 = 0x3002;
const NET80211_TX_EVENT: u32 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Net80211TxError {
    RustMailboxEmpty,
    VendorMailboxBusy,
    VendorMailboxRetainedFrame,
    VendorPendingFrame,
    ContinuationPostRejected,
}

#[repr(C)]
struct VendorTailQueue {
    head: *mut u8,
    /// Address of the link field which receives the next queue element.
    tail_slot: *mut *mut u8,
}

struct RustTxQueue {
    head: *mut u8,
    tail: *mut u8,
    event_armed: bool,
}

impl RustTxQueue {
    const fn new() -> Self {
        Self {
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
            event_armed: false,
        }
    }
}

struct RustTxQueueCell(UnsafeCell<RustTxQueue>);

// Strict publication and consumption are both confined to the one armed
// Wi-Fi hart and run to completion. The cell is never accessed from an ISR.
unsafe impl Sync for RustTxQueueCell {}

impl RustTxQueueCell {
    const fn new() -> Self {
        Self(UnsafeCell::new(RustTxQueue::new()))
    }

    unsafe fn is_idle(&self) -> bool {
        let queue = &*self.0.get();
        queue.head.is_null() && queue.tail.is_null() && !queue.event_armed
    }

    /// Append a frame and reserve the sole scheduler event token if none is
    /// already queued. The caller must publish event 5 when this returns true.
    unsafe fn push_and_arm(&self, buffer: NonNull<u8>) -> bool {
        let queue = &mut *self.0.get();
        let next = buffer.as_ptr().add(ESF_QUEUE_LINK_OFFSET).cast::<*mut u8>();
        next.write(ptr::null_mut());
        if queue.tail.is_null() {
            queue.head = buffer.as_ptr();
        } else {
            queue
                .tail
                .add(ESF_QUEUE_LINK_OFFSET)
                .cast::<*mut u8>()
                .write(buffer.as_ptr());
        }
        queue.tail = buffer.as_ptr();
        if queue.event_armed {
            false
        } else {
            queue.event_armed = true;
            true
        }
    }

    /// Consume the scheduler event token and remove exactly one frame.
    unsafe fn pop_for_event(&self) -> Option<NonNull<u8>> {
        let queue = &mut *self.0.get();
        if !queue.event_armed {
            return None;
        }
        queue.event_armed = false;
        let buffer = NonNull::new(queue.head)?;
        let next = buffer.as_ptr().add(ESF_QUEUE_LINK_OFFSET).cast::<*mut u8>();
        queue.head = next.read();
        next.write(ptr::null_mut());
        if queue.head.is_null() {
            queue.tail = ptr::null_mut();
        }
        Some(buffer)
    }

    /// Reserve a continuation token when frames remain and no nested
    /// publication has already queued one.
    unsafe fn arm_continuation(&self) -> bool {
        let queue = &mut *self.0.get();
        if queue.head.is_null() || queue.event_armed {
            false
        } else {
            queue.event_armed = true;
            true
        }
    }

    unsafe fn disarm_after_rejected_post(&self) {
        (*self.0.get()).event_armed = false;
    }
}

#[cfg_attr(
    target_arch = "riscv32",
    link_section = ".critical.bss.wifi_strict.net80211_tx_queue"
)]
static RUST_TX_QUEUE: RustTxQueueCell = RustTxQueueCell::new();

unsafe extern "C" {
    static mut s_tx_cacheq: VendorTailQueue;
    static mut net80211_funcs: *mut usize;
    fn __real_ieee80211_post_hmac_tx(buffer: *mut u8) -> u32;
    fn ieee80211_classify(node: *mut u8, buffer: *mut u8) -> u32;
    fn __real_ieee80211_classify(node: *mut u8, buffer: *mut u8) -> u32;
    fn ieee80211_output_process();
    fn pp_post(kind: u32, argument: *mut c_void) -> i32;
    fn esf_buf_recycle(buffer: *mut c_void);
}

pub(crate) fn link_wrapper_active() -> bool {
    // Proven by the final-value ASSERT in esp32s31-rom-wrap-overrides.x.
    true
}

pub(crate) fn classification_link_wrapper_active() -> bool {
    let direct_link = ptr::eq(
        ieee80211_classify as *const (),
        __wrap_ieee80211_classify as *const (),
    );
    let table_link = unsafe {
        let table = ptr::addr_of!(net80211_funcs).read_volatile();
        !table.is_null()
            && table.add(NET80211_CLASSIFY_CALLBACK_SLOT).read_volatile()
                == __wrap_ieee80211_classify as *const () as usize
    };
    direct_link && table_link
}

/// Replace the ROM consumer's classification callback in the Rust-owned
/// net80211 function table after cold initialization.
///
/// ESP32-S31 ROM output code calls slot `0x24`, not the public symbol. GNU
/// wrapping remains required for direct archive calls, while this explicit
/// adoption closes the ROM-indirect path.
pub(crate) unsafe fn adopt_classification_callback() -> bool {
    let table = ptr::addr_of!(net80211_funcs).read_volatile();
    if table.is_null() {
        return false;
    }
    let slot = table.add(NET80211_CLASSIFY_CALLBACK_SLOT);
    let current = slot.read_volatile();
    let vendor = __real_ieee80211_classify as *const () as usize;
    let replacement = __wrap_ieee80211_classify as *const () as usize;
    if current != vendor && current != replacement {
        return false;
    }
    slot.write_volatile(replacement);
    slot.read_volatile() == replacement
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

pub(crate) unsafe fn rust_mailbox_empty() -> bool {
    RUST_TX_QUEUE.is_idle()
}

/// Present at most one Rust-owned frame to the remaining vendor output stage.
///
/// The compatibility function still performs node lookup, classification,
/// encapsulation, CCMP selection, and hardware submission. Its input list is
/// constrained to one element, so its stock drain loop cannot consume an
/// unbounded batch. A follow-up event is posted only when Rust still owns
/// another frame.
pub(crate) unsafe fn dispatch_one() -> Result<(), Net80211TxError> {
    if !vendor_mailbox_empty() {
        return Err(Net80211TxError::VendorMailboxBusy);
    }
    if !crate::net80211_state::vendor_pending_tx_empty() {
        return Err(Net80211TxError::VendorPendingFrame);
    }
    let buffer = RUST_TX_QUEUE
        .pop_for_event()
        .ok_or(Net80211TxError::RustMailboxEmpty)?;

    let queue = ptr::addr_of_mut!(s_tx_cacheq);
    let next = buffer.as_ptr().add(ESF_QUEUE_LINK_OFFSET).cast::<*mut u8>();
    next.write(ptr::null_mut());
    (*queue).head = buffer.as_ptr();
    (*queue).tail_slot = next;

    ieee80211_output_process();
    if !vendor_mailbox_empty() {
        return Err(Net80211TxError::VendorMailboxRetainedFrame);
    }
    if !crate::net80211_state::vendor_pending_tx_empty() {
        return Err(Net80211TxError::VendorPendingFrame);
    }
    if RUST_TX_QUEUE.arm_continuation() && pp_post(NET80211_TX_EVENT, ptr::null_mut()) != 0 {
        RUST_TX_QUEUE.disarm_after_rejected_post();
        return Err(Net80211TxError::ContinuationPostRejected);
    }
    Ok(())
}

unsafe fn mark_fixed_per_packet_rate(buffer: *mut u8) {
    let descriptor = buffer.add(ESF_DESCRIPTOR_OFFSET).cast::<*mut u8>().read();
    if !descriptor.is_null() {
        let flags = descriptor.cast::<u32>();
        flags.write(flags.read() | TX_DESCRIPTOR_FIXED_RATE_FLAG);
    }
}

unsafe fn ordinary_ethernet_header(buffer: *mut u8) -> Option<(*mut u8, *mut u8, usize)> {
    let storage = NonNull::new(buffer.add(ESF_DATA_OFFSET).cast::<*mut u8>().read())?;
    let data = NonNull::new(
        storage
            .as_ptr()
            .add(ESF_DATA_OFFSET)
            .cast::<*mut u8>()
            .read(),
    )?;
    let prefixed =
        buffer.add(ESF_PREFIX_FLAGS_OFFSET).cast::<u16>().read() & ESF_PREFIX_PRESENT != 0;
    let ethernet = data.as_ptr().add(if prefixed { 8 } else { 0 });
    let length = usize::from(buffer.add(0x14).cast::<u16>().read())
        + usize::from(buffer.add(0x16).cast::<u16>().read());
    Some((data.as_ptr(), ethernet, length))
}

unsafe fn fixed_rate_protocol(
    node: *mut u8,
    data: *const u8,
    length: usize,
    protocol: u16,
    raw: bool,
) -> bool {
    let sta_arp = protocol == crate::net80211_classify::ETHER_TYPE_ARP
        && node.add(NODE_SPECIAL_CLASSIFIER_OFFSET).read() == 0
        && crate::net80211_state::station_interface().is_some_and(|interface| {
            node.add(NODE_INTERFACE_OFFSET).cast::<*mut u8>().read() == interface.as_ptr()
        });
    let udp_ports = if protocol == crate::net80211_classify::ETHER_TYPE_IPV4
        && !raw
        && node.add(NODE_SPECIAL_CLASSIFIER_OFFSET).read() == 0
        && length >= 38
        && data.add(23).read() == 17
    {
        Some((
            u16::from_be(data.add(34).cast::<u16>().read_unaligned()),
            u16::from_be(data.add(36).cast::<u16>().read_unaligned()),
        ))
    } else {
        None
    };
    crate::net80211_classify::uses_fixed_per_packet_rate(protocol, sta_arp, udp_ports)
}

unsafe fn classified_user_priority(
    network: *const u8,
    length: usize,
    network_offset: usize,
    protocol: u16,
) -> u32 {
    let ipv4_tos = (protocol == crate::net80211_classify::ETHER_TYPE_IPV4
        && length >= network_offset + 2)
        .then(|| network.add(1).read());
    let ipv6_prefix = (protocol == crate::net80211_classify::ETHER_TYPE_IPV6
        && length >= network_offset + 4)
        .then(|| u32::from_be(network.cast::<u32>().read_unaligned()));
    crate::net80211_classify::user_priority(protocol, ipv4_tos, ipv6_prefix)
}

unsafe fn apply_wmm_admission(node: *const u8, priority: u32) -> u32 {
    let mut admission_required = [false; 3];
    let mut access_category = 0;
    while access_category < admission_required.len() {
        admission_required[access_category] = node
            .add(NODE_WMM_ADMISSION_BASE + access_category * NODE_WMM_ADMISSION_STRIDE)
            .read()
            != 0;
        access_category += 1;
    }
    crate::net80211_classify::apply_wmm_admission(priority, admission_required)
}

/// Finite Rust port of the ordinary STA/AP classifier from the pinned
/// `libnet80211.a[ieee80211_output.o]`.
///
/// The stock function can revisit its WMM admission-control state machine.
/// This replacement expresses the monotonic four-state graph with an explicit
/// bound and reproduces the fixed-rate descriptor bit directly instead of
/// calling through the PP/TRC library.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __wrap_ieee80211_classify(node: *mut u8, buffer: *mut u8) -> u32 {
    if !crate::critical::strict_wifi_hart_armed() {
        return __real_ieee80211_classify(node, buffer);
    }
    if !crate::critical::on_strict_wifi_hart()
        || !crate::context::in_radio_context()
        || !crate::net80211_state::ordinary_sta_ap_profile()
        || node.is_null()
        || buffer.is_null()
    {
        return 7;
    }
    let Some((data, ethernet, length)) = ordinary_ethernet_header(buffer) else {
        return 7;
    };
    let descriptor = buffer.add(ESF_DESCRIPTOR_OFFSET).cast::<*mut u8>().read();
    let Some(descriptor) = NonNull::new(descriptor) else {
        return 7;
    };
    let descriptor_flags = descriptor.as_ptr().cast::<u32>().read();
    let raw = descriptor_flags & TX_DESCRIPTOR_RAW_FLAG != 0;
    let (protocol_at, required_length, network_offset) = if raw {
        (data.add(20), 22, 22)
    } else {
        let prefix = ethernet.offset_from(data) as usize;
        (ethernet.add(12), prefix + 14, 14)
    };
    if length < required_length {
        return 7;
    }
    let protocol = protocol_at.cast::<u16>().read_unaligned();
    if fixed_rate_protocol(node, data, length, protocol, raw) {
        mark_fixed_per_packet_rate(buffer);
        return 7;
    }

    let priority =
        classified_user_priority(data.add(network_offset), length, network_offset, protocol);
    if ethernet.read() & 1 != 0 || node.add(NODE_FLAGS_OFFSET).cast::<u32>().read() & 0x2 == 0 {
        7
    } else {
        apply_wmm_admission(node, priority)
    }
}

/// Replace the pinned cached/NAN selector with the strict ordinary STA/AP
/// publication path.
///
/// Publication and consumption execute as run-to-completion actions on the
/// one strict Wi-Fi hart, so no task can observe the intrusive link stores.
/// Interrupt handlers do not submit net80211 ESF objects.
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
    if !crate::critical::on_strict_wifi_hart()
        || !crate::context::in_radio_context()
        || !crate::net80211_state::ordinary_sta_ap_profile()
        || !crate::channel_switch::is_at_home_channel()
    {
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

    let publish_event = RUST_TX_QUEUE.push_and_arm(buffer);
    if !publish_event || pp_post(NET80211_TX_EVENT, ptr::null_mut()) == 0 {
        0
    } else {
        RUST_TX_QUEUE.disarm_after_rejected_post();
        // Match the pinned ABI: the frame is already queue-owned when event
        // publication fails. The caller must not recycle or retry it.
        POST_REJECTED
    }
}

const _: () = assert!(core::mem::size_of::<VendorTailQueue>() == 8);
