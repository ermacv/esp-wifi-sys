//! Strict publication boundary for the net80211 transmit queue.
//!
//! The pinned `ieee80211_post_hmac_tx` body has two independent jobs:
//! selecting the optional cached/NAN path from `g_ic`, and appending an ESF
//! object to `s_tx_cacheq` before posting PP event 5. Strict handoff already
//! proves that cached TX and NAN/mesh operation are unavailable. This module
//! replaces both the shared input list and the ordinary STA/AP event-5
//! consumer with bounded Rust code.

use core::{
    cell::UnsafeCell,
    ffi::c_void,
    ptr::{self, NonNull},
};

const ESF_QUEUE_LINK_OFFSET: usize = 0x30;
const ESF_DESCRIPTOR_OFFSET: usize = 0x34;
const ESF_STORAGE_OFFSET: usize = 0x04;
const ESF_HEADER_LENGTH_OFFSET: usize = 0x14;
const ESF_REMAINING_LENGTH_OFFSET: usize = 0x16;
const ESF_VENDOR_SEQUENCE_OFFSET: usize = 0x1c;
const ESF_PAYLOAD_LENGTH_OFFSET: usize = 0x22;
const TX_DESCRIPTOR_CONTROL_OFFSET: usize = 0x10;
const TX_DESCRIPTOR_INTERFACE_SHIFT: u32 = 18;
const TX_DESCRIPTOR_INTERFACE_MASK: u32 = 0x3;
const TX_DESCRIPTOR_RAW_FLAG: u32 = 0x0000_8000;
const TX_DESCRIPTOR_FIXED_RATE_FLAG: u32 = 0x0200_0000;
const TX_DESCRIPTOR_EAPOL_FLAG: u32 = 0x0000_0004;
const TX_DESCRIPTOR_PROTECTED_FLAG: u32 = 0x0000_0001;
const TX_DESCRIPTOR_MULTICAST_FLAG: u32 = 0x0000_0002;
const TX_DESCRIPTOR_PRIORITY_OFFSET: usize = 0x04;
const TX_DESCRIPTOR_CALLBACK_MASK_OFFSET: usize = 0x14;
const TX_DESCRIPTOR_OPAQUE_OFFSET: usize = 0x2f;
const TX_DESCRIPTOR_BYTE_0X32_OFFSET: usize = 0x32;
const ESF_DATA_OFFSET: usize = 0x04;
const ESF_PREFIX_FLAGS_OFFSET: usize = 0x24;
const ESF_PREFIX_PRESENT: u16 = 0x2000;
const NODE_INTERFACE_OFFSET: usize = 0x00;
const NODE_BSSID_OFFSET: usize = 0x04;
const NODE_FLAGS_OFFSET: usize = 0x0c;
const NODE_SECURITY_STATE_OFFSET: usize = 0x24;
const NODE_SEQUENCE_BASE: usize = 0xae;
const NODE_MODE_OFFSET: usize = 0x138;
const NODE_WMM_ADMISSION_BASE: usize = 0x89;
const NODE_WMM_ADMISSION_STRIDE: usize = 7;
const NODE_WMM_NO_ACK_BASE: usize = 0x8e;
const NODE_SPECIAL_CLASSIFIER_OFFSET: usize = 0x2f4;
const NET80211_CLASSIFY_CALLBACK_SLOT: usize = 0x24 / core::mem::size_of::<usize>();
const INTERFACE_SECURITY_FLAGS_OFFSET: usize = 0xa4;
const INTERFACE_SECURITY_ENABLED: u32 = 0x10;
const NODE_ENCRYPT_DATA_FLAG: u32 = 0x01;
const NODE_POWER_SAVE_FLAG: u32 = 0x10;
const ETHER_TYPE_EAPOL: u16 = 0x888e;
const ETHER_TYPE_WAPI: u16 = 0x88b4;

const POST_REJECTED: u32 = 0x3012;
const INVALID_STRICT_FRAME: u32 = 0x3002;
const NET80211_TX_EVENT: u32 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Net80211TxError {
    RustMailboxEmpty,
    VendorPendingFrame,
    InvalidOrdinaryFrame,
    UnsupportedPowerSave,
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
    fn ieee80211_search_node(interface: u32, frame: *const u8, error: *mut u32) -> *mut u8;
    fn ieee80211_crypto_encap(node: *mut u8, buffer: *mut u8) -> *mut u8;
    fn ieee80211_align_eb(buffer: *mut u8, reserve: u32);
    fn ieee80211_set_tx_desc(
        node: *mut u8,
        buffer: *mut u8,
        priority: u32,
        requested_flags: u32,
        unused: u32,
    );
    fn ieee80211_set_tx_pti(buffer: *mut u8, packet_type: u32);
    fn ppTxPkt(buffer: *mut u8, ownership: u32);
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

unsafe fn read_mac(source: *const u8) -> [u8; 6] {
    let mut address = [0_u8; 6];
    ptr::copy_nonoverlapping(source, address.as_mut_ptr(), address.len());
    address
}

unsafe fn recycle_invalid(buffer: NonNull<u8>, error: Net80211TxError) -> Net80211TxError {
    esf_buf_recycle(buffer.as_ptr().cast());
    error
}

unsafe fn arm_next_event() -> Result<(), Net80211TxError> {
    if RUST_TX_QUEUE.arm_continuation() && pp_post(NET80211_TX_EVENT, ptr::null_mut()) != 0 {
        RUST_TX_QUEUE.disarm_after_rejected_post();
        Err(Net80211TxError::ContinuationPostRejected)
    } else {
        Ok(())
    }
}

/// Encapsulate one validated Ethernet ESF as an ordinary STA/AP MPDU.
///
/// This is the finite non-mesh, non-NAN, non-power-save branch recovered from
/// `libnet80211.a[ieee80211_output.o]::ieee80211_encap_esfbuf`. Rust-owned
/// ADDBA state remains downstream at `ppMapTxQueue`, so the vendor BA request
/// and per-node aggregation-record branches are intentionally absent.
unsafe fn encapsulate_ordinary(
    node: NonNull<u8>,
    buffer: NonNull<u8>,
    interface_selector: u32,
) -> Result<(), Net80211TxError> {
    use crate::net80211_state::Net80211InterfaceRole;

    let buffer = buffer.as_ptr();
    let node = node.as_ptr();
    let descriptor = NonNull::new(buffer.add(ESF_DESCRIPTOR_OFFSET).cast::<*mut u8>().read())
        .ok_or(Net80211TxError::InvalidOrdinaryFrame)?;
    let storage = NonNull::new(buffer.add(ESF_STORAGE_OFFSET).cast::<*mut u8>().read())
        .ok_or(Net80211TxError::InvalidOrdinaryFrame)?;
    let data_slot = storage.as_ptr().add(ESF_DATA_OFFSET).cast::<*mut u8>();
    let data = NonNull::new(data_slot.read()).ok_or(Net80211TxError::InvalidOrdinaryFrame)?;
    let interface = NonNull::new(node.add(NODE_INTERFACE_OFFSET).cast::<*mut u8>().read())
        .ok_or(Net80211TxError::InvalidOrdinaryFrame)?;
    let role = crate::net80211_state::role_for_interface(interface.as_ptr())
        .ok_or(Net80211TxError::InvalidOrdinaryFrame)?;
    let expected_role = if interface_selector == 0 {
        Net80211InterfaceRole::Station
    } else {
        Net80211InterfaceRole::AccessPoint
    };
    let expected_mode = if matches!(role, Net80211InterfaceRole::Station) {
        0
    } else {
        1
    };
    if role != expected_role
        || interface
            .as_ptr()
            .add(NODE_MODE_OFFSET)
            .cast::<u32>()
            .read()
            != expected_mode
        || buffer.add(ESF_HEADER_LENGTH_OFFSET).cast::<u16>().read() != 0
        || buffer.add(ESF_PREFIX_FLAGS_OFFSET).cast::<u16>().read() & (ESF_PREFIX_PRESENT | 0x8000)
            != 0
        || descriptor.as_ptr().cast::<u32>().read() & TX_DESCRIPTOR_RAW_FLAG != 0
    {
        return Err(Net80211TxError::InvalidOrdinaryFrame);
    }
    let remaining_slot = buffer.add(ESF_REMAINING_LENGTH_OFFSET).cast::<u16>();
    let remaining = remaining_slot.read();
    if usize::from(remaining) < crate::net80211_encap::ETHERNET_HEADER_LEN {
        return Err(Net80211TxError::InvalidOrdinaryFrame);
    }

    let ethernet = {
        let mut header = [0_u8; crate::net80211_encap::ETHERNET_HEADER_LEN];
        ptr::copy_nonoverlapping(data.as_ptr(), header.as_mut_ptr(), header.len());
        header
    };
    let protocol = u16::from_be_bytes([ethernet[12], ethernet[13]]);
    if protocol == ETHER_TYPE_WAPI {
        return Err(Net80211TxError::InvalidOrdinaryFrame);
    }
    let descriptor_priority = descriptor
        .as_ptr()
        .add(TX_DESCRIPTOR_PRIORITY_OFFSET)
        .cast::<u32>()
        .read()
        & 0x0f;
    let priority = if descriptor_priority == 0x0f {
        ieee80211_classify(node, buffer)
    } else {
        descriptor_priority
    };
    if priority > 7 {
        return Err(Net80211TxError::InvalidOrdinaryFrame);
    }
    let queue_class = crate::net80211_encap::queue_class(priority as u8)
        .ok_or(Net80211TxError::InvalidOrdinaryFrame)?;
    let node_flags = node.add(NODE_FLAGS_OFFSET).cast::<u32>().read();
    if matches!(role, Net80211InterfaceRole::AccessPoint) && node_flags & NODE_POWER_SAVE_FLAG != 0
    {
        return Err(Net80211TxError::UnsupportedPowerSave);
    }
    let interface_mac =
        crate::net80211_state::interface_mac(role).ok_or(Net80211TxError::InvalidOrdinaryFrame)?;
    let bssid = read_mac(node.add(NODE_BSSID_OFFSET));
    let no_ack_policy = node
        .add(NODE_WMM_NO_ACK_BASE + usize::from(queue_class) * NODE_WMM_ADMISSION_STRIDE)
        .read()
        != 0;
    let mut plan = crate::net80211_encap::plan_data_encapsulation(
        role,
        bssid,
        interface_mac,
        ethernet,
        priority as u8,
        node_flags & 0x02 != 0,
        no_ack_policy,
    )
    .ok_or(Net80211TxError::InvalidOrdinaryFrame)?;
    let new_remaining = remaining
        .checked_sub(crate::net80211_encap::ETHERNET_HEADER_LEN as u16)
        .and_then(|length| length.checked_add(crate::net80211_encap::LLC_SNAP_HEADER_LEN as u16))
        .ok_or(Net80211TxError::InvalidOrdinaryFrame)?;
    let llc_data = data
        .as_ptr()
        .add(crate::net80211_encap::ETHERNET_HEADER_LEN)
        .sub(crate::net80211_encap::LLC_SNAP_HEADER_LEN);

    // Every fallible structural check is complete. From here ownership stays
    // with this adapter until `ppTxPkt` accepts the fully prepared frame.
    let descriptor_flags = descriptor.as_ptr().cast::<u32>();
    let mut flags = descriptor_flags.read();
    if protocol == ETHER_TYPE_EAPOL {
        flags |= TX_DESCRIPTOR_EAPOL_FLAG;
    }
    if plan.descriptor_multicast {
        flags |= TX_DESCRIPTOR_MULTICAST_FLAG;
    }
    descriptor_flags.write(flags);
    let opaque = descriptor.as_ptr().add(TX_DESCRIPTOR_OPAQUE_OFFSET);
    opaque.write((opaque.read() & 0x87) | 0x08);
    let byte_0x32 = descriptor.as_ptr().add(TX_DESCRIPTOR_BYTE_0X32_OFFSET);
    byte_0x32.write(byte_0x32.read() & !0x04);
    let priority_word = descriptor
        .as_ptr()
        .add(TX_DESCRIPTOR_PRIORITY_OFFSET)
        .cast::<u32>();
    priority_word.write((priority_word.read() & !0x0f) | priority);
    let layout = buffer.add(ESF_PREFIX_FLAGS_OFFSET).cast::<u16>();
    layout.write(layout.read() & 0x7fff);
    buffer
        .add(ESF_HEADER_LENGTH_OFFSET)
        .cast::<u16>()
        .write(u16::from(plan.header_len));
    data_slot.write(llc_data);
    remaining_slot.write(new_remaining);
    ptr::copy_nonoverlapping(plan.llc_snap.as_ptr(), llc_data, plan.llc_snap.len());
    buffer
        .add(ESF_PAYLOAD_LENGTH_OFFSET)
        .cast::<u16>()
        .write(new_remaining);

    let encrypt = interface
        .as_ptr()
        .add(INTERFACE_SECURITY_FLAGS_OFFSET)
        .cast::<u32>()
        .read()
        & INTERFACE_SECURITY_ENABLED
        != 0
        && (node_flags & NODE_ENCRYPT_DATA_FLAG != 0
            || (node.add(NODE_SECURITY_STATE_OFFSET).read() == 1
                && flags & TX_DESCRIPTOR_EAPOL_FLAG != 0));
    let key = if encrypt {
        ieee80211_crypto_encap(node, buffer)
    } else {
        ptr::null_mut()
    };

    ieee80211_align_eb(buffer, u32::from(plan.header_len));
    let aligned_storage = buffer.add(ESF_STORAGE_OFFSET).cast::<*mut u8>().read();
    let header = aligned_storage
        .add(ESF_DATA_OFFSET)
        .cast::<*mut u8>()
        .read();
    if !key.is_null() {
        plan.header[1] |= 0x40;
        descriptor_flags.write(descriptor_flags.read() | TX_DESCRIPTOR_PROTECTED_FLAG);
        let mut hardware_index = key.read();
        if matches!(role, Net80211InterfaceRole::AccessPoint) {
            hardware_index |= 0x40;
        }
        descriptor
            .as_ptr()
            .add(TX_DESCRIPTOR_CONTROL_OFFSET)
            .write(hardware_index);
        let cipher = key.add(0xa0).cast::<*mut u8>().read();
        let cipher_type = cipher.cast::<u32>().read() & 0x0f;
        let security = descriptor
            .as_ptr()
            .add(TX_DESCRIPTOR_CONTROL_OFFSET)
            .cast::<u32>();
        security.write((security.read() & 0xffff_f0ff) | (cipher_type << 8));
    }
    ptr::copy_nonoverlapping(plan.header.as_ptr(), header, usize::from(plan.header_len));

    let sequence_slot = node
        .add(NODE_SEQUENCE_BASE + usize::from(priority as u8) * 2)
        .cast::<u16>();
    let sequence = crate::net80211_encap::advance_sequence(sequence_slot.read());
    sequence_slot.write(sequence.next_counter);
    layout.write((layout.read() & 0xf000) | sequence.sequence_number);
    buffer
        .add(ESF_VENDOR_SEQUENCE_OFFSET)
        .cast::<u16>()
        .write(sequence.next_counter.wrapping_sub(1));
    header
        .add(22)
        .cast::<u16>()
        .write_unaligned(sequence.sequence_control);

    ieee80211_set_tx_desc(node, buffer, priority, 8, 0);
    ieee80211_set_tx_pti(buffer, u32::from(plan.packet_type));
    descriptor
        .as_ptr()
        .add(TX_DESCRIPTOR_CALLBACK_MASK_OFFSET)
        .cast::<u32>()
        .write(crate::net80211_encap::completion_callback_mask(
            role, protocol,
        ));
    ppTxPkt(buffer, 1);
    Ok(())
}

/// Consume at most one Rust-owned ordinary STA/AP Ethernet frame.
///
/// Node lookup is role-bounded, encapsulation is finite, and the completed
/// MPDU enters the existing `ppTxPkt` preparation boundary directly. The
/// vendor mailbox, its lock callbacks, `g_ic`, cached-TX/AMSDU, power-save,
/// NAN, off-channel and vendor ADDBA paths are not reachable.
pub(crate) unsafe fn dispatch_one() -> Result<(), Net80211TxError> {
    if !crate::net80211_state::vendor_pending_tx_empty() {
        return Err(Net80211TxError::VendorPendingFrame);
    }
    let buffer = RUST_TX_QUEUE
        .pop_for_event()
        .ok_or(Net80211TxError::RustMailboxEmpty)?;
    let descriptor = NonNull::new(
        buffer
            .as_ptr()
            .add(ESF_DESCRIPTOR_OFFSET)
            .cast::<*mut u8>()
            .read(),
    )
    .ok_or_else(|| recycle_invalid(buffer, Net80211TxError::InvalidOrdinaryFrame))?;
    let control = descriptor
        .as_ptr()
        .add(TX_DESCRIPTOR_CONTROL_OFFSET)
        .cast::<u32>()
        .read();
    let interface = (control >> TX_DESCRIPTOR_INTERFACE_SHIFT) & TX_DESCRIPTOR_INTERFACE_MASK;
    if interface > 1 {
        return Err(recycle_invalid(
            buffer,
            Net80211TxError::InvalidOrdinaryFrame,
        ));
    }
    let Some((_, ethernet, _)) = ordinary_ethernet_header(buffer.as_ptr()) else {
        return Err(recycle_invalid(
            buffer,
            Net80211TxError::InvalidOrdinaryFrame,
        ));
    };
    let mut search_error = 0_u32;
    let node = NonNull::new(ieee80211_search_node(
        interface,
        ethernet,
        &mut search_error,
    ));
    let result = if let Some(node) = node {
        encapsulate_ordinary(node, buffer, interface)
    } else {
        esf_buf_recycle(buffer.as_ptr().cast());
        Ok(())
    };
    if result == Err(Net80211TxError::UnsupportedPowerSave) {
        // A station may enter power save between network-stack publication
        // and this serialized event. That is a per-frame delivery outcome,
        // not corruption of the radio owner. The vendor solution would move
        // the ESF into its dynamic PS queue; until the equivalent Rust-owned
        // async queue is connected, release this one fixed-pool object and
        // keep servicing unrelated peers. No retry, wait, callback, or
        // polling loop is entered here.
        esf_buf_recycle(buffer.as_ptr().cast());
        crate::ap_power_save::record_cancelled_transmit();
        return arm_next_event();
    }
    if let Err(error) = result {
        esf_buf_recycle(buffer.as_ptr().cast());
        return Err(error);
    }
    arm_next_event()
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
