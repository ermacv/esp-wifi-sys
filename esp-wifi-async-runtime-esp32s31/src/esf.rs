//! Allocation-free strict replacement for the pinned S31 ESF buffer ABI.

use core::{
    cell::UnsafeCell,
    ffi::c_void,
    mem, ptr,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::diagnostics::BlockingCall;

const DESCRIPTOR_COUNT: usize = 11;
const DESCRIPTOR_SIZE: usize = 0x14;
const ESF_HEADER_SIZE: usize = 0x90;
const MANAGEMENT_PAYLOAD_CAPACITY: usize = 1600;
const MANAGEMENT_SLOT_SIZE: usize = ESF_HEADER_SIZE + MANAGEMENT_PAYLOAD_CAPACITY;
// Active 2.4-GHz scanning can retain one management frame for each of the
// thirteen configured channels until TX completion catches up. Keep those
// frames plus bounded authentication/association headroom entirely in BSS.
const MANAGEMENT_SLOT_CAPACITY: usize = 16;
const MANAGEMENT_SLOT_MASK: usize = (1 << MANAGEMENT_SLOT_CAPACITY) - 1;

// `wDev_IndicateFrame` and `wDev_IndicateBeaconMemoryFrame` request ESF kind
// 7 for received frames larger than the vendor's 500-byte small-frame pool.
// The original allocator serves kind 7 from the heap. Match the configured
// static RX bound with fixed Rust-owned storage instead.
const LARGE_RX_PAYLOAD_CAPACITY: usize = 1700;
const LARGE_RX_SLOT_SIZE: usize = ESF_HEADER_SIZE + LARGE_RX_PAYLOAD_CAPACITY;
const LARGE_RX_SLOT_CAPACITY: usize = 16;
const LARGE_RX_SLOT_MASK: usize = (1 << LARGE_RX_SLOT_CAPACITY) - 1;

const ESF_BUFFER_DESCRIPTOR_OFFSET: usize = 0x3c;
const ESF_TX_DESCRIPTOR_OFFSET: usize = 0x48;
const ESF_BUFFER_POINTER_OFFSET: usize = 0x10;
const ESF_BUFFER_END_OFFSET: usize = 0x40;
const ESF_TYPE_OFFSET: usize = 0x1a;
const ESF_LENGTH_OFFSET: usize = 0x16;
const ESF_FREE_NEXT_OFFSET: usize = 0x30;
const ESF_TX_DESCRIPTOR_POINTER_OFFSET: usize = 0x34;

#[repr(C, align(4))]
struct ManagementSlot(UnsafeCell<[u8; MANAGEMENT_SLOT_SIZE]>);

impl ManagementSlot {
    const fn new() -> Self {
        Self(UnsafeCell::new([0; MANAGEMENT_SLOT_SIZE]))
    }
}

unsafe impl Sync for ManagementSlot {}

#[repr(C, align(4))]
struct LargeRxSlot(UnsafeCell<[u8; LARGE_RX_SLOT_SIZE]>);

impl LargeRxSlot {
    const fn new() -> Self {
        Self(UnsafeCell::new([0; LARGE_RX_SLOT_SIZE]))
    }
}

unsafe impl Sync for LargeRxSlot {}

static MANAGEMENT_SLOTS: [ManagementSlot; MANAGEMENT_SLOT_CAPACITY] =
    [const { ManagementSlot::new() }; MANAGEMENT_SLOT_CAPACITY];
static CLAIMED_MANAGEMENT_SLOTS: AtomicUsize = AtomicUsize::new(0);
static LARGE_RX_SLOTS: [LargeRxSlot; LARGE_RX_SLOT_CAPACITY] =
    [const { LargeRxSlot::new() }; LARGE_RX_SLOT_CAPACITY];
static CLAIMED_LARGE_RX_SLOTS: AtomicUsize = AtomicUsize::new(0);
static REJECTED_ESF_OPERATIONS: AtomicUsize = AtomicUsize::new(0);
const NO_PREARM_HART: usize = usize::MAX;
static PREARM_MANAGEMENT_HART: AtomicUsize = AtomicUsize::new(NO_PREARM_HART);

unsafe extern "C" {
    static mut g_eb_list_desc: u8;
    fn esf_buf_alloc(source: *const u8, kind: u32, length: u32) -> *mut u8;
    fn __real_esf_buf_alloc(source: *const u8, kind: u32, length: u32) -> *mut u8;
    fn esf_buf_recycle(frame: *mut c_void);
    fn __real_esf_buf_recycle(frame: *mut c_void);
}

pub(crate) fn link_wrappers_active() -> bool {
    ptr::eq(
        esf_buf_alloc as *const (),
        __wrap_esf_buf_alloc as *const (),
    ) && ptr::eq(
        esf_buf_recycle as *const (),
        __wrap_esf_buf_recycle as *const (),
    )
}

/// Route connection-time management frames into the fixed Rust pool before
/// the general runtime heap/core-stall gates are armed.
pub(crate) fn enable_prearm_management_pool(expected_hart: usize) {
    PREARM_MANAGEMENT_HART.store(expected_hart, Ordering::Release);
}

/// Route management allocations through the fixed SRAM pool before the
/// strict runtime is armed.
///
/// WPA2 AP startup constructs a larger beacon than the open-AP path. The
/// vendor pre-start ESF pool can reject that frame, so the composition root
/// must enable the same bounded pool used during strict association before it
/// applies the AP configuration.
///
/// Returns `false` when the required final-link ESF wrappers are absent.
pub fn enable_prestart_management_pool() -> bool {
    if !link_wrappers_active() {
        return false;
    }
    enable_prearm_management_pool(crate::critical::current_hart());
    true
}

fn prearm_management_pool_enabled() -> bool {
    PREARM_MANAGEMENT_HART.load(Ordering::Acquire) != NO_PREARM_HART
}

fn on_prearm_management_hart() -> bool {
    crate::critical::current_hart() == PREARM_MANAGEMENT_HART.load(Ordering::Acquire)
}

fn reject(kind: u32, argument: usize) {
    REJECTED_ESF_OPERATIONS.fetch_add(1, Ordering::Relaxed);
    crate::adapter::blocking_probe().record(BlockingCall::EsfBufferRejected, kind, argument);
}

const fn is_vendor_static_kind(kind: u32) -> bool {
    matches!(kind, 1 | 5 | 6 | 8 | 9 | 10)
}

const fn is_management_kind(kind: u32) -> bool {
    matches!(kind, 2..=4)
}

unsafe fn descriptor(kind: u32) -> *mut u8 {
    ptr::addr_of_mut!(g_eb_list_desc).add(kind as usize * DESCRIPTOR_SIZE)
}

unsafe fn initialize_frame(
    frame: *mut u8,
    kind: u32,
    source: *const u8,
    length: usize,
    payload_capacity: usize,
) -> Option<*mut u8> {
    if kind as usize >= DESCRIPTOR_COUNT || length > u16::MAX as usize {
        return None;
    }
    let list = descriptor(kind);
    let prefix = list.add(0x0c).read() as usize;
    if prefix.checked_add(length)? > payload_capacity {
        return None;
    }

    frame.write_bytes(0, ESF_HEADER_SIZE);
    let buffer_descriptor = frame.add(ESF_BUFFER_DESCRIPTOR_OFFSET);
    let tx_descriptor = frame.add(ESF_TX_DESCRIPTOR_OFFSET);
    let payload = frame.add(ESF_HEADER_SIZE);
    let data = payload.add(prefix);

    frame.add(0x04).cast::<*mut u8>().write(buffer_descriptor);
    frame.add(0x08).cast::<*mut u8>().write(buffer_descriptor);
    frame.add(0x0c).cast::<u16>().write(1);
    frame
        .add(ESF_BUFFER_POINTER_OFFSET)
        .cast::<*mut u8>()
        .write(payload);
    frame
        .add(ESF_LENGTH_OFFSET)
        .cast::<u16>()
        .write(length as u16);
    frame.add(ESF_TYPE_OFFSET).write(kind as u8);
    frame
        .add(ESF_TX_DESCRIPTOR_POINTER_OFFSET)
        .cast::<*mut u8>()
        .write(tx_descriptor);
    frame
        .add(ESF_BUFFER_END_OFFSET)
        .cast::<*mut u8>()
        .write(data);

    payload.write_bytes(0, prefix);
    if !source.is_null() {
        ptr::copy_nonoverlapping(source, data, length);
    }

    let packet_length = (prefix + length) as u32;
    let buffer_flags = buffer_descriptor.cast::<u32>().read() & 0xffff_c000;
    buffer_descriptor
        .cast::<u32>()
        .write(buffer_flags | packet_length);
    buffer_descriptor.add(4).cast::<*mut u8>().write(data);

    let descriptor_flags = list.add(4).cast::<u32>().read();
    tx_descriptor
        .cast::<u32>()
        .write(tx_descriptor.cast::<u32>().read() | descriptor_flags);
    tx_descriptor
        .add(4)
        .cast::<u32>()
        .write(tx_descriptor.add(4).cast::<u32>().read() | 0x0f);
    Some(frame)
}

fn claim_management_slot() -> Option<usize> {
    let claimed = CLAIMED_MANAGEMENT_SLOTS.load(Ordering::Acquire);
    let free = !claimed & MANAGEMENT_SLOT_MASK;
    if free == 0 {
        return None;
    }
    let index = free.trailing_zeros() as usize;
    let bit = 1_usize << index;
    CLAIMED_MANAGEMENT_SLOTS
        .compare_exchange(claimed, claimed | bit, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| index)
}

fn claim_large_rx_slot() -> Option<usize> {
    let claimed = CLAIMED_LARGE_RX_SLOTS.load(Ordering::Acquire);
    let free = !claimed & LARGE_RX_SLOT_MASK;
    if free == 0 {
        return None;
    }
    let index = free.trailing_zeros() as usize;
    let bit = 1_usize << index;
    CLAIMED_LARGE_RX_SLOTS
        .compare_exchange(claimed, claimed | bit, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| index)
}

fn management_slot_index(frame: *mut u8) -> Option<usize> {
    let base = ptr::addr_of!(MANAGEMENT_SLOTS) as usize;
    let address = frame as usize;
    let stride = mem::size_of::<ManagementSlot>();
    let offset = address.checked_sub(base)?;
    if offset % stride != 0 {
        return None;
    }
    let index = offset / stride;
    (index < MANAGEMENT_SLOT_CAPACITY).then_some(index)
}

fn large_rx_slot_index(frame: *mut u8) -> Option<usize> {
    let base = ptr::addr_of!(LARGE_RX_SLOTS) as usize;
    let address = frame as usize;
    let stride = mem::size_of::<LargeRxSlot>();
    let offset = address.checked_sub(base)?;
    if offset % stride != 0 {
        return None;
    }
    let index = offset / stride;
    (index < LARGE_RX_SLOT_CAPACITY).then_some(index)
}

/// Return whether `frame` belongs to one of the fixed pools handled by the
/// strict recycler. The caller must hold a live ESF object.
pub(crate) unsafe fn is_strict_recyclable_frame(frame: *mut u8) -> bool {
    management_slot_index(frame).is_some()
        || large_rx_slot_index(frame).is_some()
        || is_vendor_static_kind(frame.add(ESF_TYPE_OFFSET).read() as u32)
}

unsafe fn allocate_management(source: *const u8, kind: u32, length: usize) -> Option<*mut u8> {
    let index = claim_management_slot()?;
    let frame = MANAGEMENT_SLOTS[index].0.get().cast::<u8>();
    if initialize_frame(frame, kind, source, length, MANAGEMENT_PAYLOAD_CAPACITY).is_none() {
        CLAIMED_MANAGEMENT_SLOTS.fetch_and(!(1_usize << index), Ordering::AcqRel);
        return None;
    }
    Some(frame)
}

unsafe fn allocate_large_rx(source: *const u8, length: usize) -> Option<*mut u8> {
    let index = claim_large_rx_slot()?;
    let frame = LARGE_RX_SLOTS[index].0.get().cast::<u8>();
    if initialize_frame(frame, 7, source, length, LARGE_RX_PAYLOAD_CAPACITY).is_none() {
        CLAIMED_LARGE_RX_SLOTS.fetch_and(!(1_usize << index), Ordering::AcqRel);
        return None;
    }
    Some(frame)
}

unsafe fn allocate_vendor_static(source: *const u8, kind: u32, length: usize) -> Option<*mut u8> {
    if length > u16::MAX as usize {
        return None;
    }
    let list = descriptor(kind);
    let interrupt_state = crate::critical::strict_wifi_int_disable();
    let frame = list.cast::<*mut u8>().read();
    if !frame.is_null() {
        list.cast::<*mut u8>()
            .write(frame.add(ESF_FREE_NEXT_OFFSET).cast::<*mut u8>().read());
        frame
            .add(ESF_FREE_NEXT_OFFSET)
            .cast::<*mut u8>()
            .write(ptr::null_mut());
    }
    crate::critical::strict_wifi_int_restore(interrupt_state);
    if frame.is_null() {
        return None;
    }

    // Strict buffers never carry a netstack ownership token. This keeps the
    // optional callback in `ieee80211_recycle_cache_eb` unreachable.
    frame.cast::<*mut c_void>().write(ptr::null_mut());
    let prefix = list.add(0x0c).read() as usize;
    frame
        .add(ESF_LENGTH_OFFSET)
        .cast::<u16>()
        .write(length as u16);
    let buffer_descriptor = frame.add(0x04).cast::<*mut u8>().read();
    if !buffer_descriptor.is_null() {
        let payload = frame
            .add(ESF_BUFFER_POINTER_OFFSET)
            .cast::<*mut u8>()
            .read();
        let data = payload.add(prefix);
        buffer_descriptor.add(4).cast::<*mut u8>().write(data);
        let packet_length = prefix.checked_add(length)? as u32;
        let flags = buffer_descriptor.cast::<u32>().read() & 0xffff_c000;
        buffer_descriptor
            .cast::<u32>()
            .write(flags | (packet_length & 0x3fff));
        if !source.is_null() {
            ptr::copy_nonoverlapping(source, data, length);
        }
    } else if !source.is_null() {
        recycle_vendor_static(frame, kind);
        return None;
    }

    let tx_descriptor = frame
        .add(ESF_TX_DESCRIPTOR_POINTER_OFFSET)
        .cast::<*mut u8>()
        .read();
    if tx_descriptor.is_null() {
        recycle_vendor_static(frame, kind);
        return None;
    }
    tx_descriptor
        .cast::<u32>()
        .write(tx_descriptor.cast::<u32>().read() | list.add(4).cast::<u32>().read());
    tx_descriptor
        .add(4)
        .cast::<u32>()
        .write(tx_descriptor.add(4).cast::<u32>().read() | 0x0f);
    Some(frame)
}

unsafe fn recycle_vendor_static(frame: *mut u8, kind: u32) {
    let tx_descriptor = frame
        .add(ESF_TX_DESCRIPTOR_POINTER_OFFSET)
        .cast::<*mut u8>()
        .read();
    if !tx_descriptor.is_null() {
        tx_descriptor.write_bytes(0, 0x48);
    }
    frame.add(0x24).cast::<u32>().write(0);
    frame.add(0x14).cast::<u16>().write(0);
    frame.add(0x22).cast::<u16>().write(0);
    frame.add(0x28).write(0);
    frame.add(0x38).cast::<u16>().write(0);
    frame.add(0x3a).write(0);

    let list = descriptor(kind);
    let interrupt_state = crate::critical::strict_wifi_int_disable();
    frame
        .add(ESF_FREE_NEXT_OFFSET)
        .cast::<*mut u8>()
        .write(list.cast::<*mut u8>().read());
    list.cast::<*mut u8>().write(frame);
    crate::critical::strict_wifi_int_restore(interrupt_state);
}

/// Final-link replacement for the vendor ESF allocator.
///
/// Before strict mode it delegates to the original initialization path. The
/// strict path uses only initialized vendor free lists or the Rust management
/// pool and returns null immediately on exhaustion.
///
/// # Safety
///
/// `source`, when non-null, must be valid for `length` readable bytes and must
/// not overlap the selected ESF payload. `kind` must follow the vendor ABI.
#[no_mangle]
pub unsafe extern "C" fn __wrap_esf_buf_alloc(
    source: *const u8,
    kind: u32,
    length: u32,
) -> *mut u8 {
    if !crate::critical::strict_wifi_hart_armed() {
        if prearm_management_pool_enabled() && is_management_kind(kind) {
            if !on_prearm_management_hart() {
                reject(kind, length as usize);
                return ptr::null_mut();
            }
            let frame = allocate_management(source, kind, length as usize);
            if frame.is_none() {
                reject(kind, length as usize);
            }
            return frame.unwrap_or(ptr::null_mut());
        }
        return __real_esf_buf_alloc(source, kind, length);
    }
    if !crate::critical::on_strict_wifi_hart() {
        reject(kind, length as usize);
        return ptr::null_mut();
    }
    let frame = if is_management_kind(kind) {
        allocate_management(source, kind, length as usize)
    } else if kind == 7 {
        allocate_large_rx(source, length as usize)
    } else if is_vendor_static_kind(kind) {
        allocate_vendor_static(source, kind, length as usize)
    } else {
        None
    };
    if frame.is_none() {
        reject(kind, length as usize);
    }
    frame.unwrap_or(ptr::null_mut())
}

/// Final-link replacement for vendor ESF recycling.
///
/// # Safety
///
/// `frame` must be null or an outstanding ESF object returned by the matching
/// allocator. Recycling transfers the object back to its fixed pool.
#[no_mangle]
pub unsafe extern "C" fn __wrap_esf_buf_recycle(frame: *mut c_void) {
    if !crate::critical::strict_wifi_hart_armed() {
        if !frame.is_null() {
            let strict_frame = frame.cast::<u8>();
            if let Some(index) = management_slot_index(strict_frame) {
                if !on_prearm_management_hart() {
                    reject(u32::MAX, strict_frame as usize);
                    return;
                }
                let bit = 1_usize << index;
                if CLAIMED_MANAGEMENT_SLOTS.fetch_and(!bit, Ordering::AcqRel) & bit == 0 {
                    reject(u32::MAX, strict_frame as usize);
                }
                return;
            }
        }
        __real_esf_buf_recycle(frame);
        return;
    }
    if frame.is_null() {
        return;
    }
    if !crate::critical::on_strict_wifi_hart() {
        reject(u32::MAX, frame as usize);
        return;
    }
    let frame = frame.cast::<u8>();
    if let Some(index) = management_slot_index(frame) {
        let bit = 1_usize << index;
        if CLAIMED_MANAGEMENT_SLOTS.fetch_and(!bit, Ordering::AcqRel) & bit == 0 {
            reject(u32::MAX, frame as usize);
        }
        return;
    }
    if let Some(index) = large_rx_slot_index(frame) {
        let bit = 1_usize << index;
        if CLAIMED_LARGE_RX_SLOTS.fetch_and(!bit, Ordering::AcqRel) & bit == 0 {
            reject(u32::MAX, frame as usize);
        }
        return;
    }
    let kind = frame.add(ESF_TYPE_OFFSET).read() as u32;
    if !is_vendor_static_kind(kind) {
        reject(kind, frame as usize);
        return;
    }
    recycle_vendor_static(frame, kind);
}

pub fn rejected_esf_operations() -> usize {
    REJECTED_ESF_OPERATIONS.load(Ordering::Acquire)
}

const _: () = assert!(mem::size_of::<ManagementSlot>() == MANAGEMENT_SLOT_SIZE);
const _: () = assert!(MANAGEMENT_SLOT_CAPACITY < usize::BITS as usize);
const _: () = assert!(mem::size_of::<LargeRxSlot>() == LARGE_RX_SLOT_SIZE);
const _: () = assert!(LARGE_RX_SLOT_CAPACITY < usize::BITS as usize);
