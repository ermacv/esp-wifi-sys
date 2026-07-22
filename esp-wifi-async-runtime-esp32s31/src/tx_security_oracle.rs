use core::sync::atomic::{AtomicU32, Ordering};

pub const HIL_TX_SECURITY_CLASS_CAPACITY: usize = 6;
const SNAPSHOT_WORDS: usize = 12;

pub type VendorTxSecurityLeaf = unsafe extern "C" fn(*mut u8) -> i32;

struct ClassCell {
    calls: AtomicU32,
    identity: AtomicU32,
    frame_control: AtomicU32,
    result: AtomicU32,
    pre: [AtomicU32; SNAPSHOT_WORDS],
    post: [AtomicU32; SNAPSHOT_WORDS],
}

impl ClassCell {
    const fn new() -> Self {
        Self {
            calls: AtomicU32::new(0),
            identity: AtomicU32::new(0),
            frame_control: AtomicU32::new(0),
            result: AtomicU32::new(0),
            pre: [const { AtomicU32::new(0) }; SNAPSHOT_WORDS],
            post: [const { AtomicU32::new(0) }; SNAPSHOT_WORDS],
        }
    }
}

#[link_section = ".critical.bss.wifi_strict.tx_security_oracle"]
static CLASSES: [ClassCell; HIL_TX_SECURITY_CLASS_CAPACITY] =
    [const { ClassCell::new() }; HIL_TX_SECURITY_CLASS_CAPACITY];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HilTxSecurityRecord {
    pub calls: u32,
    pub rate: u8,
    pub layout: u16,
    pub frame_control: u16,
    pub result: i32,
    /// Frame length/layout, first-buffer flags/pointer/data, tail flags,
    /// descriptor flags/words and node security capacity.
    pub pre: [u32; SNAPSHOT_WORDS],
    pub post: [u32; SNAPSHOT_WORDS],
}

impl HilTxSecurityRecord {
    const EMPTY: Self = Self {
        calls: 0,
        rate: u8::MAX,
        layout: u16::MAX,
        frame_control: u16::MAX,
        result: i32::MIN,
        pre: [0; SNAPSHOT_WORDS],
        post: [0; SNAPSHOT_WORDS],
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HilTxSecuritySnapshot {
    pub records: [HilTxSecurityRecord; HIL_TX_SECURITY_CLASS_CAPACITY],
}

pub fn hil_tx_security_snapshot() -> HilTxSecuritySnapshot {
    let mut records = [HilTxSecurityRecord::EMPTY; HIL_TX_SECURITY_CLASS_CAPACITY];
    let mut class = 0;
    while class < records.len() {
        let source = &CLASSES[class];
        let identity = source.identity.load(Ordering::Acquire);
        let mut pre = [0; SNAPSHOT_WORDS];
        let mut post = [0; SNAPSHOT_WORDS];
        let mut index = 0;
        while index < SNAPSHOT_WORDS {
            pre[index] = source.pre[index].load(Ordering::Acquire);
            post[index] = source.post[index].load(Ordering::Acquire);
            index += 1;
        }
        records[class] = HilTxSecurityRecord {
            calls: source.calls.load(Ordering::Acquire),
            rate: identity as u8,
            layout: (identity >> 8) as u16,
            frame_control: source.frame_control.load(Ordering::Acquire) as u16,
            result: source.result.load(Ordering::Acquire) as i32,
            pre,
            post,
        };
        class += 1;
    }
    HilTxSecuritySnapshot { records }
}

/// Observe the complete finite security-layout leaf without changing its
/// inputs, return value or ownership. Storage is fixed SRAM and last-value per
/// frame class; no allocation, wait, retry or cross-context lock is used.
///
/// # Safety
///
/// `frame` must be the valid live TX frame supplied by `ppTxPkt`; `leaf` must
/// be the original run-to-completion `ppProcTxSecFrame` implementation.
#[link_section = ".rwtext.wifi_strict.tx_security_oracle"]
pub unsafe extern "C" fn hil_observe_tx_security(
    frame: *mut u8,
    leaf: VendorTxSecurityLeaf,
) -> i32 {
    let (rate, layout, frame_control) = read_identity(frame);
    let class = security_class(rate, frame_control);
    let pre = capture(frame);
    let result = leaf(frame);
    let post = capture(frame);
    let destination = &CLASSES[class];
    let mut index = 0;
    while index < SNAPSHOT_WORDS {
        destination.pre[index].store(pre[index], Ordering::Relaxed);
        destination.post[index].store(post[index], Ordering::Relaxed);
        index += 1;
    }
    destination.identity.store(
        u32::from(rate) | (u32::from(layout) << 8),
        Ordering::Relaxed,
    );
    destination
        .frame_control
        .store(u32::from(frame_control), Ordering::Relaxed);
    destination.result.store(result as u32, Ordering::Relaxed);
    destination.calls.fetch_add(1, Ordering::Release);
    result
}

#[inline(always)]
const fn security_class(rate: u8, frame_control: u16) -> usize {
    match frame_control {
        0x00b0 | 0x0000 => 0,
        0x0188 => 1,
        0x00d0 => 2,
        0x4188 if rate >= 16 => 3,
        0x4188 => 4,
        _ => 5,
    }
}

#[inline(always)]
unsafe fn read_identity(frame: *mut u8) -> (u8, u16, u16) {
    let layout = frame.add(0x24).cast::<u16>().read_unaligned();
    let first_buffer = frame.add(0x04).cast::<*mut u8>().read_unaligned();
    let descriptor = frame.add(0x34).cast::<*mut u8>().read_unaligned();
    let data = first_buffer.add(0x04).cast::<*mut u8>().read_unaligned();
    let header = data.add(if layout & 0x2000 != 0 { 8 } else { 0 });
    (
        descriptor.add(0x0c).read(),
        layout,
        header.cast::<u16>().read_unaligned(),
    )
}

#[inline(always)]
unsafe fn capture(frame: *mut u8) -> [u32; SNAPSHOT_WORDS] {
    let first_buffer = frame.add(0x04).cast::<*mut u8>().read_unaligned();
    let tail_buffer = frame.add(0x08).cast::<*mut u8>().read_unaligned();
    let descriptor = frame.add(0x34).cast::<*mut u8>().read_unaligned();
    let data = first_buffer.add(0x04).cast::<*mut u8>().read_unaligned();
    let node = frame.add(0x2c).cast::<*mut u8>().read_unaligned();
    [
        frame.add(0x14).cast::<u32>().read_unaligned(),
        frame.add(0x24).cast::<u32>().read_unaligned(),
        first_buffer.cast::<u32>().read_unaligned(),
        data as usize as u32,
        data.cast::<u32>().read_unaligned(),
        data.add(4).cast::<u32>().read_unaligned(),
        tail_buffer.cast::<u32>().read_unaligned(),
        descriptor.cast::<u32>().read_unaligned(),
        descriptor.add(0x04).cast::<u32>().read_unaligned(),
        descriptor.add(0x10).cast::<u32>().read_unaligned(),
        descriptor.add(0x30).cast::<u32>().read_unaligned(),
        if node.is_null() {
            u32::MAX
        } else {
            u32::from(node.add(0x82).cast::<u16>().read_unaligned())
        },
    ]
}
