const LENGTH_MASK: u32 = 0x0000_3fff;
const PRESERVE_MASK: u32 = 0xf000_3fff;
const OWNER_BIT: u32 = 1 << 31;
const END_BITS: u32 = (1 << 30) | (1 << 29);
const ESF_BUFFER_DESCRIPTOR_POINTER_OFFSET: usize = 0x04;
const ESF_BUFFER_DESCRIPTOR_DATA_OFFSET: usize = 0x04;
const ESF_RX_CONTROL_POINTER_OFFSET: usize = 0x10;

/// Reproduce the pinned S31 RX recycle descriptor transformation.
///
/// This leaf is deliberately independent of global state, registers and raw
/// pointers. The hardware boundary in `wdev` owns the unsafe descriptor load
/// and store; the bit-level operation remains host-testable safe Rust.
pub(crate) const fn recycled_descriptor_word(word: u32) -> u32 {
    let length = word & LENGTH_MASK;
    ((word | OWNER_BIT) & !END_BITS & PRESERVE_MASK) | (length << 14)
}

pub(crate) const fn descriptor_buffer_length(word: u32) -> usize {
    (word & LENGTH_MASK) as usize
}

/// Restore the sole mutable buffer view changed by the RX protocol path.
///
/// Pinned `libpp.a[pp.o]::ppRecycleRxPkt` is fourteen bytes: it loads the ESF
/// buffer descriptor at `frame+0x04`, loads the original RX control pointer at
/// `frame+0x10`, stores that pointer at `descriptor+0x04`, and tail-calls
/// `esf_buf_recycle`. Keeping this field transform independent makes the
/// recovered ABI host-testable without emulating the fixed ESF pools.
///
/// # Safety
///
/// `frame` must point to a live pinned-layout ESF object. Its embedded buffer
/// descriptor must remain writable for the duration of the call.
pub(crate) unsafe fn restore_received_packet_buffer_view(frame: *mut u8) -> bool {
    if frame.is_null() {
        return false;
    }
    let buffer_descriptor = frame
        .add(ESF_BUFFER_DESCRIPTOR_POINTER_OFFSET)
        .cast::<*mut u8>()
        .read();
    let rx_control = frame
        .add(ESF_RX_CONTROL_POINTER_OFFSET)
        .cast::<*mut u8>()
        .read();
    if buffer_descriptor.is_null() || rx_control.is_null() {
        return false;
    }
    buffer_descriptor
        .add(ESF_BUFFER_DESCRIPTOR_DATA_OFFSET)
        .cast::<*mut u8>()
        .write(rx_control);
    true
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::{
        ESF_BUFFER_DESCRIPTOR_DATA_OFFSET, ESF_BUFFER_DESCRIPTOR_POINTER_OFFSET,
        ESF_RX_CONTROL_POINTER_OFFSET, descriptor_buffer_length, recycled_descriptor_word,
        restore_received_packet_buffer_view,
    };

    #[test]
    fn recycle_word_matches_the_pinned_vendor_bit_sequence() {
        for word in [0, 1, 0x0000_3fff, 0x6000_1234, 0x9abc_def0, u32::MAX] {
            let mut expected = word | (1 << 31);
            expected &= !(1 << 30);
            expected &= !(1 << 29);
            let length = expected & 0x3fff;
            expected = (expected & 0xf000_3fff) | (length << 14);
            assert_eq!(recycled_descriptor_word(word), expected);
            assert_eq!(descriptor_buffer_length(word), (word & 0x3fff) as usize);
        }
    }

    #[test]
    fn rx_packet_recycle_restores_the_original_buffer_view() {
        let mut frame = [0_u8; 0x90];
        let mut descriptor = [0_u8; 8];
        let mut rx_control = [0_u8; 80];
        let stale_view = ptr::without_provenance_mut::<u8>(0x1234);

        unsafe {
            frame
                .as_mut_ptr()
                .add(ESF_BUFFER_DESCRIPTOR_POINTER_OFFSET)
                .cast::<*mut u8>()
                .write(descriptor.as_mut_ptr());
            frame
                .as_mut_ptr()
                .add(ESF_RX_CONTROL_POINTER_OFFSET)
                .cast::<*mut u8>()
                .write(rx_control.as_mut_ptr());
            descriptor
                .as_mut_ptr()
                .add(ESF_BUFFER_DESCRIPTOR_DATA_OFFSET)
                .cast::<*mut u8>()
                .write(stale_view);

            assert!(restore_received_packet_buffer_view(frame.as_mut_ptr()));
            assert_eq!(
                descriptor
                    .as_ptr()
                    .add(ESF_BUFFER_DESCRIPTOR_DATA_OFFSET)
                    .cast::<*mut u8>()
                    .read(),
                rx_control.as_mut_ptr()
            );
        }
    }

    #[test]
    fn rx_packet_recycle_rejects_missing_owners_without_writing() {
        let mut frame = [0_u8; 0x90];
        unsafe {
            assert!(!restore_received_packet_buffer_view(ptr::null_mut()));
            assert!(!restore_received_packet_buffer_view(frame.as_mut_ptr()));
        }
    }
}
