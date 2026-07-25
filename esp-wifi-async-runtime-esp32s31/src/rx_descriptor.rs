const LENGTH_MASK: u32 = 0x0000_3fff;
const PRESERVE_MASK: u32 = 0xf000_3fff;
const OWNER_BIT: u32 = 1 << 31;
const END_BITS: u32 = (1 << 30) | (1 << 29);
const ESF_BUFFER_DESCRIPTOR_POINTER_OFFSET: usize = 0x04;
const ESF_BUFFER_DESCRIPTOR_DATA_OFFSET: usize = 0x04;
const ESF_RX_CONTROL_POINTER_OFFSET: usize = 0x10;
pub(crate) const RX_METADATA_PREFIX_BYTES: usize = 0x2c;
const RX_METADATA_BASE_PAYLOAD_OFFSET: usize = 0x38;

/// Byte-layout result produced by the pinned lower-MAC RX metadata prefix.
///
/// This is intentionally independent of pointers, MMIO and global WDEV state.
/// The target boundary copies the fixed prefix and performs the one register
/// read; all variable-offset arithmetic remains safe, host-tested Rust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RxMetadataLayout {
    pub(crate) payload_offset: usize,
    pub(crate) sublength: u16,
    pub(crate) has_sublength: bool,
    pub(crate) has_extra_field: bool,
}

fn round_up_four(value: usize) -> Option<usize> {
    value.checked_add(3).map(|rounded| rounded & !3)
}

/// Reproduce `libpp.a[wdev.o]::get_sublen_offset` without its disabled
/// logging/dump side branches.
///
/// `extended_metadata_enabled` is bit 23 of MAC register `0x2010_4098`.
/// Bytes 0x26..0x27 form a ten-bit optional field; bit 2 of byte 0x27 also
/// makes that field present when its encoded length is zero.
pub(crate) fn decode_rx_metadata_layout(
    metadata: &[u8],
    extended_metadata_enabled: bool,
) -> Option<RxMetadataLayout> {
    if metadata.len() < RX_METADATA_PREFIX_BYTES {
        return None;
    }

    let has_sublength = metadata[0x2b] & 0x80 != 0;
    let sublength = if has_sublength {
        usize::from(metadata[0x2b] & 0x7f) + usize::from(metadata[0x2a] >> 5 != 0)
    } else {
        0
    };
    let rounded_sublength = round_up_four(sublength)?;
    let mut payload_offset = RX_METADATA_BASE_PAYLOAD_OFFSET.checked_add(rounded_sublength)?;

    let extra_length =
        usize::from(metadata[0x26]) | (usize::from(metadata[0x27] & 0x03) << 8);
    let has_extra_field =
        extended_metadata_enabled && (metadata[0x27] & 0x04 != 0 || extra_length != 0);
    if has_extra_field {
        payload_offset = payload_offset.checked_add(round_up_four(extra_length)?)?;
    }

    Some(RxMetadataLayout {
        payload_offset,
        sublength: u16::try_from(rounded_sublength).ok()?,
        has_sublength,
        has_extra_field,
    })
}

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
        ESF_RX_CONTROL_POINTER_OFFSET, RX_METADATA_PREFIX_BYTES, decode_rx_metadata_layout,
        descriptor_buffer_length, recycled_descriptor_word, restore_received_packet_buffer_view,
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

    #[test]
    fn rx_metadata_layout_reproduces_base_and_rounded_sublength() {
        let mut metadata = [0_u8; RX_METADATA_PREFIX_BYTES];
        assert_eq!(
            decode_rx_metadata_layout(&metadata, false)
                .unwrap()
                .payload_offset,
            0x38
        );

        metadata[0x2b] = 0x81;
        let one_byte = decode_rx_metadata_layout(&metadata, false).unwrap();
        assert_eq!(one_byte.payload_offset, 0x3c);
        assert_eq!(one_byte.sublength, 4);
        assert!(one_byte.has_sublength);

        metadata[0x2a] = 0x20;
        metadata[0x2b] = 0xff;
        let maximum = decode_rx_metadata_layout(&metadata, false).unwrap();
        assert_eq!(maximum.payload_offset, 0xb8);
        assert_eq!(maximum.sublength, 128);
    }

    #[test]
    fn rx_metadata_layout_gates_and_rounds_the_ten_bit_extra_field() {
        let mut metadata = [0_u8; RX_METADATA_PREFIX_BYTES];
        metadata[0x26] = 1;
        let disabled = decode_rx_metadata_layout(&metadata, false).unwrap();
        assert_eq!(disabled.payload_offset, 0x38);
        assert!(!disabled.has_extra_field);

        let enabled = decode_rx_metadata_layout(&metadata, true).unwrap();
        assert_eq!(enabled.payload_offset, 0x3c);
        assert!(enabled.has_extra_field);

        metadata[0x26] = 0xff;
        metadata[0x27] = 0x03;
        let maximum = decode_rx_metadata_layout(&metadata, true).unwrap();
        assert_eq!(maximum.payload_offset, 0x438);

        metadata[0x26] = 0;
        metadata[0x27] = 0x04;
        let present_zero_length = decode_rx_metadata_layout(&metadata, true).unwrap();
        assert_eq!(present_zero_length.payload_offset, 0x38);
        assert!(present_zero_length.has_extra_field);
    }

    #[test]
    fn rx_metadata_layout_rejects_a_truncated_prefix() {
        assert_eq!(decode_rx_metadata_layout(&[0_u8; 0x2b], true), None);
    }
}
