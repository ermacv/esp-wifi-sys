/// Reproduce the complete `ppTxProtoProc` descriptor transformation recovered
/// from the ESP32-S31 `libpp.a` leaf. The result depends only on the two MAC
/// header bytes and the descriptor's existing words; it has no hidden state.
pub(crate) const fn strict_tx_proto_flags(
    mut flags: u32,
    descriptor_word_12: u32,
    frame_control: u8,
    header_flags: u8,
) -> u32 {
    if header_flags & 1 != 0 {
        flags |= 2;
    }

    let frame_type = frame_control & 0x0c;
    if frame_type == 0x08 {
        flags |= 8;
        if descriptor_word_12 & 0x0002_0000 == 0 && frame_control & 0x70 == 0x40 {
            flags &= !8;
        }
    } else if frame_type == 0 {
        match frame_control & 0xf0 {
            0x50 if flags & 2 == 0 => flags |= 0x0800_0000,
            0x40 if flags & 2 == 0 => flags |= 0x0000_0800,
            _ => {}
        }
    }
    flags
}

#[cfg(all(target_arch = "riscv32", feature = "hil-vendor-tx"))]
unsafe extern "C" {
    fn ets_printf(format: *const core::ffi::c_char, ...) -> i32;
}

/// Stateless SRAM-resident replacement for the vendor `ppTxProtoProc` leaf.
///
/// # Safety
///
/// `frame` must be the live vendor TX frame passed to `ppTxPkt`, with valid
/// first-buffer, payload and descriptor pointers. Ownership remains with the
/// caller and no concurrent context may mutate the descriptor.
#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.tx_proto"]
pub unsafe extern "C" fn strict_pp_tx_proto_proc(frame: *mut u8) {
    const FRAME_FIRST_BUFFER_OFFSET: usize = 0x04;
    const FRAME_LAYOUT_FLAGS_OFFSET: usize = 0x24;
    const FRAME_DESCRIPTOR_OFFSET: usize = 0x34;
    const BUFFER_DATA_OFFSET: usize = 0x04;
    const DESCRIPTOR_WORD_12_OFFSET: usize = 0x30;

    if frame.is_null() {
        trap_invalid_tx_proto();
    }
    let first_buffer = frame
        .add(FRAME_FIRST_BUFFER_OFFSET)
        .cast::<*mut u8>()
        .read_unaligned();
    let descriptor = frame
        .add(FRAME_DESCRIPTOR_OFFSET)
        .cast::<*mut u8>()
        .read_unaligned();
    if first_buffer.is_null() || descriptor.is_null() {
        trap_invalid_tx_proto();
    }
    let payload = first_buffer
        .add(BUFFER_DATA_OFFSET)
        .cast::<*mut u8>()
        .read_unaligned();
    if payload.is_null() {
        trap_invalid_tx_proto();
    }
    let layout = frame
        .add(FRAME_LAYOUT_FLAGS_OFFSET)
        .cast::<u16>()
        .read_unaligned();
    let header = payload.add(if layout & 0x2000 != 0 { 8 } else { 0 });
    let flags = descriptor.cast::<u32>().read_unaligned();
    let word_12 = descriptor
        .add(DESCRIPTOR_WORD_12_OFFSET)
        .cast::<u32>()
        .read_unaligned();
    #[cfg(feature = "hil-vendor-tx")]
    if header.read() & 0x0c == 0x08 {
        ets_printf(
            c"HIL TX proto: fc=%04x flags=%08x word12=%08x layout=%04x\r\n"
                .as_ptr()
                .cast(),
            u32::from(header.cast::<u16>().read_unaligned()),
            flags,
            word_12,
            u32::from(layout),
        );
    }
    descriptor
        .cast::<u32>()
        .write_unaligned(strict_tx_proto_flags(
            flags,
            word_12,
            header.read(),
            header.add(4).read(),
        ));
}

#[cfg(target_arch = "riscv32")]
#[inline(always)]
unsafe fn trap_invalid_tx_proto() -> ! {
    core::arch::asm!("ebreak", options(noreturn))
}

#[cfg(test)]
mod tests {
    use super::strict_tx_proto_flags;

    #[test]
    fn propagates_header_flag_and_data_class() {
        assert_eq!(strict_tx_proto_flags(0x100, 0, 0x08, 1), 0x10a);
        assert_eq!(strict_tx_proto_flags(0x100, 0, 0x88, 0), 0x108);
    }

    #[test]
    fn reproduces_vendor_data_subtype_exception() {
        assert_eq!(strict_tx_proto_flags(0x100, 0, 0x48, 0), 0x100);
        assert_eq!(strict_tx_proto_flags(0x100, 0x0002_0000, 0x48, 0), 0x108);
    }

    #[test]
    fn marks_probe_and_beacon_management_classes() {
        assert_eq!(strict_tx_proto_flags(0, 0, 0x50, 0), 0x0800_0000);
        assert_eq!(strict_tx_proto_flags(0, 0, 0x40, 0), 0x800);
        assert_eq!(strict_tx_proto_flags(2, 0, 0x50, 0), 2);
        assert_eq!(strict_tx_proto_flags(2, 0, 0x40, 0), 2);
    }

    #[test]
    fn leaves_other_management_and_control_classes_unchanged() {
        assert_eq!(strict_tx_proto_flags(0x1234, 0, 0xb0, 0), 0x1234);
        assert_eq!(strict_tx_proto_flags(0x1234, 0, 0xd4, 0), 0x1234);
    }
}
