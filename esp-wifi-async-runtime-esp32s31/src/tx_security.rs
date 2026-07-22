#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlaintextSecurityLayoutInput {
    pub header_len: u16,
    pub remaining_len: u16,
    pub layout: u16,
    pub buffer_flags: u32,
    pub descriptor_flags: u32,
    pub descriptor_word_1: u32,
    pub descriptor_security: u32,
    pub descriptor_word_12: u32,
    pub rate: u8,
    pub frame_control: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlaintextSecurityLayoutOutput {
    pub header_len: u16,
    pub remaining_len: u16,
    pub layout: u16,
    pub buffer_flags: u32,
    pub metadata_len: u32,
}

/// Recover the complete plaintext-headroom transformation observed at the
/// `ppProcTxSecFrame` boundary. This is deliberately a closed set: protected
/// QoS traffic does not reach this leaf in the strict STA path, and any new
/// descriptor state must be measured before it is admitted.
pub const fn strict_plaintext_security_layout(
    input: PlaintextSecurityLayoutInput,
) -> Option<PlaintextSecurityLayoutOutput> {
    const BUFFER_LENGTH_MASK: u32 = 0x0fff_c000;
    const BUFFER_TERMINAL: u32 = 0x4000_0000;

    let observed_frame = (matches!(input.frame_control, 0x00b0 | 0x0000 | 0x00d0)
        && input.descriptor_flags == 0)
        || (input.frame_control == 0x0188 && input.descriptor_flags == 0x0200_200c);
    if !observed_frame
        || input.layout & !0x0007 != 0
        || input.descriptor_word_1 != 7
        || input.descriptor_security != 0
        || input.descriptor_word_12 != 0
        || input.rate != 0
    {
        return None;
    }

    let payload_len = match input.header_len.checked_add(input.remaining_len) {
        Some(value) => value,
        None => return None,
    };
    let encoded_len = ((input.buffer_flags & BUFFER_LENGTH_MASK) >> 14) as u16;
    if encoded_len != payload_len {
        return None;
    }

    let header_len = match input.header_len.checked_add(8) {
        Some(value) => value,
        None => return None,
    };
    let remaining_len = match input.remaining_len.checked_add(4) {
        Some(value) => value,
        None => return None,
    };
    let buffer_len = match encoded_len.checked_add(12) {
        Some(value) if value <= 0x3fff => value,
        _ => return None,
    };
    let metadata_len = payload_len as u32 + 4;

    Some(PlaintextSecurityLayoutOutput {
        header_len,
        remaining_len,
        layout: input.layout | 0x2000,
        buffer_flags: (input.buffer_flags & !BUFFER_LENGTH_MASK)
            | ((buffer_len as u32) << 14)
            | BUFFER_TERMINAL,
        metadata_len,
    })
}

/// SRAM-resident, allocation-free replacement for the reachable plaintext
/// branch of the vendor `ppProcTxSecFrame` leaf.
///
/// # Safety
///
/// `frame` must be the live single-buffer TX frame supplied by `ppTxPkt`.
/// Its frame, buffer and descriptor storage must remain exclusively owned by
/// the caller for the duration of this run-to-completion transformation.
#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.tx_security"]
pub unsafe extern "C" fn strict_pp_proc_tx_sec_frame(frame: *mut u8) -> i32 {
    const FRAME_FIRST_BUFFER_OFFSET: usize = 0x04;
    const FRAME_TAIL_BUFFER_OFFSET: usize = 0x08;
    const FRAME_LENGTHS_OFFSET: usize = 0x14;
    const FRAME_LAYOUT_OFFSET: usize = 0x24;
    const FRAME_DESCRIPTOR_OFFSET: usize = 0x34;
    const BUFFER_DATA_OFFSET: usize = 0x04;
    const DESCRIPTOR_RATE_OFFSET: usize = 0x0c;
    const DESCRIPTOR_SECURITY_OFFSET: usize = 0x10;
    const DESCRIPTOR_WORD_12_OFFSET: usize = 0x30;

    if frame.is_null() {
        trap_invalid_tx_security();
    }
    let first_buffer = frame
        .add(FRAME_FIRST_BUFFER_OFFSET)
        .cast::<*mut u8>()
        .read_unaligned();
    let tail_buffer = frame
        .add(FRAME_TAIL_BUFFER_OFFSET)
        .cast::<*mut u8>()
        .read_unaligned();
    let descriptor = frame
        .add(FRAME_DESCRIPTOR_OFFSET)
        .cast::<*mut u8>()
        .read_unaligned();
    if first_buffer.is_null() || first_buffer != tail_buffer || descriptor.is_null() {
        trap_invalid_tx_security();
    }
    let data = first_buffer
        .add(BUFFER_DATA_OFFSET)
        .cast::<*mut u8>()
        .read_unaligned();
    if data.is_null() || data.addr() < 8 {
        trap_invalid_tx_security();
    }

    let lengths = frame
        .add(FRAME_LENGTHS_OFFSET)
        .cast::<u32>()
        .read_unaligned();
    let input = PlaintextSecurityLayoutInput {
        header_len: lengths as u16,
        remaining_len: (lengths >> 16) as u16,
        layout: frame
            .add(FRAME_LAYOUT_OFFSET)
            .cast::<u16>()
            .read_unaligned(),
        buffer_flags: first_buffer.cast::<u32>().read_unaligned(),
        descriptor_flags: descriptor.cast::<u32>().read_unaligned(),
        descriptor_word_1: descriptor.add(4).cast::<u32>().read_unaligned(),
        descriptor_security: descriptor
            .add(DESCRIPTOR_SECURITY_OFFSET)
            .cast::<u32>()
            .read_unaligned(),
        descriptor_word_12: descriptor
            .add(DESCRIPTOR_WORD_12_OFFSET)
            .cast::<u32>()
            .read_unaligned(),
        rate: descriptor.add(DESCRIPTOR_RATE_OFFSET).read(),
        frame_control: data.cast::<u16>().read_unaligned(),
    };
    let output = match strict_plaintext_security_layout(input) {
        Some(value) => value,
        None => trap_invalid_tx_security(),
    };

    // No packet state is mutated until every pointer and recovered invariant
    // above has been checked. Unknown states therefore trap transactionally.
    // Keep the admitted mutation order identical to the pinned leaf because
    // the frame is shared with the TX interrupt path once preparation starts.
    const BUFFER_LENGTH_MASK: u32 = 0x0fff_c000;
    const BUFFER_TERMINAL: u32 = 0x4000_0000;
    let encoded_len = ((input.buffer_flags & BUFFER_LENGTH_MASK) >> 14) as u16;
    let security_len = encoded_len + 4;
    let security_flags =
        (input.buffer_flags & !BUFFER_LENGTH_MASK) | (u32::from(security_len) << 14);

    frame
        .add(FRAME_LENGTHS_OFFSET + 2)
        .cast::<u16>()
        .write_unaligned(output.remaining_len);
    tail_buffer.cast::<u32>().write_unaligned(security_flags);
    tail_buffer
        .cast::<u32>()
        .write_unaligned(security_flags | BUFFER_TERMINAL);

    let metadata = data.sub(8);
    first_buffer
        .add(BUFFER_DATA_OFFSET)
        .cast::<*mut u8>()
        .write_unaligned(metadata);
    frame
        .add(FRAME_LENGTHS_OFFSET)
        .cast::<u16>()
        .write_unaligned(output.header_len);
    frame
        .add(FRAME_LAYOUT_OFFSET)
        .cast::<u16>()
        .write_unaligned(output.layout);
    first_buffer
        .cast::<u32>()
        .write_unaligned(output.buffer_flags);

    metadata.cast::<u32>().write_unaligned(0);
    metadata.add(4).cast::<u32>().write_unaligned(0);
    metadata.cast::<u32>().write_unaligned(output.metadata_len);
    0
}

#[cfg(target_arch = "riscv32")]
#[inline(always)]
unsafe fn trap_invalid_tx_security() -> ! {
    core::arch::asm!("ebreak", options(noreturn))
}

#[cfg(test)]
mod tests {
    use super::{
        strict_plaintext_security_layout, PlaintextSecurityLayoutInput,
        PlaintextSecurityLayoutOutput,
    };

    const fn input(
        lengths: u32,
        layout: u16,
        buffer_flags: u32,
        descriptor_flags: u32,
        frame_control: u16,
    ) -> PlaintextSecurityLayoutInput {
        PlaintextSecurityLayoutInput {
            header_len: lengths as u16,
            remaining_len: (lengths >> 16) as u16,
            layout,
            buffer_flags,
            descriptor_flags,
            descriptor_word_1: 7,
            descriptor_security: 0,
            descriptor_word_12: 0,
            rate: 0,
            frame_control,
        }
    }

    #[test]
    fn reproduces_all_hardware_observed_plaintext_layouts() {
        let cases = [
            (
                input(0x0062_0018, 0, 0xc01e_8084, 0, 0x00b0),
                PlaintextSecurityLayoutOutput {
                    header_len: 0x20,
                    remaining_len: 0x66,
                    layout: 0x2000,
                    buffer_flags: 0xc021_8084,
                    metadata_len: 0x7e,
                },
            ),
            (
                input(0x006b_001a, 1, 0xc021_4099, 0x0200_200c, 0x0188),
                PlaintextSecurityLayoutOutput {
                    header_len: 0x22,
                    remaining_len: 0x6f,
                    layout: 0x2001,
                    buffer_flags: 0xc024_4099,
                    metadata_len: 0x89,
                },
            ),
            (
                input(0x0009_0018, 2, 0xc008_402c, 0, 0x00d0),
                PlaintextSecurityLayoutOutput {
                    header_len: 0x20,
                    remaining_len: 0x0d,
                    layout: 0x2002,
                    buffer_flags: 0xc00b_402c,
                    metadata_len: 0x25,
                },
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(strict_plaintext_security_layout(input), Some(expected));
        }
    }

    #[test]
    fn rejects_unmeasured_security_rate_layout_and_length_states() {
        let base = input(0x0062_0018, 0, 0xc01e_8084, 0, 0x00b0);
        for rejected in [
            PlaintextSecurityLayoutInput {
                descriptor_security: 1,
                ..base
            },
            PlaintextSecurityLayoutInput { rate: 1, ..base },
            PlaintextSecurityLayoutInput {
                layout: 0x2000,
                ..base
            },
            PlaintextSecurityLayoutInput {
                buffer_flags: 0xc01e_4084,
                ..base
            },
            PlaintextSecurityLayoutInput {
                frame_control: 0x4188,
                ..base
            },
        ] {
            assert_eq!(strict_plaintext_security_layout(rejected), None);
        }
    }
}
