#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxSecurityLayoutInput {
    pub header_len: u16,
    pub remaining_len: u16,
    pub layout: u16,
    pub buffer_flags: u32,
    pub descriptor_flags: u32,
    pub descriptor_security: u32,
    pub frame_control: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxSecurityLayoutOutput {
    pub header_len: u16,
    pub remaining_len: u16,
    pub layout: u16,
    pub buffer_flags: u32,
    pub metadata_len: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApBeaconCompletionLayout {
    pub remaining_len: u16,
    pub buffer_flags: u32,
    pub descriptor_security: u32,
}

/// Remove the per-transmission FCS reservation from a persistent AP beacon
/// while retaining its one-time PP metadata headroom.
pub const fn strict_ap_beacon_completion_layout(
    input: TxSecurityLayoutInput,
) -> Option<ApBeaconCompletionLayout> {
    const BUFFER_LENGTH_MASK: u32 = 0x0fff_c000;

    if input.header_len != 0x20
        || input.remaining_len != 0x78
        || input.layout & 0xc000 != 0
        || input.layout & 0x2000 == 0
        || input.descriptor_flags != 0x0080_0412
        || input.descriptor_security != 0x0114_0000
        || input.frame_control != 0x0080
    {
        return None;
    }
    let encoded_len = ((input.buffer_flags & BUFFER_LENGTH_MASK) >> 14) as u16;
    if encoded_len != 0x98 {
        return None;
    }

    Some(ApBeaconCompletionLayout {
        remaining_len: 0x74,
        buffer_flags: (input.buffer_flags & !BUFFER_LENGTH_MASK) | (0x94 << 14),
        descriptor_security: 0x0004_0000,
    })
}

/// Recover the complete headroom/trailer transformation observed at the
/// `ppProcTxSecFrame` boundary. This is deliberately a closed set: plaintext
/// management/EAPOL/Action frames, the AP beacon descriptor, and the measured
/// WPA2-CCMP QoS descriptor states are admitted; any new descriptor state must
/// be measured first.
pub const fn strict_tx_security_layout(
    input: TxSecurityLayoutInput,
) -> Option<TxSecurityLayoutOutput> {
    const BUFFER_LENGTH_MASK: u32 = 0x0fff_c000;
    const BUFFER_TERMINAL: u32 = 0x4000_0000;

    let headroom_applied = input.layout & 0x2000 != 0;

    let ap_beacon = input.frame_control == 0x0080
        && input.descriptor_flags == 0x0080_0412
        && input.descriptor_security == 0x0004_0000;
    let trailer_len = if (input.descriptor_security == 0
        && ((matches!(input.frame_control, 0x00b0 | 0x0000 | 0x00d0)
            && input.descriptor_flags == 0)
            || (input.frame_control == 0x0188 && input.descriptor_flags == 0x0200_200c)))
        || ap_beacon
    {
        // AP beacons carry the pinned hardware-key direction word even though
        // the 802.11 Protected bit is clear. The first strict AP bring-up
        // trapped this exact descriptor tuple before any state was mutated.
        4_u16
    } else if input.frame_control == 0x4188
        && matches!(input.descriptor_flags, 0x0000_2009 | 0x0200_2009)
        && input.descriptor_security == 0x0000_0304
    {
        // The security selector in bits 8..11 is 3. The pinned vendor table
        // maps that selector to the eight-byte CCMP MIC plus four-byte FCS.
        12_u16
    } else {
        return None;
    };

    // The two hostap beacon buffers are persistent. Their constructor resets
    // the current MPDU/body length before every TBTT, but deliberately keeps
    // the PP metadata headroom installed by the first transmission. This is
    // the only measured path allowed to re-enter with that bit set; ordinary
    // management, EAPOL and data buffers are single-owner, one-shot objects.
    if headroom_applied
        && (!ap_beacon
            || input.layout & 0xc000 != 0
            || input.header_len != 0x20
            || input.remaining_len != 0x74)
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

    let header_len = if headroom_applied {
        input.header_len
    } else {
        match input.header_len.checked_add(8) {
            Some(value) => value,
            None => return None,
        }
    };
    let remaining_len = match input.remaining_len.checked_add(trailer_len) {
        Some(value) => value,
        None => return None,
    };
    let headroom_len = if headroom_applied { 0 } else { 8 };
    let buffer_len = match encoded_len.checked_add(headroom_len) {
        Some(value) => match value.checked_add(trailer_len) {
            Some(value) if value <= 0x3fff => value,
            _ => return None,
        },
        None => return None,
    };
    let metadata_len = header_len as u32 + remaining_len as u32 - 8;

    Some(TxSecurityLayoutOutput {
        header_len,
        remaining_len,
        layout: input.layout | 0x2000,
        buffer_flags: (input.buffer_flags & !BUFFER_LENGTH_MASK)
            | ((buffer_len as u32) << 14)
            | BUFFER_TERMINAL,
        metadata_len,
    })
}

/// SRAM-resident, allocation-free replacement for the measured plaintext and
/// WPA2-CCMP branches of the vendor `ppProcTxSecFrame` leaf.
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
    const DESCRIPTOR_SECURITY_OFFSET: usize = 0x10;

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
    let layout = frame
        .add(FRAME_LAYOUT_OFFSET)
        .cast::<u16>()
        .read_unaligned();
    let header = if layout & 0x2000 != 0 {
        data.add(8)
    } else {
        data
    };
    let input = TxSecurityLayoutInput {
        header_len: lengths as u16,
        remaining_len: (lengths >> 16) as u16,
        layout,
        buffer_flags: first_buffer.cast::<u32>().read_unaligned(),
        descriptor_flags: descriptor.cast::<u32>().read_unaligned(),
        descriptor_security: descriptor
            .add(DESCRIPTOR_SECURITY_OFFSET)
            .cast::<u32>()
            .read_unaligned(),
        frame_control: header.cast::<u16>().read_unaligned(),
    };
    let output = match strict_tx_security_layout(input) {
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
    let security_len = output.remaining_len - input.remaining_len + encoded_len;
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

    let metadata = if input.layout & 0x2000 != 0 {
        data
    } else {
        data.sub(8)
    };
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
        strict_ap_beacon_completion_layout, strict_tx_security_layout, ApBeaconCompletionLayout,
        TxSecurityLayoutInput, TxSecurityLayoutOutput,
    };

    const fn input(
        lengths: u32,
        layout: u16,
        buffer_flags: u32,
        descriptor_flags: u32,
        frame_control: u16,
    ) -> TxSecurityLayoutInput {
        TxSecurityLayoutInput {
            header_len: lengths as u16,
            remaining_len: (lengths >> 16) as u16,
            layout,
            buffer_flags,
            descriptor_flags,
            descriptor_security: 0,
            frame_control,
        }
    }

    #[test]
    fn reproduces_all_hardware_observed_plaintext_layouts() {
        let cases = [
            (
                input(0x0062_0018, 0, 0xc01e_8084, 0, 0x00b0),
                TxSecurityLayoutOutput {
                    header_len: 0x20,
                    remaining_len: 0x66,
                    layout: 0x2000,
                    buffer_flags: 0xc021_8084,
                    metadata_len: 0x7e,
                },
            ),
            (
                input(0x006b_001a, 1, 0xc021_4099, 0x0200_200c, 0x0188),
                TxSecurityLayoutOutput {
                    header_len: 0x22,
                    remaining_len: 0x6f,
                    layout: 0x2001,
                    buffer_flags: 0xc024_4099,
                    metadata_len: 0x89,
                },
            ),
            (
                input(0x0009_0018, 2, 0xc008_402c, 0, 0x00d0),
                TxSecurityLayoutOutput {
                    header_len: 0x20,
                    remaining_len: 0x0d,
                    layout: 0x2002,
                    buffer_flags: 0xc00b_402c,
                    metadata_len: 0x25,
                },
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(strict_tx_security_layout(input), Some(expected));
        }
    }

    #[test]
    fn reproduces_hardware_observed_wpa2_ccmp_layout() {
        let measured = TxSecurityLayoutInput {
            descriptor_security: 0x0304,
            ..input(0x0048_001a, 2, 0xc018_806e, 0x0000_2009, 0x4188)
        };
        let expected = TxSecurityLayoutOutput {
            header_len: 0x22,
            remaining_len: 0x54,
            layout: 0x2002,
            buffer_flags: 0xc01d_806e,
            metadata_len: 0x6e,
        };
        assert_eq!(strict_tx_security_layout(measured), Some(expected));
        assert_eq!(
            strict_tx_security_layout(TxSecurityLayoutInput {
                descriptor_flags: 0x0200_2009,
                ..measured
            }),
            Some(expected),
        );
        assert_eq!(
            strict_tx_security_layout(TxSecurityLayoutInput {
                layout: 8,
                ..measured
            }),
            Some(TxSecurityLayoutOutput {
                layout: 0x2008,
                ..expected
            }),
        );
    }

    #[test]
    fn reproduces_hardware_observed_wpa2_ap_beacon_layout() {
        let measured = TxSecurityLayoutInput {
            descriptor_security: 0x0004_0000,
            ..input(0x0074_0018, 0, 0xc023_00f8, 0x0080_0412, 0x0080)
        };
        assert_eq!(
            strict_tx_security_layout(measured),
            Some(TxSecurityLayoutOutput {
                header_len: 0x20,
                remaining_len: 0x78,
                layout: 0x2000,
                buffer_flags: 0xc026_00f8,
                metadata_len: 0x90,
            })
        );

        for rejected in [
            TxSecurityLayoutInput {
                descriptor_flags: 0x0080_0410,
                ..measured
            },
            TxSecurityLayoutInput {
                descriptor_security: 0,
                ..measured
            },
            TxSecurityLayoutInput {
                frame_control: 0x4080,
                ..measured
            },
        ] {
            assert_eq!(strict_tx_security_layout(rejected), None);
        }
    }

    #[test]
    fn refreshes_persistent_wpa2_ap_beacon_without_duplicating_headroom() {
        let refreshed = TxSecurityLayoutInput {
            descriptor_security: 0x0004_0000,
            ..input(0x0074_0020, 0x2001, 0xc025_00f8, 0x0080_0412, 0x0080)
        };
        assert_eq!(
            strict_tx_security_layout(refreshed),
            Some(TxSecurityLayoutOutput {
                header_len: 0x20,
                remaining_len: 0x78,
                layout: 0x2001,
                buffer_flags: 0xc026_00f8,
                metadata_len: 0x90,
            })
        );

        for rejected in [
            TxSecurityLayoutInput {
                header_len: 0x28,
                ..refreshed
            },
            TxSecurityLayoutInput {
                remaining_len: 0x78,
                ..refreshed
            },
            TxSecurityLayoutInput {
                layout: 0x6001,
                ..refreshed
            },
        ] {
            assert_eq!(strict_tx_security_layout(rejected), None);
        }
    }

    #[test]
    fn completion_removes_only_the_persistent_beacon_trailer() {
        let completed = TxSecurityLayoutInput {
            header_len: 0x20,
            remaining_len: 0x78,
            layout: 0x2001,
            buffer_flags: 0xc026_00f8,
            descriptor_flags: 0x0080_0412,
            descriptor_security: 0x0114_0000,
            frame_control: 0x0080,
        };
        assert_eq!(
            strict_ap_beacon_completion_layout(completed),
            Some(ApBeaconCompletionLayout {
                remaining_len: 0x74,
                buffer_flags: 0xc025_00f8,
                descriptor_security: 0x0004_0000,
            })
        );
        assert_eq!(
            strict_ap_beacon_completion_layout(TxSecurityLayoutInput {
                layout: 0x2008,
                ..completed
            }),
            strict_ap_beacon_completion_layout(completed)
        );
        assert_eq!(
            strict_ap_beacon_completion_layout(TxSecurityLayoutInput {
                remaining_len: 0x74,
                ..completed
            }),
            None
        );
    }

    #[test]
    fn ignores_rate_control_words_and_rejects_unmeasured_security_layout_and_length_states() {
        let base = input(0x0062_0018, 0, 0xc01e_8084, 0, 0x00b0);
        for rejected in [
            TxSecurityLayoutInput {
                descriptor_security: 1,
                ..base
            },
            TxSecurityLayoutInput {
                layout: 0x2000,
                ..base
            },
            TxSecurityLayoutInput {
                buffer_flags: 0xc01e_4084,
                ..base
            },
            TxSecurityLayoutInput {
                frame_control: 0x4188,
                ..base
            },
            TxSecurityLayoutInput {
                descriptor_security: 0x0304,
                descriptor_flags: 0x2009,
                frame_control: 0x0188,
                ..base
            },
            TxSecurityLayoutInput {
                descriptor_security: 0x0404,
                descriptor_flags: 0x2009,
                frame_control: 0x4188,
                ..base
            },
        ] {
            assert_eq!(strict_tx_security_layout(rejected), None);
        }
    }
}
