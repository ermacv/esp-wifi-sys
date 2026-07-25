/// Decide the only descriptor treatment used by the guarded strict STA
/// ordinary strict mapper states. Every admitted state maps to logical queue zero;
/// `Some(7)` means descriptor byte four must contain the recovered treatment.
pub(crate) fn strict_sta_ap_treatment(
    rate: u8,
    layout: u16,
    frame_control: u16,
    state: [u32; 5],
) -> Option<u8> {
    // The pinned mapper tests only layout bit 0x2000 to select the eight-byte
    // ESF prefix. Lower bits are the static slot's changing buffer identity
    // (`0x2000`, `0x2008`, `0x2010`, ...), not mapper state. Keep the adjacent
    // security leaf's upper-bit invariant but do not accidentally bind queue
    // policy to those opaque low bits.
    if layout & 0xe000 != 0x2000 || state[4] != 0 {
        return None;
    }

    let management = rate == 0
        && state[0] == 0
        && state[1] == 7
        && state[2] == 0
        && ((state[3] == 0x80 && matches!(frame_control, 0x00b0 | 0x0000))
            || (state[3] == 0x81 && frame_control == 0x00d0));
    let eapol = rate == 0 && frame_control == 0x0188 && state == [0x0200_200c, 7, 0, 0x81, 0];
    // The retained WPA2 AP beacon enters this leaf after the descriptor and
    // security policies have applied their already-qualified fixed layout.
    // Pinned ppMapTxQueue preserves descriptor byte four as 0x07 for this
    // class; no aggregation or power-save search state is consulted.
    let ap_beacon =
        rate == 12 && frame_control == 0x0080 && state == [0x0080_0412, 7, 0x0004_0000, 0x83, 0];
    // Bytes five through seven are PP aggregation-search hints. They are zero
    // before ADDBA and become nonzero after the peer accepts ADDBA, but the
    // strict single-MPDU path deliberately does not enter ppSearchTxQueue.
    // Descriptor byte four remains the complete priority/treatment input used
    // by the finite queue mapping.
    let priority_treatment = state[1] as u8;
    let ht_qos = rate == 33
        && frame_control == 0x4188
        && state[0] == 0x0000_2009
        && matches!(priority_treatment, 7 | 0x20)
        && state[2] == 0x304
        && state[3] == 0x81;
    let legacy_qos =
        rate == 0 && frame_control == 0x4188 && state == [0x0200_2009, 7, 0x304, 0x81, 0];

    if management || eapol || ap_beacon || ht_qos || legacy_qos {
        Some(7)
    } else {
        None
    }
}

/// Apply the complete mapper transformation admitted by the ordinary strict
/// STA/AP profile before Rust aggregation takes ownership.
///
/// This is the recovered finite `ppMapTxQueue` domain used by authentication,
/// association, EAPOL, Action, and single-MPDU data traffic. It reads only the
/// live frame, descriptor, and peer supplied by the caller and changes exactly
/// descriptor byte four (`0x20 -> 0x07` for a fresh QoS frame, or preserves
/// `0x07`). No PP queue, power-save state, callback, allocation, or wait is
/// reachable.
///
/// # Safety
///
/// `frame` and all pointers reached through its pinned ESF layout must remain
/// valid and exclusively owned for this run-to-completion transformation.
#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.tx_mapper"]
pub(crate) unsafe fn apply_strict_sta_ap(frame: *mut u8) -> bool {
    const FRAME_FIRST_BUFFER_OFFSET: usize = 0x04;
    const FRAME_LAYOUT_FLAGS_OFFSET: usize = 0x24;
    const FRAME_PEER_OFFSET: usize = 0x2c;
    const FRAME_DESCRIPTOR_OFFSET: usize = 0x34;
    const BUFFER_DATA_OFFSET: usize = 0x04;
    const DESCRIPTOR_RATE_OFFSET: usize = 0x0c;

    if frame.is_null() {
        return false;
    }
    let descriptor = frame.add(FRAME_DESCRIPTOR_OFFSET).cast::<*mut u8>().read();
    let peer = frame.add(FRAME_PEER_OFFSET).cast::<*mut u8>().read();
    let first_buffer = frame
        .add(FRAME_FIRST_BUFFER_OFFSET)
        .cast::<*mut u8>()
        .read();
    if descriptor.is_null() || peer.is_null() || first_buffer.is_null() {
        return false;
    }
    let layout = frame
        .add(FRAME_LAYOUT_FLAGS_OFFSET)
        .cast::<u16>()
        .read_unaligned();
    let mut header = first_buffer
        .add(BUFFER_DATA_OFFSET)
        .cast::<*mut u8>()
        .read();
    if header.is_null() {
        return false;
    }
    if layout & 0x2000 != 0 {
        header = header.add(8);
    }
    let state = [
        descriptor.cast::<u32>().read_unaligned(),
        descriptor.add(4).cast::<u32>().read_unaligned(),
        descriptor.add(0x10).cast::<u32>().read_unaligned(),
        peer.add(0x0c).cast::<u32>().read_unaligned(),
        u32::from(peer.add(0x84).read()),
    ];
    let Some(treatment) = strict_sta_ap_treatment(
        descriptor.add(DESCRIPTOR_RATE_OFFSET).read(),
        layout,
        header.cast::<u16>().read_unaligned(),
        state,
    ) else {
        return false;
    };
    descriptor.add(4).write(treatment);
    true
}

/// Fail closed while preserving the complete mapper input in the trap frame.
///
/// The register contract is intentionally stable for hardware qualification:
/// `a0=frame`, `a1=detail`, `a2=rate|(layout<<8)`,
/// `a3=frame_control|(peer[0x84]<<16)`, and `a4..a7` are the four remaining
/// state words consumed by [`strict_sta_ap_treatment`].
#[cfg(target_arch = "riscv32")]
#[inline(never)]
pub(crate) unsafe fn trap_unadmitted_strict_sta_ap(frame: *mut u8) -> ! {
    const FRAME_FIRST_BUFFER_OFFSET: usize = 0x04;
    const FRAME_LAYOUT_FLAGS_OFFSET: usize = 0x24;
    const FRAME_PEER_OFFSET: usize = 0x2c;
    const FRAME_DESCRIPTOR_OFFSET: usize = 0x34;
    const BUFFER_DATA_OFFSET: usize = 0x04;
    const DESCRIPTOR_RATE_OFFSET: usize = 0x0c;

    #[inline(always)]
    unsafe fn trap(
        frame: *mut u8,
        detail: u32,
        rate_layout: u32,
        frame_control_peer_flag: u32,
        descriptor_flags: u32,
        descriptor_priority: u32,
        descriptor_control: u32,
        peer_state: u32,
    ) -> ! {
        core::arch::asm!(
            "ebreak",
            in("a0") frame,
            in("a1") detail,
            in("a2") rate_layout,
            in("a3") frame_control_peer_flag,
            in("a4") descriptor_flags,
            in("a5") descriptor_priority,
            in("a6") descriptor_control,
            in("a7") peer_state,
            options(noreturn)
        )
    }

    if frame.is_null() {
        trap(frame, 0x3010, 0, 0, 0, 0, 0, 0);
    }
    let descriptor = frame.add(FRAME_DESCRIPTOR_OFFSET).cast::<*mut u8>().read();
    let peer = frame.add(FRAME_PEER_OFFSET).cast::<*mut u8>().read();
    let first_buffer = frame
        .add(FRAME_FIRST_BUFFER_OFFSET)
        .cast::<*mut u8>()
        .read();
    if descriptor.is_null() || peer.is_null() || first_buffer.is_null() {
        trap(frame, 0x3011, 0, 0, 0, 0, 0, 0);
    }
    let layout = frame
        .add(FRAME_LAYOUT_FLAGS_OFFSET)
        .cast::<u16>()
        .read_unaligned();
    let mut header = first_buffer
        .add(BUFFER_DATA_OFFSET)
        .cast::<*mut u8>()
        .read();
    if header.is_null() {
        trap(frame, 0x3012, u32::from(layout) << 8, 0, 0, 0, 0, 0);
    }
    if layout & 0x2000 != 0 {
        header = header.add(8);
    }
    let rate_layout =
        u32::from(descriptor.add(DESCRIPTOR_RATE_OFFSET).read()) | (u32::from(layout) << 8);
    let frame_control_peer_flag =
        u32::from(header.cast::<u16>().read_unaligned()) | (u32::from(peer.add(0x84).read()) << 16);
    trap(
        frame,
        0x3001,
        rate_layout,
        frame_control_peer_flag,
        descriptor.cast::<u32>().read_unaligned(),
        descriptor.add(4).cast::<u32>().read_unaligned(),
        descriptor.add(0x10).cast::<u32>().read_unaligned(),
        peer.add(0x0c).cast::<u32>().read_unaligned(),
    )
}

#[cfg(test)]
mod tests {
    use super::strict_sta_ap_treatment;

    #[test]
    fn admits_every_hardware_observed_strict_class() {
        let cases = [
            (0, 0x2000, 0x00b0, [0, 7, 0, 0x80, 0]),
            (0, 0x2000, 0x0000, [0, 7, 0, 0x80, 0]),
            (0, 0x2000, 0x0188, [0x0200_200c, 7, 0, 0x81, 0]),
            (0, 0x2001, 0x0188, [0x0200_200c, 7, 0, 0x81, 0]),
            (12, 0x2000, 0x0080, [0x0080_0412, 7, 0x0004_0000, 0x83, 0]),
            (12, 0x2001, 0x0080, [0x0080_0412, 7, 0x0004_0000, 0x83, 0]),
            (0, 0x2001, 0x00d0, [0, 7, 0, 0x81, 0]),
            (33, 0x2002, 0x4188, [0x0000_2009, 7, 0x304, 0x81, 0]),
            (33, 0x2003, 0x4188, [0x0000_2009, 7, 0x304, 0x81, 0]),
            (0, 0x2004, 0x4188, [0x0200_2009, 7, 0x304, 0x81, 0]),
            (0, 0x2005, 0x4188, [0x0200_2009, 7, 0x304, 0x81, 0]),
            (0, 0x2002, 0x00d0, [0, 7, 0, 0x81, 0]),
            (0, 0x2006, 0x4188, [0x0200_2009, 7, 0x304, 0x81, 0]),
            (0, 0x2007, 0x4188, [0x0200_2009, 7, 0x304, 0x81, 0]),
            (33, 0x2000, 0x4188, [0x0000_2009, 0x20, 0x304, 0x81, 0]),
            (
                33,
                0x2008,
                0x4188,
                [0x0000_2009, 0x00ab_cd20, 0x304, 0x81, 0],
            ),
            (33, 0x2010, 0x4188, [0x0000_2009, 7, 0x304, 0x81, 0]),
            (0, 0x2003, 0x00d0, [0, 7, 0, 0x81, 0]),
        ];
        for (rate, layout, frame_control, state) in cases {
            assert_eq!(
                strict_sta_ap_treatment(rate, layout, frame_control, state),
                Some(7)
            );
        }
    }

    #[test]
    fn rejects_unobserved_queue_peer_rate_and_frame_classes() {
        assert_eq!(
            strict_sta_ap_treatment(33, 0x2000, 0x4188, [0x0000_2009, 7, 0x304, 0x81, 1]),
            None
        );
        assert_eq!(
            strict_sta_ap_treatment(35, 0x2000, 0x4188, [0x0000_2009, 7, 0x304, 0x81, 0]),
            None
        );
        assert_eq!(
            strict_sta_ap_treatment(0, 0x2000, 0x0080, [0, 7, 0, 0x80, 0]),
            None
        );
        assert_eq!(
            strict_sta_ap_treatment(12, 0x2000, 0x0080, [0x0080_0412, 7, 0x0004_0000, 0x80, 0],),
            None
        );
        assert_eq!(
            strict_sta_ap_treatment(0, 0x4000, 0x00b0, [0, 7, 0, 0x80, 0]),
            None
        );
        assert_eq!(
            strict_sta_ap_treatment(33, 0x0000, 0x4188, [0x0000_2009, 7, 0x304, 0x81, 0]),
            None
        );
    }
}
