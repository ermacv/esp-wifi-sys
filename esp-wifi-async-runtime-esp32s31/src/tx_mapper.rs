/// Decide the only descriptor treatment used by the guarded strict STA
/// pre-ADDBA mapper states. Every admitted state maps to logical queue zero;
/// `Some(7)` means descriptor byte four must contain the recovered treatment.
pub(crate) fn strict_pre_addba_treatment(
    rate: u8,
    layout: u16,
    frame_control: u16,
    state: [u32; 5],
) -> Option<u8> {
    if layout & !0x0007 != 0x2000 || state[4] != 0 {
        return None;
    }

    let management = rate == 0
        && state[0] == 0
        && state[1] == 7
        && state[2] == 0
        && ((state[3] == 0x80 && matches!(frame_control, 0x00b0 | 0x0000))
            || (state[3] == 0x81 && frame_control == 0x00d0));
    let eapol = rate == 0 && frame_control == 0x0188 && state == [0x0200_200c, 7, 0, 0x81, 0];
    let ht_qos = rate == 33
        && frame_control == 0x4188
        && state[0] == 0x0000_2009
        && matches!(state[1], 7 | 0x20)
        && state[2] == 0x304
        && state[3] == 0x81;
    let legacy_qos =
        rate == 0 && frame_control == 0x4188 && state == [0x0200_2009, 7, 0x304, 0x81, 0];

    if management || eapol || ht_qos || legacy_qos {
        Some(7)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::strict_pre_addba_treatment;

    #[test]
    fn admits_every_hardware_observed_pre_addba_class() {
        let cases = [
            (0, 0x2000, 0x00b0, [0, 7, 0, 0x80, 0]),
            (0, 0x2000, 0x0000, [0, 7, 0, 0x80, 0]),
            (0, 0x2000, 0x0188, [0x0200_200c, 7, 0, 0x81, 0]),
            (0, 0x2001, 0x0188, [0x0200_200c, 7, 0, 0x81, 0]),
            (0, 0x2001, 0x00d0, [0, 7, 0, 0x81, 0]),
            (33, 0x2002, 0x4188, [0x0000_2009, 7, 0x304, 0x81, 0]),
            (33, 0x2003, 0x4188, [0x0000_2009, 7, 0x304, 0x81, 0]),
            (0, 0x2004, 0x4188, [0x0200_2009, 7, 0x304, 0x81, 0]),
            (0, 0x2005, 0x4188, [0x0200_2009, 7, 0x304, 0x81, 0]),
            (0, 0x2002, 0x00d0, [0, 7, 0, 0x81, 0]),
            (0, 0x2006, 0x4188, [0x0200_2009, 7, 0x304, 0x81, 0]),
            (0, 0x2007, 0x4188, [0x0200_2009, 7, 0x304, 0x81, 0]),
            (33, 0x2000, 0x4188, [0x0000_2009, 0x20, 0x304, 0x81, 0]),
            (0, 0x2003, 0x00d0, [0, 7, 0, 0x81, 0]),
        ];
        for (rate, layout, frame_control, state) in cases {
            assert_eq!(
                strict_pre_addba_treatment(rate, layout, frame_control, state),
                Some(7)
            );
        }
    }

    #[test]
    fn rejects_unobserved_queue_peer_rate_and_frame_classes() {
        assert_eq!(
            strict_pre_addba_treatment(33, 0x2000, 0x4188, [0x0000_2009, 7, 0x304, 0x81, 1]),
            None
        );
        assert_eq!(
            strict_pre_addba_treatment(35, 0x2000, 0x4188, [0x0000_2009, 7, 0x304, 0x81, 0]),
            None
        );
        assert_eq!(
            strict_pre_addba_treatment(0, 0x2000, 0x0080, [0, 7, 0, 0x80, 0]),
            None
        );
        assert_eq!(
            strict_pre_addba_treatment(0, 0x2100, 0x00b0, [0, 7, 0, 0x80, 0]),
            None
        );
    }
}
