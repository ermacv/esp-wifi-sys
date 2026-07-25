//! Stateless receive-protocol classification recovered from ESP32-S31 PP.

/// Numeric rate-control context selected by the pinned
/// `libpp.a[pp.o]::ppRxProtoProc` body.
///
/// The values are part of the private PP ABI. Their concrete vendor enum
/// names are not available, so this type deliberately exposes only the
/// recovered numeric identity. Route 3 means that no rate-control context is
/// looked up or updated and is therefore represented by `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RxRateControlRoute(u8);

impl RxRateControlRoute {
    pub(crate) const fn index(self) -> u8 {
        self.0
    }
}

/// Reproduce the complete route selection made from RX-control byte 3.
///
/// Bits outside `0x10 | 0x20 | 0x40` do not participate. This function owns
/// no state and performs no polling, waiting, allocation, or indirect call.
pub(crate) const fn rate_control_route(rx_flags: u8) -> Option<RxRateControlRoute> {
    if rx_flags & 0x10 != 0 {
        if rx_flags & 0x20 != 0 {
            None
        } else {
            Some(RxRateControlRoute(0))
        }
    } else if rx_flags & 0x20 != 0 {
        Some(RxRateControlRoute(1))
    } else if rx_flags & 0x40 != 0 {
        Some(RxRateControlRoute(2))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::rate_control_route;

    fn route(flags: u8) -> Option<u8> {
        rate_control_route(flags).map(|route| route.index())
    }

    #[test]
    fn reproduces_every_recovered_route_class() {
        assert_eq!(route(0x10), Some(0));
        assert_eq!(route(0x20), Some(1));
        assert_eq!(route(0x40), Some(2));
        assert_eq!(route(0x00), None);
        assert_eq!(route(0x30), None);
    }

    #[test]
    fn preserves_vendor_bit_precedence() {
        assert_eq!(route(0x50), Some(0));
        assert_eq!(route(0x60), Some(1));
        assert_eq!(route(0x70), None);
    }

    #[test]
    fn ignores_unrelated_rx_control_bits() {
        for unrelated in [0x01, 0x02, 0x04, 0x08, 0x80, 0x8f] {
            assert_eq!(route(unrelated), None);
            assert_eq!(route(unrelated | 0x10), Some(0));
            assert_eq!(route(unrelated | 0x20), Some(1));
            assert_eq!(route(unrelated | 0x40), Some(2));
        }
    }
}
