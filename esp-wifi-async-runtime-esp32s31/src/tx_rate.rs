/// Recovered finite body of the vendor `mac_tx_get_rts_rate` leaf for every
/// non-HE rate admitted by the strict runtime.
pub(crate) const fn basic_non_he_rts_rate(rate: u8) -> Option<u8> {
    if rate <= 7 {
        return Some(match rate {
            0 | 4 => 0,
            1..=3 => 1,
            _ => 5,
        });
    }
    if rate <= 15 {
        return Some(match rate {
            8 | 9 | 12 | 13 => 9,
            10 | 14 => 10,
            _ => 11,
        });
    }
    if rate > 35 {
        return None;
    }
    let mcs = (rate - 16) % 10;
    Some(if mcs == 0 {
        11
    } else if mcs <= 2 {
        10
    } else {
        9
    })
}

#[cfg(test)]
mod tests {
    use super::basic_non_he_rts_rate;

    #[test]
    fn reproduces_every_legacy_rate() {
        let expected = [0, 1, 1, 1, 0, 5, 5, 5, 9, 9, 10, 11, 9, 9, 10, 11];
        for (rate, expected_rate) in expected.into_iter().enumerate() {
            assert_eq!(basic_non_he_rts_rate(rate as u8), Some(expected_rate));
        }
    }

    #[test]
    fn reproduces_every_strict_basic_ht_rate() {
        let expected = [
            11, 10, 10, 9, 9, 9, 9, 9, 9, 9, 11, 10, 10, 9, 9, 9, 9, 9, 9, 9,
        ];

        for (offset, expected_rate) in expected.into_iter().enumerate() {
            let rate = 16 + offset as u8;
            assert_eq!(basic_non_he_rts_rate(rate), Some(expected_rate));
        }
    }

    #[test]
    fn rejects_he_and_invalid_rates() {
        for rate in 36..=u8::MAX {
            assert_eq!(basic_non_he_rts_rate(rate), None);
        }
    }
}
