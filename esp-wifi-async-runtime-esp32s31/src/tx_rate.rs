/// Recovered basic-HT branch of the vendor `mac_tx_get_rts_rate` leaf.
///
/// Rates outside the strict runtime's 16..=35 submission range are rejected
/// instead of reproducing unused legacy-rate behavior.
pub(crate) const fn basic_ht_rts_rate(rate: u8) -> Option<u8> {
    match rate {
        16 | 26 => Some(11),
        17 | 18 | 27 | 28 => Some(10),
        19..=25 | 29..=35 => Some(9),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::basic_ht_rts_rate;

    #[test]
    fn reproduces_every_strict_basic_ht_rate() {
        let expected = [
            11, 10, 10, 9, 9, 9, 9, 9, 9, 9, 11, 10, 10, 9, 9, 9, 9, 9, 9, 9,
        ];

        for (offset, expected_rate) in expected.into_iter().enumerate() {
            let rate = 16 + offset as u8;
            assert_eq!(basic_ht_rts_rate(rate), Some(expected_rate));
        }
    }

    #[test]
    fn rejects_rates_outside_the_strict_branch() {
        for rate in 0..16 {
            assert_eq!(basic_ht_rts_rate(rate), None);
        }
        for rate in 36..=u8::MAX {
            assert_eq!(basic_ht_rts_rate(rate), None);
        }
    }
}
