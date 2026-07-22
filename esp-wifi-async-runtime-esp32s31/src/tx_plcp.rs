/// Build the queue PLCP0 word for the guarded non-HE submission branch.
pub(crate) const fn basic_plcp0_word(metadata_address: usize, flags: u32) -> u32 {
    let mut word = (metadata_address as u32 & 0x000f_ffff) | 0x0060_0000;

    if flags & 0x0000_0402 != 0 || flags & 0x4048_0000 == 0x0040_0000 {
        return word;
    }

    let format = if flags & 0x0010_0000 != 0 {
        3
    } else {
        ((flags >> 19) & 1) + 1
    };
    word = (word & 0xf8ff_ffff) | (format << 24);
    word
}

/// Build the queue PLCP1 word for a rate already guarded to 16..=35.
pub(crate) const fn basic_plcp1_word(
    rate: u8,
    flags: u32,
    queue_word_low: u8,
    protection: u32,
) -> u32 {
    let mut word = if flags & 0x0100_0000 != 0 {
        0x0600_0000
    } else {
        0x0200_0000
    };

    word = (word & 0xfe01_ffff) | (queue_word_low as u32) << 17;
    word = (word & 0xfffe_0fff) | ((rate & 0x1f) as u32) << 12;
    if flags & 0x0000_4000 != 0 && protection & 0x0000_8000 != 0 {
        word |= 0x2000_0000;
    }
    word
}

#[cfg(test)]
mod tests {
    use super::{basic_plcp0_word, basic_plcp1_word};

    const ADDRESS: usize = 0x2f12_3456;
    const BASE: u32 = 0x0062_3456;

    #[test]
    fn masks_the_metadata_address_and_preserves_the_base_format() {
        assert_eq!(basic_plcp0_word(ADDRESS, 0x0000_0400), BASE);
        assert_eq!(basic_plcp0_word(ADDRESS, 0x0000_0002), BASE);
        assert_eq!(basic_plcp0_word(ADDRESS, 0x0040_0000), BASE);
    }

    #[test]
    fn reproduces_each_guarded_non_he_format() {
        assert_eq!(basic_plcp0_word(ADDRESS, 0), BASE | 0x0100_0000);
        assert_eq!(basic_plcp0_word(ADDRESS, 0x0008_0000), BASE | 0x0200_0000);
        assert_eq!(basic_plcp0_word(ADDRESS, 0x0010_0000), BASE | 0x0300_0000);
    }

    #[test]
    fn reproduces_basic_ht_plcp1_format_and_rate_fields() {
        assert_eq!(basic_plcp1_word(16, 0, 0, 0), 0x0201_0000);
        assert_eq!(basic_plcp1_word(35, 0x0100_0000, 0, 0), 0x0600_3000);
        assert_eq!(basic_plcp1_word(16, 0x0100_0000, 0x12, 0), 0x0625_0000);
    }

    #[test]
    fn sets_protection_only_when_both_guard_bits_are_present() {
        assert_eq!(basic_plcp1_word(16, 0x0000_4000, 0, 0), 0x0201_0000);
        assert_eq!(basic_plcp1_word(16, 0, 0, 0x0000_8000), 0x0201_0000);
        assert_eq!(
            basic_plcp1_word(16, 0x0000_4000, 0, 0x0000_8000),
            0x2201_0000
        );
    }
}
