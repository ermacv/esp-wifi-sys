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

#[cfg(test)]
mod tests {
    use super::basic_plcp0_word;

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
}
