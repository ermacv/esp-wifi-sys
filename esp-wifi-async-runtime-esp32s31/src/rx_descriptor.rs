const LENGTH_MASK: u32 = 0x0000_3fff;
const PRESERVE_MASK: u32 = 0xf000_3fff;
const OWNER_BIT: u32 = 1 << 31;
const END_BITS: u32 = (1 << 30) | (1 << 29);

/// Reproduce the pinned S31 RX recycle descriptor transformation.
///
/// This leaf is deliberately independent of global state, registers and raw
/// pointers. The hardware boundary in `wdev` owns the unsafe descriptor load
/// and store; the bit-level operation remains host-testable safe Rust.
pub(crate) const fn recycled_descriptor_word(word: u32) -> u32 {
    let length = word & LENGTH_MASK;
    ((word | OWNER_BIT) & !END_BITS & PRESERVE_MASK) | (length << 14)
}

pub(crate) const fn descriptor_buffer_length(word: u32) -> usize {
    (word & LENGTH_MASK) as usize
}

pub(crate) const fn descriptor_owned_by_hardware(word: u32) -> bool {
    word & OWNER_BIT != 0
}

#[cfg(test)]
mod tests {
    use super::{
        descriptor_buffer_length, descriptor_owned_by_hardware, recycled_descriptor_word,
    };

    #[test]
    fn recycle_word_matches_the_pinned_vendor_bit_sequence() {
        for word in [0, 1, 0x0000_3fff, 0x6000_1234, 0x9abc_def0, u32::MAX] {
            let mut expected = word | (1 << 31);
            expected &= !(1 << 30);
            expected &= !(1 << 29);
            let length = expected & 0x3fff;
            expected = (expected & 0xf000_3fff) | (length << 14);
            assert_eq!(recycled_descriptor_word(word), expected);
            assert_eq!(descriptor_buffer_length(word), (word & 0x3fff) as usize);
        }
    }

    #[test]
    fn owner_bit_is_the_only_terminal_restart_authority() {
        assert!(!descriptor_owned_by_hardware(0));
        assert!(!descriptor_owned_by_hardware(0x7fff_ffff));
        assert!(descriptor_owned_by_hardware(0x8000_0000));
        assert!(descriptor_owned_by_hardware(u32::MAX));
    }
}
