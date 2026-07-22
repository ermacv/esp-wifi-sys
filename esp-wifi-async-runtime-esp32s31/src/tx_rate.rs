#[cfg(target_arch = "riscv32")]
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(target_arch = "riscv32")]
const RATE_CONTEXT_PRIMARY_RATE_OFFSET: usize = 0x08;
#[cfg(target_arch = "riscv32")]
const RATE_CONTEXT_SECONDARY_RATE_OFFSET: usize = 0x09;
#[cfg(target_arch = "riscv32")]
const RATE_CONTEXT_MODE_OFFSET: usize = 0x0c;
#[cfg(target_arch = "riscv32")]
const RATE_CONTEXT_PRIMARY_SCHEDULE_OFFSET: usize = 0x64;
#[cfg(target_arch = "riscv32")]
const RATE_CONTEXT_SECONDARY_SCHEDULE_OFFSET: usize = 0x68;
#[cfg(target_arch = "riscv32")]
const DESCRIPTOR_SELECTED_RATE_OFFSET: usize = 0x0c;
#[cfg(target_arch = "riscv32")]
const DESCRIPTOR_SCHEDULE_OFFSET: usize = 0x1c;
#[cfg(target_arch = "riscv32")]
const DESCRIPTOR_RATE_CLASS_OFFSET: usize = 0x2f;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FixedRateScheduleSnapshot {
    pub primary_fixed: u32,
    pub secondary_stateless: u32,
    pub vendor_fallbacks: u32,
}

#[cfg(target_arch = "riscv32")]
static FIXED_RATE_PRIMARY: AtomicU32 = AtomicU32::new(0);
#[cfg(target_arch = "riscv32")]
static FIXED_RATE_SECONDARY: AtomicU32 = AtomicU32::new(0);
#[cfg(target_arch = "riscv32")]
static DYNAMIC_RATE_FALLBACKS: AtomicU32 = AtomicU32::new(0);

#[cfg(target_arch = "riscv32")]
pub fn fixed_rate_schedule_snapshot() -> FixedRateScheduleSnapshot {
    FixedRateScheduleSnapshot {
        primary_fixed: FIXED_RATE_PRIMARY.load(Ordering::Acquire),
        secondary_stateless: FIXED_RATE_SECONDARY.load(Ordering::Acquire),
        vendor_fallbacks: DYNAMIC_RATE_FALLBACKS.load(Ordering::Acquire),
    }
}

/// Record a temporary HIL delegation to the pinned adaptive-rate body.
///
/// This counter exists only to prove that enabling both fixed-rate modes
/// closes every active STA submission branch before the fallback is removed.
#[cfg(target_arch = "riscv32")]
pub fn record_dynamic_rate_schedule_fallback() {
    DYNAMIC_RATE_FALLBACKS.fetch_add(1, Ordering::Relaxed);
}

const fn rate_class_bits(previous: u8, rate: u8) -> u8 {
    if rate <= 7 {
        previous & !0x78
    } else if rate <= 15 {
        (previous & !0x78) | 0x08
    } else if rate <= 40 {
        previous
    } else {
        (previous & !0x78) | 0x50
    }
}

const fn stateless_schedule_rate(
    primary: bool,
    mode: u16,
    descriptor_flags: u32,
    configured_rate: u8,
    schedule_rate: u8,
) -> Option<u8> {
    if primary {
        return if mode & 0x01 != 0 {
            Some(configured_rate)
        } else {
            None
        };
    }
    if mode & 0x02 != 0 {
        return Some(configured_rate);
    }
    // The ordinary secondary branch in the pinned body is already stateless:
    // absent its adaptive/special-mode guards, it selects schedule[0]. This
    // covers measured auth, association, EAPOL, Action and secondary data.
    if mode & 0x80 == 0 && descriptor_flags & 0x0020_0800 == 0 {
        Some(schedule_rate)
    } else {
        None
    }
}

/// Recovered fixed-rate branches of the pinned `rcGetSched` implementation.
///
/// Returns `false` without modifying the descriptor if the selected branch is
/// still configured for adaptive rate control. The HIL wrapper may then call
/// the vendor oracle while measuring whether that branch remains reachable.
///
/// # Safety
///
/// `rate_context` and `descriptor` must point to live pinned vendor objects
/// exclusively owned by the current run-to-completion TX submission.
#[cfg(target_arch = "riscv32")]
#[link_section = ".rwtext.wifi_strict.tx_rate_schedule"]
pub unsafe fn try_fixed_rate_schedule(rate_context: *mut u8, descriptor: *mut u8) -> bool {
    if rate_context.is_null() || descriptor.is_null() {
        return false;
    }

    let descriptor_flags = descriptor.cast::<u32>().read_unaligned();
    let primary = descriptor_flags & 0x0200_0008 == 0x0000_0008;
    let (rate_offset, schedule_offset) = if primary {
        (
            RATE_CONTEXT_PRIMARY_RATE_OFFSET,
            RATE_CONTEXT_PRIMARY_SCHEDULE_OFFSET,
        )
    } else {
        (
            RATE_CONTEXT_SECONDARY_RATE_OFFSET,
            RATE_CONTEXT_SECONDARY_SCHEDULE_OFFSET,
        )
    };
    let mode = rate_context
        .add(RATE_CONTEXT_MODE_OFFSET)
        .cast::<u16>()
        .read_unaligned();
    let schedule = rate_context
        .add(schedule_offset)
        .cast::<*mut u8>()
        .read_unaligned();
    if schedule.is_null() {
        return false;
    }
    let Some(rate) = stateless_schedule_rate(
        primary,
        mode,
        descriptor_flags,
        rate_context.add(rate_offset).read(),
        schedule.read(),
    ) else {
        return false;
    };
    let class = descriptor.add(DESCRIPTOR_RATE_CLASS_OFFSET).read();

    descriptor
        .add(DESCRIPTOR_SCHEDULE_OFFSET)
        .cast::<*mut u8>()
        .write_unaligned(schedule);
    descriptor.add(DESCRIPTOR_SELECTED_RATE_OFFSET).write(rate);
    descriptor
        .add(DESCRIPTOR_RATE_CLASS_OFFSET)
        .write(rate_class_bits(class, rate));

    if primary {
        FIXED_RATE_PRIMARY.fetch_add(1, Ordering::Relaxed);
    } else {
        FIXED_RATE_SECONDARY.fetch_add(1, Ordering::Relaxed);
    }
    true
}

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
    use super::{basic_non_he_rts_rate, rate_class_bits, stateless_schedule_rate};

    #[test]
    fn admits_only_recovered_stateless_schedule_branches() {
        assert_eq!(stateless_schedule_rate(true, 1, 0x2009, 33, 0), Some(33));
        assert_eq!(stateless_schedule_rate(true, 0, 0x2009, 33, 0), None);
        assert_eq!(stateless_schedule_rate(false, 0, 0, 33, 0), Some(0));
        assert_eq!(
            stateless_schedule_rate(false, 0, 0x0200_200c, 33, 0),
            Some(0)
        );
        assert_eq!(stateless_schedule_rate(false, 2, 0, 7, 0), Some(7));
        assert_eq!(stateless_schedule_rate(false, 0x80, 0, 7, 0), None);
        assert_eq!(stateless_schedule_rate(false, 0, 0x0000_0800, 7, 0), None);
    }

    #[test]
    fn reproduces_rc_get_sched_rate_classes() {
        assert_eq!(rate_class_bits(0xff, 7), 0x87);
        assert_eq!(rate_class_bits(0xff, 8), 0x8f);
        assert_eq!(rate_class_bits(0x35, 16), 0x35);
        assert_eq!(rate_class_bits(0x35, 40), 0x35);
        assert_eq!(rate_class_bits(0xff, 41), 0xd7);
    }

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
