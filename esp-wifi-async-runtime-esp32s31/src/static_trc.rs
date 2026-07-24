//! Fixed ownership for the three default transmit-rate-control contexts.
//!
//! The pinned `trc_init` allocates three zeroed 0x98-byte objects and publishes
//! them at `g_per_conn_trc[19..=21]`. It then writes the same schedule pointers,
//! flags and interface identities into each object. The strict runtime uses
//! these default STA/AP/NAN contexts but never creates per-peer adaptive-rate
//! contexts after handoff.

use core::ptr;

const TRC_CONTEXT_SIZE: usize = 0x98;
const TRC_CONTEXT_COUNT: usize = 3;
const TRC_DEFAULT_INDEX: usize = 19;
const PRIMARY_RATE_OFFSET: usize = 0x64;
const SECONDARY_RATE_OFFSET: usize = 0x68;
const FALLBACK_RATE_OFFSET: usize = 0x6c;
const P2P_RATE_OFFSET: usize = 0x70;
const LEGACY_RATE_OFFSET: usize = 0x74;
const FLAGS_OFFSET: usize = 0x0c;
const CURRENT_RATE_OFFSET: usize = 0x28;
const IDENTITY_OFFSET: usize = 0x85;
const FINAL_STATE_OFFSET: usize = 0x87;
const ESP_OK: i32 = 0;
const ESP_ERR_WIFI_STATE: i32 = 0x3006;

#[repr(C, align(4))]
struct StaticTrcContext([u8; TRC_CONTEXT_SIZE]);

#[link_section = ".critical.bss.wifi_strict.trc_default_contexts"]
static mut STATIC_TRC_CONTEXTS: [StaticTrcContext; TRC_CONTEXT_COUNT] = [
    StaticTrcContext([0; TRC_CONTEXT_SIZE]),
    StaticTrcContext([0; TRC_CONTEXT_SIZE]),
    StaticTrcContext([0; TRC_CONTEXT_SIZE]),
];

unsafe extern "C" {
    static mut g_per_conn_trc: u8;
    static rc11BSchedTbl: u8;
    static rcP2P11GSchedTbl: u8;
}

unsafe fn table_slot(index: usize) -> *mut *mut u8 {
    ptr::addr_of_mut!(g_per_conn_trc)
        .add(index * size_of::<*mut u8>())
        .cast::<*mut u8>()
}

unsafe fn context(index: usize) -> *mut u8 {
    ptr::addr_of_mut!(STATIC_TRC_CONTEXTS)
        .cast::<u8>()
        .add(index * TRC_CONTEXT_SIZE)
}

unsafe fn initialize_context(context: *mut u8, identity: u8) {
    let legacy = ptr::addr_of!(rc11BSchedTbl) as u32;
    let primary = ptr::addr_of!(rc11BSchedTbl).add(0x24) as u32;
    let p2p = ptr::addr_of!(rcP2P11GSchedTbl).add(0x54) as u32;
    for offset in [PRIMARY_RATE_OFFSET, SECONDARY_RATE_OFFSET, FALLBACK_RATE_OFFSET] {
        context.add(offset).cast::<u32>().write_unaligned(primary);
    }
    context
        .add(P2P_RATE_OFFSET)
        .cast::<u32>()
        .write_unaligned(p2p);
    context
        .add(LEGACY_RATE_OFFSET)
        .cast::<u32>()
        .write_unaligned(legacy);
    context
        .add(FLAGS_OFFSET)
        .cast::<u16>()
        .write_unaligned(0x80);
    context.add(CURRENT_RATE_OFFSET).write(0);
    context.add(FINAL_STATE_OFFSET).write(0);
    context.add(IDENTITY_OFFSET).write(identity);
}

/// Return whether all three default table cells own the fixed Rust contexts.
///
/// # Safety
///
/// The caller must serialize this check with Wi-Fi initialization teardown.
pub unsafe fn static_trc_contexts_bound() -> bool {
    (0..TRC_CONTEXT_COUNT).all(|index| {
        table_slot(TRC_DEFAULT_INDEX + index).read_volatile() == context(index)
    })
}

/// Replace the three-allocation vendor default-context initializer.
#[cfg(feature = "rust-static-trc-init-interpose")]
#[no_mangle]
pub unsafe extern "C" fn __wrap_trc_init() -> i32 {
    if (0..TRC_CONTEXT_COUNT)
        .any(|index| !table_slot(TRC_DEFAULT_INDEX + index).read_volatile().is_null())
    {
        return ESP_ERR_WIFI_STATE;
    }
    ptr::addr_of_mut!(STATIC_TRC_CONTEXTS)
        .cast::<u8>()
        .write_bytes(0, TRC_CONTEXT_SIZE * TRC_CONTEXT_COUNT);
    for index in 0..TRC_CONTEXT_COUNT {
        let context = context(index);
        initialize_context(context, index as u8);
        table_slot(TRC_DEFAULT_INDEX + index).write_volatile(context);
    }
    ESP_OK
}

/// Withdraw only the three exact fixed publications.
///
/// Any changed pointer fails closed: the strict owner never delegates an
/// unknown object to `free`.
#[cfg(feature = "rust-static-trc-init-interpose")]
#[no_mangle]
pub unsafe extern "C" fn __wrap_trc_deinit() -> i32 {
    if !static_trc_contexts_bound() {
        return ESP_ERR_WIFI_STATE;
    }
    for index in 0..TRC_CONTEXT_COUNT {
        table_slot(TRC_DEFAULT_INDEX + index).write_volatile(ptr::null_mut());
    }
    ESP_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_context_arena_has_exact_vendor_shape() {
        assert_eq!(size_of::<StaticTrcContext>(), TRC_CONTEXT_SIZE);
        assert_eq!(align_of::<StaticTrcContext>(), 4);
        assert_eq!(
            size_of::<[StaticTrcContext; TRC_CONTEXT_COUNT]>(),
            TRC_CONTEXT_SIZE * TRC_CONTEXT_COUNT
        );
    }

    #[test]
    fn recovered_fields_fit_the_fixed_context() {
        for offset in [
            PRIMARY_RATE_OFFSET,
            SECONDARY_RATE_OFFSET,
            FALLBACK_RATE_OFFSET,
            P2P_RATE_OFFSET,
            LEGACY_RATE_OFFSET,
        ] {
            assert!(offset + size_of::<u32>() <= TRC_CONTEXT_SIZE);
        }
        assert!(IDENTITY_OFFSET < TRC_CONTEXT_SIZE);
        assert!(FINAL_STATE_OFFSET < TRC_CONTEXT_SIZE);
    }
}
