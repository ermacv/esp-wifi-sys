#![no_std]
#![doc(html_logo_url = "https://avatars.githubusercontent.com/u/46717278")]
// bindgen generated code
#![allow(unnecessary_transmutes)]

pub mod c_types;
mod fmt;
pub mod include;

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of, MaybeUninit};

    use crate::include::wifi_sta_config_t;

    #[test]
    fn wifi_sta_config_matches_vendor_gcc_layout() {
        assert_eq!(size_of::<wifi_sta_config_t>(), 184);
        assert_eq!(offset_of!(wifi_sta_config_t, pmf_cfg), 128);
        assert_eq!(offset_of!(wifi_sta_config_t, _bitfield_1), 130);
        assert_eq!(offset_of!(wifi_sta_config_t, sae_pwe_h2e), 136);
        assert_eq!(offset_of!(wifi_sta_config_t, failure_retry_cnt), 144);
        assert_eq!(offset_of!(wifi_sta_config_t, _bitfield_2), 145);
        assert_eq!(offset_of!(wifi_sta_config_t, sae_h2e_identifier), 151);
    }

    #[test]
    fn he_mcs9_uses_vendor_byte_and_bit() {
        let mut config = unsafe { MaybeUninit::<wifi_sta_config_t>::zeroed().assume_init() };
        config.set_he_mcs9_enabled(1);

        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&config as *const wifi_sta_config_t).cast::<u8>(),
                size_of::<wifi_sta_config_t>(),
            )
        };

        assert_eq!(config.he_mcs9_enabled(), 1);
        assert_eq!(bytes[145] & (1 << 5), 1 << 5);
    }
}

#[cfg(feature = "sys-logs")]
#[no_mangle]
extern "C" fn __esp_radio_printf(tag: *const core::ffi::c_char, msg: *const core::ffi::c_char) {
    unsafe {
        info!(
            "{} {}",
            core::ffi::CStr::from_ptr(tag).to_str().unwrap(),
            core::ffi::CStr::from_ptr(msg).to_str().unwrap()
        );
    }
}

#[cfg(not(feature = "sys-logs"))]
#[no_mangle]
extern "C" fn __esp_radio_printf(_tag: *const core::ffi::c_char, _msg: *const core::ffi::c_char) {
    // nothing
}
