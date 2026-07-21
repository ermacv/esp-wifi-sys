/*
 * ESP32-S31 ECO0 functions below are exported by esp-rom-sys as absolute
 * linker-script assignments. LLD applies --wrap to those assignments too,
 * which would replace the Rust __wrap_* definition with the ROM address.
 *
 * Load this fragment after the esp-rom-sys ROM fragments. Calls through the
 * public name enter Rust, while pre-strict delegation uses the pinned ROM
 * address through __real_*. No ROM or vendor archive bytes are modified.
 */
__real_ieee80211_set_tx_pti = 0x2f800cb8;
ieee80211_set_tx_pti = __wrap_ieee80211_set_tx_pti;

__real_ieee80211_search_node = 0x2f800ca8;
ieee80211_search_node = __wrap_ieee80211_search_node;

__real_esf_buf_alloc = 0x2f800d1c;
esf_buf_alloc = __wrap_esf_buf_alloc;

__real_esf_buf_recycle = 0x2f800d24;
esf_buf_recycle = __wrap_esf_buf_recycle;

__real_hal_mac_get_txq_state = 0x2f800d3c;
hal_mac_get_txq_state = __wrap_hal_mac_get_txq_state;

__real_lmacTxDone = 0x2f800dec;
lmacTxDone = __wrap_lmacTxDone;

__real_pm_on_beacon_rx = 0x2f800e98;
pm_on_beacon_rx = __wrap_pm_on_beacon_rx;

__real_pm_on_data_tx = 0x2f800ea0;
pm_on_data_tx = __wrap_pm_on_data_tx;

__real_esp_test_tx_enab_statistics = 0x2f801144;
esp_test_tx_enab_statistics = __wrap_esp_test_tx_enab_statistics;
