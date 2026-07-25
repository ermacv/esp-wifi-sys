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

/* ESF alignment is another absolute ROM export. The strict Rust leaf keeps
 * the original address only for pre-handoff delegation. */
__real_ieee80211_align_eb = 0x2f800c7c;
EXTERN(wifi_strict_ieee80211_align_eb);
ieee80211_align_eb = wifi_strict_ieee80211_align_eb;

/* Like ieee80211_post_hmac_tx below, this ROM export captures the generated
 * __wrap symbol. Use a unique Rust boundary and keep the pinned ROM leaf only
 * for pre-strict cold-init delegation. */
__real_ieee80211_crypto_encap = 0x2f800cac;
EXTERN(wifi_strict_ieee80211_crypto_encap);
ieee80211_crypto_encap = wifi_strict_ieee80211_crypto_encap;

/* GNU --wrap cannot be used for this ROM export: it aliases the generated
 * __wrap symbol itself to 0x2f800cc0. Keep a separate pre-strict entry and
 * route the public name to the uniquely named Rust runtime boundary. */
__real_ieee80211_post_hmac_tx = 0x2f800cc0;
EXTERN(wifi_strict_ieee80211_post_hmac_tx);
ieee80211_post_hmac_tx = wifi_strict_ieee80211_post_hmac_tx;

__real_ets_delay_us = 0x2f80003c;
ets_delay_us = __wrap_ets_delay_us;

__real_esf_buf_alloc = 0x2f800d1c;
esf_buf_alloc = __wrap_esf_buf_alloc;

__real_esf_buf_recycle = 0x2f800d24;
esf_buf_recycle = __wrap_esf_buf_recycle;

__real_wDev_AppendRxBlocks = 0x2f8010c4;
wDev_AppendRxBlocks = __wrap_wDev_AppendRxBlocks;

__real_hal_mac_get_txq_state = 0x2f800d3c;
hal_mac_get_txq_state = __wrap_hal_mac_get_txq_state;

__real_hal_mac_get_txq_complete = 0x2f800d44;
hal_mac_get_txq_complete = __wrap_hal_mac_get_txq_complete;

__real_lmacTxDone = 0x2f800dec;
lmacTxDone = __wrap_lmacTxDone;

__real_pm_on_beacon_rx = 0x2f800e98;
pm_on_beacon_rx = __wrap_pm_on_beacon_rx;

__real_pm_on_data_rx = 0x2f800e9c;
pm_on_data_rx = __wrap_pm_on_data_rx;

__real_pm_on_data_tx = 0x2f800ea0;
pm_on_data_tx = __wrap_pm_on_data_tx;

/* This leaf is replaced directly rather than through --wrap: the ROM export
 * otherwise defines __wrap_ppTxProtoProc itself before LTO can retain Rust. */
EXTERN(wifi_strict_pp_tx_proto_proc);
ppTxProtoProc = wifi_strict_pp_tx_proto_proc;

EXTERN(wifi_strict_pp_proc_tx_sec_frame);
ppProcTxSecFrame = wifi_strict_pp_proc_tx_sec_frame;

__real_esp_test_tx_enab_statistics = 0x2f801144;
esp_test_tx_enab_statistics = __wrap_esp_test_tx_enab_statistics;

__real_esp_test_rx_process_complete = 0x2f801158;
esp_test_rx_process_complete = __wrap_esp_test_rx_process_complete;

__real_esp_test_rx_parse_mu = 0x2f801178;
esp_test_rx_parse_mu = __wrap_esp_test_rx_parse_mu;
