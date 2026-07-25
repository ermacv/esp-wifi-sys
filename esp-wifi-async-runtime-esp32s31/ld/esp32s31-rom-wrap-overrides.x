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

/* The ROM linker fragment exports ieee80211_set_tx_desc as an absolute
 * assignment and consequently captures GNU --wrap's generated __wrap symbol.
 * Route the public name through a unique Rust boundary and retain the pinned
 * ROM address only for calls made before strict ownership handoff. */
__real_ieee80211_set_tx_desc = 0x2f800c98;
EXTERN(wifi_strict_ieee80211_set_tx_desc);
ieee80211_set_tx_desc = wifi_strict_ieee80211_set_tx_desc;
ASSERT(ieee80211_set_tx_desc == wifi_strict_ieee80211_set_tx_desc,
       "ESP32-S31 ieee80211_set_tx_desc Rust boundary is inactive");

/* ESF alignment is another absolute ROM export. The strict Rust leaf keeps
 * the original address only for pre-handoff delegation. */
__real_ieee80211_align_eb = 0x2f800c7c;
EXTERN(wifi_strict_ieee80211_align_eb);
ieee80211_align_eb = wifi_strict_ieee80211_align_eb;
ASSERT(ieee80211_align_eb == wifi_strict_ieee80211_align_eb,
       "ESP32-S31 ieee80211_align_eb Rust boundary is inactive");

/* Like ieee80211_post_hmac_tx below, this ROM export captures the generated
 * __wrap symbol. Use a unique Rust boundary and keep the pinned ROM leaf only
 * for pre-strict cold-init delegation. */
__real_ieee80211_crypto_encap = 0x2f800cac;
EXTERN(wifi_strict_ieee80211_crypto_encap);
ieee80211_crypto_encap = wifi_strict_ieee80211_crypto_encap;
ASSERT(ieee80211_crypto_encap == wifi_strict_ieee80211_crypto_encap,
       "ESP32-S31 ieee80211_crypto_encap Rust boundary is inactive");

/* GNU --wrap cannot be used for this ROM export: it aliases the generated
 * __wrap symbol itself to 0x2f800cc0. Keep a separate pre-strict entry and
 * route the public name to the uniquely named Rust runtime boundary. */
__real_ieee80211_post_hmac_tx = 0x2f800cc0;
EXTERN(wifi_strict_ieee80211_post_hmac_tx);
ieee80211_post_hmac_tx = wifi_strict_ieee80211_post_hmac_tx;
ASSERT(ieee80211_post_hmac_tx == wifi_strict_ieee80211_post_hmac_tx,
       "ESP32-S31 ieee80211_post_hmac_tx Rust boundary is inactive");

__real_ets_delay_us = 0x2f80003c;
ets_delay_us = __wrap_ets_delay_us;

__real_esf_buf_alloc = 0x2f800d1c;
esf_buf_alloc = __wrap_esf_buf_alloc;

__real_esf_buf_recycle = 0x2f800d24;
esf_buf_recycle = __wrap_esf_buf_recycle;

/* This public PP leaf is also an absolute ROM export. The pinned libpp.a
 * reference body proves its complete fourteen-byte field transform, but GNU
 * --wrap would rename the ROM assignment itself. Route every public call to
 * a unique Rust owner and retain the ROM address only for cold delegation. */
__real_ppRecycleRxPkt = 0x2f800f98;
EXTERN(wifi_strict_pp_recycle_rx_pkt);
ppRecycleRxPkt = wifi_strict_pp_recycle_rx_pkt;
ASSERT(ppRecycleRxPkt == wifi_strict_pp_recycle_rx_pkt,
       "ESP32-S31 ppRecycleRxPkt Rust boundary is inactive");

/* libpp.a[if_hwctrl.o]::esp_wifi_internal_free_rx_buffer is only an
 * eight-byte tail-call to ppRecycleRxPkt. Publish the Rust owner directly so
 * the archive object is not extracted and no redundant vendor boundary
 * remains on the network-buffer Drop path. */
EXTERN(wifi_strict_esp_wifi_internal_free_rx_buffer);
esp_wifi_internal_free_rx_buffer =
    wifi_strict_esp_wifi_internal_free_rx_buffer;
ASSERT(esp_wifi_internal_free_rx_buffer ==
           wifi_strict_esp_wifi_internal_free_rx_buffer,
       "ESP32-S31 free RX buffer Rust boundary is inactive");
/* The RX callback is published through a mutable WDEV table rather than a
 * normal final-link relocation. Keep its unique symbol so the strict audit
 * can prove both the publication target and its internal-SRAM placement. */
EXTERN(wifi_strict_lmac_rx_done);

__real_wDev_AppendRxBlocks = 0x2f8010c4;
wDev_AppendRxBlocks = __wrap_wDev_AppendRxBlocks;

/* wDev_DiscardFrame is the adjacent absolute ROM export. GNU --wrap would
 * capture the generated __wrap symbol at 0x2f8010c8 and discard the Rust
 * body. Retain that address only for cold delegation and publish the unique
 * SRAM Rust ownership boundary after all ROM fragments. */
__real_wDev_DiscardFrame = 0x2f8010c8;
EXTERN(wifi_strict_wdev_discard_frame);
wDev_DiscardFrame = wifi_strict_wdev_discard_frame;
ASSERT(wDev_DiscardFrame == wifi_strict_wdev_discard_frame,
       "ESP32-S31 wDev_DiscardFrame Rust boundary is inactive");

/* The remaining successful-RX aggregate is an absolute ROM export too.
 * Retain its pinned body as the current protocol oracle, but force every
 * caller through the SRAM Rust metadata decoder so each subsequently ported
 * routing branch has an explicit, measurable boundary. */
__real_wDev_ProcessRxSucData = 0x2f8010f4;
EXTERN(wifi_strict_wdev_process_rx_success_data);
wDev_ProcessRxSucData = wifi_strict_wdev_process_rx_success_data;
ASSERT(wDev_ProcessRxSucData == wifi_strict_wdev_process_rx_success_data,
       "ESP32-S31 wDev_ProcessRxSucData Rust boundary is inactive");

__real_hal_mac_get_txq_state = 0x2f800d3c;
hal_mac_get_txq_state = __wrap_hal_mac_get_txq_state;

__real_hal_mac_get_txq_complete = 0x2f800d44;
hal_mac_get_txq_complete = __wrap_hal_mac_get_txq_complete;

__real_lmacTxDone = 0x2f800dec;
lmacTxDone = __wrap_lmacTxDone;

/* TX rate completion is an absolute ROM export even though the pinned archive
 * also contains its reference body. Keep the ROM entry only as an oracle and
 * route runtime calls to the unique finite Rust adapter. */
__real_rcUpdateTxDone = 0x2f80106c;
EXTERN(wifi_strict_rc_update_tx_done);
rcUpdateTxDone = wifi_strict_rc_update_tx_done;
ASSERT(rcUpdateTxDone == wifi_strict_rc_update_tx_done,
       "ESP32-S31 rcUpdateTxDone Rust boundary is inactive");

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

__real_esp_test_set_rx_error_occurs = 0x2f801164;
EXTERN(wifi_strict_esp_test_set_rx_error_occurs);
esp_test_set_rx_error_occurs = wifi_strict_esp_test_set_rx_error_occurs;
ASSERT(esp_test_set_rx_error_occurs == wifi_strict_esp_test_set_rx_error_occurs,
       "ESP32-S31 RX error diagnostic Rust boundary is inactive");

__real_esp_test_rx_process_complete = 0x2f801158;
esp_test_rx_process_complete = __wrap_esp_test_rx_process_complete;

__real_esp_test_rx_parse_mu = 0x2f801178;
esp_test_rx_parse_mu = __wrap_esp_test_rx_parse_mu;
