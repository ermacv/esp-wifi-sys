# ESP32-S31 linked state and interposition audit

- final ELF: `wifi-sta`
- ELF SHA-256: `57d1cec8fb648f99c0939aede499ee7bc735011153734ed2522c820f1474120f`
- strict vendor roots: 30
- separately auditable static-binding roots: `net80211_data_ptr_init`, `wdev_data_init`
- separately auditable static-PM root: `pm_beacon_offset_funcs_init`
- vendor functions reachable from those roots: 53
- live mutable blob globals reached by strict leaves: 5 symbols / 3004 bytes
- ROM-ABI mutable indirection cells reached by strict leaves: 5 cells / 20 inferred bytes
- fixed cold-init bindings live in this ELF: 43 / 43
- live mutable blob globals outside the strict-root graph: 180 symbols / 19199 bytes
- Rust strict static sections: 44 sections / 181513 bytes
- retained code wrappers: 64

The archive relocation graph supplies `vendor function -> data symbol`; the final ELF supplies liveness, address, size and section. A wrapper boundary stops traversal into the replaced vendor body. “Outside strict roots” means linked but not proven runtime-reachable by this vendor-leaf graph; it is not automatically safe to delete because cold initialization and non-Wi-Fi owners can still use it.
Run `audit-strict-esp32s31 --include-static-binding-init --include-static-pm-init --enforce` to prove the fixed-storage cold-init leaves together with the runtime roots.

## Mutable blob state reached by strict vendor leaves

| symbol | size | placement | archive owner | strict referrers |
|---|---:|---|---|---|
| `phy_param` | 508 | `internal SRAM` / `.data` | `libphy.a[phy_init.o]` | `phy_chip_set_chan` |
| `TxRxCxt` | 1044 | `internal SRAM` / `.data` | `libpp.a[pp.o]` | `ppDequeueRxq_Locked`, `ppDequeueTxQ` |
| `wDevCtrl` | 72 | `internal SRAM` / `.data` | `libpp.a[wdev.o]` | `esp_test_set_rx_error_occurs`, `rcUpdateTxDone` |
| `g_ic` | 788 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211.o]` | `ieee80211_hostapd_data_txcb`, `ieee80211_post_hmac_tx`, `ieee80211_set_tx_desc` |
| `gChmCxt` | 592 | `internal SRAM` / `.bss` | `libnet80211.a[wl_chm.o]` | `chm_get_chan_info`, `chm_get_home_channel` |

## Mutable ROM-ABI indirection cells reached by strict leaves

These absolute symbols name four-byte pointer/callback cells in the S31 ROM ABI RAM table. They are state even though `llvm-nm` reports linker kind `A`. A conventional `*_ptr -> *` backing is shown when the backing object is present in the ELF.

| cell | address | inferred backing | strict referrers |
|---|---:|---|---|
| `esp_test_rx_error_occurs` | `0x2f07fc84` | RX diagnostic scalar | `esp_test_set_rx_error_occurs` |
| `g_osi_funcs_p` | `0x2f07ff44` | Rust-installed strict OSI table pointer | `hal_crypto_set_key_entry` |
| `pTxRx` | `0x2f07ff58` | `TxRxCxt` | `ppDequeueRxq_Locked`, `ppDequeueTxQ` |
| `s_netstack_free` | `0x2f07ff78` | registered netstack-free callback | `ieee80211_recycle_cache_eb` |
| `g_chm` | `0x2f07ff88` | `gChmCxt` | `chm_get_chan_info`, `chm_get_home_channel` |

## Fixed cold-init state bindings

These are the exact direct stores recovered from the two separately audited cold-init leaves. The Rust interposition path publishes the same backing addresses without calling either vendor body.

| published pointer cell | address | fixed backing | bytes | placement |
|---|---:|---|---:|---|
| `g_wifi_nvs` | `0x2f016794` | `s_wifi_nvs` | 1440 | `internal SRAM` / `.bss` |
| `g_scan` | `0x2f07ff8c` | `gScanStruct` | 284 | `internal SRAM` / `.bss` |
| `g_chm` | `0x2f07ff88` | `gChmCxt` | 592 | `internal SRAM` / `.bss` |
| `g_ic_ptr` | `0x2f07ff84` | `g_ic` | 788 | `internal SRAM` / `.bss` |
| `g_hmac_cnt_ptr` | `0x2f07ff80` | `g_hmac_cnt` | 64 | `internal SRAM` / `.bss` |
| `g_tx_cacheq_ptr` | `0x2f07ff7c` | `s_tx_cacheq` | 8 | `internal SRAM` / `.bss` |
| `g_mac_sleep_en_ptr` | `0x2f07fed4` | `g_mac_sleep_en` | 1 | `internal SRAM` / `.bss` |
| `g_esp_mesh_quick_funcs_ptr` | `0x2f07fedc` | `esp_mesh_quick_funcs` | 176 | `internal SRAM` / `.bss` |
| `g_mesh_init_ps_type_ptr` | `0x2f07fec8` | `g_mesh_init_ps_type` | 4 | `internal SRAM` / `.data.wifi` |
| `g_mesh_is_started_ptr` | `0x2f07fec4` | `g_mesh_is_started` | 1 | `internal SRAM` / `.data.wifi` |
| `g_mesh_is_root_ptr` | `0x2f07fed0` | `g_mesh_is_root` | 1 | `internal SRAM` / `.data.wifi` |
| `g_mesh_topology_ptr` | `0x2f07fecc` | `g_mesh_topology` | 4 | `internal SRAM` / `.bss` |
| `pTxRx` | `0x2f07ff58` | `TxRxCxt` | 1044 | `internal SRAM` / `.data` |
| `lmacConfMib_ptr` | `0x2f07ff54` | `lmacConfMib` | 48 | `internal SRAM` / `.data` |
| `wDevCtrl_ptr` | `0x2f07ff40` | `wDevCtrl` | 72 | `internal SRAM` / `.data` |
| `wDevMacSleep_ptr` | `0x2f07ff3c` | `wDevMacSleep` | 120 | `internal SRAM` / `.bss` |
| `g_lmac_cnt_ptr` | `0x2f07ff38` | `g_lmac_cnt` | 192 | `internal SRAM` / `.bss` |
| `pp_sig_cnt_ptr` | `0x2f07ff34` | `pp_sig_cnt` | 36 | `internal SRAM` / `.data.wifi` |
| `g_wifi_menuconfig_ptr` | `0x2f07fef0` | `g_wifi_menuconfig` | 104 | `internal SRAM` / `.bss` |
| `g_eb_list_desc_ptr` | `0x2f07ff30` | `g_eb_list_desc` | 220 | `internal SRAM` / `.data` |
| `s_fragment_ptr` | `0x2f07ff2c` | `s_fragment` | 16 | `internal SRAM` / `.bss` |
| `if_ctrl_ptr` | `0x2f07ff28` | `if_ctrl` | 40 | `internal SRAM` / `.bss` |
| `ap_no_lr_ptr` | `0x2f07ff08` | `ap_no_lr` | 1 | `internal SRAM` / `.bss` |
| `rcLoRaSchedTbl_ptr` | `0x2f07fefc` | `rcLoRaSchedTbl` | 24 | `internal SRAM` / `.data` |
| `rc11NSchedTbl_ptr` | `0x2f07ff00` | `rc11NSchedTbl` | 168 | `internal SRAM` / `.data` |
| `rc11BSchedTbl_ptr` | `0x2f07ff04` | `rc11BSchedTbl` | 72 | `internal SRAM` / `.data` |
| `BasicOFDMSched_ptr` | `0x2f07fef8` | `BasicOFDMSched` | 12 | `internal SRAM` / `.data` |
| `trc_ctl_ptr` | `0x2f07fef4` | `trc_ctl` | 28 | `internal SRAM` / `.data` |
| `g_pm_cfg_ptr` | `0x2f07fee4` | `g_pm_cfg` | 88 | `internal SRAM` / `.data` |
| `g_pm_ptr` | `0x2f07fee8` | `g_pm` | 1176 | `internal SRAM` / `.bss` |
| `g_txop_queue_status_ptr` | `0x2f07fed8` | `g_txop_queue_status` | 3 | `internal SRAM` / `.data` |
| `g_pm_cnt_ptr` | `0x2f07feec` | `g_pm_cnt` | 72 | `internal SRAM` / `.bss` |
| `g_pp_timer_info_ptr` | `0x2f07fc7c` | `g_pp_timer_info` | 136 | `internal SRAM` / `.data` |
| `g_rts_threshold_bytes_ptr` | `0x2f07fc78` | `g_rts_threshold_bytes` | 120 | `internal SRAM` / `.bss` |
| `g_pm_twt_ptr` | `0x2f07fee0` | `g_pm_twt` | 24 | `internal SRAM` / `.data` |
| `g_he_max_apep_length_tab_ptr` | `0x2f07fc74` | `g_he_max_apep_length_tab` | 480 | `internal SRAM` / `.bss` |
| `g_wdev_dbg_rx_ptr` | `0x2f07fda4` | `g_wdev_dbg_rx` | 16 | `internal SRAM` / `.bss` |
| `s_pm_beacon_offset_ptr` | `0x2f07fc70` | `s_pm_beacon_offset` | 76 | `internal SRAM` / `.bss` |
| `s_pm_beacon_offset_config_ptr` | `0x2f07fc6c` | `s_pm_beacon_offset_config` | 6 | `internal SRAM` / `.bss` |
| `s_tbttstart_ptr` | `0x2f07fc68` | `s_tbttstart` | 8 | `internal SRAM` / `.bss` |
| `s_offchan_tx_progress_in_ptr` | `0x2f07fc64` | `offchan_tx_progress_in` | 1 | `internal SRAM` / `.bss` |
| `g_offchan_packet_lifetime_ptr` | `0x2f07fc60` | `g_offchan_packet_lifetime` | 4 | `internal SRAM` / `.bss` |
| `g_send_wake_null_timer_ptr` | `0x2f07fc5c` | `send_wake_null_timer` | 20 | `internal SRAM` / `.bss` |

## Rust-owned strict static storage

| section | address | bytes | placement |
|---|---:|---:|---|
| `.data.wifi` | `0x2f017638` | 408 | `internal SRAM` |
| `.critical.data.wifi_strict.commands` | `0x2f0177d0` | 17196 | `internal SRAM` |
| `.critical.bss.wifi_strict.misc_nvs_initialized` | `0x2f01db68` | 1 | `internal SRAM` |
| `.critical.bss.wifi_strict.misc_nvs` | `0x2f01db6c` | 60 | `internal SRAM` |
| `.critical.bss.wifi_strict.esf_large_rx_slots` | `0x2f01dba8` | 59008 | `internal SRAM` |
| `.critical.bss.wifi_strict.esf_management_slots` | `0x2f02c228` | 27904 | `internal SRAM` |
| `.critical.bss.wifi_strict.esf_large_rx_claims` | `0x2f032f28` | 4 | `internal SRAM` |
| `.critical.data.wifi_strict.esf_prearm_hart` | `0x2f032f2c` | 4 | `internal SRAM` |
| `.critical.bss.wifi_strict.esf_rejections` | `0x2f032f30` | 4 | `internal SRAM` |
| `.critical.bss.wifi_strict.esf_management_claims` | `0x2f032f34` | 4 | `internal SRAM` |
| `.critical.bss.wifi_strict.tx_ampdu_owners` | `0x2f032f38` | 1424 | `internal SRAM` |
| `.critical.bss.wifi_strict.tx_ampdu_completion_state` | `0x2f0334c8` | 584 | `internal SRAM` |
| `.critical.data.wifi_strict.tx_backoff` | `0x2f033710` | 4 | `internal SRAM` |
| `.critical.bss.wifi_strict.rx_recycle_probe` | `0x2f033714` | 32 | `internal SRAM` |
| `.critical.bss.wifi_strict.rx_recycle_timer` | `0x2f033734` | 20 | `internal SRAM` |
| `.critical.bss.wifi_strict.indicate_frame_probe` | `0x2f033748` | 12 | `internal SRAM` |
| `.critical.bss.wifi_strict.data_rx_channel` | `0x2f033754` | 788 | `internal SRAM` |
| `.critical.bss.wifi_strict.data_rx_slots` | `0x2f033a68` | 4160 | `internal SRAM` |
| `.critical.bss.wifi_strict.data_tx_channel` | `0x2f034aa8` | 276 | `internal SRAM` |
| `.critical.bss.wifi_strict.data_tx_slots` | `0x2f034bbc` | 51584 | `internal SRAM` |
| `.critical.data.wifi_strict.basic_secondary_schedule` | `0x2f04153c` | 12 | `internal SRAM` |
| `.critical.bss.wifi_strict.critical_probe` | `0x2f041548` | 24 | `internal SRAM` |
| `.critical.bss.wifi_strict.tx_queue_process_hil` | `0x2f041560` | 156 | `internal SRAM` |
| `.critical.bss.wifi_strict.tx_trace` | `0x2f0415fc` | 2312 | `internal SRAM` |
| `.critical.bss.wifi_strict.pm_beacon_offset_functions` | `0x2f041f04` | 68 | `internal SRAM` |
| `.critical.bss.wifi_strict.rate_contexts` | `0x2f041f48` | 2432 | `internal SRAM` |
| `.critical.bss.wifi_strict.rate_table_scratch` | `0x2f0428c8` | 212 | `internal SRAM` |
| `.critical.bss.wifi_strict.deferred_ap_management` | `0x2f04299c` | 288 | `internal SRAM` |
| `.critical.bss.wifi_strict.management_tx_rejection` | `0x2f042abc` | 64 | `internal SRAM` |
| `.critical.bss.wifi_strict.ap_assoc_rejection` | `0x2f042afc` | 44 | `internal SRAM` |
| `.critical.bss.wifi_strict.ap_assoc_response_capture` | `0x2f042b28` | 272 | `internal SRAM` |
| `.critical.data.wifi_strict.critical_hart` | `0x2f042c38` | 4 | `internal SRAM` |
| `.critical.bss.wifi_strict.critical_state` | `0x2f042c3c` | 8 | `internal SRAM` |
| `.critical.bss.wifi_strict.rx_addba` | `0x2f042c44` | 15 | `internal SRAM` |
| `.critical.bss.wifi_strict.sta_node` | `0x2f042c54` | 1544 | `internal SRAM` |
| `.critical.bss.wifi_strict.ap_nodes` | `0x2f04325c` | 10400 | `internal SRAM` |
| `.critical.bss.wifi_strict.rx_recycle_state` | `0x2f045b14` | 24 | `internal SRAM` |
| `.critical.bss.wifi_strict.lmac_tx_done_state` | `0x2f045b2c` | 16 | `internal SRAM` |
| `.critical.bss.wifi_strict.tx_done_state` | `0x2f045b3c` | 12 | `internal SRAM` |
| `.critical.bss.wifi_strict.data_tx_wakers` | `0x2f045b48` | 24 | `internal SRAM` |
| `.critical.bss.wifi_strict.ap_join_diagnostics` | `0x2f045b60` | 8 | `internal SRAM` |
| `.critical.bss.wifi_strict.critical_callbacks` | `0x2f045b68` | 16 | `internal SRAM` |
| `.critical.bss.wifi_strict.tx_block_ack` | `0x2f045b78` | 48 | `internal SRAM` |
| `.bss.esp_wifi_async_net80211` | `0x2f045ba8` | 33 | `internal SRAM` |

## Final-link interposition

| boundary | replacement | mode | `__real_*` target |
|---|---:|---|---|
| `calloc` | `0x400c5f6c` | GNU `--wrap` boundary | - |
| `chm_return_home_channel` | `0x400c58e2` | GNU `--wrap` boundary | - |
| `chm_start_op` | `0x400c577a` | GNU `--wrap` boundary | - |
| `cnx_add_to_blacklist` | `0x2f003d06` | retained replacement only | - |
| `cnx_check_bssid_in_blacklist` | `0x2f003d02` | retained replacement only | - |
| `cnx_clear_blacklist` | `0x2f003d08` | retained replacement only | - |
| `cnx_node_alloc` | `0x400d19cc` | GNU `--wrap` boundary | - |
| `cnx_node_search` | `0x400d1b04` | retained replacement only | - |
| `cnx_remove_from_blacklist` | `0x2f003d06` | retained replacement only | - |
| `dbg_dump_rx_ppdu` | `0x400c70d2` | retained replacement only | - |
| `dbg_dump_rx_sigb` | `0x400c70d4` | retained replacement only | - |
| `dbg_read_tx_ppdu` | `0x400c70d4` | retained replacement only | - |
| `esf_buf_alloc` | `0x2f003322` | direct public alias | `0x2f800d1c` (ROM export) |
| `esf_buf_recycle` | `0x2f003598` | direct public alias | `0x2f800d24` (ROM export) |
| `esp_test_rx_parse_mu` | `0x400c70d2` | direct public alias | `0x2f801178` (ROM export) |
| `esp_test_rx_process_complete` | `0x400c70dc` | direct public alias | `0x2f801158` (ROM export) |
| `esp_test_tx_enab_statistics` | `0x400c70d8` | direct public alias | `0x2f801144` (ROM export) |
| `ets_delay_us` | `0x400c616e` | direct public alias | `0x2f80003c` (ROM export) |
| `free` | `0x400c60fe` | GNU `--wrap` boundary | - |
| `hal_crypto_set_key_entry` | `0x400c685a` | retained replacement only | - |
| `hal_mac_get_txq_complete` | `0x2f003b18` | direct public alias | `0x2f800d44` (ROM export) |
| `hal_mac_get_txq_state` | `0x400c6264` | direct public alias | `0x2f800d3c` (ROM export) |
| `ic_get_next_tbtt` | `0x400c64a8` | retained replacement only | - |
| `ieee80211_hostapd_beacon_txcb` | `0x400c62da` | GNU `--wrap` boundary | - |
| `ieee80211_mgmt_output` | `0x400c5988` | GNU `--wrap` boundary | - |
| `ieee80211_search_node` | `0x400d1b0c` | direct public alias | `0x2f800ca8` (ROM export) |
| `ieee80211_set_tx_pti` | `0x400c5c22` | direct public alias | `0x2f800cb8` (ROM export) |
| `ieee80211_timer_process` | `0x400c5626` | GNU `--wrap` boundary | - |
| `ieee80211_tx_mgt_cb` | `0x400c639c` | retained replacement only | - |
| `lmacTxDone` | `0x2f003c6a` | direct public alias | `0x2f800dec` (ROM export) |
| `malloc` | `0x400c5e1c` | GNU `--wrap` boundary | - |
| `misc_nvs_deinit` | `0x400d1bec` | retained replacement only | - |
| `misc_nvs_init` | `0x400d1c00` | retained replacement only | - |
| `net80211_data_ptr_init` | `0x400d1c46` | retained replacement only | - |
| `os_sleep` | `0x400c61f0` | GNU `--wrap` boundary | - |
| `pm_funcs_deinit` | `0x400d1d08` | retained replacement only | - |
| `pm_funcs_init` | `0x400d1d14` | retained replacement only | - |
| `pm_on_beacon_rx` | `0x400c70f6` | direct public alias | `0x2f800e98` (ROM export) |
| `pm_on_coex_schm_status_config` | `0x2f003f1e` | retained replacement only | - |
| `pm_on_data_rx` | `0x400c70f8` | direct public alias | `0x2f800e9c` (ROM export) |
| `pm_on_data_tx` | `0x400c70fa` | direct public alias | `0x2f800ea0` (ROM export) |
| `pm_set_beacon_duration` | `0x400c70fc` | retained replacement only | - |
| `pp_create_task` | `0x400d1d4c` | retained replacement only | - |
| `pp_delete_task` | `0x400d1dda` | retained replacement only | - |
| `pp_post` | `0x400c5346` | GNU `--wrap` boundary | - |
| `rcGetSched` | `0x2f000dac` | retained replacement only | - |
| `realloc` | `0x400c603a` | GNU `--wrap` boundary | - |
| `sleep` | `0x400beaa6` | GNU `--wrap` boundary | - |
| `sta_rx_cb` | `0x400af478` | GNU `--wrap` boundary | - |
| `usleep` | `0x400beb50` | GNU `--wrap` boundary | - |
| `vTaskDelay` | `0x400beb7c` | GNU `--wrap` boundary | - |
| `wDev_AppendRxBlocks` | `0x2f003f3e` | direct public alias | `0x2f8010c4` (ROM export) |
| `wDev_IndicateCtrlFrame` | `0x2f003f20` | GNU `--wrap` boundary | - |
| `wDev_SnifferRxData` | `0x400c70fa` | retained replacement only | - |
| `wDev_ftm_set_t1t4` | `0x400c70fe` | retained replacement only | - |
| `wDev_isNANPktInValidSlot` | `0x400c710e` | GNU `--wrap` boundary | - |
| `wDev_record_ftm_data` | `0x400c70e6` | retained replacement only | - |
| `wdev_csi_rx_process` | `0x400c70fa` | retained replacement only | - |
| `wdev_data_init` | `0x400d1ea2` | retained replacement only | - |
| `wifi_assert` | `0x400c70de` | retained replacement only | - |
| `wifi_gpio_debug` | `0x400c70d6` | retained replacement only | - |
| `wifi_log` | `0x400c70fa` | retained replacement only | - |
| `wpa_ap_rx_eapol` | `0x400c6818` | retained replacement only | - |
| `wpa_sm_rx_eapol` | `0x400c67da` | retained replacement only | - |

## Linked mutable blob state outside the strict-root graph

| symbol | size | placement | archive owner | known archive referrers |
|---|---:|---|---|---|
| `est_PHY_RESP_FTM_COMP_40_40D_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_RESP_FTM_COMP_40_40D_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_RESP_FTM_COMP_40_40U_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_RESP_FTM_COMP_40_40U_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_40_40D_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_40_40D_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_40_40U_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_40_40U_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | `ftm_get_phy_comp` |
| `est_PHY_RESP_FTM_COMP_20_40D_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_RESP_FTM_COMP_20_40D_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_RESP_FTM_COMP_20_40U_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_RESP_FTM_COMP_20_40U_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_20_40D_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_20_40D_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_20_40U_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_20_40U_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_RESP_FTM_COMP_20_20D_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_RESP_FTM_COMP_20_20D_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_RESP_FTM_COMP_20_20U_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_RESP_FTM_COMP_20_20U_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_20_20D_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_20_20D_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_20_20U_MHZ_DIS` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `est_PHY_INIT_FTM_COMP_20_20U_MHZ` | 2 | `internal SRAM` / `.data` | `libwifi_support.a[ftm_calibration_data.o]` | - |
| `ccmp` | 24 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_crypto_ccmp.o]` | `mt_set_lmk` |
| `TmpSTAAPCloseAP` | 1 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_hostap.o]` | - |
| `g_mesh_self_organized` | 1 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_mesh_quick.o]` | `candidate_monitor_timer_start`, `cnx_connect_to_bss`, `cnx_sta_connect_cmd`, `esp_mesh_get_self_organized`, `esp_mesh_is_root`, +4 |
| `s_itwt_id` | 16 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_twt.o]` | - |
| `s_tmp_itwt_id` | 16 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_twt.o]` | - |
| `setup_timer_param` | 372 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_twt.o]` | - |
| `g_def_2g_channels` | 11 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_nan_datapath.o]` | - |
| `s_wfa_oui` | 3 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_nan_sd.o]` | - |
| `g_espnow_user_oui` | 3 | `internal SRAM` / `.data` | `libespnow.a[manatick.o]` | `ieee80211_add_ie_vendor_esp_freq_annon`, `ieee80211_add_ie_vendor_esp_head`, `ieee80211_add_ie_vendor_esp_manufacturer`, `ieee80211_add_ie_vendor_esp_mesh_group`, `ieee80211_add_ie_vendor_esp_now`, +3 |
| `g_phy_cap_rx_stbc` | 1 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_ht.o]` | `esp_wifi_enable_rx_stbc` |
| `g_wifi_nvs` | 4 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_nvs.o]` | `_do_wifi_disconnect`, `chm_check_channel_is_valid`, `chm_init`, `cnx_auth_done`, `cnx_bss_alloc`, +135 |
| `tkip` | 24 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_crypto_tkip.o]` | - |
| `wep` | 24 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_crypto_wep.o]` | - |
| `sms4` | 24 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_crypto_sms4.o]` | - |
| `g_timer_info` | 376 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_timer.o]` | - |
| `gcmp` | 24 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_crypto_gcmp.o]` | - |
| `WIFI_MESH_EVENT` | 4 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_api.o]` | `mesh_wifi_event_deinit` |
| `g_wifi_event_mask` | 4 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_api.o]` | `wifi_set_event_mask` |
| `esp_test_tx_addba_request` | 1 | `internal SRAM` / `.data` | `libnet80211.a[wl_cnx.o]` | - |
| `g_dynamic_cs` | 12 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_sta.o]` | - |
| `send_deauth` | 1 | `internal SRAM` / `.data` | `libnet80211.a[ieee80211_sta.o]` | - |
| `g_pp_timer_info` | 136 | `internal SRAM` / `.data` | `libpp.a[pp_timer.o]` | `wdev_data_init` |
| `g_pm_cfg` | 88 | `internal SRAM` / `.data` | `libpp.a[pm.o]` | `ic_update_light_sleep_wake_ahead_time`, `pm_beacon_offset_reset`, `pm_coex_pwr_configure`, `pm_twt_set_config`, `wdev_data_init` |
| `g_eb_list_desc` | 220 | `internal SRAM` / `.data` | `libpp.a[esf_buf.o]` | `wdev_data_init` |
| `g_txop_queue_status` | 3 | `internal SRAM` / `.data` | `libpp.a[lmac.o]` | `wdev_data_init` |
| `lmacConfMib` | 48 | `internal SRAM` / `.data` | `libpp.a[lmac.o]` | `ppProcessLifeTime`, `ppRxFragmentProc`, `ppTxFragmentProc`, `wdev_data_init` |
| `g_pm_twt` | 24 | `internal SRAM` / `.data` | `libpp.a[pm_twt.o]` | `wdev_data_init` |
| `BasicOFDMSched` | 12 | `internal SRAM` / `.data` | `libpp.a[trc.o]` | `wdev_data_init` |
| `rc11AXSchedTbl` | 192 | `internal SRAM` / `.data` | `libpp.a[trc.o]` | - |
| `rc11BSchedTbl` | 72 | `internal SRAM` / `.data` | `libpp.a[trc.o]` | `wdev_data_init` |
| `rc11GSchedTbl` | 156 | `internal SRAM` / `.data` | `libpp.a[trc.o]` | - |
| `rc11NSchedTbl` | 168 | `internal SRAM` / `.data` | `libpp.a[trc.o]` | `wdev_data_init` |
| `rcLoRaSchedTbl` | 24 | `internal SRAM` / `.data` | `libpp.a[trc.o]` | `wdev_data_init` |
| `rcP2P11GSchedTbl` | 96 | `internal SRAM` / `.data` | `libpp.a[trc.o]` | - |
| `rcP2P11NSchedTbl` | 120 | `internal SRAM` / `.data` | `libpp.a[trc.o]` | - |
| `trc_ctl` | 28 | `internal SRAM` / `.data` | `libpp.a[trc.o]` | `wdev_data_init` |
| `txop_max_list` | 8 | `internal SRAM` / `.data` | `libpp.a[trc.o]` | - |
| `BcnInterval` | 4 | `internal SRAM` / `.data` | `libpp.a[wdev.o]` | - |
| `he_data_bits_per_sym` | 160 | `internal SRAM` / `.data` | `libpp.a[hal_mac_ctl.o]` | - |
| `he_preamble_ersu` | 16 | `internal SRAM` / `.data` | `libpp.a[hal_mac_ctl.o]` | - |
| `he_preamble_su` | 16 | `internal SRAM` / `.data` | `libpp.a[hal_mac_ctl.o]` | - |
| `he_time_per_sym` | 12 | `internal SRAM` / `.data` | `libpp.a[hal_mac_ctl.o]` | - |
| `coex_pti_tab` | 48 | `internal SRAM` / `.data.wifi` | `libcoexist.a[coexist_core.o]` | `coex_rom_data_init` |
| `g_mesh_is_started` | 1 | `internal SRAM` / `.data.wifi` | `libnet80211.a[ieee80211_mesh_quick.o]` | `ic_set_trc`, `lmacAdjustTimestamp`, `net80211_data_ptr_init`, `pm_allow_tx`, `pm_disconnected_wake`, +10 |
| `g_mesh_init_ps_type` | 4 | `internal SRAM` / `.data.wifi` | `libnet80211.a[ieee80211_mesh_quick.o]` | `esp_mesh_is_ps_enabled`, `esp_mesh_parse_ps_ie`, `esp_mesh_process_ps_type`, `esp_mesh_set_beacon_interval`, `ieee80211_add_ie_vendor_esp_ssid`, +19 |
| `g_mesh_is_root` | 1 | `internal SRAM` / `.data.wifi` | `libnet80211.a[ieee80211_mesh_quick.o]` | `candidate_monitor_timer_start`, `cnx_connect_next_ap`, `cnx_connect_to_bss`, `cnx_sta_connect_cmd`, `esp_mesh_get_layer`, +34 |
| `pp_sig_cnt` | 36 | `internal SRAM` / `.data.wifi` | `libpp.a[pp.o]` | `wdev_data_init` |
| `eb_txdesc_space` | 288 | `internal SRAM` / `.data.wifi` | `libpp.a[esf_buf.o]` | - |
| `ptr_beacon_offset_funcs` | 4 | `internal SRAM` / `.data.wifi` | `libpp.a[pm_beacon_offset.o]` | `ic_beacon_offset_configure`, `ic_beacon_offset_set_rx_beacon_standard`, `pm_beacon_add_loss_counter`, `pm_beacon_add_total_counter`, `pm_beacon_monitor_tbtt_start`, +4 |
| `ap_rxcb` | 4 | `internal SRAM` / `.bss.esp_wifi_async_net80211` | `libnet80211.a[ieee80211_hostap.o]` | `ieee80211_decap_amsdu` |
| `eloop_lifecycle_busy` | 1 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[eloop.c.obj]` | `eloop_lifecycle_unlock` |
| `eloop_data_lock` | 4 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[eloop.c.obj]` | - |
| `g_wpa_config_changed` | 1 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[esp_wpa_main.c.obj]` | `config_changed_handler` |
| `wpa_cb` | 4 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[esp_wpa_main.c.obj]` | - |
| `wifi_funcs` | 4 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[esp_wpa_main.c.obj]` | `os_timer_disarm.constprop.0` |
| `g_wpa_pmk_caching_disabled` | 1 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[esp_wpa_main.c.obj]` | `esp_supplicant_disable_pmk_caching` |
| `s_sm_valid_bitmap` | 4 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[wpa_auth.c.obj]` | - |
| `s_wps_sm_cb` | 4 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[esp_wps.c.obj]` | `wps_get_wps_sm_cb` |
| `global_hapd` | 4 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[esp_hostap.c.obj]` | `hostapd_get_hapd_data` |
| `wpa_crypto_funcs` | 52 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_crypto.o]` | `key_derivation_hmac_sha256`, `mt_copy_peer`, `nan_compute_service_hash`, `wapi_mk_mic.constprop.0.isra.0`, `wpa_crypto_funcs_init` |
| `color_change_timer` | 20 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_he.o]` | - |
| `esp_test_rx_trs_count` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_he.o]` | - |
| `esp_wifi_opr_bss_color` | 3 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_he.o]` | - |
| `len_dh_ie` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_output.o]` | - |
| `s_tx_cacheq` | 8 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_output.o]` | `net80211_data_ptr_init` |
| `g_beacon_eb` | 8 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_hostap.o]` | `ieee80211_getbcnframe` |
| `g_beacon_idx` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_hostap.o]` | `ieee80211_getbcnframe` |
| `g_deauth_mac_list` | 12 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_hostap.o]` | - |
| `g_sa_query_mac_list` | 12 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_hostap.o]` | - |
| `esp_mesh_quick_funcs` | 176 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_mesh_quick.o]` | `esp_mesh_quick_funcs_deinit`, `esp_mesh_quick_funcs_init`, `net80211_data_ptr_init`, `pm_go_to_sleep`, `pm_mesh_set_next_tbtt`, +5 |
| `g_mesh_topology` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_mesh_quick.o]` | `esp_mesh_get_layer`, `esp_mesh_get_topology`, `esp_mesh_ie_init`, `esp_mesh_print_route_table`, `esp_mesh_scan_done_vote`, +23 |
| `g_log_level` | 4 | `internal SRAM` / `.bss` | `libcore.a[misc_nvs.o]` | `_mesh_find_root_competitor`, `esp_mesh_ap_enqueue`, `esp_mesh_ap_list_clear`, `esp_mesh_ap_list_clear_expire`, `esp_mesh_ap_list_clear_invalid`, +150 |
| `g_log_mod` | 24 | `internal SRAM` / `.bss` | `libcore.a[misc_nvs.o]` | `esp_wifi_internal_get_log`, `wifi_set_log_mod_process` |
| `itwt_information_timer` | 160 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_twt.o]` | - |
| `s_itwt_flow_id_bitmap` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_twt.o]` | - |
| `s_itwt_resume_flow_id_bitmap` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_twt.o]` | - |
| `s_itwt_suspend_flow_id_bitmap` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_twt.o]` | - |
| `btwt_setup_timer` | 1248 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_btwt.o]` | - |
| `g_btwt_num` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_btwt.o]` | - |
| `s_btwt_id_bitmap` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_btwt.o]` | `he_twt_teardown_txcb`, `ieee80211_close_all_twt_sessions` |
| `s_avail_seq` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_nan_datapath.o]` | - |
| `s_dp` | 1324 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_nan_datapath.o]` | - |
| `action_q` | 8 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_nan_common.o]` | - |
| `g_nan_secure_dp_funcs` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_nan_common.o]` | `nan_send_ndp_confirm`, `nan_update_static_sdfs` |
| `g_nan_started` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_nan_common.o]` | `nan_action_timeout`, `nan_disc_bcn_timeout`, `nan_dwend_timeout`, `nan_dwstart_timeout`, `nan_faw_end_timeout`, +5 |
| `ndp_rxcb` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_nan_common.o]` | - |
| `s_nan_cb` | 52 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_nan_common.o]` | `nan_update_static_sdfs` |
| `s_ni` | 376 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_nan_common.o]` | - |
| `g_offchan_ctx` | 28 | `internal SRAM` / `.bss` | `libnet80211.a[wl_offchan.o]` | - |
| `g_offchan_packet_lifetime` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[wl_offchan.o]` | `wdev_data_init` |
| `offchan_tx_progress_in` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[wl_offchan.o]` | `offchan_in_progress`, `wdev_data_init` |
| `g_hmac_cnt` | 64 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_debug.o]` | `hostap_input`, `ieee80211_psq_send_one_pkt`, `net80211_data_ptr_init`, `sta_input` |
| `app_scan_params` | 16 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_scan.o]` | `wifi_get_scan_params_process` |
| `connect_scan_flag` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_scan.o]` | - |
| `gScanStruct` | 284 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_scan.o]` | `_cnx_start_connect_without_scan`, `cnx_sta_connect_cmd`, `ieee80211_scan_attach`, `ieee80211_scan_deattach`, `net80211_data_ptr_init`, +26 |
| `scannum` | 2 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_scan.o]` | `ieee80211_sta_scan` |
| `esp_test_baparas_support_amsdu` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_ht.o]` | - |
| `s_wifi_nvs` | 1440 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_nvs.o]` | `net80211_data_ptr_init` |
| `g_mac_sleep_en` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_ioctl.o]` | `esp_wifi_internal_set_mac_sleep`, `net80211_data_ptr_init` |
| `g_wifi_menuconfig` | 104 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_ioctl.o]` | `ampdu_rx_start.constprop.0`, `dbg_dump_rx_links`, `esf_buf_setup`, `ftm_is_initiator_supported`, `ftm_is_responder_supported`, +22 |
| `itwt_probe_timer` | 20 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_ioctl.o]` | `itwt_probe_rc_tx_cb`, `itwt_stop_process` |
| `mac_list_lock` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_ioctl.o]` | `clear_mac_queue` |
| `s_wifi_task_hdl` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_ioctl.o]` | - |
| `ftm_resp_ctx` | 12 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_ftm.o]` | - |
| `s_wifi_api_lock` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_api.o]` | - |
| `s_wifi_stop_in_progress` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_api.o]` | `esp_sta_reset_rmac_process`, `wifi_stop_old_mode` |
| `ap_no_lr` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[wl_cnx.o]` | `wdev_data_init` |
| `g_authmode_incompatible` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[wl_cnx.o]` | - |
| `g_authmode_threshold_failure` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[wl_cnx.o]` | - |
| `g_cnxMgr` | 5256 | `internal SRAM` / `.bss` | `libnet80211.a[wl_cnx.o]` | `_cnx_start_connect_without_scan`, `cnx_add_rc`, `cnx_add_to_blacklist`, `cnx_auth_done`, `cnx_bss_alloc`, +14 |
| `g_cnx_probe_rc_list_cb` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[wl_cnx.o]` | - |
| `g_in_blacklist_flag` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[wl_cnx.o]` | - |
| `g_in_blacklist_scanned_again` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[wl_cnx.o]` | - |
| `g_rssi_threshold_failure` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[wl_cnx.o]` | - |
| `in_rssi_adjust` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_sta.o]` | - |
| `rssi_index` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_sta.o]` | - |
| `rssi_saved` | 8 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_sta.o]` | - |
| `s_eapol_txdone_cb` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_sta.o]` | - |
| `send_wake_null_timer` | 20 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_sta.o]` | `wdev_data_init` |
| `sta_csa_timer` | 20 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_sta.o]` | - |
| `g_wifi_improve_contention_ability` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[ieee80211_proto.o]` | `esp_wifi_improve_contention_ability` |
| `esp_test_rx_ctrl` | 72 | `internal SRAM` / `.bss` | `libnet80211.a[test.o]` | `esp_test_rx_parse_trig` |
| `g_rx_trig_idx` | 4 | `internal SRAM` / `.bss` | `libnet80211.a[test_rx_trig.o]` | - |
| `g_store_rx_trig` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[test_rx_trig.o]` | - |
| `g_store_rx_trig_print` | 1 | `internal SRAM` / `.bss` | `libnet80211.a[test_rx_trig.o]` | - |
| `test_rx_trig_bfrp` | 1200 | `internal SRAM` / `.bss` | `libnet80211.a[test_rx_trig.o]` | - |
| `g_phyFuns` | 4 | `internal SRAM` / `.bss` | `libphy.a[phy_init.o]` | `phy_bt_set_tx_gain_new`, `phy_bt_tx_pwctrl_init`, `phy_start_tx_tone_step_new`, `phy_tx_cap_init`, `phy_tx_gain_print`, +3 |
| `g_pm` | 1176 | `internal SRAM` / `.bss` | `libpp.a[pm.o]` | `hal_get_time_to_sta_next_tbtt`, `ic_update_light_sleep_wake_ahead_time`, `pm_beacon_offset_check`, `pm_beacon_offset_get_average`, `pm_beacon_offset_get_expect`, +35 |
| `g_rts_threshold_bytes` | 120 | `internal SRAM` / `.bss` | `libpp.a[if_hwctrl.o]` | `wdev_data_init` |
| `if_ctrl` | 40 | `internal SRAM` / `.bss` | `libpp.a[if_hwctrl.o]` | `wdev_data_init` |
| `s_is_6m` | 1 | `internal SRAM` / `.bss` | `libpp.a[if_hwctrl.o]` | - |
| `s_fragment` | 16 | `internal SRAM` / `.bss` | `libpp.a[pp.o]` | `wdev_data_init` |
| `g_bss_color_collision_detection_enabled` | 2 | `internal SRAM` / `.bss` | `libpp.a[pp_he_ctrl.o]` | `wifi_enable_bss_color_collision_detection_process` |
| `eb_space` | 240 | `internal SRAM` / `.bss` | `libpp.a[esf_buf.o]` | - |
| `g_he_max_apep_length_tab` | 480 | `internal SRAM` / `.bss` | `libpp.a[trc.o]` | `wdev_data_init` |
| `s_fix_rate` | 12 | `internal SRAM` / `.bss` | `libpp.a[trc.o]` | - |
| `s_fix_rate_mask` | 4 | `internal SRAM` / `.bss` | `libpp.a[trc.o]` | - |
| `g_lmac_cnt` | 192 | `internal SRAM` / `.bss` | `libpp.a[pp_debug.o]` | `esf_buf_alloc_dynamic`, `esf_buf_statis_dump`, `lmacDebugTxDrop`, `wdev_data_init` |
| `g_pm_cnt` | 72 | `internal SRAM` / `.bss` | `libpp.a[pp_debug.o]` | `pm_active_timeout_process`, `pm_beacon_timestamp_statistic`, `wdev_data_init` |
| `BcnSendTick` | 4 | `internal SRAM` / `.bss` | `libpp.a[wdev.o]` | - |
| `g_wdev_csi_rx` | 4 | `internal SRAM` / `.bss` | `libpp.a[wdev.o]` | - |
| `g_wdev_dbg_rx` | 16 | `internal SRAM` / `.bss` | `libpp.a[wdev.o]` | `wdev_data_init` |
| `g_wdev_is_nan_pkt_in_valid_slot_cb` | 4 | `internal SRAM` / `.bss` | `libpp.a[wdev.o]` | - |
| `g_wdev_record_t1t4_cb` | 4 | `internal SRAM` / `.bss` | `libpp.a[wdev.o]` | - |
| `g_wdev_record_t2t3_cb` | 4 | `internal SRAM` / `.bss` | `libpp.a[wdev.o]` | - |
| `g_wdev_set_t1t4_cb` | 4 | `internal SRAM` / `.bss` | `libpp.a[wdev.o]` | - |
| `wDevMacSleep` | 120 | `internal SRAM` / `.bss` | `libpp.a[wdev.o]` | `wdev_data_init` |
| `s_pm_beacon_offset` | 76 | `internal SRAM` / `.bss` | `libpp.a[pm_beacon_offset.o]` | `wdev_data_init` |
| `s_pm_beacon_offset_config` | 6 | `internal SRAM` / `.bss` | `libpp.a[pm_beacon_offset.o]` | `wdev_data_init` |
| `s_tbttstart` | 8 | `internal SRAM` / `.bss` | `libpp.a[hal_tsf.o]` | `wdev_data_init` |
| `strid.1` | 20 | `internal SRAM` / `.bss` | `libpp.a[hal_utilities.o]` | - |
| `assoc_ie_buf` | 48 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[wpa.c.obj]` | - |
| `gWpaSm` | 1160 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[wpa.c.obj]` | `esp_wifi_set_okc_support`, `get_wpa_sm`, `set_assoc_ie`, `wpa_config_reload`, `wpa_set_pmk`, +6 |
| `eloop` | 36 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[eloop.c.obj]` | `eloop_insert_timeout_locked.isra.0`, `eloop_is_running` |
| `s_sm_table` | 64 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[wpa_auth.c.obj]` | - |
| `g_wpa_supp` | 144 | `internal SRAM` / `.bss` | `libwpa_supplicant.a[esp_common.c.obj]` | `esp_supplicant_common_deinit` |
