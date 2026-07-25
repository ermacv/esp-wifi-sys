// Shared roots and interposition boundaries for the two ESP32-S31 strict
// auditors. Keep this policy in one place: the control-flow proof and the
// linked-state inventory must classify the same vendor graph.

pub const ROOTS: &[&str] = &[
    "wDev_ProcessRxSucData",
    "hal_mac_rx_get_last_dscr",
    "hal_mac_tx_set_cca",
    "hal_mac_is_txq_valid",
    "hal_mac_set_txq_invalid",
    "hal_mac_txq_disable",
    "lmacReleaseTxopQueue",
    "rcUpdateAckSnr",
    "rcTxUpdatePer",
    "hal_get_tsf_time",
    "ic_set_current_channel",
    "phy_change_channel",
    "hal_mac_set_csi_cbw",
    "ic_mac_init",
    "ic_set_mac",
    "ic_set_rx_policy",
    "ic_set_rx_policy_ubssid_check",
    "ieee80211_getmgtframe",
    "esp_wifi_internal_free_rx_buffer",
    "ppRxProtoProc",
    "ppRecycleRxPkt",
    "ic_del_key",
    "ic_set_key",
    "wDev_Insert_KeyEntry",
];

// Channel-manager getters are intentionally absent. Strict handoff adopts the
// finite `gChmCxt` selector/table state once; runtime channel lookup and
// home/current checks are then Rust-owned and atomic.

// These pinned leaves only bind fixed archive storage into ROM ABI pointer
// cells. They contain no allocation, wait, indirect call or control-flow
// cycle, and are the first reusable part of a future Rust-owned cold init.
pub const STATIC_BINDING_ROOTS: &[&str] = &["net80211_data_ptr_init", "wdev_data_init"];

// The Rust PM cold-init wrapper supplies fixed storage, then calls only this
// finite callback-table publisher.
pub const STATIC_PM_INIT_ROOTS: &[&str] = &["pm_beacon_offset_funcs_init"];

pub const WRAPPED_VENDOR_BOUNDARIES: &[&str] = &[
    "lmacTxDone",
    "hal_mac_get_txq_state",
    "hal_mac_get_txq_complete",
    "ieee80211_hostapd_beacon_txcb",
    "ieee80211_tx_mgt_cb",
    "wDev_record_ftm_data",
    "pm_on_beacon_rx",
    "pm_on_data_rx",
    "pm_on_data_tx",
    "pm_set_beacon_duration",
    "dbg_read_tx_ppdu",
    "dbg_dump_rx_ppdu",
    "dbg_dump_rx_sigb",
    "wifi_gpio_debug",
    "esp_test_tx_enab_statistics",
    "esp_test_set_rx_error_occurs",
    "esp_test_rx_parse_mu",
    "esp_test_rx_process_complete",
    "wDev_SnifferRxData",
    "wdev_csi_rx_process",
    "wDev_ftm_set_t1t4",
    "wDev_isNANPktInValidSlot",
    "wDev_AppendRxBlocks",
    "wDev_IndicateCtrlFrame",
    "wpa_sm_rx_eapol",
    "wpa_ap_rx_eapol",
    "hal_crypto_set_key_entry",
    "wifi_log",
    "wifi_assert",
    "pp_post",
    "ieee80211_post_hmac_tx",
    "ieee80211_timer_process",
    "chm_start_op",
    "chm_return_home_channel",
    "esf_buf_alloc",
    "esf_buf_recycle",
    "ieee80211_mgmt_output",
    "ieee80211_set_tx_pti",
    "ieee80211_classify",
    "ieee80211_align_eb",
    "ieee80211_crypto_encap",
    "ieee80211_search_node",
    "cnx_node_alloc",
    "cnx_node_search",
    "rcGetSched",
    "ppTxProtoProc",
    "ppProcTxSecFrame",
    "ppTxPkt",
    "rcUpdateTxDone",
];

/// Public runtime entry points which must resolve to an exact Rust symbol.
///
/// Some ESP32-S31 ROM linker exports cannot use ordinary GNU `--wrap`: the
/// generated `__wrap_*` name is itself captured by the absolute ROM alias.
/// Keep these pairs shared by the enforcing and reporting audits so a direct
/// alias cannot disappear from the linked-state report.
pub const REQUIRED_RUNTIME_ALIASES: &[(&str, &str)] = &[
    ("pm_on_data_rx", "__wrap_pm_on_data_rx"),
    ("wDev_AppendRxBlocks", "__wrap_wDev_AppendRxBlocks"),
    (
        "ieee80211_post_hmac_tx",
        "wifi_strict_ieee80211_post_hmac_tx",
    ),
    (
        "ieee80211_crypto_encap",
        "wifi_strict_ieee80211_crypto_encap",
    ),
    ("ieee80211_align_eb", "wifi_strict_ieee80211_align_eb"),
    ("ieee80211_set_tx_desc", "wifi_strict_ieee80211_set_tx_desc"),
    ("ppTxProtoProc", "wifi_strict_pp_tx_proto_proc"),
    ("ppProcTxSecFrame", "wifi_strict_pp_proc_tx_sec_frame"),
];
