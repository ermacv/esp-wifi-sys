#![no_std]
#![doc = "Experimental stackless runtime for the ESP32-S31 vendor Wi-Fi blobs."]
#![doc = ""]
#![doc = "This crate deliberately does not initialize Wi-Fi hardware. It replaces the"]
#![doc = "top-level `ppTask` scheduling loop with a wake-driven Rust `Future` while"]
#![doc = "continuing to call the original run-to-completion blob handlers."]

#[cfg(test)]
extern crate std;

#[cfg(all(feature = "strict-no-wait", feature = "wpa-async-eap"))]
compile_error!(
    "strict-no-wait cannot be combined with wpa-async-eap: the vendor Enterprise EAP leaves still allocate"
);

pub mod adapter;
pub mod allocation;
pub mod channel;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
mod channel_switch;
pub mod command;
pub mod context;
pub mod critical;
pub mod crypto;
pub mod data_rx;
pub mod data_tx;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
mod debug;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
mod delay;
pub mod diagnostics;
#[cfg(all(target_arch = "riscv32", feature = "wpa-async-eap"))]
mod eap;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
mod esf;
pub mod event;
pub mod event_bridge;
#[cfg(target_arch = "riscv32")]
mod handoff;
pub mod interrupt;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
mod lmac;
#[cfg(all(target_arch = "riscv32", feature = "wpa-async-mic"))]
pub mod michael;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
mod net80211_timer;
pub mod osi;
pub mod policy;
pub mod queue;
pub mod radio;
pub mod runtime;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
mod rx;
pub mod scan;
mod sta_link;
pub mod strict;
pub mod task;
mod tbtt;
pub mod timer;
pub mod tx_ampdu;
#[cfg(all(target_arch = "riscv32", feature = "hil-ampdu-intercept"))]
mod tx_intercept;
mod tx_mapper;
mod tx_plcp;
mod tx_proto;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
mod tx_queue;
mod tx_rate;
mod tx_security;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
mod txdone;
#[cfg(target_arch = "riscv32")]
pub mod vendor;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
mod wdev;
pub mod wpa2;
pub mod wpa2_aes;
pub mod wpa2_ap;
pub mod wpa2_ap_async;
pub mod wpa2_crypto;
pub mod wpa2_frames;
pub mod wpa2_io;
pub mod wpa2_retry;
pub mod wpa2_rx;
pub mod wpa2_s31;
pub mod wpa2_sha1;
pub mod wpa2_sta;
pub mod wpa2_sta_async;
pub mod wpa2_state;
pub mod wpa2_txdone;

pub use adapter::{
    blocking_probe, internal_event_queue_snapshot, next_timer_deadline_us, radio_queue,
    task_delay_snapshot, timer_alarm_interrupt, timer_snapshot, ShutdownQueueFull,
    TaskDelaySnapshot, DEFAULT_EVENT_BUDGET, INTERNAL_EVENT_QUEUE_CAPACITY, PP_QUEUE_CAPACITY,
    TIMER_CAPACITY,
};
#[cfg(target_arch = "riscv32")]
pub use adapter::{
    configure_wifi_runtime_clock, drain_wifi_initialization_events, patch_pp_runtime_callbacks,
    request_shutdown, take_radio_future, take_wifi_runtime, InitializationDrainError,
};
pub use allocation::{allocation_probe, AllocationProbe, AllocationSnapshot};
#[cfg(target_arch = "riscv32")]
pub use allocation::{allow_heap_for_wifi_teardown, patch_allocator_probes};
#[cfg(target_arch = "riscv32")]
pub use esf::enable_prestart_management_pool;
pub use channel::{BoundedChannel, Receive, TrySendError};
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use channel_switch::{channel_switch_snapshot, ChannelSwitchError, ChannelSwitchSnapshot};
pub use command::{
    RadioCommandHandler, RadioCommandQueue, RadioCommandReady, RadioCommandSnapshot,
    RadioOwnerFuture, RADIO_COMMAND_CONTEXT_EVENT,
};
pub use context::{current_event, in_radio_context, RadioContextGuard};
#[cfg(target_arch = "riscv32")]
pub use critical::{allow_core_stalls_for_wifi_teardown, patch_critical_section_probes};
pub use critical::{critical_section_probe, CriticalSectionProbe, CriticalSectionSnapshot};
#[cfg(target_arch = "riscv32")]
pub use crypto::{install_precomputed_wpa_pmk, PmkInstallError};
pub use crypto::{
    CryptoFuture, CryptoJob, CryptoJobError, CryptoOperation, InterruptCryptoBackend,
    InterruptCryptoEngine, SoftwarePbkdf2Future, SoftwarePbkdf2Progress, WpaPskJob, AES_BLOCK_SIZE,
    WPA_PBKDF2_ITERATIONS, WPA_PMK_LENGTH, WPA_PSK_PASSPHRASE_CAPACITY, WPA_SSID_CAPACITY,
};
#[cfg(target_arch = "riscv32")]
pub use data_rx::{
    async_wifi_data_rx_installed, install_async_wifi_data_rx, WifiDataRxInstallError,
};
pub use data_rx::{
    poll_receive_wifi_data, receive_wifi_data, rejected_wifi_data_frames, try_receive_wifi_data,
    wifi_data_rx_snapshot, OwnedWifiDataFrame, WifiDataInterface, WifiDataRxSnapshot,
    WIFI_DATA_RX_CAPACITY, WIFI_DATA_RX_FRAME_CAPACITY,
};
pub use data_tx::{
    flush_wifi_data_tx, poll_wifi_data_tx_ready, receive_wifi_data_tx, try_receive_wifi_data_tx,
    try_send_wifi_data, wifi_data_tx_snapshot, OwnedWifiDataTxFrame, WifiDataTxEnqueueError,
    WifiDataTxSnapshot, WIFI_DATA_TX_CAPACITY, WIFI_DATA_TX_FRAME_CAPACITY,
};
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use delay::{
    direct_delay_snapshot, DirectDelaySiteSnapshot, DirectDelaySnapshot, DIRECT_DELAY_SITE_CAPACITY,
};
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use esf::rejected_esf_operations;
pub use event::{PpAction, PpEvent};
#[cfg(target_arch = "riscv32")]
pub use event_bridge::patch_async_event_post;
pub use event_bridge::{EventCopyError, OwnedWifiEvent, WifiEventBridge, WIFI_EVENT_BASE_CAPACITY};
#[cfg(target_arch = "riscv32")]
pub use handoff::{
    arm_pp_task_handoff, begin_pp_task_handoff, install_pp_task_handoff,
    request_armed_pp_task_handoff, PpTaskHandoff, PpTaskHandoffError, PpTaskHandoffInstallError,
    TaskDeleteCompletionRegistrar,
};
pub use interrupt::{InterruptSignal, WaitForInterrupt};
#[cfg(all(
    target_arch = "riscv32",
    feature = "strict-no-wait",
    feature = "hil-vendor-tx"
))]
pub use lmac::{
    lmac_retry_snapshot, lmac_tx_complete_snapshot, LmacRetrySnapshot, LmacTxCompleteSnapshot,
};
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use lmac::{submit_basic_ht_ampdu, LmacAsyncError};
#[cfg(target_arch = "riscv32")]
pub use txdone::{
    complete_initial_ap_start, strict_management_tx_done_snapshot, InitialApStartError,
    StrictManagementTxDoneSnapshot,
};
#[cfg(all(target_arch = "riscv32", feature = "wpa-async-mic"))]
pub use michael::{
    async_michael_callback_installed, install_async_michael_callback,
    uninstall_async_michael_callback, MichaelInstallError,
};
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use net80211_timer::{
    rejected_net80211_timer_events, request_initial_ap_beacon, Net80211TimerError,
};
pub use osi::{OsiPpQueue, RawQueueError};
#[cfg(target_arch = "riscv32")]
pub use policy::{
    configure_static_wifi_buffers, disable_dynamic_wifi_buffers, disable_frame_aggregation,
    disable_ftm, disable_vendor_nvs, prepare_strict_runtime, prepare_strict_runtime_before_handoff,
    validate_strict_basic_config, StaticWifiBufferConfig, StrictConfigError, StrictRuntimeError,
    StrictRuntimePreparation, StrictRuntimeProof,
};
pub use queue::{PushError, RadioQueue, RadioQueueSnapshot};
pub use radio::{DispatchControl, PpDispatcher, RadioFuture};
pub use runtime::WifiRuntimeFuture;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use rx::{strict_rx_snapshot, RxPumpError, StrictRxSnapshot};
pub use scan::{
    best_matching_ssid, StrictScanError, StrictScanRecord, StrictScanSummary,
    STRICT_SCAN_EXTENDED_RATES_CAPACITY, STRICT_SCAN_RECORD_CAPACITY, STRICT_SCAN_RSNXE_CAPACITY,
    STRICT_SCAN_RSN_IE_CAPACITY,
};
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use scan::{passive_scan_2_4ghz, tune_home_channel};
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use sta_link::{associate_sta, authenticate_open};
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use sta_link::{sta_assoc_snapshot, sta_auth_snapshot};
pub use sta_link::{
    StaAssocError, StaAssocSecurityError, StaAssocSnapshot, StaAssociation, StaAuthError,
    StaAuthSnapshot, OPEN_AUTH_DEFAULT_ATTEMPTS, OPEN_AUTH_DEFAULT_TIMEOUT_US,
    STA_ASSOC_DEFAULT_ATTEMPTS, STA_ASSOC_DEFAULT_TIMEOUT_US,
};
pub use strict::{AuditedFuture, StrictAudit, StrictPolicy, StrictViolation};
pub use task::VirtualPpTask;
pub use timer::{RawOsiTimer, RuntimeTimerPool, RuntimeTimerSnapshot, TIMER_CONTEXT_EVENT};
#[cfg(target_arch = "riscv32")]
pub use tx_ampdu::{
    apply_basic_ht_ampdu_completion, assemble_basic_ht_ampdu, prepare_basic_ht_ampdu_chain,
    read_ht_block_ack, restore_basic_ht_ampdu_chain,
};
pub use tx_ampdu::{
    basic_ht_ampdu_assembly, basic_ht_ampdu_completion, decode_ht_block_ack_registers,
    AddbaRequest, BasicHtAmpduAssemblyError, BasicHtAmpduAssemblyInput, BasicHtAmpduAssemblyOutput,
    BasicHtAmpduChain, BasicHtAmpduChainError, BasicHtAmpduCompletionInput,
    BasicHtAmpduCompletionOutput, BasicHtAmpduFrameCompletionError, BasicHtAmpduRestoreError,
    HtAmpduLength, HtAmpduLengthAccumulator, HtAmpduLengthError, HtBlockAckReadError,
    HtBlockAckRegisters, OperationalTxBlockAck, TxAmpduBatch, TxAmpduBatchError, TxAmpduCompletion,
    TxAmpduDisposition, TxAmpduMpdu, TxAmpduSlot, TxBlockAckAlarm, TxBlockAckBitmap,
    TxBlockAckConfig, TxBlockAckError, TxBlockAckResponse, TxBlockAckSession,
    ADDBA_ACTION_BODY_LEN, TX_AMPDU_SLOT_CAPACITY, TX_BLOCK_ACK_MAX_WINDOW,
};
#[cfg(all(target_arch = "riscv32", feature = "hil-ampdu-intercept"))]
pub use tx_intercept::{
    hil_ampdu_hardware_snapshot, hil_ampdu_intercept_pp_map_tx_queue, hil_ampdu_intercept_snapshot,
    hil_pre_enable_mapper_snapshot, HilAmpduHardwareSnapshot, HilAmpduInterceptSnapshot,
    HilPreEnableMapperRecord, HilPreEnableMapperSnapshot, HIL_PRE_ENABLE_MAPPER_RECORD_CAPACITY,
};
#[cfg(target_arch = "riscv32")]
pub use tx_proto::strict_pp_tx_proto_proc;
#[cfg(all(target_arch = "riscv32", feature = "strict-no-wait"))]
pub use tx_queue::TxQueueProcessError;
#[cfg(all(
    target_arch = "riscv32",
    feature = "strict-no-wait",
    feature = "hil-vendor-tx"
))]
pub use tx_queue::{hil_tx_queue_process_snapshot, HilTxQueueProcessSnapshot};
pub use tx_rate::FixedRateScheduleSnapshot;
#[cfg(target_arch = "riscv32")]
pub use tx_rate::{fixed_rate_schedule_snapshot, strict_rate_schedule, try_fixed_rate_schedule};
#[cfg(target_arch = "riscv32")]
pub use tx_security::strict_pp_proc_tx_sec_frame;
pub use tx_security::{
    strict_ap_beacon_completion_layout, strict_tx_security_layout, ApBeaconCompletionLayout,
    TxSecurityLayoutInput, TxSecurityLayoutOutput,
};
#[cfg(all(
    target_arch = "riscv32",
    feature = "strict-no-wait",
    feature = "hil-vendor-tx"
))]
pub use txdone::{
    hil_data_tx_done_snapshot, hil_eapol_tx_done_snapshot, HilDataTxDoneSnapshot,
    HilEapolTxDoneSnapshot,
};
#[cfg(all(target_arch = "riscv32", feature = "hil-vendor-tx"))]
pub use vendor::{
    pp_timer_diagnostic_snapshot, vendor_rx_diagnostic_snapshot, PpTimerDiagnosticSnapshot,
    VendorRxDiagnosticSnapshot,
};
#[cfg(target_arch = "riscv32")]
pub use vendor::{VendorDispatchError, VendorPpDispatcher};
pub use wpa2::{
    EapolCopyError, EapolKeyFrame, EapolKeyInfo, EapolKeyMessage, EapolParseError, OwnedEapolFrame,
    Wpa2Ingress, Wpa2IngressError, Wpa2Interface, DEFAULT_EAPOL_FRAME_CAPACITY, EAPOL_HEADER_LEN,
    EAPOL_KEY_FIXED_LEN, EAPOL_KEY_PACKET_LEN,
};
pub use wpa2_aes::{
    AsyncWpa2KeyUnwrap, AsyncWpa2KeyWrap, SoftwareAesKeyUnwrapError, SoftwareAesKeyWrapError,
    Wpa2SoftwareAes, Wpa2UnwrappedKeyData, Wpa2WrappedKeyData, WPA2_WRAPPED_KEY_DATA_CAPACITY,
};
#[cfg(target_arch = "riscv32")]
pub use wpa2_ap::{
    async_wpa2_ap_callbacks_installed, install_async_wpa2_ap_callbacks, Wpa2ApInstallError,
};
pub use wpa2_ap::{
    receive_wpa2_ap_event, rejected_wpa2_ap_events, try_receive_wpa2_ap_event,
    validate_wpa2_ap_rsn, Wpa2ApPeerEvent, Wpa2ApRsnError, WPA2_AP_ASSOC_CAPACITY,
};
pub use wpa2_ap_async::{
    complete_wpa2_ap_message2, complete_wpa2_ap_message4, complete_wpa2_ap_pairwise_key_install,
    start_wpa2_ap_handshake, Wpa2ApMessage2, Wpa2ApMessage2Error, Wpa2ApMessage3,
    Wpa2ApMessage3Error, Wpa2ApMessage4Error, Wpa2ApStartError,
};
pub use wpa2_crypto::{
    new_key_data_job, new_key_data_wrap_job, new_mic_job, new_ptk_job, new_tx_mic_job, verify_mic,
    Wpa2KeyDataJob, Wpa2KeyDataWrapJob, Wpa2MicJob, Wpa2Ptk, Wpa2PtkJob, WPA2_KCK_LEN,
    WPA2_KEK_LEN, WPA2_KEY_DATA_CAPACITY, WPA2_MIC_OUTPUT_LEN, WPA2_PTK_CONTEXT_LEN, WPA2_PTK_LEN,
    WPA2_TK_LEN, WPA2_UNWRAPPED_KEY_DATA_CAPACITY,
};
pub use wpa2_frames::{
    build_ap_action_frame, build_sta_action_frame, parse_gtk_key_data, OwnedAssociationSecurityIes,
    OwnedRsnIe, Wpa2EthernetFrame, Wpa2FrameError, Wpa2Gtk, Wpa2PlainKeyData, Wpa2TxFrame,
    WPA2_ASSOC_SECURITY_IES_CAPACITY, WPA2_GTK_LEN, WPA2_PLAIN_KEY_DATA_CAPACITY,
    WPA2_RSN_IE_CAPACITY, WPA2_TX_EAPOL_CAPACITY, WPA2_TX_ETHERNET_CAPACITY,
};
pub use wpa2_io::{
    AlignedCcmpKey, StaticKeyTableError, StaticWpa2Keys, TryWpa2Io, Wpa2IoCommand, Wpa2IoFailure,
    Wpa2IoHandler, Wpa2IoQueue, Wpa2KeyInstall, Wpa2KeyKind,
};
pub use wpa2_retry::{Wpa2Retry, Wpa2RetryAction, Wpa2RetryAlarm, Wpa2RetryConfig, Wpa2RetryError};
pub use wpa2_rx::{
    receive_wpa2_eapol, rejected_wpa2_eapol, try_receive_wpa2_eapol, WPA2_RX_CAPACITY,
};
#[cfg(feature = "hil-vendor-tx")]
pub use wpa2_rx::{wpa2_rx_diagnostic_snapshot, Wpa2RxDiagnosticSnapshot};
#[cfg(target_arch = "riscv32")]
pub use wpa2_s31::S31StaticWpa2Io;
#[cfg(all(target_arch = "riscv32", feature = "hil-vendor-tx"))]
pub use wpa2_s31::{hil_sta_pairwise_key_snapshot, HilStaPairwiseKeySnapshot};
pub use wpa2_s31::{S31StaticKeyStorage, S31Wpa2IoError};
pub use wpa2_sha1::{
    AsyncSha1, SoftwareSha1Error, Wpa2Sha1Crypto, Wpa2SoftwareSha1,
    WPA2_SOFTWARE_SHA1_MAX_MESSAGE_LEN,
};
#[cfg(all(target_arch = "riscv32", feature = "hil-vendor-tx"))]
pub use wpa2_sta::publish_vendor_wpa2_sta_m2_diagnostic_state;
#[cfg(target_arch = "riscv32")]
pub use wpa2_sta::{
    async_wpa2_sta_callbacks_installed, copy_wpa2_sta_assoc_rsn_ie,
    copy_wpa2_sta_assoc_security_ies, install_async_wpa2_sta_callbacks, Wpa2StaAssocRsnError,
    Wpa2StaInstallError,
};
pub use wpa2_sta::{
    receive_wpa2_sta_link_event, rejected_wpa2_sta_link_events, set_wpa2_sta_handshake_active,
    try_receive_wpa2_sta_link_event, Wpa2StaLinkEvent, WPA2_STA_LINK_CAPACITY,
};
pub use wpa2_sta_async::{
    complete_wpa2_sta_message3, derive_wpa2_sta_message2, AsyncWpa2StaCrypto, Wpa2StaMessage2,
    Wpa2StaMessage2Error, Wpa2StaMessage4, Wpa2StaMessage4Error,
};
pub use wpa2_state::{
    PtkContext, Wpa2ApAction, Wpa2ApPeerError, Wpa2ApPeers, Wpa2ApPhase, Wpa2ApState,
    Wpa2StaAction, Wpa2StaPhase, Wpa2StaState, Wpa2StateError, Wpa2Ticket, Wpa2Transmit,
    Wpa2TxMessage, WPA2_NONCE_LEN,
};
pub use wpa2_txdone::{
    async_wpa2_sta_tx_done_installed, receive_wpa2_sta_tx_done, rejected_wpa2_sta_tx_done,
    try_receive_wpa2_sta_tx_done, Wpa2StaTxDone, Wpa2TxDoneInstallError, WPA2_STA_TX_DONE_CAPACITY,
};
#[cfg(all(target_arch = "riscv32", feature = "hil-vendor-tx"))]
pub use wpa2_txdone::{hil_completed_eapol_snapshot, HilCompletedEapolSnapshot};
#[cfg(target_arch = "riscv32")]
pub use wpa2_txdone::{install_async_wpa2_sta_tx_done, uninstall_async_wpa2_sta_tx_done};
