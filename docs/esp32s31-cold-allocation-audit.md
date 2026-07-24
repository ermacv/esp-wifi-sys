# ESP32-S31 cold Wi-Fi allocation audit

This inventory covers the taskless strict STA cold-start path through
`prepare_strict_runtime`. It was captured on hardware with
`hil-cold-allocation-trace`, after the direct Rust
`wifi_init_in_caller_task` replacement was enabled. The fixed trace itself
uses only internal SRAM and performs no allocation.

The qualified run observed 115 allocations, no reallocations, 24 frees and
128,984 requested bytes. The allocation count and byte count remained
unchanged through scan, open authentication, association, WPA2 M1-M4,
network traffic, teardown and a second complete connection. The blocking
probe remained zero and no allocation ran in radio context.

Addresses below are expressed as a function-relative return offset so that
the audit does not depend on application link layout. `esf_buf_alloc_dynamic`
is a ROM implementation address and is identified by its ROM symbol rather
than a link-time offset.

| Allocator source | Returning function | Offset | Size | Count | Bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| `OsiCallocInternal` | `pm_funcs_init` | `+0x18` | 68 | 1 | 68 |
| `OsiCallocInternal` | `wdev_funcs_init` | `+0x34` | 1,560 | 1 | 1,560 |
| `OsiCallocInternal` | `net80211_funcs_init` | `+0x30` | 332 | 1 | 332 |
| `OsiWifiZalloc` | `esp_wifi_init_internal` | `+0xd6` | 24 | 1 | 24 |
| `OsiWifiZalloc` | `wifi_nvs_cfg_init` | `+0x46` | 4,628 | 1 | 4,628 |
| `OsiMallocInternal` | `wifi_nvs_load` | `+0x28` | 1,024 | 1 | 1,024 |
| `OsiWifiZalloc` | `trc_init` | `+0x1e` | 152 | 1 | 152 |
| `OsiWifiZalloc` | `trc_init` | `+0x32` | 152 | 1 | 152 |
| `OsiWifiZalloc` | `trc_init` | `+0x42` | 152 | 1 | 152 |
| `OsiMallocInternal` | `pp_attach` | `+0x4a` | 40 | 4 | 160 |
| `OsiWifiMalloc` | ROM `esf_buf_alloc_dynamic` | ROM | 648 | 8 | 5,184 |
| `OsiMallocInternal` | ROM `esf_buf_alloc_dynamic` | ROM | 1,748 | 32 | 55,936 |
| `OsiMallocInternal` | ROM `esf_buf_alloc_dynamic` | ROM | 788 | 2 | 1,576 |
| `OsiZallocInternal` | `wDev_Rxbuf_Init` | `+0x36` | 384 | 1 | 384 |
| `OsiMallocInternal` | `wDev_Rxbuf_Init` | `+0x108` | 1,704 | 32 | 54,528 |
| `OsiCallocInternal` | `pm_extend_tbtt_adaptive_attach` | `+0x22` | 4 | 1 | 4 |
| `OsiWifiZalloc` | `esp_wifi_set_mode` | `+0x1e` | 24 | 3 | 72 |
| direct `calloc` | `esp_supplicant_init` | `+0x26` | 108 | 1 | 108 |
| `OsiWifiZalloc` | `esp_wifi_register_mgmt_frame_internal` | `+0x22` | 24 | 1 | 24 |
| `OsiWifiZalloc` | `esp_wifi_internal_reg_rxcb` | `+0x28` | 24 | 4 | 96 |
| `OsiWifiZalloc` | `esp_wifi_set_country` | `+0x1e` | 24 | 1 | 24 |
| `OsiWifiZalloc` | `esp_wifi_set_ps` | `+0x2c` | 24 | 2 | 48 |
| `OsiWifiMalloc` | `esp_wifi_stop` | `+0x2e` | 24 | 1 | 24 |
| `OsiWifiZalloc` | `esp_wifi_set_config` | `+0x2e` | 208 | 2 | 416 |
| `OsiWifiZalloc` | `esp_wifi_set_protocols` | `+0x144` | 24 | 2 | 48 |
| `OsiWifiZalloc` | `esp_wifi_start` | `+0x1a` | 24 | 1 | 24 |
| `OsiWifiZalloc` | `wifi_create_sta` | `+0x30` | 612 | 1 | 612 |
| `OsiWifiZalloc` | `wifi_create_sta` | `+0x6e` | 1,296 | 1 | 1,296 |
| `OsiWifiZalloc` | `ieee80211_setup_ratetable` | `+0x26` | 212 | 1 | 212 |
| direct `calloc` | `pmksa_cache_init` | `+0x16` | 20 | 1 | 20 |
| `OsiWifiZalloc` | `esp_wifi_ipc_internal` | `+0x34` | 24 | 2 | 48 |
| `OsiWifiZalloc` | `esp_wifi_set_max_tx_power` | `+0x40` | 24 | 1 | 24 |
| `OsiWifiZalloc` | `esp_wifi_set_promiscuous` | `+0x4a` | 24 | 1 | 24 |

## Replacement order

The five `wDev_Rxbuf_Init` and ROM ESF pool classes account for 75 calls and
117,608 bytes, or 91.2 percent of all requested memory. They are persistent,
bounded buffer arrays and are the first replacement target.

`rust-static-rx-buffer-init` now supplies the pinned `wDev_Rxbuf_Init`
descriptor arena and payload buffers from 16-byte-aligned internal SRAM. It
accepts only the audited allocator source, exact return offsets and exact
1,704-byte payload size. The descriptor count is bounded to the qualified 32;
the pool can be expanded only after more cold heap storage has been removed.
Teardown
recognizes and releases only exact pool addresses. The vendor function still
performs the finite descriptor construction and hardware list publication.

The ROM ESF pools are deliberately kept separate until their implementation
return address, object classes, alignment and teardown ownership are pinned.
After those pools, the next high-value leaf is `wifi_nvs_cfg_init` plus
`wifi_nvs_load`; the numerous 24-byte entries are API command envelopes and
should disappear when the upper initialization/configuration state machine is
called directly instead of being replaced by generic allocator exceptions.
