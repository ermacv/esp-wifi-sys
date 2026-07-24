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
Teardown recognizes and releases only exact pool addresses. The vendor function still
performs the finite descriptor construction and hardware list publication.

Hardware qualification of this first replacement produced the exact expected
delta:

- allocator calls: 115 to 82;
- requested heap bytes: 128,984 to 74,072;
- `wDev_Rxbuf_Init` heap sites: both absent from the trace;
- first and second scan/association/WPA2/network cycles: successful;
- post-handoff allocations, reallocations and allocation failures: zero;
- radio-context allocator calls and blocking-probe hits: zero.

The test image reduced its temporary bootstrap heap from 128 KiB to 80 KiB.
It used 72,292 bytes and retained 9,628 bytes after handoff, proving that the
new SRAM pool replaced rather than duplicated the old heap ownership.

The explicit `rust-static-esf-buffer-init` boundary supplies
the three ROM ESF classes from separate 16-byte-aligned internal-SRAM arrays.
Admission requires the fixed ECO0 implementation return address `0x2f832460`
plus the exact allocator source and size pair observed above. Each class has
its exact observed capacity, and teardown recognizes only aligned slot bases
in those arrays. An unexpected ROM revision, source, size or extra request
therefore falls back to the traced bootstrap allocator instead of aliasing
storage.

Static ESF storage reduces cold allocation from 82 calls / 74,072 requested
bytes to 40 calls / 11,376 requested bytes. The apparent reconnect-time
`g_phyFuns` corruption was not an ESF lifetime failure. A JTAG write
watchpoint stopped in the ROM `memcpy` called by the Rust WPA2 continuation:
the generated `strict_wpa2_m1_m2_with_security` poll frame was 10,288 bytes,
while the 24 KiB bootstrap heap plus the new static sections left CPU0 only
about 10 KiB of stack. Its local copy crossed `_stack_end_cpu0` and overwrote
the adjacent vendor BSS.

Reducing the cold-only heap to 16 KiB leaves 18,328 bytes of CPU0 stack while
the measured post-init heap occupancy is 9,428 bytes. A post-link audit now
rejects static-ESF images with less than 16 KiB of CPU0 stack. Two independent
cold boots, each containing scan, WPA2 association, network traffic, teardown
and a second complete connection, then passed with unchanged allocation
counters, zero blocking-probe hits and an intact PHY function-table pointer.
A subsequent six-connection run completed five teardown/reconnect boundaries
with post-link traffic after every handshake. Channel work stayed balanced,
all TX/RX owners returned to their pools and the same allocation and PHY
snapshots remained intact. The application static cold-init profile therefore
now includes the ESF boundary; its former explicit feature name remains only
as a compatibility alias.

The next qualified boundary supplies the `wifi_nvs_cfg_init` descriptor table
and `wifi_nvs_load` scratch page from separate 16-byte-aligned internal-SRAM
owners. Admission is exact: `OsiWifiZalloc`, 4,628 bytes and
`wifi_nvs_cfg_init + 0x46` for the 89-by-52-byte table; or
`OsiMallocInternal`, 1,024 bytes and `wifi_nvs_cfg_init + 0x13b6` for the
serialized load page. The first owner lives until `wifi_nvs_deinit`; the
second is released inside `wifi_nvs_load`. Every other source, size or caller
falls through to the ordinary cold allocator.

This reduces cold allocation to 38 calls / 5,724 requested bytes and the
largest remaining request to 1,560 bytes. An 8 KiB bootstrap heap measured
4,796 bytes used / 3,396 free and leaves 20,848 bytes of CPU0 stack. Two cold
boots passed; the second completed six WPA2 scan/auth/association/handshake
and post-link cycles with five teardown/reconnect boundaries, unchanged
allocation counters, balanced channel work, an intact PHY function-table
pointer and fully returned TX/RX owners. The application static cold-init
profile now includes this boundary.

The numerous remaining 24-byte entries are API command envelopes and should
disappear when the upper initialization/configuration state machine is called
directly instead of being replaced by generic allocator exceptions.

The `wdev_funcs_init` and `net80211_funcs_init` callback tables are the next
qualified persistent owners. `rust-static-function-table-storage` admits only
`OsiCallocInternal` requests of exactly 1,560 bytes returning at
`wdev_funcs_init + 0x34`, or exactly 332 bytes returning at
`net80211_funcs_init + 0x30`. Both owners are separately 16-byte aligned in
internal SRAM, claimed with one non-retrying CAS, zeroed before publication,
and recognized by exact base address during teardown. The vendor constructors
remain finite direct function-pointer stores; their corresponding deinitializers
free the same published bases.

This reduces cold allocation to 36 calls / 3,832 requested bytes and the
largest request to 1,296 bytes. The unchanged 8 KiB bootstrap heap measured
2,896 bytes used / 5,296 free. A two-cycle A/B run and a promoted six-cycle
run both completed scan, authentication, association, WPA2 M1-M4 and post-link
traffic without changing the allocation snapshot. The six-cycle run ended
with 70/70 channel switches, 55/55 TX owners and 57/57 RX owners, no queue
rejection, no allocation failure, no radio-context allocator call and an
unchanged PHY function-table pointer. The application static cold-init profile
now includes this boundary; its explicit feature name is retained only as a
compatibility alias.

The existing fixed 212-byte `ieee80211_setup_ratetable` scratch owner is now
also admitted during cold init, not only after heap lockout. The admission
still requires `OsiWifiZalloc`, the exact size and the pinned
`ieee80211_setup_ratetable + 0x26` return address. The vendor leaf serializes
use and frees the scratch before returning; the Rust release path wipes it and
clears its one-shot claim without retrying.

This removes one allocation and its matching free: the qualified two-cycle
run measured 35 allocations, 22 frees and 3,620 requested bytes, with the
largest request unchanged at 1,296 bytes. Both WPA2 connections and post-link
traffic completed with an unchanged runtime snapshot, zero allocation failure
and zero radio-context allocator calls. Heap occupancy remains 2,896 bytes
because the former heap scratch was already transient.

The next boundary supplies the two allocations made by `wifi_create_sta` or
`wifi_create_softap`. `rust-static-interface-storage` recognizes only
`OsiWifiZalloc` with these pinned caller and size pairs:

- `wifi_create_sta + 0x30` or `wifi_create_softap + 0x32`, 612 bytes, for the
  interface state;
- `wifi_create_sta + 0x6e` or `wifi_create_softap + 0x6e`, 1,296 bytes, for
  the interface PHY state.

The interface state has a 624-byte physical internal-SRAM reservation so its
612-byte logical range can start and remain 16-byte aligned. The PHY owner is
an independently aligned 1,296-byte internal-SRAM reservation. Each owner is
claimed with one non-retrying CAS, zeroed before publication and released only
for its exact base address. The blob destroy paths first clear the published
global interface pointer, then free the PHY state and finally the interface
state; the Rust release path wipes each exact owner and clears its claim.

There is deliberately one shared pair of owners. It supports the qualified STA
or softAP modes, but not simultaneous APSTA construction: an unexpected second
claim falls through to the cold allocator and is therefore visible instead of
silently aliasing live state. Strict heap-free APSTA remains unsupported until
separate per-interface lifetime evidence is available.

The two-cycle A/B qualification removed exactly two allocations and 1,908
requested bytes. The promoted six-cycle run measured 33 allocations, 22 frees,
1,712 requested bytes and a 208-byte largest request. The 8 KiB bootstrap heap
retained only 980 bytes after handoff and CPU0 retained 17,016 bytes of stack.
All six scan/authentication/association/WPA2/network cycles completed with an
unchanged allocation snapshot, zero allocation failures and zero
radio-context allocator calls. The final pool snapshot showed 56/56 TX owners
and 58/58 RX owners returned, with no queue rejection. One TX ADDBA response
timed out during the run and the asynchronous state machine recovered without
affecting association, WPA2 or post-link traffic. The application static
cold-init profile now includes this boundary; its explicit feature name is a
compatibility alias.

The remaining `esp_wifi_stop + 0x2e` command was not merely an allocation
site. The pinned public wrapper can retry stop phase one up to 500 times,
calling the registered OSI delay for 10 ms between attempts. The qualified
cold-start caller invokes it only while `g_ic + 0x1f5` is state 1, before the
radio has started; the vendor stop process maps that state to
`ESP_ERR_WIFI_NOT_STARTED` and the public wrapper converts it to success.

`rust-direct-cold-stop` replaces this narrow pre-start use with one volatile
state read. States 0 and 1 return success immediately. State 2 or greater is
rejected and counted rather than entering the vendor active-stop body. A
running radio must later be stopped by an explicit Rust asynchronous lifecycle,
not through this synchronous compatibility ABI. The final ELF audit requires
the wrapper to contain exactly one byte load, no call and no control-flow
cycle, and rejects an image which still links `esp_wifi_stop` or
`__real_esp_wifi_stop`.

Hardware observed one call in state 1, one pre-start success and zero active
rejections. The expected allocation delta was exact: 33 to 32 calls, 22 to 21
frees and 1,712 to 1,688 requested bytes. Two complete WPA2 scan,
authentication, association, handshake and post-link cycles then passed with
the allocation snapshot unchanged, 22/22 TX owners and 20/20 RX owners
returned, and no queue rejection.
