# ESP32-S31 async boundary and heap audit

This document complements the generated symbol inventory in
`esp32s31-async-runtime-audit.md`. It is tied to the same pinned archives:

- `libpp.a`: `f863c65c3ed89cf5d2a2cbe0d6bca3b783ca35788a704bb68e13958e4b94958e`
- `libwpa_supplicant.a`: `f1c03da6047ccc5a9dca67d69d9c260ef711bea5119c9a451728c560e4eb34e3`

## Feasibility summary

| Boundary | Can be replaced without changing the blob? | Current solution |
|---|---|---|
| PP and WPA worker receive loops | Yes | Stackless bounded dispatcher |
| `ppTask` creation | Yes | Pre-init OSI interception returns a logical handle; the entry point is never called |
| OS timers | Yes | Executor alarm plus timer pool |
| Wi-Fi event posting | Yes, if the ESP event loop is replaced | Owned bounded `WifiEventBridge` |
| Interrupt-to-task notification | Yes | `InterruptSignal` or `BoundedChannel` |
| STA/AP data RX callback | Yes | Eight fixed payload slots plus a producer-woken owned channel |
| STA/AP application data TX | Yes | Eight fixed payload slots, one radio-owner submission attempt, and AP authorization at submit |
| NVS writes | Yes, by disabling vendor NVS | `disable_vendor_nvs`; application restores and persists configuration |
| Dynamic RX/TX/cache buffers | Partly | `disable_dynamic_wifi_buffers`; caller supplies adequate static pools |
| WPA2-Personal RX ownership | Yes | Fixed `Wpa2Ingress` plus validated owned EAPOL-Key frames |
| WPA2-Personal handshake control | Yes, above blob | Fixed STA/AP states, replay protection, completion tickets, and owned actions |
| WPA2 PTK/MIC/key unwrap | Yes, above blob | IRQ-driven fixed `CryptoJob` operations; no hardware-status polling before IRQ |
| WPA2 M1-M4/GTK framing | Yes, above blob | Fixed owned builders/parser, exact lengths, replay/nonce context binding |
| WPA2 TX/key command ownership | Yes, above blob | `Wpa2IoQueue`, aligned CCMP keys, fixed key table, one fail-fast backend attempt |
| WPA2 retransmission scheduling | Yes, above blob | Finite generation-tagged one-shot alarms; one action per alarm edge |
| STA EAPOL TX completion | Yes, opt-in replacement | Registered fixed-channel callback copies only M2/M4 metadata |
| STA link notifications | Yes, required replacement | Connected/disconnected events use a fixed channel; the four-way query is Rust-owned state |
| S31 static TX/pairwise key backend | Partial | Static-pool TX and stable `0xb8` CCMP objects implemented; GTK/authorization fail closed |
| WPA2-Personal crypto callback table | Only synchronously | Precompute PBKDF2 asynchronously with `WpaPskJob`; replace remaining handshake transitions above this ABI |
| WPA3 SAE in this S31 blob | No usable implementation | Out of current scope; feature is disabled and registered SAE callbacks are null |
| Rust-owned async crypto | Yes | Pinned `CryptoJob` plus `InterruptCryptoEngine` and ISR signal |
| Enterprise EAP/TLS crypto inside blob | No | Requires replacement of the EAP/TLS state machine above the crypto calls |
| `malloc` inside WPA/EAP/TLS | No | Requires replacement of the allocating protocol code or a fixed arena compatibility layer |
| `ets_delay_us` inside PP leaf functions | No | Requires replacement of the containing leaf with a timer-driven continuation |
| Lifecycle waits in `eloop_destroy` | No | Serialize lifecycle and replace the complete async deinit boundary |
| WPS `eloop_register_timeout_blocking` | No | Keep WPS disabled until its control flow is replaced |

## Cryptography

The current secured target is WPA2-Personal AP/STA. WPA3 is intentionally not
implemented by this runtime: the bundled S31 supplicant has no usable SAE
engine behind the net80211 glue. Enterprise EAP is also outside the current
priority.

`wifi_init_config_t` embeds `wpa_crypto_funcs_t`. AES, SHA, HMAC, PBKDF2,
CCMP, GMAC, wrap, and unwrap callbacks can therefore be replaced with Rust or
hardware implementations without modifying an archive. Every callback has a
synchronous C ABI, however: the result buffer must be complete when the
callback returns. There is no request context, completion callback, or pending
return value.

Consequences:

1. A hardware peripheral may be used only if the callback polls it to
   completion. That removes software compute but still blocks the executor.
2. Returning after starting DMA is invalid because the blob immediately reads
   the output and often releases the input buffers.
3. WPA-Personal PBKDF2 should be performed before connection and the resulting
   PMK supplied to the connection state where possible. The remaining
   handshake hashes are short bounded operations.
4. Enterprise EAP uses the internal TLS/EAP implementation and calls
   `eap_sm_process_request` as one synchronous operation. The Wi-Fi crypto
   callback table is not an async boundary for certificate parsing, RSA, or
   TLS record processing.

`Wpa2Ingress` now removes borrowed vendor RX-buffer lifetime from the WPA2
boundary. It validates the complete EAPOL and RSN key-data lengths before a
bounded copy, owns peer/interface metadata, and hands the frame to a
producer-woken async consumer. This is transport ownership and parsing, not a
key-install or TX implementation.

The control-flow portion is now implemented separately from hardware actions.
STA/AP states accept one owned frame or one ticketed completion and return one
action. Replayed M3 never causes key reinstallation, AP peer count is a const
generic fixed table, and stale crypto completions cannot advance a newer
handshake. PTK, MIC, key wrap/unwrap, and TX frame jobs own all inputs/outputs.
The I/O queue also owns complete Ethernet frames and aligned CCMP install keys.
`S31StaticWpa2Io` now submits into the configured static PP pool and programs
pairwise hardware/software CCMP state. Its software objects live in caller
provided `'static` storage, and the existing vendor slot must be null or point
to that exact object. GTK node metadata and AP authorization remain target
integration boundaries.

The viable fully async design is a Rust WPA/EAP/TLS state machine that owns its
buffers and submits crypto commands to an async engine. A hardware completion
ISR calls `InterruptSignal::notify_from_isr`; the crypto future resumes on the
executor and only then advances the protocol state. This cannot be inserted
under an existing synchronous crypto callback.

That Rust-owned hardware boundary is now implemented by
`InterruptCryptoEngine`. Its backend starts the peripheral using a pinned
`CryptoJob`, reports hardware status without polling in a loop, and finalizes
only after `InterruptSignal` wakes the future. Cancellation calls `abort`, and
job storage is wiped on drop. `WpaPskJob` specializes this path for the
4096-iteration WPA/WPA2-Personal PBKDF2-SHA1 derivation, allowing a 32-byte PMK
to be ready before the synchronous connect path begins. The audited exported
`wpa_set_pmk` (`0x8c` bytes in the pinned archive) then copies that key from a
completed job when invoked by the single radio owner.

The S31 has no verified SHA-1 completion interrupt, so its concrete PBKDF2 path
is a Rust software future with a caller-selected HMAC budget per poll. Every
poll advances cryptographic work; it never reads a busy flag or waits for an
RTOS object. The future uses only fixed job/intermediate storage and wipes
partial output if cancelled. This is distinct from the HAL CPU SHA work queue,
whose recall mechanism polls hardware busy state and is therefore excluded
from the strict runtime.

## Critical sections and locks

There are four different mechanisms and they must not be treated alike:

- `_wifi_int_disable`/`_wifi_int_restore` protect state shared with the Wi-Fi
  ISR, including `pp_sig_cnt`. Initialization delegates to the hardware
  adapter. The strict phase requires the executor and Wi-Fi ISR on
  `wifi_task_core_id`, validates the current hart, and uses local MIE masking;
  it neither spins on nor stalls the second core.
- `wifi_api_lock` skips its mutex when `current_task_is_wifi_task()` is true.
  PP and timer callbacks already run under the virtual PP identity, so this
  bypass is active there.
- `g_wifi_global_lock`, eloop mutexes, and other OSI mutexes do not all have an
  identity bypass. The current adapter never waits for them. If contention is
  observed, silently returning failure is not generally correct because many
  blob callers ignore the return value.
- `_dport_access_stall_other_cpu_*` remains supplied by the hardware adapter
  only during initialization. After `prepare_strict_runtime` the wrapper
  records a violation and returns without entering the stall.

All public Wi-Fi operations should therefore be serialized as commands to the
single radio owner instead of calling synchronous `esp_wifi_*` APIs from
arbitrary futures. Rust-owned queues and signals use atomics and do not need
the vendor mutexes. The interrupt masks around blob-owned shared state remain
until that state is also moved to Rust.

`RadioCommandQueue<C, N>` and `RadioOwnerFuture` now implement this ownership
boundary. Producers move typed commands into a fixed-capacity channel. Only
the owner handles them under virtual Wi-Fi identity, with a finite per-poll
budget before PP/timer work is polled.

The production initialization path prevents the task from existing at all.
Before `esp_wifi_init_internal`, the stable OSI table is patched in place. Its
task-create callback recognizes only the pinned `ppTask` entry, publishes a
logical handle and releases the startup latch without invoking the entry point.
Already queued initialization events are then dispatched synchronously with an
explicit finite budget before the next vendor API consumes their effects.
There is no RTOS task creation, event-15 retirement, delay, status poll, or
blocking semaphore. The older event-15 handoff is retained only as a
comparative HIL mode and cannot establish the production taskless invariant.

## Interrupt synchronization

`InterruptSignal` is an edge counter plus a waker. Its interrupt side performs
one atomic increment and a non-spinning wake. Vendor code is never called from
the ISR. `wait_after(generation)` turns the next edge into a future and detects
multiple/coalesced interrupts through the generation value.

`BoundedChannel<T, N>` is used when the ISR also has to transfer owned data. It
is fixed-capacity and lock-free; overflow is returned immediately. The async
consumer registers its waker before checking the queue to avoid a lost wake.

Ordinary STA/AP data is also detached from arbitrary netstack callbacks.
`install_async_wifi_data_rx` registers two finite callbacks which claim one of
eight static 1600-byte slots, copy the frame, recycle the vendor RX object, and
return immediately. `receive_wifi_data` owns the slot until its frame guard is
dropped. Oversized input or exhaustion is counted and rejected without retry.
Recycling runs under the virtual Wi-Fi task identity, so the pinned API-lock
path cannot wait.

The matching application TX channel also owns eight fixed 1600-byte slots.
Producers call `try_send_wifi_data`; the radio owner awaits
`receive_wifi_data_tx` and calls `S31StaticWpa2Io::try_transmit_wifi_data` once.
Static pool exhaustion is returned immediately. AP submission rechecks the
destination against the current Rust controlled-port table, while STA follows
the same direct peer lookup, buffer claim, descriptor setup, and PP post path.
Promiscuous/sniffer RX remains disabled: the strict event-13 dispatcher always
fails closed before entering the vendor handler, which would otherwise invoke
an optional callback and then release two heap-owned objects.

Vendor ioctl event 6 is also outside the strict runtime. Its envelope contains
an arbitrary callback, heap ownership flags, and an optional completion
semaphore, while its dispatcher enters PM wake/sleep bookkeeping around that
callback. Wi-Fi configuration, start, stop, and mode changes must complete
before `prepare_strict_runtime`; a later event 6 is rejected without invoking
or freeing the envelope.

Stock net80211 output event 5 is rejected as well: its handler repeatedly
drains a shared list, whereas all strict application/EAPOL/association paths
submit one static frame directly. For timers, the original producer allocates
an eight-byte envelope and posts event 7. The final-link timer wrapper replaces
that producer with a sixteen-slot fixed pool and a private executor event. Only
the proven `timer_connect` success action is completed locally. The
`chm_dwell` action is rejected because its downstream `chm_end_op` contains an
arbitrary completion callback and an OSI synchronization call.
Stock auth/assoc/handshake/reconnect/scan/beacon/hostap timeout recovery can
reach synchronous MAC deinit or channel switching and therefore fails closed
after the strict proof. WPA2 retry timing is Rust-owned and remains async.

The strict profile has a separate Rust-owned passive scan and does not call
`esp_wifi_scan_start`. `passive_scan_2_4ghz` enqueues one channel command at a
time to the radio owner, uses the executor timer-backed channel-operation
boundary for dwell completion, and awaits one wake edge per channel. Beacon
and probe-response frames are parsed before the vendor management-frame tail
and deduplicated by BSSID into a 32-entry BSS table. The caller supplies the
output slice; no vendor AP list, `Vec`, semaphore, task delay, or polling loop
is used. Table overflow is reported in the scan summary and never waits.
The pinned RX-policy jump table is not entered: its exact policy-3 and policy-0
branches are expressed as direct calls to audited finite `ic_*` leaves. Dwell
completion likewise accepts only the Rust scan callback, clears the fixed
channel-operation state directly, and makes no arbitrary indirect call.

## Heap and indirect calls

Setting dynamic RX, dynamic TX, and cache TX counts to zero removes only the
explicitly configurable dynamic packet-buffer modes. Adequate static buffer
counts and the correct target-specific static buffer type must be configured
by the hardware integration.

It does not remove these allocations:

- EAP request and response `wpabuf` objects;
- EAP/TLS/PEAP/TTLS method state;
- certificate, ASN.1, RSA, and bignum objects;
- eloop timeout nodes;
- WPA and net80211 temporary frames and nodes.

Direct `malloc`, `calloc`, `realloc`, and `free` references are widespread in
`libwpa_supplicant.a`. The final firmware must link with
`--wrap=malloc`, `--wrap=calloc`, `--wrap=realloc`, and `--wrap=free`.
The crate's `__wrap_*` functions delegate during initialization, then deny all
four operations after `prepare_strict_runtime`. This is a runtime tripwire, not
permission to use allocating WPA/EAP/TLS paths: a denied allocation may leave
vendor state partially mutated, so every strict root must still be statically
proven not to reach it.

`patch_allocator_probes` measures all allocator slots reached through the OSI
table, including internal and Wi-Fi-specific malloc/calloc/realloc variants.
It delegates only before the strict phase. The linker wrappers cover direct C
symbols, and the final-ELF auditor rejects a firmware missing any wrapper.

`AuditedFuture` combines the blocking, allocation, critical-section, and
other-core-stall probes into a fail-closed runtime gate. Allocation tripwires
cover OSI slots and direct C symbols, while the relocation audit must still
prove that normal strict execution never triggers either class.

The final link uses LLD `--wrap` for `pp_post`,
`ieee80211_timer_process`, and
`--wrap=ieee80211_hostapd_beacon_txcb`, and
`--wrap=ieee80211_tx_mgt_cb`, and
`--wrap=wDev_record_ftm_data`, and
`--wrap=wDev_ftm_set_t1t4`, and
`--wrap=wDev_isNANPktInValidSlot`, and
`--wrap=dbg_read_tx_ppdu`, `--wrap=dbg_dump_rx_ppdu`, and
`--wrap=dbg_dump_rx_sigb`, and
`--wrap=wifi_gpio_debug`,
`--wrap=wpa_sm_rx_eapol`, `--wrap=wpa_ap_rx_eapol`, and
`--wrap=hal_crypto_set_key_entry`, and `--wrap=wifi_log`. Every vendor success,
retry, discard, and
collision branch converges on `lmacTxDone`; its strict wrapper replaces the
inline callback bitmap, `ppProcTxDone` power-management tail, and tail-call to
`ppProcessTxQ` with one-callback/event and queue-resume continuations. The TXQ
state wrapper reads pinned MMIO without test/log hooks and exposes one
completion/collision bitmap bit per event. The original archive sections must
not remain in the final ELF.

Nine ROM-exported entries cannot use LLD wrapping because the ROM linker
scripts assign their public symbols after `--wrap` rewriting. The late
`esp32s31-rom-wrap-overrides.x` fragment instead aliases
`ieee80211_set_tx_pti`, `esf_buf_alloc`, `esf_buf_recycle`,
`hal_mac_get_txq_state`, `hal_mac_get_txq_complete`, `lmacTxDone`,
`pm_on_beacon_rx`, `pm_on_data_tx`, and
`esp_test_tx_enab_statistics` to Rust wrappers while pinning their
`__real_*` names to the audited ROM addresses.

The AP-beacon replacement uses
`ld/esp32s31-net80211-locals.x` to name the pinned local timer/flag sections.
It only resets the send flag, reads the next TBTT, and rearms the fixed OSI
timer. Mesh, sleeping-client multicast flush, and the optional indirect hook
fail closed before invocation.

The management-completion replacement accepts ordinary authentication,
association, probe, and beacon subtypes without entering the stock callback.
Disassociation, deauthentication, and action/off-channel completions fail
closed. The stock branches behind those subtypes mutate node/key/channel state
and can eventually reach the MAC deinitialization delay; supporting them needs
an explicit bounded async command/state machine.

FTM is outside the strict basic profile. `disable_ftm` clears both capability
bits and validation rejects either bit if restored. The final-link wrapper is
defense in depth: an unexpected FTM action frame records a strict failure
instead of entering `wDev_record_ftm_data_local -> ets_delay_us(50)`.
The TX-side optional T1/T4 hook records the same failure without calling its
registered callback. GPIO tracing and TX test statistics are unconditional
no-ops, so their callback/time-query paths cannot enter the strict graph.
The NAN valid-slot hook retains its recovered descriptor-kind test: ordinary
AP/STA frames return true, while NAN frames return false without entering the
registered scheduler callback.

The strict `WIFI_PS_NONE` profile also replaces `pm_on_beacon_rx` with a
no-op. PP/net80211 performs ordinary beacon parsing and delivery before this
hook; the removed tail is limited to power-save/mesh bookkeeping and contains
the TIM-to-radio-shutdown delay path. Both direct calls and the saved vendor
function-table pointer are redirected by the mandatory final-link wrapper.

The three verbose PPDU/SIG-B decoders are also no-op wrappers under the verified
`WIFI_LOG_NONE` policy. This removes their formatting loops and direct
`puts`/`putchar` leaves from ordinary TX completion and RX success without
changing descriptor or retry state.
The `wifi_log` dispatcher itself is interposed as a no-op as well, so error and
diagnostic branches cannot re-enter a formatter or an arbitrary logging sink.

The STA/AP WPA2 RX entry points are Rust-owned as well. Their wrappers copy one
validated EAPOL-Key packet and peer identity into a global eight-slot channel;
they never call the stock supplicant/authenticator. Queue full and invalid
frames return “not consumed” immediately and increment a rejection counter.
The saved WPA function-table addresses are linker-verified against both Rust
wrappers before the strict proof is issued.

The remaining STA runtime notification slots are patched after
`esp_supplicant_init` and before RX starts. Connected/disconnected callbacks
copy bounded metadata into a fixed channel, and the four-way-handshake query
reads an explicit Rust-owned atomic flag. This removes the stock disconnect
edge through `wpa_sm_notify_disassoc -> eloop_cancel_timeout -> free` from the
active strict graph. The normal connect request remains a serialized
initialization/control operation; automatic reconnect is not part of the
strict runtime profile.

Indirect calls are also part of the protocol ABI: EAP method `process`
pointers, WPA crypto tables, callbacks, eloop timeouts, and PP registered
handlers. They cannot all be removed while retaining the vendor protocol
implementation. New Rust-facing paths should use enums and typed bounded
channels; the remaining indirect calls must be confined to audited vendor
dispatch boundaries.

## Event, logging, and NVS policy

`wifi_event_post` passes `UINT32_MAX` to `_event_post`. `WifiEventBridge` copies
both the event-base name and payload before returning, then transfers ownership
through a bounded channel. It deliberately replaces the ESP event loop, so its
async consumer owns application event dispatch.

The S31 `libprintf.a` formats radio logs into an 80-byte stack buffer and calls
`__esp_radio_printf`. Without the `sys-logs` feature the Rust symbol is a no-op,
so the default path does not block or allocate. Enabling `sys-logs` delegates
to the selected logger and is only async-safe if that logger is a nonblocking
ring-buffer sink.

`disable_vendor_nvs` makes the blob's Wi-Fi NVS paths no-ops. The application
must load configuration before Wi-Fi operation and persist changed settings in
an async storage task. A deferred wrapper around only `_nvs_commit` is not
sufficient because setters and blob operations may themselves enter flash.

## Remaining replacements

1. Route every application-facing Wi-Fi event through `WifiEventBridge` and
   define an explicit overflow policy per event class.
2. Define the product's command enum and response channels on top of the
   implemented `RadioCommandQueue`; never call vendor APIs from producers.
3. Keep WPS disabled and make deinit an explicit async state machine.
4. Replace remaining TX-stop/deinit leaves containing `ets_delay_us` or hardware
   polling with timer/interrupt continuations.
5. For strict heap-free Enterprise support, replace EAP/TLS with fixed protocol
   buffers on the implemented async crypto boundary. There is no ABI-only shortcut.

## Strict no-wait gate

`audit-strict-esp32s31` builds a direct call graph from RISC-V relocations in
all S31 archives. Its roots are the PP handlers still called by the Rust
dispatcher plus the vendor leaves called by Rust replacements. Direct heap,
delay, RTOS wait, NVS, logging, abort, and core-stall symbols are forbidden.
An unresolved `jalr`/`jr` is also rejected until its OSI slot or callback is
classified explicitly. Control-flow cycles are rejected until a fixed bound
is proven; the auditor builds an intra-function CFG so a backwards layout edge
without a path back is not mistaken for a loop. This catches polling loops and
data-dependent queue drains that a symbol-only import inventory misses.

The first implemented replacement is PP event 22. With `strict-no-wait`, the
16-us `lmacDisableTransmit` settling delay is split across an executor alarm.
The linked-list scan and MSDU drain from `lmacDiscardMSDU` are also split so a
continuation touches at most one link or one MSDU. The replacement reads and
clears the pinned S31 TXQ interrupt MMIO directly, avoiding the vendor HAL's
optional test/log callbacks. The audit pins the original
`lmacProcessTxTimeout` (`0x62`), `lmacDisableTransmit` (`0xae`),
`lmacDiscardFrameExchangeSequence` (`0xd6`), and `lmacDiscardMSDU` (`0xd2`)
sizes in addition to the complete archive digest.

Strict initialization must call `configure_static_wifi_buffers`,
`disable_vendor_nvs`, `disable_frame_aggregation`, `disable_ftm`, and
`validate_strict_basic_config`. The archive defaults select dynamic TX/RX and
provide no static TX pool. After driver init and before executor start,
`prepare_strict_runtime` sets and verifies both `WIFI_PS_NONE` and
`WIFI_LOG_NONE`, verifies that `patch_pp_runtime_callbacks` replaced the RTOS
OSI table and that the allocator plus critical-section probes were installed
before init, verifies all sixteen final-link wrapper addresses, then arms runtime
heap and core-stall guards and returns the proof
required by `S31StaticWpa2Io`. Allocation callbacks return null, free callbacks
do not enter the heap, and core-stall callbacks return immediately until
explicit post-executor teardown; strict dispatch rejects
unexpected aggregation, PM, BSS-color, modem-beacon, and coexistence events.

Pre-handoff preparation switches connection-time management allocation to the
fixed Rust pool. Authentication, association, and probe frames therefore
cannot remain as heap-owned objects when the runtime heap gate is armed.

PP event 16 is also replaced. The original `ppProcTxDone` drains the complete
linked list, iterates callback bitmaps, and ends in power management. The Rust
state machine performs one dequeue, one classified mode-0 callback, or one
fixed-pool recycle per continuation. It verifies the callback-table pointer before
the direct call and fails closed on unknown bits, user TX callbacks,
fragment/trace descriptors, and frame types outside the strict fixed pools. The pinned leaves are
`pp_coex_tx_release` (`0x74`), `esf_buf_recycle` (`0x156`), and the four basic
STA/AP mode-0 callback sizes.

The strict timeout/discard path also replaces the `lmacTxDone` mode-1 bitmap
loop with one classified callback bit per executor event before it appends the
frame to event 16. Final-link interposition routes the other vendor
TX-completion calls through the same state machine. The replacement accepts
only the pinned STA EAPOL mode-1 callback. Off-channel connection-probe and AP
power-save callbacks fail before invocation, as do direct-recycle/aggregation
descriptors and optional TX-time recording.

The strict gate still intentionally fails. Confirmed remaining paths include:

- the stock WPA2-Personal `eapol_txcb` target reaching `calloc/free` through
  eloop timeouts and `ets_delay_us` through deauthentication if strict
  integration fails to install the provided async TX-done callback first;
- basic retry submission now enters only the pinned hardware-transmit leaf;
  unobserved RTS and generic-error outcomes still enter their complete vendor
  handlers, and collision plus connection-management state transitions are
  not yet reconstructed;
- explicit disassociation, deauthentication, and off-channel action completion
  is not implemented; the Rust management wrapper rejects those subtypes before
  the stock channel-change and `hal_mac_deinit -> ets_delay_us` branches;
- allocator and OSI callbacks reached through unresolved indirect calls;
- remaining callback chains and TX/RX queue drains with unproven backward
  branches.

### TX A-MPDU boundary

The successful Rust-owned ADDBA exchange is only protocol negotiation; it does
not make the vendor aggregation scheduler safe to enable. The pinned S31
`ieee80211_ampdu_request` allocates a `0x78`-byte per-TID object and owns an OS
timer. Those two responsibilities are now replaced by `TxBlockAckSession` and
the executor timer pool, but the stock data path would still enter a separate
stateful subsystem:

- `ppCalTxAMPDULength` moves frames between linked lists in `pTxRx`, pauses the
  hardware TXQ, and can call `ppAssembleAMPDU` repeatedly;
- `ppAssembleAMPDU` mutates every descriptor and contains a fatal logging path
  followed by a non-returning loop;
- `lmacEndFrameExchangeSequence` reads the 64-bit hardware BlockAck, updates a
  vendor bitmap, and selects recycle, BAR resend, regression, or resort paths;
- `ppRecycleAmpdu`, `ppRegressAmpdu`, and `ppResortTxAMPDU` walk and relink the
  aggregate chain, and can post more PP work.

Consequently `ic_ampdu_op` is not a sufficient stateless enable switch. The
strict runtime keeps the vendor operational bit clear until all aggregate
descriptor completion and timeout ownership has moved to Rust.

`TxAmpduBatch` is the first half of that replacement. It owns up to 32 fixed TX
slot indices, assigns consecutive 12-bit sequence numbers, consumes a 64-bit
BlockAck including sequence wrap, and returns exactly one acknowledged/retry
result per executor step. It owns no raw frame pointer and has no allocator,
timer, lock, polling operation, or variable-length drain. The remaining work is
to construct the hardware descriptor chain from those slots and replace the
aggregate branches of TX completion/timeout before enabling the negotiated
agreement.

The strict basic-HT completion path also replaces `hal_mac_get_txq_complete`.
The original `0x81e`-byte body performs the required fixed MMIO decode first,
then enters HE MPLEN list maintenance, connection-state locks, formatters, and
debug logging. The replacement reproduces the two six/eight-byte completion
records and traps after recording a strict failure if it observes HE, BAR,
A-MPDU, or live MPLEN state. A trap is required because the pinned vendor
caller discards the callee's return value and would otherwise interpret a
returned error as a completion record. Rust now owns the basic completion
outcome state machine while rejecting those unrelated tails.
The independent `hal_mac_tx_get_blockack` leaf is only `0x3e` bytes, contains
fixed MMIO loads/stores and no calls or cycles, and passes the strict auditor as
the future Rust A-MPDU completion input.

Strict event 23 no longer enters `lmacProcessTxComplete`. Rust selects one bit
from the completion bitmap, decodes one fixed completion record, copies the six
recovered queue-state fields, clears that queue's completion bit, and uses a
direct `match` for success, RTS error, CTS timeout, TX error, or ACK timeout.
The stock outer loop, test hook, formatter, and indirect outcome jump table are
therefore absent. Hardware stress over 5,012 completions proved that the 4,790
successes used only queue zero/kind three, with zero TXOP ownership, no linked
MPDU, and no aggregate descriptor state. The strict success path now performs
the recovered short/optional-long state updates and basic MPDU recycle count in
Rust, then enters the existing bounded Rust TX-done continuations directly.
ACK and CTS timeout processing now has the same strict basic-HT boundary. Rust
updates the short/long queue and descriptor counters, applies the recovered
rate fallback, evaluates the rate-control and MIB retry limits, performs the
non-aggregate lifetime check from the MAC clock, and either prepares one retry
or enters the existing one-frame-per-event discard continuation. It rejects
TXOP, linked, HE, BAR, A-MPDU, aborted, and trigger/MU states before mutation.
The narrow submission body implements the pinned non-HE `rcGetRate` behavior
as either one direct per-peer selection or at most four cumulative fallback
table entries, then submits exactly one frame with `lmacTxFrame`. This removes
the vendor rate helper and its `wifi_assert` failure path. HE and aggregate
descriptors are rejected before selection, so the nested `rcGetSMPDURate`
logic is outside this profile. `ppCalFrameTimes` is also absent: its controlling
bit is rejected before mutation and the Rust selector changes only the rate
byte. `lmacRetryTxFrame`, the outer ACK/CTS bodies, retry-failure bodies,
end-exchange dispatcher, test hook, retry-limit helper, and lifetime helper are
no longer called.

A 5,014-completion hardware stress run exercised 222 ACK and one CTS timeout
through this direct Rust rate-selection path. All 223 retries retained the same
basic-HT frame, queue-zero/kind-three ownership, no TXOP, and no linked MPDU.
The complete WPA2/DHCP/DNS/TCP/HTTP/UDP test passed at 25.979 Mbit/s with 4/4
HTTP transfers and zero post-takeover allocation, blocking callbacks, task
delays, direct delays, or queue rejection. An earlier direct split stalled
because `rcGetRate` had incorrectly been declared with one argument;
disassembly confirmed its two-argument ABI before the equivalent bounded body
was moved into Rust.

The `hil-vendor-tx` build records allocation-free before/after snapshots for
success and retry outcomes, including queue kind, status, retry counters,
TXOP/list state, and descriptor flags. This remains the HIL oracle for the
remaining hardware-transmit leaf and future aggregate enablement. RTS-error
and generic TX-error outcomes were not observed and remain vendor roots.

For WPA2 specifically, `hal_crypto_set_key_entry` is replaced at final link.
The Rust wrapper reproduces the pinned fixed key-table register writes for keys
up to 32 bytes and performs no temporary allocation irrespective of pointer
alignment. The surrounding `wDev_Insert_KeyEntry` bookkeeping and finite
`hal_crypto_enable` call remain. This is not enough to call the stock higher
key wrappers: AP and non-delete STA paths allocate a persistent opaque
software-key object. `S31StaticWpa2Io` instead
reproduces the pinned pairwise/group object in stable `S31StaticKeyStorage` and
reads the `g_ic` key slot directly, rejecting a foreign pointer before either
hardware or metadata mutation. It stores the verified static pointer itself;
the getter and potentially freeing vendor setter are no longer roots. AP
PTK/SPP lookup and STA GTK metadata use `cnx_node_search` plus the recovered
bounded byte loads/stores.
Its initialization reproduces the exact bounded `wifi_init_key` layout fills
directly in Rust-owned storage, so no vendor initializer remains on that path.
The final link replaces `esf_buf_alloc/recycle`. Strict data TX uses the
already initialized vendor kind-1 free list under local MIE masking, while
management kinds 2 through 4 use eight Rust-owned 1600-byte slots. Exhaustion
returns immediately; no OSI mutex, malloc, free, or dynamic buffer fallback is
called. A final-link management-output gate admits only ordinary association,
authentication, and probe subtypes on the home channel. It rechecks live
non-mesh/non-NAN and AP no-power-save invariants before the stock body; a
rejected frame is returned to the fixed ESF pool.
The neighboring `ieee80211_set_tx_pti` wrapper replaces its OSI-table call with
the exact bounded success operation from the pinned coexistence archive: one
volatile byte read from exported `coex_pti_tab[48]` and two descriptor stores.
An out-of-range event is handed to the management-output gate for one-time
recycle instead of continuing with an invalid descriptor.
`S31StaticWpa2Io` no longer
calls `esp_wifi_internal_tx`, because its
global OSI lock can wait; it enters the bounded peer/static-buffer/post leaves
directly and fails immediately on exhaustion or a power-save peer. STA GTK maps
all logical ids to the pinned hardware group slot one and
uses the finite `ieee80211_set_sta_gtk_index` byte stores; AP GTK uses hardware
slots 8 through 11. Since the blob has no independent controlled-port setter,
AP authorization lives in a fixed Rust peer table and must gate every ordinary
data-channel operation; EAPOL uses a separate pre-auth path. TXQ bitmap
processing, the common TX-done tail, beacon completion, ordinary management
completion, basic retry accounting/discard, and retry rate selection are
classified. Final hardware submission and connection paths are not yet fully
Rust-owned. Key installation additionally
requires no live RX fragment from the old key, because the stock cleanup path
can call `wifi_log`.

The strict WPA2 AP boundary now patches the complete callback group before AP
start. Stock `hostap_init/deinit`, station join/remove, RSN lookup, and peer-SPP
lookup are replaced together, so the heap-backed authenticator and its eloop
rekey timers are never created. Rust retains one validated WPA2-PSK/CCMP RSN IE
and eight stable `0x28` station slots. Association events are copied into a
fixed wake-driven channel; the response uses only the pinned subtype
`0x10`/`0x30` constructor, fixed management pool, and management output. The
stock allocating `esp_send_assoc_resp` and ioctl envelope are bypassed.

Use `--elf final.elf --enforce` after linking. Presence of a forbidden symbol,
a missing direct-heap wrapper, or a replaced vendor entry is a build failure;
`--verbose` prints every archive path.
