# ESP32-S31 stackless Wi-Fi runtime

This experimental crate replaces the infinite vendor `ppTask` loop with a
wake-driven Rust `Future`. It does not modify the vendor archives and does not
initialize Wi-Fi peripherals.

The current prototype provides:

- the recovered ESP32-S31 `ppTask` event map;
- direct calls to the original exported run-to-completion handlers;
- the required `pp_sig_cnt[36]` receive accounting;
- a fixed-capacity lock-free queue for task and ISR producers;
- a bounded `WifiRuntimeFuture` with no RTOS task or separate C stack;
- recognition of `ppTask` in an OSI task-create callback;
- an allocation-free OS timer bridge whose callbacks run in async context;
- non-blocking normal and recursive OSI mutexes;
- a stackless Enterprise EAP dispatcher replacing `wpa2_task`;
- an async Michael MIC countermeasure continuation replacing its 10 ms sleep;
- a generic fixed-capacity owned-data channel and ISR-to-async edge signal;
- an optional owned Wi-Fi event bridge replacing blocking ESP event posting;
- critical-section/core-stall reachability counters that preserve hardware semantics;
- a typed, fixed-capacity application command channel serviced by one radio owner;
- pinned owned crypto jobs with interrupt-driven async completion and cancellation;
- an async WPA-Personal PBKDF2/PMK precomputation job;
- fixed WPA2-Personal STA/AP state, M1-M4/GTK builders, and owned crypto jobs;
- a fail-fast WPA2 I/O command boundary with aligned CCMP keys and static key storage;
- finite WPA2 retransmission schedules driven only by one-shot alarm edges;
- an owned STA EAPOL TX-done bridge replacing the stock WPA state callback;
- an owned fixed-slot STA/AP data RX channel replacing arbitrary netstack callbacks;
- an owned fixed-slot application data TX channel with fail-fast static-pool submission;
- an S31 static-pool TX and pairwise-CCMP backend with stable opaque key objects;
- a strict future wrapper that fails on observed blocking, allocation, or core-stall paths;
- allocation-free recording of unexpected blocking calls.

The binary audit and exact dispatch table are in
[`../docs/esp32s31-async-runtime-audit.md`](../docs/esp32s31-async-runtime-audit.md).
Regenerate and validate them with:

```console
cargo +stable run -p xtask --bin analyze-esp32s31 -- --write
```

## Integration boundary

This crate intentionally does not own the complete OSI table. It patches the
runtime fields of a table supplied by the hardware integration and preserves
that table's PHY, clock source, allocator, NVS, and coexistence callbacks.

On ESP32-S31, `patch_pp_runtime_callbacks` patches these fields in an existing
complete `wifi_osi_funcs_t` supplied by the hardware integration:

- semaphore create/delete/take/give and thread semaphore;
- queue send/receive/count and Wi-Fi queue create/delete;
- task create/delete/delay/current-task identity;
- millisecond-to-tick conversion and maximum task priority.
- normal/recursive mutex create/delete/lock/unlock;
- event-group create/delete/set/clear and non-waiting state checks;
- OS timer set/arm/disarm/done and monotonic time access.

The PP queue and semaphores are fixed-capacity and allocation-free. Semaphore
take never waits: an unavailable semaphore with a non-zero timeout is recorded
as a blocking-path violation. Unknown task entries and generic queues are also
rejected and recorded.

```rust,ignore
patch_pp_runtime_callbacks(&mut wifi_osi_table);

fn now_us() -> u64 {
    // Read the application's monotonic hardware/executor clock.
}

fn rearm_alarm(deadline_us: Option<u64>) {
    // Program or cancel one non-blocking hardware/executor alarm.
}

let wifi = take_wifi_runtime(
    DEFAULT_EVENT_BUDGET,
    DEFAULT_EVENT_BUDGET,
    now_us,
    rearm_alarm,
)
.expect("the Wi-Fi runtime may only be taken once");
executor.spawn(wifi);
```

The alarm interrupt must call `timer_alarm_interrupt()`. It only wakes the
future; vendor timer callbacks never execute in interrupt context. After each
poll the runtime calls `rearm_alarm` with the nearest absolute microsecond
deadline, so there is no periodic polling.

Timer callbacks execute under the logical PP identity. This makes
`esp_wifi_ipc_internal()` take its inline path instead of posting an ioctl to
`ppTask` and synchronously waiting on a semaphore.

PP events 5 through 7 are not accepted after the strict proof. Event 5 drains
the stock net80211 output list in a loop; application data and strict
management paths bypass that list. Event 6's vendor ioctl envelope
contains an arbitrary callback, heap ownership flags, an optional completion
semaphore, and PM wake/sleep bookkeeping. Configuration, mode changes,
start/stop, and any API that would post such an ioctl must finish before
`prepare_strict_runtime`. The original event-7 producer allocates an eight-byte
timer envelope; its mandatory wrapper instead claims one of sixteen fixed
slots and posts a private one-action executor event. Only the `timer_connect`
success action is completed locally. `chm_dwell` and vendor
auth/assoc/handshake/reconnect/scan/beacon/hostap recovery timers can enter
synchronous MAC teardown or channel switching and therefore fail closed;
WPA2 retry timing remains Rust-owned. Any unexpected stock event 5, 6, or 7
fails immediately.

Every vendor handler must still return without waiting. NVS writes, direct
delays, logging, and application-facing synchronous Wi-Fi calls need
reachability instrumentation on hardware before the runtime is complete.

For a runtime that owns application event dispatch, install a static event
bridge before Wi-Fi initialization:

```rust,ignore
static EVENTS: WifiEventBridge<16, 1536> = WifiEventBridge::new();

unsafe { patch_async_event_post(&mut wifi_osi_table, &EVENTS) };

loop {
    let event = EVENTS.receive().await;
    // `base()` and `data()` are owned slices; no vendor pointer escapes.
    handle_wifi_event(event.base(), event.id(), event.data()).await;
}
```

The callback copies the payload and never honors the blob's infinite event
post timeout. Full or oversize events are rejected instead of blocking.

Application control calls can be serialized onto the same executor stack with
`RadioCommandQueue` and `RadioOwnerFuture`. The command handler is the only
application-facing code entered under virtual Wi-Fi task identity:

```rust,ignore
static COMMANDS: RadioCommandQueue<Command, 8> = RadioCommandQueue::new();

let wifi = take_wifi_runtime(/* ... */).unwrap();
let owner = RadioOwnerFuture::new(wifi, &COMMANDS, CommandHandler, 4);
executor.spawn(owner);

// From any other future or an ISR producer:
COMMANDS.try_submit(Command::Disconnect)?;
```

Commands are transferred by value. A full queue returns the original command;
it never turns into a hidden semaphore wait or a vendor call from the producer.

Call `disable_vendor_nvs` before `esp_wifi_init` when the application owns
persistence. `disable_dynamic_wifi_buffers` also clears the explicit dynamic
RX/TX/cache counts, but the caller must still configure adequate static pools
and target-correct static buffer types.

`InterruptSignal` converts a hardware/DMA completion interrupt into a future
without running vendor code in the ISR. `patch_critical_section_probes` counts
Wi-Fi interrupt critical sections and other-core stalls. Before strict mode it
delegates to the hardware adapter; strict mode requires the executor to run on
`wifi_task_core_id`, switches the interrupt lock to local MIE masking, rejects
wrong-hart `pp_post`, and never stalls the second core.

`patch_allocator_probes` similarly wraps all OSI allocator slots and reports
counts, sizes, failures, and calls made from radio context. Direct C allocator
references in the vendor archives must additionally pass through the GNU
linker's wrappers. TX/RX completion, WPA2 ingress, and key programming also
require symbol interposition. Twenty of the twenty-eight entries are ordinary
archive definitions and use LLD wrapping:

```text
-Wl,--wrap=malloc
-Wl,--wrap=calloc
-Wl,--wrap=realloc
-Wl,--wrap=free
-Wl,--wrap=pp_post
-Wl,--wrap=ieee80211_timer_process
-Wl,--wrap=ieee80211_mgmt_output
-Wl,--wrap=ieee80211_hostapd_beacon_txcb
-Wl,--wrap=ieee80211_tx_mgt_cb
-Wl,--wrap=wDev_record_ftm_data
-Wl,--wrap=wDev_ftm_set_t1t4
-Wl,--wrap=wDev_isNANPktInValidSlot
-Wl,--wrap=dbg_read_tx_ppdu
-Wl,--wrap=dbg_dump_rx_ppdu
-Wl,--wrap=dbg_dump_rx_sigb
-Wl,--wrap=wifi_gpio_debug
-Wl,--wrap=wpa_sm_rx_eapol
-Wl,--wrap=wpa_ap_rx_eapol
-Wl,--wrap=hal_crypto_set_key_entry
-Wl,--wrap=ieee80211_search_node
-Wl,--wrap=cnx_node_search
-Wl,--wrap=vTaskDelay
-Wl,--wrap=os_sleep
-Wl,--wrap=sleep
-Wl,--wrap=usleep
-Wl,--wrap=wifi_log
```

The other eight entries (`esf_buf_alloc`, `esf_buf_recycle`,
`ieee80211_set_tx_pti`, `lmacTxDone`, `hal_mac_get_txq_state`,
`pm_on_beacon_rx`, `pm_on_data_tx`, and
`esp_test_tx_enab_statistics`) are ECO0 ROM exports. Do not pass them through
LLD `--wrap`: `esp-rom-sys` defines them with absolute linker-script
assignments, and LLD would rewrite the Rust `__wrap_*` definition itself to a
ROM address. Load `esp32s31-rom-wrap-overrides.x` after all `esp-rom-sys` ROM
fragments instead. It pins each original address under `__real_*` and aliases
the public entry to Rust without modifying ROM or a vendor archive.

Before the strict-runtime proof is issued, both OSI and direct-C wrappers
delegate to the original allocator so vendor initialization can complete.
The management-output wrapper accepts only ordinary AP/STA association,
authentication, and probe subtypes on the home channel. It checks live
non-mesh/non-NAN and AP no-power-save invariants before entering the stock
body; rejection recycles the fixed ESF slot immediately.
The adjacent TX-PTI wrapper does not call the OSI coexistence callback. For a
validated event below 48 it performs the pinned `coex_pti_tab[event]` byte read
directly; an invalid event marks the buffer so the following management-output
gate consumes and recycles it exactly once.
The low-level NAN-slot hook is also interposed: non-NAN AP/STA descriptors pass
the recovered bit test, while a NAN descriptor returns false without invoking
the optional scheduler callback.
Afterwards allocation returns null immediately and `free` is recorded without
entering the heap. Heap access can be restored only after the executor and all
Wi-Fi callbacks have stopped.

After installing both probes, `AuditedFuture` can enforce the observed runtime
boundary:

```rust,ignore
patch_allocator_probes(&mut wifi_osi_table);
patch_critical_section_probes(&mut wifi_osi_table);
let audit = StrictAudit::global(StrictPolicy::heap_free_single_owner());
executor.spawn(AuditedFuture::new(owner, audit));
```

This fails closed on the first recorded blocking callback, OSI allocation,
unbalanced interrupt restore, excessive nesting, or other-core stall. The
final-ELF audit also requires the four allocator wrappers,
`__wrap_lmacTxDone`, `__wrap_hal_mac_get_txq_state`, and the strict AP-beacon,
management-completion, FTM-rejection, PS-beacon, radio-debug, and WPA2 RX
wrappers, so omitting one of the linker arguments is a build failure.
The strict AP-beacon state aliases are supplied by an additional linker
fragment. WPA2 AP also needs the local audited join boundary:

```text
-Tesp-wifi-async-runtime-esp32s31/ld/esp32s31-net80211-locals.x
-Tesp-wifi-async-runtime-esp32s31/ld/esp32s31-wpa2-ap-locals.x
-Tesp-wifi-async-runtime-esp32s31/ld/esp32s31-wpa2-sta-locals.x
-Tesp-wifi-async-runtime-esp32s31/ld/esp32s31-rom-wrap-overrides.x
```

The production path patches the stable OSI table before
`esp_wifi_init_internal`. The task-create callback recognizes the exact pinned
`ppTask` entry, returns a logical task handle, and releases the vendor startup
latch without ever calling the entry point or creating an RTOS task. Unknown
task entries fail closed. Immediately after the vendor init call,
`drain_wifi_initialization_events(budget)` runs only the already-queued finite
handlers on the caller's stack. An empty queue completes immediately; budget
exhaustion, shutdown, or an unsupported handler is an error, never a wait or a
fallback to RTOS.

The `handoff` module remains solely for comparative HIL against the original
blob. It deliberately starts the real `ppTask`, so it is not an acceptable
production configuration and must not be used to claim taskless operation.

`derive_wpa2_sta_message2` is the first composed handshake transition. It
consumes the owned M1, awaits an `AsyncWpa2StaCrypto` PTK operation, awaits the
M2 HMAC-SHA1 operation, advances the ticketed STA state, and returns a complete
owned Ethernet/EAPOL M2 plus the persistent PTK. A hardware implementation of
the crypto trait must wake from completion IRQs; the transition contains no
heap use, delay, RTOS wait, or hardware-status loop. The returned frame still
has to be moved to the radio owner and the M3/key-install/M4 composition must
be completed before an on-air WPA2 connection can be claimed.

Runtime shutdown must likewise be
exposed as an async command that completes after `RadioFuture` drains its queue,
instead of calling that blocking wrapper directly. Call `request_shutdown()`
and then await completion of the spawned `WifiRuntimeFuture`; its final poll
cancels the external alarm. A subsequent vendor deinit may call
`pp_delete_task`: the adapter rejects its duplicate event 15, selecting the
blob's non-waiting `pp_delete_task_manually` cleanup path for the private task
and queue globals.

## WPA async features

Enable `wpa-async-eap` for the Enterprise EAP worker replacement,
`wpa-async-mic` for the Michael MIC callback replacement, or `wpa-async` for
both. The final firmware link must include the corresponding linker fragments:

```text
-Tesp-wifi-async-runtime-esp32s31/ld/esp32s31-eap-locals.x
-Tesp-wifi-async-runtime-esp32s31/ld/esp32s31-wpa-locals.x
```

These fragments do not patch `libwpa_supplicant.a`. They assign external alias
names to audited local function/data sections during the normal final link.
Runtime size checks reject a different local layout, while the analyzer checks
the complete archive digest and symbol sizes.

The normal WPA `eloop_run` path is finite: it processes due timeouts and
returns. It is serviced by `WifiRuntimeFuture` through the OSI timer bridge.

With `wpa-async-eap`, the adapter recognizes the exact generic queue created by
`esp_eap_client.c.obj` (three 8-byte entries) and the `wpa2_task` entry point.
No task or receive-loop is started. Messages 0 and 1 are put onto the existing
radio queue; message 1 processes one RX node per poll and schedules a
continuation if more nodes remain. Message 2 performs only the finite teardown
inline, before vendor deinit can free `gEapSm`. The former completion-semaphore
take for messages 0 and 1 now means async queue acceptance and never waits.

With `wpa-async-mic`, install the callback after supplicant initialization and
restore it before supplicant deinitialization:

```rust,ignore
unsafe { install_async_michael_callback()? };
// Wi-Fi operation; the second MIC failure now schedules a 10 ms continuation.
unsafe { uninstall_async_michael_callback()? };
```

The replacement keeps the original WPA states, key-request call, countermeasure
flag, and 60-second stop timeout. Only the direct `os_sleep(..., 10000, ...)` is
replaced by the shared executor-driven timer.

## Strict no-wait profile

Enable `strict-no-wait` to replace PP event 22 with executor continuations. The
original `lmacProcessTxTimeout` performs a 16-us busy delay for every active TX
queue, and its discard path contains two data-dependent loops. The replacement
preserves the two sides of the settling interval, scans at most one list link,
and discards at most one MSDU per executor event. Test-statistics/logging HAL
wrappers on that path are replaced by the pinned S31 TXQ MMIO fields.

The strict basic profile requires static pools and no aggregation:

```rust,ignore
configure_static_wifi_buffers(
    &mut config,
    StaticWifiBufferConfig {
        rx: 10,
        tx: 16,
        management_rx: 5,
    },
);
disable_vendor_nvs(&mut config);
disable_frame_aggregation(&mut config);
disable_ftm(&mut config);
validate_strict_basic_config(&config)?;
```

The generated S31 defaults are not strict: TX buffers are dynamic and the
static TX count is zero. After the cold-start drain and before the executor,
`prepare_strict_runtime_before_handoff(&config)` (legacy name) sets and verifies
`WIFI_PS_NONE` and `WIFI_LOG_NONE` through the initialization OS adapter.
That preparation also routes connection-time management frames into the fixed
Rust pool before the connection request, so no heap-owned authentication,
association, or probe frame can cross the strict boundary.
`prepare_strict_runtime(&config, preparation)` then does not call a vendor
control API; it refuses to issue a proof unless the `ppTask` entry was
virtualized (or the explicitly selected legacy HIL handoff completed) and
`patch_pp_runtime_callbacks`, `patch_allocator_probes`, and
`patch_critical_section_probes` were applied to the OSI table before Wi-Fi
init. It also compares the linked allocator, ESF, timer, TX/RX, and WPA symbol
addresses with all twenty-four required `__wrap_*` functions. Issuing the proof
arms the allocator and core-stall wrappers: runtime
allocation calls return null, runtime frees never enter the heap, and a
requested other-core stall is recorded but never entered.
`allow_heap_for_wifi_teardown` and `allow_core_stalls_for_wifi_teardown` can be
called only after the strict executor has fully stopped. The proof token is
required by the S31 backend. In strict mode,
unexpected AMPDU, power-save, BSS-color, modem-beacon, or coexistence events
fail closed instead of entering vendor handlers with reachable delay paths.

This feature is not yet a claim that every remaining PP path is strict. Run the
fail-closed relocation audit while replacing them:

```console
cargo +stable run -p xtask --bin audit-strict-esp32s31 -- --enforce
cargo +stable run -p xtask --bin audit-strict-esp32s31 -- \
    --elf path/to/final-firmware.elf --enforce
```

The archive audit rejects direct heap/delay/RTOS/flash/logging paths, every
unproven register-indirect call, and every unproven backward branch. The
final-ELF audit additionally rejects forbidden symbols and vendor entries that
the strict Rust dispatcher replaced. Direct allocator references are accepted
only when the corresponding `__wrap_malloc`, `__wrap_calloc`,
`__wrap_realloc`, or `__wrap_free` symbol is linked. `lmacTxDone` must resolve
through `__wrap_lmacTxDone`; its callback bitmap, inline `ppProcTxDone`/PM tail,
and TX-queue resume are then executor continuations.
`hal_mac_get_txq_state` must resolve through its wrapper as well: completion
and collision handlers receive one bitmap bit per event, while the wrapper
posts another event for a captured remainder. It is expected to fail
until all reported roots are replaced or their exact indirect target and loop
bound are proven.

The next blocking boundary is the contents of classified TX callbacks and the
remaining TX/RX completion handlers, not event 22. The strict timeout/discard
path no longer calls `lmacTxDone`: its mode-1 bitmap is advanced one known bit
per executor event, the frame is appended to the TX-done list without the
vendor callback loop, and event 16 is posted normally. Strict event 16 no
longer calls `ppProcTxDone`: its Rust continuation dequeues one frame, invokes at most one
directly classified mode-0 callback, or recycles one fixed-pool frame per event.
It rejects unknown callback bits, a registered user TX callback, fragmented or
trace descriptors, and frame types outside the strict fixed pools. The original unbounded queue
drain and its power-management tail are therefore absent from this path.

The mode-1 replacement accepts only the STA EAPOL bit and checks that its
registered pointer matches the pinned vendor symbol. Off-channel rate-probe
and AP power-save callbacks fail before invocation. It also rejects
aggregation/direct-recycle descriptors and optional TX-time recording. The
classified basic callback roots are audited separately. AP beacon completion
now only rearms the fixed timer and rejects mesh/power-save branches.
Management completion is also Rust-owned: authentication, association, probe,
and ordinary beacon subtypes complete without vendor side effects, while
disassociation, deauthentication, and action/off-channel subtypes poison the
strict dispatcher before their hidden node/key/channel state machines can run.
Those three operations need explicit executor commands before they can be
supported. Other RX/retry/connection paths still prevent certifying basic
AP/STA for the stated zero-allocation/zero-wait requirement.

## Remaining WPA scope

The active secured scope is WPA2-Personal AP/STA. WPA3 SAE is not being
reimplemented: this S31 build advertises `WIFI_ENABLE_WPA3_SAE = 0`, its
`sae.c.obj` and `esp_wpa3.c.obj` contain no usable high-level SAE engine, and
`esp_supplicant_init` leaves the net80211 SAE callback slots empty. The
net80211 glue symbols are ABI-pinned only so a future blob update cannot make
that conclusion stale silently.

The EAP leaf handlers still execute to completion and may perform synchronous
cryptography or allocation inside the vendor blob. The removed waits are the
RTOS queue receive-loop and completion semaphore. Hardware reachability tests
are still required for EAP methods and failure paths used by a product.
Accordingly `strict-no-wait` and `wpa-async-eap` are compile-time incompatible.

This restriction does not by itself certify WPA2-Personal. The pinned stock
`sta_eapol_txdone_cb` slot normally resolves to `eapol_txcb` (`0x182`), whose
reachable state transitions contain `calloc/free` for eloop timeouts and a
deauthenticate path to `ets_delay_us`. Strict integration must call
`install_async_wpa2_sta_tx_done` after setup. Its callback validates M2/M4 and
copies only message kind, replay counter, and status into a fixed channel; it
does not enter the stock WPA state. The stock callback is restored only under
exclusive teardown ownership. Installation is permitted during serialized
initialization before IRQ/executor start, and `prepare_strict_runtime` refuses
to issue its proof until it is complete.

`Wpa2Ingress` is connected directly to the pinned STA and AP RX callbacks by
`--wrap=wpa_sm_rx_eapol` and `--wrap=wpa_ap_rx_eapol`. Both callbacks validate
an exact RSN EAPOL-Key length, copy it into the global eight-frame
`OwnedEapolFrame` channel, and return immediately. `receive_wpa2_eapol` is
producer-woken and performs no timer polling; invalid input or capacity
exhaustion is counted by `rejected_wpa2_eapol` and reported to the blob as not
consumed. AP peer MAC is copied from the pinned station-object field at offset
eight. The parser exposes descriptor flags, replay counter, nonce, MIC, and key
data and classifies pairwise messages 1 through 4 plus group messages.

Before AP start, `install_async_wpa2_ap_callbacks(&rsn_ie)` replaces the
complete heap-owning AP callback group: hostap init/deinit, station join/remove,
RSN-IE lookup, and peer SPP lookup. The supplied IE must be WPA2-PSK with CCMP;
SAE/OWE, TKIP, PMF-required, PMKID, and group-management extensions fail
closed. The replacement keeps the advertised IE and eight pinned `0x28`
station objects in static Rust storage. A successful join copies an
`Associated` event into the producer-woken channel returned by
`receive_wpa2_ap_event`; removal emits `Removed`. Capacity exhaustion sends an
association failure immediately and never waits.

The association response does not enter `esp_send_assoc_resp`, its temporary
`calloc`, or the allocating ioctl wrapper. It calls only the pinned
association-response constructor, fixed management-buffer pool, descriptor
setup, and management output for subtype `0x10`/`0x30`. TX power-management
accounting is interposed as a no-op under the already verified
`WIFI_PS_NONE` invariant. Install the callbacks after `esp_supplicant_init`
created `wpa_cb`, while AP RX is still stopped, then start AP and issue the
strict-runtime proof. The stock hostap authenticator and its eloop rekey timers
are never created.

For STA, `install_async_wpa2_sta_callbacks()` replaces the connected,
disconnected, and four-way-handshake-query slots in the same `wpa_cb` table.
The two notifications copy only BSSID/reason metadata into the fixed channel
returned by `receive_wpa2_sta_link_event`; they never enter the stock
disconnect path, whose eloop timeout cancellation can end in `free`.
`set_wpa2_sta_handshake_active` makes the Rust handshake owner responsible for
the query result. Install these callbacks after `esp_supplicant_init`, before
STA RX, automatic reconnect, or the executor runtime can run.

`Wpa2StaState` and `Wpa2ApState` now consume those owned frames one at a time.
They validate role, peer, descriptor version, message order, nonces, replay
counters, and async completion tickets. The STA acknowledges a repeated M3
after completion without reinstalling PTK/GTK. The AP uses `Wpa2ApPeers<P>` for
a fixed peer limit and authorizes a station only after M2/M4 MIC completion and
pairwise-key installation. Every transition emits at most one owned
crypto/install/TX action and returns.

PTK PRF-384, HMAC-SHA1 EAPOL MIC, and RFC 3394 key unwrap have fixed
`CryptoJob` constructors. EAPOL MIC input is copied with the MIC field cleared,
MIC comparison is constant-time, and the persistent 48-byte CCMP PTK wipes KCK,
KEK, and TK on drop. `CryptoFuture` reads peripheral completion status only
after an interrupt-generation change; unrelated executor polls do not poll the
hardware.

`Wpa2TxFrame` now builds exact CCMP M1-M4 frames, `Wpa2PlainKeyData` builds the
RSN IE plus GTK KDE for RFC 3394 wrapping, and `parse_gtk_key_data` validates
the corresponding plaintext after unwrap. `build_sta_action_frame` and
`build_ap_action_frame` bind transmit actions to the state machine's peer and
nonce context. Plain GTK/key-data, PTK, and aligned install-key objects wipe
their secret storage on drop.

`Wpa2IoQueue` moves complete Ethernet frames, CCMP key installs, and peer
authorization commands by value to the single radio owner. `TryWpa2Io` permits
one immediate submission attempt only and returns the complete command on
backpressure. The mandatory `hal_crypto_set_key_entry` wrapper writes the
pinned fixed key-table MMIO directly for keys up to the hardware maximum of 32
bytes, so pointer alignment can no longer select the vendor temporary
malloc/copy/free path. `AlignedCcmpKey` still keeps the Rust-owned key ABI
stable, and `StaticWpa2Keys<P>` retains a fixed number of STA/AP keys.

`Wpa2Retry` turns an original M1-M4 transmit action into a finite sequence of
generation-tagged one-shot alarms. An alarm event emits at most one
retransmission and one next absolute deadline. Cancellation invalidates an
already pending IRQ; there is no sleep, periodic tick, hardware-status read, or
catch-up loop.

On the target, `S31StaticWpa2Io<K>` bypasses `esp_wifi_internal_tx`, because
that wrapper always acquires `g_wifi_global_lock` through an OSI callback. The
strict path instead performs bounded peer lookup, one fixed-pool buffer claim,
descriptor setup, and `ieee80211_post_hmac_tx` directly. Pool exhaustion and AP
power-save peers are rejected immediately. A failed post poisons the backend
until Wi-Fi deinit rather than retrying an ambiguously owned buffer. A STA
transmission is rejected until the async EAPOL TX-done callback is active.
Pairwise and group CCMP installation bypass both stock allocating wrappers: the
hardware leaf receives an aligned key and net80211 receives a pinned `0xb8`
software-key object from `S31StaticKeyStorage<K>`. Before registration the
backend reads the pinned `g_ic` key slot directly, verifies that it is empty or
already points to the same static object, and then performs the exact pointer
store itself; neither `ieee80211_get_key` nor the potentially freeing
`ieee80211_set_key` remains a runtime root. AP PTK/SPP lookup uses a mandatory
finite `cnx_node_search` wrapper over the nine statically provisioned AP/BSS
node entries; the original eight-bit wraparound/assert loop is unreachable.
The adjacent `ieee80211_search_node` wrapper accepts STA/AP only and rejects
NAN before its assert loop. STA GTK metadata is reduced to pinned byte
loads/stores. The pinned `wifi_init_key` call is reduced to its exact two
constant-length fills inside that object, so it is no longer a vendor runtime
root. STA GTK ids share the chip's single hardware group slot and update
the pinned two-byte metadata mapping directly; AP GTK ids use fixed hardware
slots 8 through 11.

The pinned blob exports no independent AP controlled-port setter. The backend
therefore owns authorization in a fixed peer table: authorization succeeds only
after an AP pairwise key exists, deauthorization is immediate, and
`is_ap_peer_authorized` is the mandatory gate for every ordinary Rust-owned AP
data-channel enqueue/transmit. EAPOL ingress remains a separate pre-auth channel.

Application Ethernet traffic uses `try_send_wifi_data` and
`receive_wifi_data_tx`. Both directions own one of eight fixed 1600-byte slots;
there is no borrowed netstack lifetime and no allocation on backpressure. The
single radio owner submits a received TX guard with
`S31StaticWpa2Io::try_transmit_wifi_data`. STA uses the same one-attempt static
buffer path as EAPOL. AP additionally checks the destination against the live
controlled-port table at submission time, so a queued frame cannot retain
authorization after peer removal.

Promiscuous/sniffer RX is outside this basic profile. Strict mode rejects event
13 unconditionally before `ppProcessRxPktHdr`: that vendor handler not only
invokes the optional `pTxRx + 0x404` callback, but also releases its payload and
envelope through the OSI heap hook.

```rust,ignore
static KEY_STORAGE: S31StaticKeyStorage<4> = S31StaticKeyStorage::new();

// patch_pp_runtime_callbacks(&mut osi) and patch_allocator_probes(&mut osi)
// must run before Wi-Fi init.
// After esp_supplicant_init, before AP start/RX:
unsafe { install_async_wpa2_ap_callbacks(ap_rsn_ie)? };
unsafe { install_async_wpa2_sta_callbacks()? };
unsafe { install_async_wpa2_sta_tx_done()? };
unsafe { install_async_wifi_data_rx()? };
// Complete the finite vendor controls after the cold-start drain.
let preparation = unsafe { prepare_strict_runtime_before_handoff(&config)? };
// The proof accepts only a virtualized ppTask (or the separate legacy HIL path).
let proof = unsafe { prepare_strict_runtime(&config, preparation)? };
// Then under the single radio owner:
let io = unsafe { S31StaticWpa2Io::new(&KEY_STORAGE, &proof)? };
let handler = Wpa2IoHandler::new(io);
```

This still does not prove an on-air strict WPA2 handshake. The implemented
target backend covers static-pool submission, pairwise/group CCMP, and a
Rust-owned AP controlled-port gate. The downstream PP transmit/completion graph
still needs final classification and the application data path must enforce the
gate for every non-EAPOL frame.
Until those branches are connected and final-ELF-audited, WPA2-Personal is
deliberately not reported as strict-ready.

The crypto callbacks embedded in `wifi_init_config_t` are replaceable but have
a strictly synchronous ABI. They can select Rust or hardware crypto, but cannot
return pending. Fully async Enterprise crypto requires moving the EAP/TLS state
machine to Rust; see
[`../docs/esp32s31-async-boundaries.md`](../docs/esp32s31-async-boundaries.md).

For Rust-owned protocol work, `InterruptCryptoEngine` provides the actual async
boundary. A pinned `CryptoJob` owns all buffers until completion; the hardware
backend arms DMA and returns, while its ISR calls only
`InterruptSignal::notify_from_isr`. Dropping the future aborts the backend and
the job wipes key, IV, input, and output storage on drop.

The expensive WPA-Personal derivation is available directly:

```rust,ignore
let mut job = WpaPskJob::wpa_psk(passphrase, ssid)?;
// Every poll performs up to 32 useful HMACs and then cooperatively requeues
// itself. It does not poll a peripheral or wait on an RTOS object.
job.derive_software::<32>().await?;
let pmk: &[u8] = job.result()?; // 32-byte PMK, ready before connect

// Execute this command through RadioOwnerFuture after supplicant init.
unsafe { install_precomputed_wpa_pmk(&job)? };
```

The software future owns fixed intermediate `U`/XOR blocks, wipes them on
completion or cancellation, and matches the standard WPA `password`/`IEEE`
test vector. An IRQ-capable SHA-1 backend may instead execute the same
`CryptoJob` through `InterruptCryptoEngine`; the S31 SHA work queue is not used
as an async substitute because its SHA-1 path recalls itself to read busy
status rather than receiving a completion interrupt.
