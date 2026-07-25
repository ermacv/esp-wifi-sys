# ESP32-S31 Wi-Fi Rust ownership migration

This document records the method and the evidence used while replacing hidden
vendor Wi-Fi state with explicit Rust ownership. It is intentionally separate
from the generated [linked-state audit](esp32s31-linked-state-audit.md): the
audit answers what is linked and reachable, while this document answers why a
boundary exists and how it may be removed.

## Target architecture

The final dependency direction is:

```text
WPA2/WPA3, association, scan policy
                 |
       async MAC/radio runtime
                 |
        ESP32-S31 radio HAL
                 |
          PAC/MMIO registers
```

The HAL boundary must expose finite register operations. It must not own
credentials, timers, queues, cryptography, allocation, or an executor. Unknown
register fields remain typed opaque values with an evidence comment until
their meaning is demonstrated. An SVD/PAC description is useful after stable
register groups have been recovered; it is not a prerequisite for moving
state out of the blob.

## Migration rules

Each migrated object follows one vertical slice:

1. Identify every archive and ROM reader/writer, callback, timer, and pointer
   cell.
2. Recover only the layout and transitions needed by the current AP/STA
   profile.
3. Put the state machine in a safe, host-testable Rust module.
4. Keep raw pointers, MMIO, and ABI callbacks in one target-specific adapter.
5. Copy cold state once, before strict handoff, and reject an in-flight
   operation rather than transferring ambiguous ownership.
6. Remove runtime vendor getters/setters from the strict root graph.
7. Prove the final ELF with the no-wait/no-heap audit and update the linked
   state report.
8. Remove the vendor backing only after its cold initializer and deinitializer
   have also moved to Rust.

The single radio owner serializes state-machine transitions. Interrupts only
publish edges or data into bounded static channels. Cross-context scalar
snapshots use atomics; they do not disable interrupts or enter a vendor
critical section.

## Completed slice: channel manager

### Evidence

The reference is the pinned `libnet80211.a[wl_chm.o]` object. Its disassembly
establishes:

- `g_chm` is a ROM-ABI pointer cell whose backing is the 592-byte `gChmCxt`;
- home and current selectors are at offsets `0x50` and `0x52`;
- the 2.4 GHz table starts at `0x54` and contains 14 records of 12 bytes;
- record byte zero is the primary channel and the little-endian frequency is
  at byte two;
- the two vendor timer objects start at offsets `0x24` and `0x38`;
- the operation envelope contains channel, dwell durations, context, start
  callback, and end callback;
- `chm_init` produces channels 1 through 13 at 2412 MHz plus 5 MHz per channel,
  channel 14 at 2484 MHz, and the observed opaque record word `0x83`.

Fields without a demonstrated meaning remain opaque bytes in
`channel_state.rs`. This preserves evidence without turning guesses into an
API.

### Rust ownership

`ChannelState` owns the validated channel table. Home/current selectors use
atomic publication, so WPA2 AP checks and diagnostic snapshots do not need a
critical section. `ChannelResources` owns:

- the channel state;
- the channel-switch operation state machine;
- the start/end callback envelope;
- two stable-address `RawOsiTimer` objects registered in the fixed Rust timer
  pool.

`prepare_strict_runtime_before_handoff` performs the only `g_chm` read. It
requires an idle vendor operation, validates the selectors and all 14 records,
then publishes the Rust state. After handoff:

- scan dwell and MAC-settle delays are Rust async timer events;
- `chm_get_chan_info`, `chm_get_home_channel`, and
  `chm_is_at_home_channel` are not strict runtime dependencies;
- returning home and promoting the associated channel are Rust state
  transitions;
- no channel-state transition allocates, polls, waits, or masks interrupts.

The current Rust section is 256 bytes. The 592-byte vendor backing remains
linked for cold initialization, so this step temporarily adds 256 bytes. Once
`chm_init/chm_deinit` are replaced and the ROM pointer binding is unnecessary,
removing `gChmCxt` yields a net 336-byte SRAM reduction.

### Verification

The strict `wifi-rust-static-cold-init-hil` STA final link passes with zero
no-wait/no-heap audit violations. In the generated linked-state report,
`gChmCxt` and `g_chm` are absent from mutable state reachable by strict vendor
leaves. They remain listed only as cold-init linked state.

The same image was verified on ESP32-S31 hardware against a WPA2 AP after the
Rust channel-state handoff. Passive scan, open authentication, association,
the WPA2 four-way handshake, DHCP, gateway ping, DNS, TCP, and post-link data
all completed. The allocation counters remained zero through association and
post-link operation.

## Next slices

Priority is based on current strict reachable bytes and how much unsafe state
each slice can remove:

1. `g_ic` net80211/interface state: split association, peer/interface, scan,
   and configuration ownership before attempting one monolithic replacement.
2. `TxRxCxt` and `pTxRx`: isolate descriptor queues, completion state, and
   hardware ring ownership.
3. `wDevCtrl`: separate RX/TX interrupt-visible fields from diagnostics and
   optional modes.
4. `phy_param`: recover the channel/rate/calibration subset used by the
   qualified profile, keeping calibration and coexistence fields explicit.
5. Replace channel-manager cold init so `gChmCxt` can be removed from the
   image, not merely from runtime reachability.

For every slice, record coexistence-related fields even when Wi-Fi-only policy
does not use them. BT/BLE/802.15.4 support should be able to add a coordinator
above the radio HAL without rediscovering discarded ownership or register
evidence.

Public `ieee80211` and supplicant crates should remain behind adapters for now.
Adopting them before the hardware/state boundaries are stable would combine a
protocol migration with an ownership migration and make regressions harder to
localize.

## In-progress slice: `g_ic`

The linked-state audit reports the complete 788-byte `g_ic` object because ELF
symbols do not describe fields. This is intentionally conservative; it does
not mean that all 788 bytes are needed by the strict runtime. Relocation and
instruction inspection of the original three strict vendor referrers, plus
the event-5 consumer called directly by Rust, gives the narrower graph:

| vendor leaf | `g_ic` fields read | current purpose | status |
|---|---|---|---|
| `ieee80211_set_tx_desc` | `0x10`, `0x14` | identify STA versus AP interface | interface registry ready; leaf remains |
| `ieee80211_hostapd_data_txcb` | `0x14`, `0x74` | find AP state and enter mesh-only activity update | replaced by exact non-mesh Rust no-op |
| `ieee80211_post_hmac_tx` | `0x258` | select optional cached-TX path | replaced; ordinary STA/AP queue publication is Rust |
| `ieee80211_output_process` | `0x1ac`, `0x1b0` | optional pending-frame queue | one-frame compatibility stage; classifier, CCMP key/header, and ESF alignment leaves replaced; consumer remains |

The reference objects are pinned
`libnet80211.a[ieee80211_output.o]` and
`libnet80211.a[ieee80211_hostap.o]`. The offsets above are instruction
operands or relocation addends, not inferred names.

Rust code currently touches additional `g_ic` fields because it already
reproduces finite pieces of vendor STA/AP behavior. They must be migrated by
meaning rather than collected into a Rust byte-for-byte `g_ic` clone:

- interface publications at `0x10` and `0x14`;
- mesh-mode gate at `0x74`;
- software-key pointer slots beginning at `0x148`;
- AP TIM state beginning at `0x1b6`;
- lifecycle/promiscuous state at `0x1f5` and `0x1f7`;
- crypto gate and AP/STA MAC addresses at `0x210`, `0x214`, and `0x21a`;
- configuration-dirty state at `0x226`;
- cached-TX policy at `0x258`;
- STA authorization state at `0x274`;
- protocol selection at `0x2be` and `0x2c0`;
- RX-policy selector at `0x2cc`.

The first implementation step is complete: an interface registry adopts the
STA/AP publications during cold handoff and exposes role-checked handles, not
raw `g_ic` offsets. STA link, WPA2 STA/AP node lookup, AP TIM handling, and the
strict AP beacon completion now obtain interface identities from this
registry. The pre-handoff AP-start probe deliberately retains its separate
cold read because the registry is not published yet.

The same handoff rejects active mesh state, a non-empty `g_ic+0x1ac`
pending-frame queue, and the vendor cached-TX mode.
Those are immutable strict-profile invariants, not flags polled on each
runtime operation. Under the non-mesh invariant the pinned
`ieee80211_hostapd_data_txcb` returns before reading its frame, so the strict
TX callback table now installs the exact Rust no-op instead. This removes that
function as a strict vendor root.

Node tables and interface contents remain separate owners: publishing an
interface does not grant arbitrary mutable access to every field behind its
pointer. Cold adoption now also copies each present interface's six-byte MAC
address into 16 bytes of aligned atomic SRAM storage; the live encapsulator
does not call `wifi_get_macaddr` or inspect a vendor interface field. This was
verified on S31 hardware through passive scan, WPA2 association, DHCP, ping,
DNS, TCP, and post-link data with zero recorded allocations. The final ELF
still passes the strict no-wait/no-heap audit with zero violations.

The Rust replacement validates the descriptor interface, strict-hart and
radio-owner identity, and home-channel state, appends through the recovered
`frame+0x30` intrusive link, and reserves the sole PP event-5 token. Event
publication occurs only on the empty-to-non-empty transition. It contains no
allocation, wait, retry, indirect call, or `g_ic` access. The persistent input
queue and its event-token state are now one explicit Rust object in internal
SRAM.

Event 5 removes exactly one frame from that queue and runs the recovered
ordinary STA/AP path directly. It resolves the bounded peer, copies the
Ethernet header into an owned local value, rejects raw/WAPI/HE-prefix,
NAN/mesh, off-channel, and AP power-save cases, then applies the pure
address/LLC/QoS plan. The live target adapter advances the per-TID sequence,
invokes only the separately interposed classifier, CCMP, alignment,
descriptor, and PTI leaves, and enters `ppTxPkt` without publishing a vendor
mailbox. Another Rust event token is reserved only when another frame remains
and no nested publication already reserved it.

Completion ownership is no longer inherited from recycled descriptor state.
The recovered `ieee80211_output_process` branch is an explicit pure rule:
STA EAPOL (`0x888e`) gets callback bit 3, ordinary STA data gets zero, and AP
traffic gets the encapsulator's callback bit 12. Host tests cover the complete
STA/AP matrix. Hardware validation observed M2 and M4 through the Rust
completion path, completed authorization, DHCP, ping, DNS, TCP, and HTTP, then
passed the 4096-datagram/four-HTTP strict stress workload with all 4786 TX
credits returned, empty queues, no rejected event posts, and unchanged
post-handoff allocation counters.

The next leaf inside that compatibility stage is now Rust-owned.
`ieee80211_classify` was recovered from the pinned
`libnet80211.a[ieee80211_output.o]`: EAPOL and WAPI select the fixed-rate bit
and priority 7; STA ARP and DHCP/DNS select the same fixed-rate policy; IPv4
DSCP and the IPv6 traffic class select user priority; multicast or a non-QoS
node use priority 7; and WMM admission control follows the recovered monotonic
four-state downgrade graph. The Rust implementation writes descriptor bit
`0x0200_0000` directly rather than calling the PP/TRC helper and bounds the
four-state admission graph to three transitions.

ESP32-S31 ROM does not reach this leaf through the exported symbol. JTAG and
ROM disassembly establish that `ieee80211_output_process` calls
`net80211_funcs+0x24`. Strict handoff therefore validates that slot against
the pinned vendor address or the Rust replacement, writes the replacement,
and reads it back. GNU wrapping remains mandatory for direct archive
references. A JTAG snapshot of the running image showed the slot equal to
`__wrap_ieee80211_classify`; the same image completed passive scan, WPA2
association, DHCP, ping, DNS, TCP, and HTTP with zero allocation counters.

The WPA2-CCMP security-selection leaf is now Rust-owned as well. Its reference
is the pinned `libnet80211.a[ieee80211_crypto.o]` and
`libnet80211.a[ieee80211_crypto_ccmp.o]` pair. Descriptor bit 1 selects the
group hardware-key index at `node+0x135`; otherwise the pairwise index at
`node+0x134` is used. The Rust boundary resolves that index only through the
fixed `STATIC_VENDOR_KEY_SLOTS` registry, validates the pinned CCMP object and
16-byte key length, advances the key object's 48-bit TX packet number by the
recovered value three, and inserts the exact eight-byte CCMP header. It neither
reads the vendor software-key pointer array at `g_ic+0x148` nor dispatches
through the cipher object at offset `+0x10`.

The ESP32-S31 runtime reaches this leaf through `net80211_funcs+0x44`. Strict
handoff adopts and reads back that slot exactly as it does the classifier
slot. The public `ieee80211_crypto_encap` name is an absolute ROM export at
`0x2f800cac`, so GNU wrapping is not used: the final linker fragment aliases
the public name to the uniquely named Rust boundary and retains the pinned ROM
address only for pre-strict cold-init delegation. The strict ELF audit proves
both the alias and the callback-table adoption contract. Hardware verification
completed passive scan, WPA2 association, DHCP, ping, DNS, TCP, and HTTP with
zero allocations after this replacement.

The subsequent `ieee80211_align_eb` leaf is also an exact finite Rust port.
The pinned `libnet80211.a[ieee80211_output.o]` implementation reserves the
802.11 header, moves the MPDU down by the resulting zero-to-three-byte
alignment delta, and encodes the total length into bits 27:14 of the ESF
storage word. The Rust policy admits only the ordinary STA/AP 24-byte legacy
or 26-byte QoS headers, requires the caller's reservation to equal that header
length, checks every subtraction and the 14-bit total length before mutation,
then commits the data pointer and packed storage word. It performs no
allocation, wait, retry, global-state read, or indirect callback.

As with the CCMP leaf, `ieee80211_align_eb` is an absolute ESP32-S31 ROM export
(`0x2f800c7c`). The final linker fragment aliases it directly to the unique
Rust boundary and retains the ROM address only for pre-strict delegation.
The final ELF records both addresses explicitly, and the hardware image passed
WPA2 plus post-link traffic without entering the invalid-layout trap.

The ordinary non-HE part of `ieee80211_set_tx_desc` has now been recovered
from the pinned `libnet80211.a[ieee80211_output.o]` oracle as a pure Rust
policy plus a target adapter. The pure policy reproduces the eight-priority
WMM queue mapping, STA/AP rate-context selector, descriptor flag and security
masks, bounded opaque node-bit transforms, TWT record selection, and the
remaining finite descriptor bytes. HE descriptor bit 31, priorities above
seven, and unobserved request flags trap before the first mutation.

Strict handoff now adopts two additional scalar inputs: the initialized
configuration byte formerly read through `g_wifi_nvs+0x44a`, and
`g_itwt_fid`, which is rejected above seven. This is a transitional one-time
cold-state read, not an NVS call: the strict descriptor path reads only the
Rust registry. A later cold-initialization slice should construct both values
directly from Rust configuration and remove the vendor publications entirely.

The public `ieee80211_set_tx_desc` name is another absolute ROM export
(`0x2f800c98`). GNU `--wrap` cannot interpose it reliably because the ROM
linker fragment captures the generated `__wrap_*` name. The late linker
fragment therefore retains the ROM address as
`__real_ieee80211_set_tx_desc`, aliases the public name to the unique Rust
entrypoint, and has a final-value `ASSERT` for the alias. Equivalent assertions
now protect the existing post-HMAC, CCMP, and ESF-alignment ROM aliases. Runtime
Rust pointer comparisons are intentionally not used as link proofs because
LLVM does not model linker-script aliases.

This alias immediately replaces direct management-frame calls from Rust.
The STA HIL completed passive scan, open authentication, HT20/WMM association,
the Rust WPA2 four-way handshake, DHCP, gateway ping, DNS, TCP, and HTTP.
Allocation counters were unchanged across strict authentication and
association, all 19 post-link TX frames released their static credits, and
the one-shot critical snapshot reported zero other-core stalls and zero
wrong-hart entries.

The Ethernet-to-802.11 geometry adjacent to the descriptor leaf is now the
live data encapsulator: STA/AP address selection, RFC 1042 LLC/SNAP,
QoS/no-ack policy, multicast handling, sequence wrap, callback ownership, and
the priority byte are bounded and allocation-free. The final-ELF auditor
rejects any direct call to `ieee80211_output_process`; its absolute ROM symbol
may remain linked for cold/vendor compatibility but is not callable by the
strict image.

The outer `libpp.a[pp.o]::ppTxPkt` shell is now Rust-owned. The pinned RV32
disassembly supplies the exact interface selector, priority-to-hardware-queue
table, MAC-time register read, and `pTxRx` tail-link offsets. In the armed
profile Rust sequences the existing protocol, security and rate leaves,
applies the finite observed mapper table, and publishes the frame. It does not
call `ic_interface_enabled`, `lmacIsIdle`, `ppMapTxQueue`, or the cached-HMAC
queue consumer.

The first hardware run with this shell completed the full STA workload:
passive scan, HT20/WMM association, WPA2, DHCP, ping, DNS, TCP, HTTP, ADDBA,
and 4,096 UDP datagrams. It released 4,786 of 4,786 TX frames and 690 of 690 RX
frames, drained 21,284 of 21,284 PP events with no rejects, and preserved the
post-handoff allocation snapshot. This also established that the observed
`0x2000`, `0x2008`, and `0x2010` ESF layout values are static-slot identities:
only bit `0x2000` is consumed by the pinned mapper.

The TX scheduler slice is now separated from the 1,044-byte `pTxRx` object.
Strict handoff proves all sixteen vendor logical queues empty and idle,
validates each empty intrusive tail link, and copies only four initialized
hardware masks and four rotation cursors. From that point producer append,
selection, dequeue, error rollback, and timeout-chain requeue operate on one
fixed SRAM `StrictTxQueueState`. The last runtime `ppDequeueTxQ` call is gone.
A full hardware stress run released 4,787/4,787 TX frames and 692/692 RX
frames, drained 21,371 PP events without rejection, and changed no allocation
counter.

The TX-done registration/list slice has now moved as well. Handoff rejects a
non-empty vendor completion queue or an invalid empty tail link, then copies
the two callback masks and six strict-profile callback identities into one
fixed SRAM `StrictTxDoneRegistry`. Completion append/dequeue and callback
filtering no longer touch `pTxRx`. Hardware qualification completed WPA2,
ADDBA, the full network workload, 4,096 UDP datagrams, and 4 HTTP transfers
with balanced TX/RX/PP ownership and an unchanged allocation snapshot.

The two observed per-logical-queue PPDU-format bytes now move with the
scheduler state. Their bits are not assigned speculative names: they remain
opaque adopted PLCP length/data inputs until a register-level meaning is
proven. The LMAC TX path consequently has no post-handoff `pTxRx` access.

The RX callback registry is now Rust-owned too. Handoff copies only the three
words used by the pinned `ppRxPkt` router: STA, AP, and NAN callbacks at
`pTxRx+0x3f8/+0x3fc/+0x400`. It rejects an AP callback other than
`ap_rx_cb` and rejects any NAN callback. Runtime RX routing and A-MPDU gap
expiry read the immutable SRAM registry and never dereference `pTxRx`.

The queue layout comes directly from pinned `libpp.a[pp.o]` disassembly:
`ppEnqueueRxq` clears `packet+0x30`, appends through the tail-link stored at
`pTxRx+0x398`, then points that slot at the new link; dequeue reads the head
at `+0x394`, advances through `packet+0x30`, and restores the empty tail-link
invariant. Neither leaf locks, waits, or retries; `Locked` documents an
external serialization requirement. `lmacRxDone` is the interrupt-side
producer and immediately publishes PP event 17.

Hardware verification after callback adoption completed passive scan, WPA2,
DHCP, ping, DNS, TCP, HTTP, ADDBA, 4,096 UDP datagrams and 4 HTTP transfers.
It released 4,786/4,786 TX and 692/692 RX owners, drained 21,295/21,295 PP
events, changed no allocation counter, and measured 20.931 Mbit/s.

The interrupt-to-executor RX queue is now Rust-owned too. Pinned
`libpp.a[wdev.o]::wdev_funcs_init` stores the ROM `lmacRxDone` address in the
mutable `pp_wdev_funcs+0x1dc` slot. Handoff masks only local interrupts,
requires the vendor RX queue to be empty with its canonical tail link, and
redirects that slot to `wifi_strict_lmac_rx_done`. The replacement appends
through `packet+0x30` into a fixed internal-SRAM queue; executor dequeue uses
the same queue and the final ELF forbids calls to both `lmacRxDone` and
`ppDequeueRxq_Locked`.

RX readiness is durable queue state rather than a fallible continuation
message. The empty-to-non-empty edge wakes the Rust executor, while
`RadioFuture` checks RX directly as a third round-robin source beside vendor
and internal events. Thus a full finite event queue cannot strand an RX
packet, and a continuously ready RX source cannot starve the other two.
The earlier USB-JTAG observation found the registered Embassy waker vtable at
`0x4000bc5c` and its wake target at `0x400b556e`, both in flash; the task data
was in SRAM at `0x2f06ab00`. Disassembly identified the target as
`embassy_executor::raw::waker::wake`: it atomically marked the task runnable,
pushed it into the shared executor transfer stack with a CAS retry, then
called the SRAM `__pender`.

The strict STA HIL now replaces that boundary with a fixed one-owner executor.
`RadioOwnerFuture` is initialized once in SRAM. Its custom `RawWaker` vtable
and clone/wake/wake-by-ref/drop leaves are also in SRAM, and wake performs only
the bounded S31 `FROM_CPU_INTR2` register write and readback. The final-image
auditor reads the vtable from
`.critical.data.wifi_strict.radio_executor`, resolves all four entries to
their exact SRAM symbols, and requires the software-interrupt entry itself in
SRAM. Consequently the hard RX ISR no longer enters the shared Embassy run
queue or any CAS retry. The first hardware stress run passed WPA2, 4,096 UDP
datagrams and four HTTP transfers with balanced TX/RX/PP ownership, no rejects
or allocation delta, and 27.477 Mbit/s.

The cache boundary now has explicit Rust ownership too. S31 exposes no
hardware cache-enable status bit, so the upstream ESP-IDF cache HAL maintains
that state in software. One internal-SRAM atomic byte records whether cached
execution is available, whether the radio future currently owns the poll
lease, whether readiness was deferred, and whether the immortal future
terminated. The SRAM `try_suspend` leaf closes cached execution only when no
poll is active and otherwise fails immediately; callers must retry
asynchronously. The SRAM `resume` leaf reopens execution and re-pends one
software interrupt for durable deferred readiness. The interrupt acquires the
poll lease with one AMO, never waits, and does not dereference cached future
state while the gate is closed.

The final-image audit requires both cache leaves, every waker target, and the
software-interrupt entry in SRAM. A hardware run that deliberately began with
the gate closed passed the complete WPA2/network stress workload with
4,786/4,786 TX, 691/691 RX, 20,598/20,598 PP events, no allocation delta, and
25.801 Mbit/s. It verifies deferred startup and normal reopening, not a
physical cache-disable cycle. This ownership protocol must be wired into every
future flash/cache owner before the repository can assert a whole-firmware
cache-off proof.

The final hardware run with the durable Rust producer/consumer queue completed
scan, WPA2, DHCP, ping, DNS, TCP, HTTP, ADDBA, 4,096/4,096 UDP datagrams and
4/4 HTTP transfers. It balanced 4,786/4,786 TX and 691/691 RX owners, drained
20,591/20,591 PP events without rejection, preserved the allocation snapshot,
and measured 19.634 Mbit/s. No strict-runtime path now dereferences `pTxRx`;
the object remains a cold-initialization and one-shot handoff oracle until
those initializers are ported. The remaining RX vendor boundaries are
`ppRxProtoProc` and `ppRecycleRxPkt`.

Final ELF verification must continue to use a non-empty STA configuration;
otherwise the HIL binary deliberately enters `pending()` before Wi-Fi
initialization and LTO removes the unreachable strict runtime.
