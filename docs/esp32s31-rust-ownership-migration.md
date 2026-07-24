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
instruction inspection of the three remaining strict vendor referrers gives
the narrower initial graph:

| vendor leaf | `g_ic` fields read | current purpose | intended Rust owner |
|---|---|---|---|
| `ieee80211_set_tx_desc` | `0x10`, `0x14` | identify STA versus AP interface | interface registry |
| `ieee80211_hostapd_data_txcb` | `0x14`, `0x74` | find AP state and reject mesh mode | AP peer/activity owner and mode policy |
| `ieee80211_post_hmac_tx` | `0x258` | select optional cached-TX path | fixed TX queue policy |

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

Node tables and interface contents remain separate owners: publishing an
interface does not grant arbitrary mutable access to every field behind its
pointer. The registry adds 12 bytes of internal SRAM and was verified on S31
hardware through passive scan, WPA2 association, DHCP, ping, DNS, TCP, and
post-link data with zero recorded allocations. The final ELF still passes the
strict no-wait/no-heap audit with zero violations.

After the three vendor leaves above have Rust replacements, the linked-state
audit should no longer report `g_ic` as strict-vendor-reachable even while cold
initialization still retains its backing.
