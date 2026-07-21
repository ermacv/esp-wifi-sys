//! Fixed owned application-data transmit channel.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::Context,
};

use crate::{channel::BoundedChannel, data_rx::WifiDataInterface, queue::WakerCell};

pub const WIFI_DATA_TX_CAPACITY: usize = 8;
pub const WIFI_DATA_TX_FRAME_CAPACITY: usize = 1600;
const ETHERNET_HEADER_LEN: usize = 14;

struct TxSlotData {
    interface: WifiDataInterface,
    length: usize,
    bytes: [u8; WIFI_DATA_TX_FRAME_CAPACITY],
}

struct TxSlot {
    occupied: AtomicBool,
    data: UnsafeCell<TxSlotData>,
}

impl TxSlot {
    const fn new() -> Self {
        Self {
            occupied: AtomicBool::new(false),
            data: UnsafeCell::new(TxSlotData {
                interface: WifiDataInterface::Station,
                length: 0,
                bytes: [0; WIFI_DATA_TX_FRAME_CAPACITY],
            }),
        }
    }
}

unsafe impl Sync for TxSlot {}

static TX_SLOTS: [TxSlot; WIFI_DATA_TX_CAPACITY] = [const { TxSlot::new() }; WIFI_DATA_TX_CAPACITY];
static TX_CHANNEL: BoundedChannel<TxSlotToken, WIFI_DATA_TX_CAPACITY> = BoundedChannel::new();
static TX_CAPACITY_WAKER: WakerCell = WakerCell::new();
static TX_CLAIMED: AtomicUsize = AtomicUsize::new(0);
static TX_ENQUEUED: AtomicUsize = AtomicUsize::new(0);
static TX_DEQUEUED: AtomicUsize = AtomicUsize::new(0);
static TX_RELEASED: AtomicUsize = AtomicUsize::new(0);
static TX_REJECTED_INVALID: AtomicUsize = AtomicUsize::new(0);
static TX_REJECTED_SLOTS_FULL: AtomicUsize = AtomicUsize::new(0);
static TX_REJECTED_CHANNEL_CONTENDED: AtomicUsize = AtomicUsize::new(0);
static TX_OCCUPIED: AtomicUsize = AtomicUsize::new(0);
static TX_OCCUPIED_HIGH_WATER: AtomicUsize = AtomicUsize::new(0);

fn record_high_water(counter: &AtomicUsize, value: usize) {
    let observed = counter.load(Ordering::Relaxed);
    if value > observed {
        // Diagnostics must preserve the runtime's wait-free producer
        // contract. A racing update may conservatively win; never retry.
        let _ = counter.compare_exchange(observed, value, Ordering::Relaxed, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WifiDataTxSnapshot {
    pub claimed: usize,
    pub enqueued: usize,
    pub dequeued: usize,
    pub released: usize,
    pub rejected_invalid: usize,
    pub rejected_slots_full: usize,
    pub rejected_channel_contended: usize,
    pub occupied: usize,
    pub occupied_high_water: usize,
    pub queued: usize,
}

pub fn wifi_data_tx_snapshot() -> WifiDataTxSnapshot {
    WifiDataTxSnapshot {
        claimed: TX_CLAIMED.load(Ordering::Acquire),
        enqueued: TX_ENQUEUED.load(Ordering::Acquire),
        dequeued: TX_DEQUEUED.load(Ordering::Acquire),
        released: TX_RELEASED.load(Ordering::Acquire),
        rejected_invalid: TX_REJECTED_INVALID.load(Ordering::Acquire),
        rejected_slots_full: TX_REJECTED_SLOTS_FULL.load(Ordering::Acquire),
        rejected_channel_contended: TX_REJECTED_CHANNEL_CONTENDED.load(Ordering::Acquire),
        occupied: TX_OCCUPIED.load(Ordering::Acquire),
        occupied_high_water: TX_OCCUPIED_HIGH_WATER.load(Ordering::Acquire),
        queued: TX_CHANNEL.len(),
    }
}

struct TxSlotToken {
    index: usize,
}

impl Drop for TxSlotToken {
    fn drop(&mut self) {
        TX_SLOTS[self.index]
            .occupied
            .store(false, Ordering::Release);
        TX_RELEASED.fetch_add(1, Ordering::Relaxed);
        TX_OCCUPIED.fetch_sub(1, Ordering::AcqRel);
        TX_CAPACITY_WAKER.wake();
    }
}

pub struct OwnedWifiDataTxFrame {
    token: TxSlotToken,
}

impl OwnedWifiDataTxFrame {
    pub fn interface(&self) -> WifiDataInterface {
        unsafe { (*TX_SLOTS[self.token.index].data.get()).interface }
    }

    pub fn as_bytes(&self) -> &[u8] {
        let data = unsafe { &*TX_SLOTS[self.token.index].data.get() };
        &data.bytes[..data.length]
    }

    pub fn destination(&self) -> &[u8; 6] {
        self.as_bytes()[..6].try_into().unwrap()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiDataTxEnqueueError {
    InvalidLength,
    SlotsFull,
    ChannelContended,
}

/// Copy one complete Ethernet frame into fixed storage without waiting.
pub fn try_send_wifi_data(
    interface: WifiDataInterface,
    frame: &[u8],
) -> Result<(), WifiDataTxEnqueueError> {
    if frame.len() < ETHERNET_HEADER_LEN || frame.len() > WIFI_DATA_TX_FRAME_CAPACITY {
        TX_REJECTED_INVALID.fetch_add(1, Ordering::Relaxed);
        return Err(WifiDataTxEnqueueError::InvalidLength);
    }
    let Some((index, slot)) = TX_SLOTS.iter().enumerate().find(|(_, slot)| {
        slot.occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        TX_REJECTED_SLOTS_FULL.fetch_add(1, Ordering::Relaxed);
        return Err(WifiDataTxEnqueueError::SlotsFull);
    };

    TX_CLAIMED.fetch_add(1, Ordering::Relaxed);
    let occupied = TX_OCCUPIED.fetch_add(1, Ordering::AcqRel) + 1;
    record_high_water(&TX_OCCUPIED_HIGH_WATER, occupied);

    let data = unsafe { &mut *slot.data.get() };
    data.interface = interface;
    data.length = frame.len();
    data.bytes[..frame.len()].copy_from_slice(frame);
    if let Err(error) = TX_CHANNEL.try_send(TxSlotToken { index }) {
        TX_REJECTED_CHANNEL_CONTENDED.fetch_add(1, Ordering::Relaxed);
        drop(error.0);
        return Err(WifiDataTxEnqueueError::ChannelContended);
    }
    TX_ENQUEUED.fetch_add(1, Ordering::Release);
    Ok(())
}

pub fn try_receive_wifi_data_tx() -> Option<OwnedWifiDataTxFrame> {
    TX_CHANNEL.try_receive().map(|token| {
        TX_DEQUEUED.fetch_add(1, Ordering::Relaxed);
        OwnedWifiDataTxFrame { token }
    })
}

pub async fn receive_wifi_data_tx() -> OwnedWifiDataTxFrame {
    let token = TX_CHANNEL.receive().await;
    TX_DEQUEUED.fetch_add(1, Ordering::Relaxed);
    OwnedWifiDataTxFrame { token }
}

/// Register an executor waker and report whether a fixed TX slot is free.
///
/// The returned readiness is advisory: the caller must still handle the
/// bounded `try_send_wifi_data` result. Dropping a radio-owned frame wakes the
/// registered network driver without a timer or retry loop.
pub fn poll_wifi_data_tx_ready(cx: &mut Context<'_>) -> bool {
    TX_CAPACITY_WAKER.register(cx.waker());
    TX_SLOTS
        .iter()
        .any(|slot| !slot.occupied.load(Ordering::Acquire))
        && TX_CHANNEL.len() < WIFI_DATA_TX_CAPACITY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_slot_owns_complete_ethernet_frame() {
        let mut frame = [0_u8; ETHERNET_HEADER_LEN];
        frame[..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(
            try_send_wifi_data(WifiDataInterface::AccessPoint, &frame),
            Ok(())
        );
        let owned = try_receive_wifi_data_tx().unwrap();
        assert_eq!(owned.interface(), WifiDataInterface::AccessPoint);
        assert_eq!(owned.destination(), &[1, 2, 3, 4, 5, 6]);
        assert_eq!(owned.as_bytes(), &frame);
    }

    #[test]
    fn tx_rejects_non_ethernet_and_oversized_frames() {
        assert_eq!(
            try_send_wifi_data(WifiDataInterface::Station, &[0; 13]),
            Err(WifiDataTxEnqueueError::InvalidLength)
        );
        assert_eq!(
            try_send_wifi_data(
                WifiDataInterface::Station,
                &[0; WIFI_DATA_TX_FRAME_CAPACITY + 1],
            ),
            Err(WifiDataTxEnqueueError::InvalidLength)
        );
    }
}
