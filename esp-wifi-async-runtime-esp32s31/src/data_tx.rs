//! Fixed owned application-data transmit channel.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
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

struct TxSlotToken {
    index: usize,
}

impl Drop for TxSlotToken {
    fn drop(&mut self) {
        TX_SLOTS[self.index]
            .occupied
            .store(false, Ordering::Release);
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
        return Err(WifiDataTxEnqueueError::InvalidLength);
    }
    let Some((index, slot)) = TX_SLOTS.iter().enumerate().find(|(_, slot)| {
        slot.occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        return Err(WifiDataTxEnqueueError::SlotsFull);
    };

    let data = unsafe { &mut *slot.data.get() };
    data.interface = interface;
    data.length = frame.len();
    data.bytes[..frame.len()].copy_from_slice(frame);
    if let Err(error) = TX_CHANNEL.try_send(TxSlotToken { index }) {
        drop(error.0);
        return Err(WifiDataTxEnqueueError::ChannelContended);
    }
    Ok(())
}

pub fn try_receive_wifi_data_tx() -> Option<OwnedWifiDataTxFrame> {
    TX_CHANNEL
        .try_receive()
        .map(|token| OwnedWifiDataTxFrame { token })
}

pub async fn receive_wifi_data_tx() -> OwnedWifiDataTxFrame {
    OwnedWifiDataTxFrame {
        token: TX_CHANNEL.receive().await,
    }
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
