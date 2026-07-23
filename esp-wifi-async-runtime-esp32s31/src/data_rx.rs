//! Fixed, owned STA/AP data receive boundary.

use core::{
    cell::UnsafeCell,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll},
};

use crate::channel::BoundedChannel;

pub const WIFI_DATA_RX_CAPACITY: usize = 32;
pub const WIFI_DATA_RX_FRAME_CAPACITY: usize = 1600;
#[cfg(target_arch = "riscv32")]
const WIFI_DATA_RX_COPY_CAPACITY: usize = 8;
#[cfg(not(target_arch = "riscv32"))]
const WIFI_DATA_RX_COPY_CAPACITY: usize = WIFI_DATA_RX_CAPACITY;
#[cfg(target_arch = "riscv32")]
const WIFI_DATA_RX_COPY_FRAME_CAPACITY: usize = 512;
#[cfg(not(target_arch = "riscv32"))]
const WIFI_DATA_RX_COPY_FRAME_CAPACITY: usize = WIFI_DATA_RX_FRAME_CAPACITY;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiDataInterface {
    Station,
    AccessPoint,
}

struct RxSlotData {
    length: usize,
    bytes: [u8; WIFI_DATA_RX_COPY_FRAME_CAPACITY],
}

struct RxSlot {
    occupied: AtomicBool,
    data: UnsafeCell<RxSlotData>,
}

impl RxSlot {
    const fn new() -> Self {
        Self {
            occupied: AtomicBool::new(false),
            data: UnsafeCell::new(RxSlotData {
                length: 0,
                bytes: [0; WIFI_DATA_RX_COPY_FRAME_CAPACITY],
            }),
        }
    }
}

// `occupied` transfers exclusive access from the callback to the channel
// consumer. A slot is never written again until its token is dropped.
unsafe impl Sync for RxSlot {}

#[cfg_attr(
    target_arch = "riscv32",
    link_section = ".critical.bss.wifi_strict.data_rx_slots"
)]
static RX_SLOTS: [RxSlot; WIFI_DATA_RX_COPY_CAPACITY] =
    [const { RxSlot::new() }; WIFI_DATA_RX_COPY_CAPACITY];
#[cfg_attr(
    target_arch = "riscv32",
    link_section = ".critical.bss.wifi_strict.data_rx_channel"
)]
static RX_CHANNEL: BoundedChannel<RxSlotToken, WIFI_DATA_RX_CAPACITY> = BoundedChannel::new();
static REJECTED_RX_FRAMES: AtomicUsize = AtomicUsize::new(0);
static RX_CLAIMED: AtomicUsize = AtomicUsize::new(0);
static RX_ENQUEUED: AtomicUsize = AtomicUsize::new(0);
static RX_DEQUEUED: AtomicUsize = AtomicUsize::new(0);
static RX_RELEASED: AtomicUsize = AtomicUsize::new(0);
static RX_REJECTED_INVALID: AtomicUsize = AtomicUsize::new(0);
static RX_REJECTED_SLOTS_FULL: AtomicUsize = AtomicUsize::new(0);
static RX_REJECTED_CHANNEL_CONTENDED: AtomicUsize = AtomicUsize::new(0);
static RX_OCCUPIED: AtomicUsize = AtomicUsize::new(0);
static RX_OCCUPIED_HIGH_WATER: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "riscv32")]
static RX_CALLBACKS_INSTALLED: AtomicBool = AtomicBool::new(false);

fn record_high_water(counter: &AtomicUsize, value: usize) {
    let observed = counter.load(Ordering::Relaxed);
    if value > observed {
        // The interrupt producer gets one attempt; diagnostics must never
        // introduce a CAS retry loop into the packet path.
        let _ = counter.compare_exchange(observed, value, Ordering::Relaxed, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WifiDataRxSnapshot {
    pub claimed: usize,
    pub enqueued: usize,
    pub dequeued: usize,
    pub released: usize,
    pub rejected: usize,
    pub rejected_invalid: usize,
    pub rejected_slots_full: usize,
    pub rejected_channel_contended: usize,
    pub occupied: usize,
    pub occupied_high_water: usize,
    pub queued: usize,
}

pub fn wifi_data_rx_snapshot() -> WifiDataRxSnapshot {
    WifiDataRxSnapshot {
        claimed: RX_CLAIMED.load(Ordering::Acquire),
        enqueued: RX_ENQUEUED.load(Ordering::Acquire),
        dequeued: RX_DEQUEUED.load(Ordering::Acquire),
        released: RX_RELEASED.load(Ordering::Acquire),
        rejected: REJECTED_RX_FRAMES.load(Ordering::Acquire),
        rejected_invalid: RX_REJECTED_INVALID.load(Ordering::Acquire),
        rejected_slots_full: RX_REJECTED_SLOTS_FULL.load(Ordering::Acquire),
        rejected_channel_contended: RX_REJECTED_CHANNEL_CONTENDED.load(Ordering::Acquire),
        occupied: RX_OCCUPIED.load(Ordering::Acquire),
        occupied_high_water: RX_OCCUPIED_HIGH_WATER.load(Ordering::Acquire),
        queued: RX_CHANNEL.len(),
    }
}

enum RxStorage {
    Copied { index: usize },
    #[cfg(target_arch = "riscv32")]
    LargeEsf {
        buffer: *mut u8,
        length: usize,
        frame: *mut u8,
    },
}

struct RxSlotToken {
    interface: WifiDataInterface,
    storage: RxStorage,
}

#[cfg(target_arch = "riscv32")]
unsafe impl Send for RxSlotToken {}

impl Drop for RxSlotToken {
    fn drop(&mut self) {
        match &self.storage {
            RxStorage::Copied { index } => {
                RX_SLOTS[*index].occupied.store(false, Ordering::Release);
            }
            #[cfg(target_arch = "riscv32")]
            RxStorage::LargeEsf { frame, .. } => {
                if unsafe { !crate::esf::release_owned_large_rx_frame(*frame) } {
                    RX_REJECTED_INVALID.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        RX_RELEASED.fetch_add(1, Ordering::Relaxed);
        RX_OCCUPIED.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct OwnedWifiDataFrame {
    token: RxSlotToken,
}

impl OwnedWifiDataFrame {
    pub fn interface(&self) -> WifiDataInterface {
        self.token.interface
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.token.storage {
            RxStorage::Copied { index } => {
                let data = unsafe { &*RX_SLOTS[*index].data.get() };
                &data.bytes[..data.length]
            }
            #[cfg(target_arch = "riscv32")]
            RxStorage::LargeEsf { buffer, length, .. } => unsafe {
                core::slice::from_raw_parts(*buffer, *length)
            },
        }
    }

    /// Mutable packet view for a network-stack receive token.
    ///
    /// Ownership of the slot token guarantees exclusive access until this
    /// frame is dropped and returns the slot to the interrupt producer.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        match &mut self.token.storage {
            RxStorage::Copied { index } => {
                let data = unsafe { &mut *RX_SLOTS[*index].data.get() };
                &mut data.bytes[..data.length]
            }
            #[cfg(target_arch = "riscv32")]
            RxStorage::LargeEsf { buffer, length, .. } => unsafe {
                core::slice::from_raw_parts_mut(*buffer, *length)
            },
        }
    }
}

pub fn try_receive_wifi_data() -> Option<OwnedWifiDataFrame> {
    RX_CHANNEL.try_receive().map(|token| {
        RX_DEQUEUED.fetch_add(1, Ordering::Relaxed);
        OwnedWifiDataFrame { token }
    })
}

pub async fn receive_wifi_data() -> OwnedWifiDataFrame {
    let token = RX_CHANNEL.receive().await;
    RX_DEQUEUED.fetch_add(1, Ordering::Relaxed);
    OwnedWifiDataFrame { token }
}

/// Register an executor waker and receive one owned Ethernet frame if ready.
///
/// This is the synchronous poll boundary required by `embassy-net-driver`;
/// the interrupt producer wakes it through the same bounded channel used by
/// [`receive_wifi_data`].
pub fn poll_receive_wifi_data(cx: &mut Context<'_>) -> Poll<OwnedWifiDataFrame> {
    let mut receive = RX_CHANNEL.receive();
    Pin::new(&mut receive).poll(cx).map(|token| {
        RX_DEQUEUED.fetch_add(1, Ordering::Relaxed);
        OwnedWifiDataFrame { token }
    })
}

pub fn rejected_wifi_data_frames() -> usize {
    REJECTED_RX_FRAMES.load(Ordering::Acquire)
}

#[cfg(any(test, target_arch = "riscv32"))]
#[cfg_attr(
    target_arch = "riscv32",
    link_section = ".rwtext.wifi_strict.data_rx_copy"
)]
unsafe fn copy_into_slot(interface: WifiDataInterface, buffer: *const u8, length: usize) -> bool {
    if buffer.is_null() || length == 0 || length > WIFI_DATA_RX_COPY_FRAME_CAPACITY {
        REJECTED_RX_FRAMES.fetch_add(1, Ordering::Relaxed);
        RX_REJECTED_INVALID.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let Some((index, slot)) = RX_SLOTS.iter().enumerate().find(|(_, slot)| {
        slot.occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        REJECTED_RX_FRAMES.fetch_add(1, Ordering::Relaxed);
        RX_REJECTED_SLOTS_FULL.fetch_add(1, Ordering::Relaxed);
        return false;
    };

    let data = &mut *slot.data.get();
    data.length = length;
    core::ptr::copy_nonoverlapping(buffer, data.bytes.as_mut_ptr(), length);
    enqueue_token(RxSlotToken {
        interface,
        storage: RxStorage::Copied { index },
    })
}

fn enqueue_token(token: RxSlotToken) -> bool {
    RX_CLAIMED.fetch_add(1, Ordering::Relaxed);
    let occupied = RX_OCCUPIED.fetch_add(1, Ordering::AcqRel) + 1;
    record_high_water(&RX_OCCUPIED_HIGH_WATER, occupied);
    if let Err(error) = RX_CHANNEL.try_send(token) {
        REJECTED_RX_FRAMES.fetch_add(1, Ordering::Relaxed);
        if RX_CHANNEL.len() >= WIFI_DATA_RX_CAPACITY {
            RX_REJECTED_SLOTS_FULL.fetch_add(1, Ordering::Relaxed);
        } else {
            RX_REJECTED_CHANNEL_CONTENDED.fetch_add(1, Ordering::Relaxed);
        }
        drop(error.0);
        return false;
    }
    RX_ENQUEUED.fetch_add(1, Ordering::Release);
    true
}

#[cfg(target_arch = "riscv32")]
mod target {
    use core::ffi::c_void;

    use esp_wifi_sys_esp32s31::include::{
        esp_wifi_internal_free_rx_buffer, esp_wifi_internal_reg_rxcb, wifi_interface_t_WIFI_IF_AP,
        wifi_interface_t_WIFI_IF_STA, ESP_ERR_NO_MEM, ESP_OK,
    };

    use super::*;

    unsafe extern "C" {
        static mut sta_rxcb: usize;
        static mut ap_rxcb: usize;
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum WifiDataRxInstallError {
        AlreadyInstalled,
        StationRegistration(i32),
        AccessPointRegistration(i32),
    }

    #[no_mangle]
    #[link_section = ".rwtext.wifi_strict.data_rx_sta"]
    pub unsafe extern "C" fn __esp_wifi_async_data_rx_sta(
        buffer: *mut c_void,
        length: u16,
        vendor_buffer: *mut c_void,
    ) -> i32 {
        receive(WifiDataInterface::Station, buffer, length, vendor_buffer)
    }

    #[no_mangle]
    #[link_section = ".rwtext.wifi_strict.data_rx_ap"]
    pub unsafe extern "C" fn __esp_wifi_async_data_rx_ap(
        buffer: *mut c_void,
        length: u16,
        vendor_buffer: *mut c_void,
    ) -> i32 {
        receive(
            WifiDataInterface::AccessPoint,
            buffer,
            length,
            vendor_buffer,
        )
    }

    #[link_section = ".rwtext.wifi_strict.data_rx_dispatch"]
    unsafe fn receive(
        interface: WifiDataInterface,
        buffer: *mut c_void,
        length: u16,
        vendor_buffer: *mut c_void,
    ) -> i32 {
        let length = usize::from(length);
        let owns_large_esf = length <= WIFI_DATA_RX_FRAME_CAPACITY
            && !vendor_buffer.is_null()
            && crate::esf::owned_large_rx_view_valid(
                vendor_buffer.cast(),
                buffer.cast(),
                length,
            );
        let accepted = if owns_large_esf {
            // Transfer the live kind-7 object into the bounded safe channel.
            // Its token releases the one Rust pool bit directly on Drop, so
            // no vendor mutex or task identity crosses into embassy-net.
            enqueue_token(RxSlotToken {
                interface,
                storage: RxStorage::LargeEsf {
                    buffer: buffer.cast(),
                    length,
                    frame: vendor_buffer.cast(),
                },
            })
        } else {
            // Small vendor-static frames cannot be returned to their intrusive
            // free list from an arbitrary network task. Copy them into the
            // compact owned pool, then recycle while still on the radio owner.
            let accepted = copy_into_slot(interface, buffer.cast(), length);
            if !vendor_buffer.is_null() {
                esp_wifi_internal_free_rx_buffer(vendor_buffer);
            }
            accepted
        };
        if accepted {
            ESP_OK as i32
        } else {
            ESP_ERR_NO_MEM as i32
        }
    }

    pub fn async_wifi_data_rx_installed() -> bool {
        RX_CALLBACKS_INSTALLED.load(Ordering::Acquire)
            && unsafe {
                core::ptr::addr_of!(sta_rxcb).read()
                    == __esp_wifi_async_data_rx_sta as *const () as usize
                    && core::ptr::addr_of!(ap_rxcb).read()
                        == __esp_wifi_async_data_rx_ap as *const () as usize
            }
    }

    /// Install owned, nonblocking data callbacks for both STA and AP.
    ///
    /// # Safety
    /// Call after Wi-Fi initialization and before either interface can receive
    /// data. No other code may replace these callbacks while strict runtime is
    /// active. The callbacks must only run under the virtual Wi-Fi task
    /// identity established by `VendorPpDispatcher`.
    pub unsafe fn install_async_wifi_data_rx() -> Result<(), WifiDataRxInstallError> {
        if RX_CALLBACKS_INSTALLED.load(Ordering::Acquire) {
            return Err(WifiDataRxInstallError::AlreadyInstalled);
        }
        let result = esp_wifi_internal_reg_rxcb(
            wifi_interface_t_WIFI_IF_STA,
            Some(__esp_wifi_async_data_rx_sta),
        );
        if result != ESP_OK as i32 {
            return Err(WifiDataRxInstallError::StationRegistration(result));
        }
        let result = esp_wifi_internal_reg_rxcb(
            wifi_interface_t_WIFI_IF_AP,
            Some(__esp_wifi_async_data_rx_ap),
        );
        if result != ESP_OK as i32 {
            let _ = esp_wifi_internal_reg_rxcb(wifi_interface_t_WIFI_IF_STA, None);
            return Err(WifiDataRxInstallError::AccessPointRegistration(result));
        }
        RX_CALLBACKS_INSTALLED.store(true, Ordering::Release);
        Ok(())
    }
}

#[cfg(target_arch = "riscv32")]
pub use target::{
    async_wifi_data_rx_installed, install_async_wifi_data_rx, WifiDataRxInstallError,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_slot_owns_bytes_until_frame_drop() {
        let bytes = [1_u8, 2, 3, 4];
        assert!(unsafe {
            copy_into_slot(WifiDataInterface::AccessPoint, bytes.as_ptr(), bytes.len())
        });
        let frame = try_receive_wifi_data().unwrap();
        assert_eq!(frame.interface(), WifiDataInterface::AccessPoint);
        assert_eq!(frame.as_bytes(), &bytes);
        drop(frame);
        assert!(unsafe { copy_into_slot(WifiDataInterface::Station, bytes.as_ptr(), bytes.len()) });
        drop(try_receive_wifi_data().unwrap());
    }

    #[test]
    fn invalid_length_is_rejected_without_claiming_slot() {
        let byte = 0_u8;
        assert!(!unsafe { copy_into_slot(WifiDataInterface::Station, &byte, 0) });
        assert!(!unsafe {
            copy_into_slot(
                WifiDataInterface::Station,
                &byte,
                WIFI_DATA_RX_FRAME_CAPACITY + 1,
            )
        });
    }
}
