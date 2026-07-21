//! Fixed, owned STA/AP data receive boundary.

use core::{
    cell::UnsafeCell,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll},
};

use crate::channel::BoundedChannel;

pub const WIFI_DATA_RX_CAPACITY: usize = 8;
pub const WIFI_DATA_RX_FRAME_CAPACITY: usize = 1600;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiDataInterface {
    Station,
    AccessPoint,
}

struct RxSlotData {
    interface: WifiDataInterface,
    length: usize,
    bytes: [u8; WIFI_DATA_RX_FRAME_CAPACITY],
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
                interface: WifiDataInterface::Station,
                length: 0,
                bytes: [0; WIFI_DATA_RX_FRAME_CAPACITY],
            }),
        }
    }
}

// `occupied` transfers exclusive access from the callback to the channel
// consumer. A slot is never written again until its token is dropped.
unsafe impl Sync for RxSlot {}

static RX_SLOTS: [RxSlot; WIFI_DATA_RX_CAPACITY] = [const { RxSlot::new() }; WIFI_DATA_RX_CAPACITY];
static RX_CHANNEL: BoundedChannel<RxSlotToken, WIFI_DATA_RX_CAPACITY> = BoundedChannel::new();
static REJECTED_RX_FRAMES: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "riscv32")]
static RX_CALLBACKS_INSTALLED: AtomicBool = AtomicBool::new(false);

struct RxSlotToken {
    index: usize,
}

impl Drop for RxSlotToken {
    fn drop(&mut self) {
        RX_SLOTS[self.index]
            .occupied
            .store(false, Ordering::Release);
    }
}

pub struct OwnedWifiDataFrame {
    token: RxSlotToken,
}

impl OwnedWifiDataFrame {
    pub fn interface(&self) -> WifiDataInterface {
        unsafe { (*RX_SLOTS[self.token.index].data.get()).interface }
    }

    pub fn as_bytes(&self) -> &[u8] {
        let data = unsafe { &*RX_SLOTS[self.token.index].data.get() };
        &data.bytes[..data.length]
    }
}

pub fn try_receive_wifi_data() -> Option<OwnedWifiDataFrame> {
    RX_CHANNEL
        .try_receive()
        .map(|token| OwnedWifiDataFrame { token })
}

pub async fn receive_wifi_data() -> OwnedWifiDataFrame {
    OwnedWifiDataFrame {
        token: RX_CHANNEL.receive().await,
    }
}

/// Register an executor waker and receive one owned Ethernet frame if ready.
///
/// This is the synchronous poll boundary required by `embassy-net-driver`;
/// the interrupt producer wakes it through the same bounded channel used by
/// [`receive_wifi_data`].
pub fn poll_receive_wifi_data(cx: &mut Context<'_>) -> Poll<OwnedWifiDataFrame> {
    let mut receive = RX_CHANNEL.receive();
    Pin::new(&mut receive)
        .poll(cx)
        .map(|token| OwnedWifiDataFrame { token })
}

pub fn rejected_wifi_data_frames() -> usize {
    REJECTED_RX_FRAMES.load(Ordering::Acquire)
}

#[cfg(any(test, target_arch = "riscv32"))]
unsafe fn copy_into_slot(interface: WifiDataInterface, buffer: *const u8, length: usize) -> bool {
    if buffer.is_null() || length == 0 || length > WIFI_DATA_RX_FRAME_CAPACITY {
        return false;
    }
    let Some((index, slot)) = RX_SLOTS.iter().enumerate().find(|(_, slot)| {
        slot.occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        return false;
    };

    let data = &mut *slot.data.get();
    data.interface = interface;
    data.length = length;
    core::ptr::copy_nonoverlapping(buffer, data.bytes.as_mut_ptr(), length);
    if let Err(error) = RX_CHANNEL.try_send(RxSlotToken { index }) {
        drop(error.0);
        return false;
    }
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
    pub unsafe extern "C" fn __esp_wifi_async_data_rx_sta(
        buffer: *mut c_void,
        length: u16,
        vendor_buffer: *mut c_void,
    ) -> i32 {
        receive(WifiDataInterface::Station, buffer, length, vendor_buffer)
    }

    #[no_mangle]
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

    unsafe fn receive(
        interface: WifiDataInterface,
        buffer: *mut c_void,
        length: u16,
        vendor_buffer: *mut c_void,
    ) -> i32 {
        let accepted = copy_into_slot(interface, buffer.cast(), usize::from(length));
        if !vendor_buffer.is_null() {
            // The callback owns `vendor_buffer`. Under the virtual Wi-Fi task
            // identity its API-lock path cannot wait, and the pinned S31
            // function immediately recycles the fixed RX object.
            esp_wifi_internal_free_rx_buffer(vendor_buffer);
        }
        if accepted {
            ESP_OK as i32
        } else {
            REJECTED_RX_FRAMES.fetch_add(1, Ordering::Relaxed);
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
