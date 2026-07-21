/* Stable alias for the pinned local scan channel-completion callback. */
EXTERN(ieee80211_scan_attach)

SECTIONS
{
  .text.esp_wifi_async_channel_locals : ALIGN(2)
  {
    __esp_scan_op_end = .;
    KEEP(*(.text.scan_op_end))
    __esp_scan_op_end_end = .;
  }
}
INSERT AFTER .text;

ASSERT(__esp_scan_op_end_end - __esp_scan_op_end == 0x26e,
       "ESP32-S31 scan_op_end ABI changed");
