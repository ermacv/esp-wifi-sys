# esp-wifi-sys-esp32s31

Low-level unsafe bindings for the binary blobs required by the ESP32-S31 Wi-Fi radio.

The libraries and header files are taken from [ESP-IDF], and the bindings are generated using [bindgen].

The current ESP32-S31 artifacts were prepared from ESP-IDF commit
`25fe69f9`, with `esp_wifi` commit `77143eec` and `esp_phy` commit
`e294ff26`. Bluetooth controller support is intentionally not included yet.

[esp-idf]: https://github.com/espressif/esp-idf
[bindgen]: https://github.com/rust-lang/rust-bindgen

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
