use std::{env, path::PathBuf};

fn main() {
    // Put the linker script somewhere the linker can find it
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let libs = [
        "btbb",
        "coexist",
        "core",
        "espnow",
        "mesh",
        "net80211",
        "wifi_support",
        "phy",
        "pp",
        "smartconfig",
        "wapi",
        "wpa_supplicant",
        "printf",
        "regulatory",
    ];

    for lib in libs {
        // `libcore.a` shadows Rust's target `libcore.rlib` when Cargo passes
        // OUT_DIR as a native link-search path. Rename only the copied vendor
        // archive; archive member names and exported symbols are unchanged.
        let link_name = if lib == "core" { "esp_wifi_core" } else { lib };
        std::fs::copy(
            format!("libs/lib{}.a", lib),
            out.join(format!("lib{}.a", link_name)),
        )
        .unwrap_or_else(|e| panic!("Failed to copy the {lib} library: {e}"));
        println!("cargo:rustc-link-lib={link_name}");
    }

    println!("cargo:rustc-link-search={}", out.display());
}
