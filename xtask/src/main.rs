use std::{
    fs,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, Result};
use bindgen::Builder;
use directories::UserDirs;
use log::LevelFilter;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Arch {
    RiscV,
    Xtensa,
}

fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_module("xtask", LevelFilter::Info)
        .init();

    // The directory containing the cargo manifest for the 'xtask' package is a
    // subdirectory within the cargo workspace:
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = workspace.parent().unwrap().canonicalize()?;

    // Determine the $HOME directory, and subsequently the Espressif tools
    // directory:
    let home = UserDirs::new().unwrap().home_dir().to_path_buf();
    let mut tools = home.join(".espressif").join("tools");

    if !tools.join("xtensa-esp-elf").exists() {
        println!("Tools not found in home - using ESP_TOOLS_DIR env variable");
        tools = PathBuf::from(std::env::var("ESP_TOOLS_DIR")?);
    }

    let requested_chip = std::env::args().nth(1);
    let chips = [
        ("esp32", "xtensa-esp-elf", Arch::Xtensa),
        ("esp32s2", "xtensa-esp-elf", Arch::Xtensa),
        ("esp32s3", "xtensa-esp-elf", Arch::Xtensa),
        ("esp32c2", "riscv32-esp-elf", Arch::RiscV),
        ("esp32c3", "riscv32-esp-elf", Arch::RiscV),
        ("esp32h2", "riscv32-esp-elf", Arch::RiscV),
        ("esp32c6", "riscv32-esp-elf", Arch::RiscV),
        ("esp32c5", "riscv32-esp-elf", Arch::RiscV),
        ("esp32c61", "riscv32-esp-elf", Arch::RiscV),
        ("esp32s31", "riscv32-esp-elf", Arch::RiscV),
    ];

    for (chip, tool, arch) in chips {
        if requested_chip
            .as_deref()
            .is_some_and(|requested| requested != chip)
        {
            continue;
        }
        generate_bindings_for_chip(chip, arch, &workspace, &tools, tool)?;
    }

    Ok(())
}

fn generate_bindings_for_chip(
    chip: &str,
    arch: Arch,
    workspace: &Path,
    tools: &Path,
    tool: &str,
) -> Result<()> {
    let sysroot_path = find_sysroot(tools, tool)?;
    let include_path = sysroot_path.join(format!("{tool}/include"));
    let c_path = workspace.join("c");
    let crate_path = workspace.join(format!("esp-wifi-sys-{chip}"));

    println!(
        "{}",
        c_path
            .join("include")
            .join(chip)
            .join("soc")
            .display()
            .to_string()
            .replace("/", "\\")
    );

    // Generate the bindings using `bindgen`:
    log::info!("Generating bindings for: {chip}");
    let chip_header = c_path.join("headers").join(chip).join("include.h");
    let header = if chip_header.is_file() {
        chip_header
    } else {
        c_path.join("include/include.h")
    };

    let bindings = Builder::default()
        .clang_args([
            &format!("-DCONFIG_IDF_TARGET_{}", chip.to_uppercase()),
            &format!(
                "-I{}",
                c_path
                    .join("headers")
                    .join(chip)
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "-I{}",
                c_path
                    .join("headers")
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "-I{}",
                c_path
                    .join("headers")
                    .join("local")
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "-I{}",
                c_path
                    .join("include")
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "-I{}",
                include_path
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "-I{}",
                c_path
                    .join("include")
                    .join(chip)
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "--sysroot={}",
                sysroot_path
                    .display()
                    .to_string()
                    .replace("\\", "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "--target={}",
                if arch == Arch::Xtensa {
                    "xtensa"
                } else {
                    "riscv32"
                }
            ),
        ])
        .ctypes_prefix("crate::c_types")
        .derive_debug(false)
        .header(header.to_string_lossy())
        .layout_tests(false)
        .raw_line("#![allow(non_camel_case_types,non_snake_case,non_upper_case_globals,dead_code,improper_ctypes)]")
        .use_core()
        .generate()
        .map_err(|_| anyhow!("Failed to generate bindings"))?;

    // Write out the bindings to the appropriate path:
    let path = crate_path.join("src").join("include.rs");
    log::info!("Writing out bindings to: {}", path.display());
    bindings.write_to_file(&path)?;

    if chip == "esp32s31" {
        fix_esp32s31_sta_config_layout(&path)?;
    }

    // We additionally need to implement a `Send` for a couple types:
    let mut file = File::options().append(true).open(&path)?;
    writeln!(
        file,
        "\n{}\n{}",
        "unsafe impl Sync for wifi_init_config_t {}", "unsafe impl Sync for wifi_osi_funcs_t {}"
    )?;

    // Format the bindings:
    Command::new("rustfmt")
        .arg(path.to_string_lossy().to_string())
        .output()?;

    Ok(())
}

/// Match the GCC layout used to build the ESP32-S31 Wi-Fi binary.
///
/// Clang/bindgen aligns the `uint32_t` bitfield groups in
/// `wifi_sta_config_t` to the next four-byte boundary. GCC instead reuses the
/// bytes following `pmf_cfg` and `failure_retry_cnt`. Both layouts are 184
/// bytes, so a size check alone cannot detect this ABI mismatch.
fn fix_esp32s31_sta_config_layout(path: &Path) -> Result<()> {
    let source = fs::read_to_string(path)?;
    let start = source
        .find("pub struct wifi_sta_config_t {")
        .ok_or_else(|| anyhow!("wifi_sta_config_t was not generated"))?;
    let end = source[start..]
        .find("impl wifi_sta_config_t {")
        .map(|offset| start + offset)
        .ok_or_else(|| anyhow!("wifi_sta_config_t implementation was not generated"))?;

    let body = source[start..end].replace(
        "    pub _bitfield_align_1: [u32; 0],\n    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 4usize]>,",
        "    // GCC places this group immediately after `pmf_cfg`; bindgen's u32\n\
         // alignment does not match the ESP32-S31 vendor-library ABI.\n\
         pub _bitfield_align_1: [u8; 0],\n\
         pub _bitfield_1: __BindgenBitfieldUnit<[u8; 4usize]>,\n\
         pub _bitfield_tail_1: [u8; 2usize],",
    );
    let body = body.replace(
        "    pub _bitfield_align_2: [u32; 0],\n    pub _bitfield_2: __BindgenBitfieldUnit<[u8; 4usize]>,",
        "    // GCC places this group immediately after `failure_retry_cnt`;\n\
         // the tail preserves the following C-field offsets.\n\
         pub _bitfield_align_2: [u8; 0],\n\
         pub _bitfield_2: __BindgenBitfieldUnit<[u8; 4usize]>,\n\
         pub _bitfield_tail_2: [u8; 2usize],",
    );
    if !body.contains("pub _bitfield_tail_1: [u8; 2usize]")
        || !body.contains("pub _bitfield_tail_2: [u8; 2usize]")
    {
        return Err(anyhow!(
            "wifi_sta_config_t no longer matches the expected bindgen output"
        ));
    }

    fs::write(
        path,
        format!("{}{}{}", &source[..start], body, &source[end..]),
    )?;
    Ok(())
}

fn find_sysroot(tools: &Path, tool: &str) -> Result<PathBuf> {
    let tool_dir = tools.join(tool);
    let mut candidates = std::fs::read_dir(&tool_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join(tool))
        .filter(|path| path.join(format!("{tool}/include")).is_dir())
        .collect::<Vec<_>>();

    candidates.sort();
    candidates
        .pop()
        .ok_or_else(|| anyhow!("No {tool} sysroot found below {}", tool_dir.display()))
}
