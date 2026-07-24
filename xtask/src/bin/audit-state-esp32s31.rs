use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{bail, Context, Result};

#[path = "../esp32s31_strict_policy.rs"]
mod strict_policy;
use strict_policy::{ROOTS, STATIC_BINDING_ROOTS, WRAPPED_VENDOR_BOUNDARIES};

// Exact store pairs in the pinned net80211_data_ptr_init (first 12) and
// wdev_data_init (remaining 31) disassemblies.
const ROM_ABI_BACKINGS: &[(&str, &str)] = &[
    ("g_wifi_nvs", "s_wifi_nvs"),
    ("g_scan", "gScanStruct"),
    ("g_chm", "gChmCxt"),
    ("g_ic_ptr", "g_ic"),
    ("g_hmac_cnt_ptr", "g_hmac_cnt"),
    ("g_tx_cacheq_ptr", "s_tx_cacheq"),
    ("g_mac_sleep_en_ptr", "g_mac_sleep_en"),
    ("g_esp_mesh_quick_funcs_ptr", "esp_mesh_quick_funcs"),
    ("g_mesh_init_ps_type_ptr", "g_mesh_init_ps_type"),
    ("g_mesh_is_started_ptr", "g_mesh_is_started"),
    ("g_mesh_is_root_ptr", "g_mesh_is_root"),
    ("g_mesh_topology_ptr", "g_mesh_topology"),
    ("pTxRx", "TxRxCxt"),
    ("lmacConfMib_ptr", "lmacConfMib"),
    ("wDevCtrl_ptr", "wDevCtrl"),
    ("wDevMacSleep_ptr", "wDevMacSleep"),
    ("g_lmac_cnt_ptr", "g_lmac_cnt"),
    ("pp_sig_cnt_ptr", "pp_sig_cnt"),
    ("g_wifi_menuconfig_ptr", "g_wifi_menuconfig"),
    ("g_eb_list_desc_ptr", "g_eb_list_desc"),
    ("s_fragment_ptr", "s_fragment"),
    ("if_ctrl_ptr", "if_ctrl"),
    ("ap_no_lr_ptr", "ap_no_lr"),
    ("rcLoRaSchedTbl_ptr", "rcLoRaSchedTbl"),
    ("rc11NSchedTbl_ptr", "rc11NSchedTbl"),
    ("rc11BSchedTbl_ptr", "rc11BSchedTbl"),
    ("BasicOFDMSched_ptr", "BasicOFDMSched"),
    ("trc_ctl_ptr", "trc_ctl"),
    ("g_pm_cfg_ptr", "g_pm_cfg"),
    ("g_pm_ptr", "g_pm"),
    ("g_txop_queue_status_ptr", "g_txop_queue_status"),
    ("g_pm_cnt_ptr", "g_pm_cnt"),
    ("g_pp_timer_info_ptr", "g_pp_timer_info"),
    ("g_rts_threshold_bytes_ptr", "g_rts_threshold_bytes"),
    ("g_pm_twt_ptr", "g_pm_twt"),
    ("g_he_max_apep_length_tab_ptr", "g_he_max_apep_length_tab"),
    ("g_wdev_dbg_rx_ptr", "g_wdev_dbg_rx"),
    ("s_pm_beacon_offset_ptr", "s_pm_beacon_offset"),
    ("s_pm_beacon_offset_config_ptr", "s_pm_beacon_offset_config"),
    ("s_tbttstart_ptr", "s_tbttstart"),
    ("s_offchan_tx_progress_in_ptr", "offchan_tx_progress_in"),
    ("g_offchan_packet_lifetime_ptr", "g_offchan_packet_lifetime"),
    ("g_send_wake_null_timer_ptr", "send_wake_null_timer"),
];

#[derive(Clone)]
struct Symbol {
    address: u64,
    size: u64,
    kind: char,
}

#[derive(Default)]
struct ArchiveInventory {
    data_owners: BTreeMap<String, BTreeSet<String>>,
    function_owners: BTreeMap<String, BTreeSet<String>>,
    calls: BTreeMap<String, BTreeSet<String>>,
    references: BTreeMap<String, BTreeSet<String>>,
}

struct Section {
    name: String,
    address: u64,
    size: u64,
}

fn main() -> Result<()> {
    let mut elf = None;
    let mut write = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--elf" => {
                elf = Some(PathBuf::from(
                    arguments.next().context("--elf requires a path")?,
                ));
            }
            "--write" => {
                write = Some(PathBuf::from(
                    arguments.next().context("--write requires a path")?,
                ));
            }
            _ => bail!("unknown argument: {argument}"),
        }
    }
    let elf = elf.context("--elf is required")?;
    if !elf.is_file() {
        bail!("ELF does not exist: {}", elf.display());
    }

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask must be inside the workspace")?
        .to_path_buf();
    let library_dir = workspace.join("esp-wifi-sys-esp32s31/libs");
    let report = build_report(&library_dir, &elf)?;
    if let Some(path) = write {
        let path = if path.is_absolute() {
            path
        } else {
            workspace.join(path)
        };
        fs::write(&path, &report)?;
        println!("wrote {}", path.display());
    } else {
        print!("{report}");
    }
    Ok(())
}

fn build_report(library_dir: &Path, elf: &Path) -> Result<String> {
    let inventory = inventory_archives(library_dir)?;
    let final_symbols = parse_posix_symbols(&text(checked(
        Command::new("llvm-nm")
            .arg("-S")
            .arg("-P")
            .arg("--defined-only")
            .arg(elf),
    )?)?);
    let sections = parse_sections(&text(checked(
        Command::new("llvm-readelf").arg("-S").arg("-W").arg(elf),
    )?)?);
    let reachable = reachable_vendor_functions(&inventory.calls);
    let mut reverse_references = reverse_references(&inventory.references);
    let pointer_backings = augment_pointer_backing_references(
        &mut reverse_references,
        &inventory.data_owners,
        &final_symbols,
    );
    let elf_digest = digest(elf)?;

    let mut runtime_globals = Vec::new();
    let mut linked_other_globals = Vec::new();
    for (name, owners) in &inventory.data_owners {
        let Some(symbol) = final_symbols.get(name) else {
            continue;
        };
        if !is_mutable_data(symbol.kind) || symbol.address == 0 || name.starts_with('.') {
            continue;
        }
        let all_referrers = reverse_references.get(name).cloned().unwrap_or_default();
        let runtime_referrers = all_referrers
            .intersection(&reachable)
            .cloned()
            .collect::<BTreeSet<_>>();
        let row = (
            name.clone(),
            symbol.clone(),
            owners.clone(),
            runtime_referrers,
            all_referrers,
        );
        if row.3.is_empty() {
            linked_other_globals.push(row);
        } else {
            runtime_globals.push(row);
        }
    }

    runtime_globals.sort_by_key(|(_, symbol, ..)| symbol.address);
    linked_other_globals.sort_by_key(|(_, symbol, ..)| symbol.address);

    let mut runtime_indirections = reverse_references
        .iter()
        .filter_map(|(name, referrers)| {
            let symbol = final_symbols.get(name)?;
            let runtime_referrers = referrers
                .intersection(&reachable)
                .cloned()
                .collect::<BTreeSet<_>>();
            (symbol.kind == 'A'
                && is_rom_data_indirection(symbol.address)
                && !runtime_referrers.is_empty())
            .then(|| {
                (
                    name.clone(),
                    symbol.clone(),
                    pointer_backings.get(name).cloned(),
                    runtime_referrers,
                )
            })
        })
        .collect::<Vec<_>>();
    runtime_indirections.sort_by_key(|(_, symbol, ..)| symbol.address);

    let wrappers = final_symbols
        .iter()
        .filter(|(name, symbol)| name.starts_with("__wrap_") && is_code(symbol.kind))
        .collect::<Vec<_>>();
    let strict_sections = sections
        .iter()
        .filter(|section| {
            section.name.contains("wifi_strict")
                || section.name == ".data.wifi"
                || section.name == ".bss.esp_wifi_async_net80211"
        })
        .collect::<Vec<_>>();

    let runtime_bytes = runtime_globals
        .iter()
        .map(|(_, symbol, ..)| symbol.size)
        .sum::<u64>();
    let other_bytes = linked_other_globals
        .iter()
        .map(|(_, symbol, ..)| symbol.size)
        .sum::<u64>();
    let strict_static_bytes = strict_sections
        .iter()
        .map(|section| section.size)
        .sum::<u64>();
    let live_static_bindings = ROM_ABI_BACKINGS
        .iter()
        .filter(|(cell, backing)| {
            final_symbols.contains_key(*cell) && final_symbols.contains_key(*backing)
        })
        .count();

    let mut report = String::new();
    pushln(
        &mut report,
        "# ESP32-S31 linked state and interposition audit",
    );
    pushln(&mut report, "");
    pushln(
        &mut report,
        &format!(
            "- final ELF: `{}`",
            elf.file_name().unwrap().to_string_lossy()
        ),
    );
    pushln(&mut report, &format!("- ELF SHA-256: `{elf_digest}`"));
    pushln(
        &mut report,
        &format!("- strict vendor roots: {}", ROOTS.len()),
    );
    pushln(
        &mut report,
        &format!(
            "- separately auditable static-binding roots: `{}`",
            STATIC_BINDING_ROOTS.join("`, `")
        ),
    );
    pushln(
        &mut report,
        &format!(
            "- vendor functions reachable from those roots: {}",
            reachable.len()
        ),
    );
    pushln(
        &mut report,
        &format!(
            "- live mutable blob globals reached by strict leaves: {} symbols / {} bytes",
            runtime_globals.len(),
            runtime_bytes
        ),
    );
    pushln(
        &mut report,
        &format!(
            "- ROM-ABI mutable indirection cells reached by strict leaves: {} cells / {} inferred bytes",
            runtime_indirections.len(),
            runtime_indirections.len() * 4
        ),
    );
    pushln(
        &mut report,
        &format!(
            "- fixed cold-init bindings live in this ELF: {live_static_bindings} / {}",
            ROM_ABI_BACKINGS.len()
        ),
    );
    pushln(
        &mut report,
        &format!(
            "- live mutable blob globals outside the strict-root graph: {} symbols / {} bytes",
            linked_other_globals.len(),
            other_bytes
        ),
    );
    pushln(
        &mut report,
        &format!(
            "- Rust strict static sections: {} sections / {} bytes",
            strict_sections.len(),
            strict_static_bytes
        ),
    );
    pushln(
        &mut report,
        &format!("- retained code wrappers: {}", wrappers.len()),
    );
    pushln(&mut report, "");
    pushln(
        &mut report,
        "The archive relocation graph supplies `vendor function -> data symbol`; the final ELF supplies liveness, address, size and section. A wrapper boundary stops traversal into the replaced vendor body. “Outside strict roots” means linked but not proven runtime-reachable by this vendor-leaf graph; it is not automatically safe to delete because cold initialization and non-Wi-Fi owners can still use it.",
    );
    pushln(
        &mut report,
        "Run `audit-strict-esp32s31 --include-static-binding-init --enforce` to prove the two fixed-storage binding leaves together with the runtime roots.",
    );

    pushln(&mut report, "");
    pushln(
        &mut report,
        "## Mutable blob state reached by strict vendor leaves",
    );
    pushln(&mut report, "");
    pushln(
        &mut report,
        "| symbol | size | placement | archive owner | strict referrers |",
    );
    pushln(&mut report, "|---|---:|---|---|---|");
    for (name, symbol, owners, runtime_referrers, _) in &runtime_globals {
        pushln(
            &mut report,
            &format!(
                "| `{name}` | {} | `{}` / `{}` | {} | {} |",
                symbol.size,
                placement(symbol.address),
                section_name(symbol.address, &sections),
                code_set(owners, 3),
                code_set(runtime_referrers, 5),
            ),
        );
    }
    if runtime_globals.is_empty() {
        pushln(&mut report, "| _none_ | 0 | - | - | - |");
    }

    pushln(&mut report, "");
    pushln(
        &mut report,
        "## Mutable ROM-ABI indirection cells reached by strict leaves",
    );
    pushln(&mut report, "");
    pushln(
        &mut report,
        "These absolute symbols name four-byte pointer/callback cells in the S31 ROM ABI RAM table. They are state even though `llvm-nm` reports linker kind `A`. A conventional `*_ptr -> *` backing is shown when the backing object is present in the ELF.",
    );
    pushln(&mut report, "");
    pushln(
        &mut report,
        "| cell | address | inferred backing | strict referrers |",
    );
    pushln(&mut report, "|---|---:|---|---|");
    for (name, symbol, backing, referrers) in &runtime_indirections {
        pushln(
            &mut report,
            &format!(
                "| `{name}` | `0x{:08x}` | {} | {} |",
                symbol.address,
                backing
                    .as_ref()
                    .map_or_else(|| cell_role(name).to_owned(), |name| format!("`{name}`")),
                code_set(referrers, 5)
            ),
        );
    }

    pushln(&mut report, "");
    pushln(&mut report, "## Fixed cold-init state bindings");
    pushln(&mut report, "");
    pushln(
        &mut report,
        "These are the exact direct stores recovered from the two separately audited cold-init leaves. The Rust interposition path publishes the same backing addresses without calling either vendor body.",
    );
    pushln(&mut report, "");
    pushln(
        &mut report,
        "| ROM ABI cell | address | fixed backing | bytes | placement |",
    );
    pushln(&mut report, "|---|---:|---|---:|---|");
    for (cell, backing) in ROM_ABI_BACKINGS {
        let Some(cell_symbol) = final_symbols.get(*cell) else {
            continue;
        };
        let Some(backing_symbol) = final_symbols.get(*backing) else {
            continue;
        };
        pushln(
            &mut report,
            &format!(
                "| `{cell}` | `0x{:08x}` | `{backing}` | {} | `{}` / `{}` |",
                cell_symbol.address,
                backing_symbol.size,
                placement(backing_symbol.address),
                section_name(backing_symbol.address, &sections),
            ),
        );
    }

    pushln(&mut report, "");
    pushln(&mut report, "## Rust-owned strict static storage");
    pushln(&mut report, "");
    pushln(&mut report, "| section | address | bytes | placement |");
    pushln(&mut report, "|---|---:|---:|---|");
    for section in &strict_sections {
        pushln(
            &mut report,
            &format!(
                "| `{}` | `0x{:08x}` | {} | `{}` |",
                section.name,
                section.address,
                section.size,
                placement(section.address)
            ),
        );
    }

    pushln(&mut report, "");
    pushln(&mut report, "## Final-link interposition");
    pushln(&mut report, "");
    pushln(
        &mut report,
        "| boundary | replacement | mode | `__real_*` target |",
    );
    pushln(&mut report, "|---|---:|---|---|");
    for (wrapper_name, wrapper) in wrappers {
        let public_name = wrapper_name.trim_start_matches("__wrap_");
        let real_name = format!("__real_{public_name}");
        let public = final_symbols.get(public_name);
        let real = final_symbols.get(&real_name);
        let mode = match public {
            Some(public) if public.address == wrapper.address => "direct public alias",
            Some(_) => "GNU `--wrap` boundary",
            None => "retained replacement only",
        };
        let real_target = real.map_or_else(
            || "-".to_owned(),
            |symbol| {
                format!(
                    "`0x{:08x}` ({})",
                    symbol.address,
                    target_placement(symbol.address)
                )
            },
        );
        pushln(
            &mut report,
            &format!(
                "| `{public_name}` | `0x{:08x}` | {mode} | {real_target} |",
                wrapper.address
            ),
        );
    }

    pushln(&mut report, "");
    pushln(
        &mut report,
        "## Linked mutable blob state outside the strict-root graph",
    );
    pushln(&mut report, "");
    pushln(
        &mut report,
        "| symbol | size | placement | archive owner | known archive referrers |",
    );
    pushln(&mut report, "|---|---:|---|---|---|");
    for (name, symbol, owners, _, all_referrers) in &linked_other_globals {
        pushln(
            &mut report,
            &format!(
                "| `{name}` | {} | `{}` / `{}` | {} | {} |",
                symbol.size,
                placement(symbol.address),
                section_name(symbol.address, &sections),
                code_set(owners, 3),
                code_set(all_referrers, 5),
            ),
        );
    }

    Ok(report)
}

fn inventory_archives(library_dir: &Path) -> Result<ArchiveInventory> {
    let mut inventory = ArchiveInventory::default();
    let mut archives = fs::read_dir(library_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|extension| extension == "a"))
        .collect::<Vec<_>>();
    archives.sort();

    for archive in archives {
        let archive_name = archive
            .file_name()
            .and_then(|name| name.to_str())
            .context("archive name is not UTF-8")?;
        let nm = text(checked(
            Command::new("llvm-nm")
                .arg("-A")
                .arg("-S")
                .arg("-P")
                .arg("--defined-only")
                .arg(&archive),
        )?)?;
        for line in nm.lines() {
            let Some((source, (name, symbol))) = parse_archive_symbol(line) else {
                continue;
            };
            let owner = short_owner(source, archive_name);
            if is_mutable_data(symbol.kind) && !name.starts_with('.') {
                inventory
                    .data_owners
                    .entry(name.to_owned())
                    .or_default()
                    .insert(owner.clone());
            } else if is_code(symbol.kind) && !name.starts_with('.') {
                inventory
                    .function_owners
                    .entry(name.to_owned())
                    .or_default()
                    .insert(owner);
            }
        }

        let disassembly = text(checked(
            Command::new("llvm-objdump")
                .arg("-dr")
                .arg("--no-show-raw-insn")
                .arg(&archive),
        )?)?;
        parse_archive_relocations(&disassembly, &mut inventory);
    }
    Ok(inventory)
}

fn parse_archive_symbol(line: &str) -> Option<(&str, (&str, Symbol))> {
    let (source, fields) = line.rsplit_once(": ")?;
    let fields = fields.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 4 {
        return None;
    }
    let kind = fields[1].chars().next()?;
    let address = u64::from_str_radix(fields[2], 16).ok()?;
    let size = u64::from_str_radix(fields[3], 16).ok()?;
    Some((
        source,
        (
            fields[0],
            Symbol {
                address,
                size,
                kind,
            },
        ),
    ))
}

fn short_owner(source: &str, fallback_archive: &str) -> String {
    let file = source
        .rsplit(std::path::MAIN_SEPARATOR)
        .next()
        .unwrap_or(source);
    if file.contains('[') {
        file.to_owned()
    } else {
        fallback_archive.to_owned()
    }
}

fn parse_archive_relocations(disassembly: &str, inventory: &mut ArchiveInventory) {
    let mut function = None::<String>;
    for line in disassembly.lines() {
        if let Some(name) = definition_name(line) {
            function = (!name.starts_with('.')).then(|| normalize_symbol(name));
            continue;
        }
        let Some(caller) = function.as_ref() else {
            continue;
        };
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(index) = fields
            .iter()
            .position(|field| field.starts_with("R_RISCV_"))
        else {
            continue;
        };
        let Some(target) = fields.get(index + 1) else {
            continue;
        };
        let target = normalize_symbol(target);
        if target.starts_with('.') || target == "*ABS*" {
            continue;
        }
        inventory
            .references
            .entry(caller.clone())
            .or_default()
            .insert(target.clone());
        if matches!(
            fields.get(index).copied(),
            Some("R_RISCV_CALL" | "R_RISCV_CALL_PLT" | "R_RISCV_JAL")
        ) {
            inventory
                .calls
                .entry(caller.clone())
                .or_default()
                .insert(target);
        }
    }
}

fn reachable_vendor_functions(calls: &BTreeMap<String, BTreeSet<String>>) -> BTreeSet<String> {
    let mut reachable = BTreeSet::new();
    let mut pending = VecDeque::from_iter(ROOTS.iter().map(|root| (*root).to_owned()));
    while let Some(function) = pending.pop_front() {
        if !reachable.insert(function.clone()) {
            continue;
        }
        if !ROOTS.contains(&function.as_str())
            && WRAPPED_VENDOR_BOUNDARIES.contains(&function.as_str())
        {
            continue;
        }
        if let Some(targets) = calls.get(&function) {
            pending.extend(targets.iter().cloned());
        }
    }
    reachable
}

fn reverse_references(
    references: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut reverse = BTreeMap::<String, BTreeSet<String>>::new();
    for (function, symbols) in references {
        for symbol in symbols {
            reverse
                .entry(symbol.clone())
                .or_default()
                .insert(function.clone());
        }
    }
    reverse
}

fn augment_pointer_backing_references(
    reverse: &mut BTreeMap<String, BTreeSet<String>>,
    data_owners: &BTreeMap<String, BTreeSet<String>>,
    final_symbols: &BTreeMap<String, Symbol>,
) -> BTreeMap<String, String> {
    let aliases = reverse
        .iter()
        .filter_map(|(alias, referrers)| {
            let alias_symbol = final_symbols.get(alias)?;
            let backing = ROM_ABI_BACKINGS
                .iter()
                .find_map(|(cell, backing)| (*cell == alias).then_some(*backing))
                .or_else(|| alias.strip_suffix("_ptr"))?;
            (alias_symbol.kind == 'A'
                && is_rom_data_indirection(alias_symbol.address)
                && data_owners.contains_key(backing)
                && final_symbols
                    .get(backing)
                    .is_some_and(|symbol| is_mutable_data(symbol.kind)))
            .then(|| (alias.clone(), backing.to_owned(), referrers.clone()))
        })
        .collect::<Vec<_>>();
    let mut backings = BTreeMap::new();
    for (alias, backing, referrers) in aliases {
        reverse
            .entry(backing.clone())
            .or_default()
            .extend(referrers);
        backings.insert(alias, backing);
    }
    backings
}

fn parse_posix_symbols(nm: &str) -> BTreeMap<String, Symbol> {
    let mut symbols = BTreeMap::new();
    for line in nm.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            continue;
        }
        let Some(kind) = fields[1].chars().next() else {
            continue;
        };
        let Ok(address) = u64::from_str_radix(fields[2], 16) else {
            continue;
        };
        let Ok(size) = u64::from_str_radix(fields[3], 16) else {
            continue;
        };
        symbols.insert(
            fields[0].to_owned(),
            Symbol {
                address,
                size,
                kind,
            },
        );
    }
    symbols
}

fn parse_sections(readelf: &str) -> Vec<Section> {
    let mut sections = Vec::new();
    for line in readelf.lines() {
        let Some((_, tail)) = line.split_once(']') else {
            continue;
        };
        let fields = tail.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 {
            continue;
        }
        let Ok(address) = u64::from_str_radix(fields[2], 16) else {
            continue;
        };
        let Ok(size) = u64::from_str_radix(fields[4], 16) else {
            continue;
        };
        sections.push(Section {
            name: fields[0].to_owned(),
            address,
            size,
        });
    }
    sections
}

fn section_name(address: u64, sections: &[Section]) -> &str {
    sections
        .iter()
        .find(|section| {
            section.size != 0
                && (section.address..section.address.saturating_add(section.size))
                    .contains(&address)
        })
        .map_or("unknown", |section| section.name.as_str())
}

fn placement(address: u64) -> &'static str {
    match address {
        0x2f00_0000..=0x2fff_ffff => "internal SRAM",
        0x5000_0000..=0x5fff_ffff => "PSRAM",
        0x4000_0000..=0x4fff_ffff => "flash-mapped",
        _ => "other",
    }
}

fn target_placement(address: u64) -> &'static str {
    match address {
        0x2f80_0000..=0x2f80_ffff => "ROM export",
        _ => placement(address),
    }
}

fn is_rom_data_indirection(address: u64) -> bool {
    (0x2f07_fc00..0x2f08_0000).contains(&address)
}

fn cell_role(name: &str) -> &'static str {
    match name {
        "g_osi_funcs_p" => "Rust-installed strict OSI table pointer",
        "s_netstack_free" => "registered netstack-free callback",
        "esp_test_rx_error_occurs" => "RX diagnostic scalar",
        _ => "unresolved ROM ABI cell",
    }
}

fn is_mutable_data(kind: char) -> bool {
    matches!(
        kind,
        'B' | 'b' | 'C' | 'c' | 'D' | 'd' | 'G' | 'g' | 'S' | 's'
    )
}

fn is_code(kind: char) -> bool {
    matches!(kind, 'T' | 't' | 'W' | 'w')
}

fn definition_name(line: &str) -> Option<&str> {
    let start = line.find('<')? + 1;
    let end = line[start..].find(">:")? + start;
    line[..start - 1]
        .trim()
        .chars()
        .all(|character| character.is_ascii_hexdigit())
        .then_some(&line[start..end])
}

fn normalize_symbol(symbol: &str) -> String {
    symbol
        .split(['+', '@'])
        .next()
        .unwrap_or(symbol)
        .trim()
        .to_owned()
}

fn code_set(values: &BTreeSet<String>, limit: usize) -> String {
    if values.is_empty() {
        return "-".to_owned();
    }
    let shown = values
        .iter()
        .take(limit)
        .map(|value| format!("`{value}`"))
        .collect::<Vec<_>>()
        .join(", ");
    if values.len() > limit {
        format!("{shown}, +{}", values.len() - limit)
    } else {
        shown
    }
}

fn digest(path: &Path) -> Result<String> {
    let output = text(checked(Command::new("sha256sum").arg(path))?)?;
    output
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .context("sha256sum returned no digest")
}

fn pushln(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
}

fn checked(command: &mut Command) -> Result<Output> {
    let output = command
        .output()
        .with_context(|| format!("running {command:?}"))?;
    if !output.status.success() {
        bail!(
            "command failed: {command:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output)
}

fn text(output: Output) -> Result<String> {
    String::from_utf8(output.stdout).context("tool output was not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::{
        definition_name, parse_archive_symbol, parse_posix_symbols, parse_sections, placement,
        ROM_ABI_BACKINGS,
    };

    #[test]
    fn pinned_cold_init_has_43_unique_bindings() {
        assert_eq!(ROM_ABI_BACKINGS.len(), 43);
        let cells = ROM_ABI_BACKINGS
            .iter()
            .map(|(cell, _)| *cell)
            .collect::<std::collections::BTreeSet<_>>();
        let backings = ROM_ABI_BACKINGS
            .iter()
            .map(|(_, backing)| *backing)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(cells.len(), ROM_ABI_BACKINGS.len());
        assert_eq!(backings.len(), ROM_ABI_BACKINGS.len());
    }

    #[test]
    fn parses_archive_posix_symbol() {
        let line = "libs/libpp.a[pp.o]: pp_sig_cnt D 0 24";
        let (source, (name, symbol)) = parse_archive_symbol(line).unwrap();
        assert_eq!(source, "libs/libpp.a[pp.o]");
        assert_eq!(name, "pp_sig_cnt");
        assert_eq!(symbol.size, 0x24);
    }

    #[test]
    fn parses_final_posix_symbol() {
        let symbols = parse_posix_symbols("pp_sig_cnt D 2f01750c 24\n");
        assert_eq!(symbols["pp_sig_cnt"].address, 0x2f01_750c);
        assert_eq!(symbols["pp_sig_cnt"].size, 0x24);
    }

    #[test]
    fn parses_wide_section_table() {
        let sections = parse_sections(
            "  [ 7] .critical.data.wifi_strict.commands PROGBITS 2f017668 017858 00432c 00 WA 0 0 4\n",
        );
        assert_eq!(sections[0].name, ".critical.data.wifi_strict.commands");
        assert_eq!(sections[0].address, 0x2f01_7668);
        assert_eq!(sections[0].size, 0x432c);
    }

    #[test]
    fn recognizes_function_definitions_and_memory() {
        assert_eq!(
            definition_name("00000000 <wDev_ProcessRxSucData>:"),
            Some("wDev_ProcessRxSucData")
        );
        assert_eq!(placement(0x2f01_0000), "internal SRAM");
        assert_eq!(placement(0x5000_0000), "PSRAM");
    }
}
