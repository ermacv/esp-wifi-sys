use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{bail, Context, Result};

const ROOTS: &[&str] = &[
    "ppProcessTxQ",
    "pp_timer_do_process",
    "pp_default_event_handler",
    "ppRxPkt",
    "lmacProcessTxComplete",
    "lmacProcessCollisions_task",
    "wdevProcessRxSucDataAll",
    // Targets of callback bits required by basic STA/AP. Strict continuations
    // dispatch both mode-0 and the timeout/discard mode-1 bits directly. The
    // same callbacks remain reachable from vendor TX-completion roots until
    // those entries are replaced as well.
    "ieee80211_hostapd_data_txcb",
    // Direct vendor leaves called by the Rust event-22 continuation.
    "hal_mac_tx_set_cca",
    "hal_mac_is_txq_valid",
    "hal_mac_set_txq_invalid",
    "hal_mac_txq_disable",
    "lmacReleaseTxopQueue",
    "ppDequeueTxQ",
    "rcUpdateTxDone",
    "ic_get_next_tbtt",
    // Direct finite leaves used by the Rust-owned channel switch and strict
    // passive-scan receive-policy branches.
    "chm_get_chan_info",
    "ic_set_current_channel",
    "phy_change_channel",
    "hal_mac_set_csi_cbw",
    "ic_mac_init",
    "ic_set_mac",
    "ic_set_rx_policy",
    "ic_set_rx_policy_ubssid_check",
    // Direct leaves used by the one-frame strict event-16 continuation.
    "pp_coex_tx_release",
    "esp_wifi_internal_free_rx_buffer",
    // Rust owns WPA2 PTK/MIC/framing and bypasses the stock allocating TX/key
    // wrappers. Only the exact lower leaves called by `S31StaticWpa2Io` remain
    // roots here.
    "ieee80211_post_hmac_tx",
    "ic_del_key",
    "ic_set_key",
    "wDev_Insert_KeyEntry",
    // Exact allocation-free AP association-response branch used after the
    // heap-backed WPA station callbacks have been patched.
    "ieee80211_assoc_resp_construct",
    "ieee80211_set_tx_desc",
    // Timer ID 0 is completed entirely by Rust; no vendor timer callback is a
    // strict root. All other stock net80211 timers fail closed.
];

const REPLACED_VENDOR_ROOTS: &[&str] = &[
    "lmacProcessTxTimeout",
    "lmacDiscardFrameExchangeSequence",
    "lmacDiscardMSDU",
    "ppProcTxDone",
    "lmacTxDone",
    "hal_mac_get_txq_state",
    "ieee80211_hostapd_beacon_txcb",
    "ieee80211_tx_mgt_cb",
    "wDev_record_ftm_data",
    "pm_on_beacon_rx",
    "pm_on_data_tx",
    "dbg_read_tx_ppdu",
    "dbg_dump_rx_ppdu",
    "dbg_dump_rx_sigb",
    "wifi_gpio_debug",
    "esp_test_tx_enab_statistics",
    "wDev_ftm_set_t1t4",
    "wDev_isNANPktInValidSlot",
    "wpa_sm_rx_eapol",
    "wpa_ap_rx_eapol",
    "hal_crypto_set_key_entry",
    "wifi_log",
    "pp_post",
    "ieee80211_timer_process",
    "ieee80211_timer_do_process",
    "chm_start_op",
    "chm_return_home_channel",
    "esf_buf_alloc",
    "esf_buf_recycle",
    "ieee80211_mgmt_output",
    "ieee80211_set_tx_pti",
    "ieee80211_search_node",
    "cnx_node_search",
];

// Calls to these archive symbols are redirected by mandatory final-link GNU
// wrappers. Their original bodies are therefore graph boundaries, not strict
// runtime callees.
const WRAPPED_VENDOR_BOUNDARIES: &[&str] = &[
    "lmacTxDone",
    "hal_mac_get_txq_state",
    "ieee80211_hostapd_beacon_txcb",
    "ieee80211_tx_mgt_cb",
    "wDev_record_ftm_data",
    "pm_on_beacon_rx",
    "pm_on_data_tx",
    "dbg_read_tx_ppdu",
    "dbg_dump_rx_ppdu",
    "dbg_dump_rx_sigb",
    "wifi_gpio_debug",
    "esp_test_tx_enab_statistics",
    "wDev_ftm_set_t1t4",
    "wDev_isNANPktInValidSlot",
    "wpa_sm_rx_eapol",
    "wpa_ap_rx_eapol",
    "hal_crypto_set_key_entry",
    "wifi_log",
    "pp_post",
    "ieee80211_timer_process",
    "chm_start_op",
    "chm_return_home_channel",
    "esf_buf_alloc",
    "esf_buf_recycle",
    "ieee80211_mgmt_output",
    "ieee80211_set_tx_pti",
    "ieee80211_search_node",
    "cnx_node_search",
];

// These pinned register-indirect sites are excluded only after their live
// guards have been reproduced at the strict call sites: mesh is rejected
// before association construction, ESF frame[0] is forced null before cache
// recycle.
const INVARIANT_EXCLUDED_INDIRECTS: &[&str] = &[
    "ieee80211_assoc_resp_construct",
    "ieee80211_recycle_cache_eb",
];

// `phy_get_romfunc_addr` overwrites these exact slots after obtaining the ROM
// table. The pinned S31 object writes offset 20 to `phy_set_rx_comp_new` and
// offset 36 to `phy_wifi_get_tx_tab_new`; both targets audit cleanly.
const PINNED_INDIRECT_TARGETS: &[(&str, &str)] = &[
    ("phy_chip_set_chan", "phy_set_rx_comp_new"),
    ("phy_wifi_set_tx_gain_new", "phy_wifi_get_tx_tab_new"),
];

// `phy_wifi_set_tx_gain_new` calls this leaf with count=32. Its outer loop is
// exactly that count and its inner loop copies four u16 words (offset 0..8 by
// two), so neither cycle observes hardware state or has an unbounded exit.
const PINNED_BOUNDED_CYCLE_SITES: &[(&str, u64)] = &[
    ("phy_set_tx_gain_mem_new", 0xaa),
    ("phy_set_tx_gain_mem_new", 0x12e),
];

const REQUIRED_RUNTIME_WRAPPERS: &[&str] = &[
    "__wrap_lmacTxDone",
    "__wrap_hal_mac_get_txq_state",
    "__wrap_ieee80211_hostapd_beacon_txcb",
    "__wrap_ieee80211_tx_mgt_cb",
    "__wrap_wDev_record_ftm_data",
    "__wrap_pm_on_beacon_rx",
    "__wrap_pm_on_data_tx",
    "__wrap_dbg_read_tx_ppdu",
    "__wrap_dbg_dump_rx_ppdu",
    "__wrap_dbg_dump_rx_sigb",
    "__wrap_wifi_gpio_debug",
    "__wrap_esp_test_tx_enab_statistics",
    "__wrap_wDev_ftm_set_t1t4",
    "__wrap_wDev_isNANPktInValidSlot",
    "__wrap_wpa_sm_rx_eapol",
    "__wrap_wpa_ap_rx_eapol",
    "__wrap_hal_crypto_set_key_entry",
    "__wrap_wifi_log",
    "__wrap_pp_post",
    "__wrap_ieee80211_timer_process",
    "__wrap_chm_start_op",
    "__wrap_chm_return_home_channel",
    "__esp_scan_op_end",
    "__esp_scan_op_end_end",
    "__wrap_esf_buf_alloc",
    "__wrap_esf_buf_recycle",
    "__wrap_ieee80211_mgmt_output",
    "__wrap_ieee80211_set_tx_pti",
    "__wrap_ieee80211_search_node",
    "__wrap_cnx_node_search",
    "__wrap_ets_delay_us",
    "__esp_hostap_sta_join",
    "__esp_hostap_sta_join_end",
    "__esp_wifi_async_wpa2_ap_join",
    "__esp_wifi_async_wpa2_ap_remove",
    "__esp_wifi_async_wpa2_ap_get_peer_spp_msg",
    "__esp_wifi_async_wpa2_ap_init",
    "__esp_wifi_async_wpa2_ap_deinit",
    "__esp_wifi_async_wpa2_ap_get_rsn",
    "__esp_wifi_async_wpa2_sta_txdone",
    "__esp_wpa_sta_connected_cb",
    "__esp_wpa_sta_connected_cb_end",
    "__esp_wpa_sta_disconnected_cb",
    "__esp_wpa_sta_disconnected_cb_end",
    "__esp_wifi_async_wpa2_sta_connected",
    "__esp_wifi_async_wpa2_sta_disconnected",
    "__esp_wifi_async_wpa2_sta_in_4way",
    "__esp_wifi_async_data_rx_sta",
    "__esp_wifi_async_data_rx_ap",
];

const DIRECT_HEAP_WRAPPERS: [(&str, &str); 4] = [
    ("malloc", "__wrap_malloc"),
    ("calloc", "__wrap_calloc"),
    ("realloc", "__wrap_realloc"),
    ("free", "__wrap_free"),
];

const DIRECT_FORBIDDEN_WRAPPERS: &[(&str, &str)] = &[("ets_delay_us", "__wrap_ets_delay_us")];

const FORBIDDEN: &[(&str, &str)] = &[
    ("malloc", "heap"),
    ("calloc", "heap"),
    ("realloc", "heap"),
    ("free", "heap"),
    ("vTaskDelay", "delay"),
    ("ets_delay_us", "delay"),
    ("sleep", "delay"),
    ("usleep", "delay"),
    ("os_sleep", "delay"),
    ("taskYIELD", "scheduler"),
    ("xQueueReceive", "RTOS wait"),
    ("xSemaphoreTake", "RTOS wait"),
    ("xEventGroupWaitBits", "RTOS wait"),
    ("esp_event_post", "event-loop wait/allocation"),
    ("nvs_commit", "flash wait"),
    ("nvs_set_blob", "flash wait/allocation"),
    ("nvs_erase_key", "flash wait"),
    ("puts", "unbounded logging"),
    ("putchar", "unbounded logging"),
    ("printf", "unbounded logging"),
    ("abort", "non-returning"),
    ("__assert_func", "non-returning"),
    ("esp_dport_access_stall_other_cpu_start", "other-core stall"),
    ("dport_access_stall_other_cpu_start", "other-core stall"),
];

#[derive(Default)]
struct FunctionInfo {
    direct: BTreeSet<String>,
    indirect_sites: BTreeSet<String>,
    control_flow_cycles: BTreeSet<String>,
    objects: BTreeSet<String>,
}

#[derive(Clone)]
struct Instruction {
    address: u64,
    mnemonic: String,
    target: Option<u64>,
    text: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Violation {
    Forbidden {
        root: String,
        category: &'static str,
        path: Vec<String>,
    },
    Indirect {
        root: String,
        function: String,
        site: String,
        path: Vec<String>,
    },
    ControlFlowCycle {
        root: String,
        function: String,
        site: String,
        path: Vec<String>,
    },
    MissingRoot(String),
    ElfSymbol {
        category: &'static str,
        symbol: String,
    },
}

fn main() -> Result<()> {
    let mut enforce = false;
    let mut verbose = false;
    let mut elf = None;
    let mut requested_roots = Vec::<String>::new();
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--enforce" => enforce = true,
            "--verbose" => verbose = true,
            "--elf" => {
                elf = Some(PathBuf::from(
                    arguments.next().context("--elf requires a path")?,
                ));
            }
            "--root" => requested_roots.push(arguments.next().context("--root requires a symbol")?),
            _ => bail!("unknown argument: {argument}"),
        }
    }
    let roots = if requested_roots.is_empty() {
        ROOTS.iter().map(|root| (*root).to_owned()).collect()
    } else {
        requested_roots
    };

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask must be inside the workspace")?
        .to_path_buf();
    let library_dir = workspace.join("esp-wifi-sys-esp32s31/libs");
    let temporary =
        env::temp_dir().join(format!("esp-wifi-s31-strict-audit-{}", std::process::id()));
    if temporary.exists() {
        fs::remove_dir_all(&temporary)?;
    }
    fs::create_dir(&temporary)?;

    let result = run(
        &library_dir,
        elf.as_deref(),
        &temporary,
        &roots,
        enforce,
        verbose,
    );
    fs::remove_dir_all(&temporary)?;
    result
}

fn run(
    library_dir: &Path,
    elf: Option<&Path>,
    temporary: &Path,
    roots: &[String],
    enforce: bool,
    verbose: bool,
) -> Result<()> {
    let graph = build_graph(library_dir, temporary)?;
    let mut violations = audit_graph(&graph, roots);
    if let Some(elf) = elf {
        violations.extend(audit_elf(elf)?);
    }

    print_report(&graph, &violations, roots, elf, verbose);
    if enforce && !violations.is_empty() {
        bail!(
            "strict ESP32-S31 audit rejected {} reachable or final-link paths",
            violations.len()
        );
    }
    Ok(())
}

fn build_graph(library_dir: &Path, temporary: &Path) -> Result<BTreeMap<String, FunctionInfo>> {
    let mut graph = BTreeMap::<String, FunctionInfo>::new();
    let mut archives = fs::read_dir(library_dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|extension| extension == "a"))
        .collect::<Vec<_>>();
    archives.sort();

    for archive in archives {
        let archive_name = archive
            .file_stem()
            .and_then(|name| name.to_str())
            .context("archive has no UTF-8 stem")?;
        let output_dir = temporary.join(archive_name);
        fs::create_dir(&output_dir)?;
        checked(
            Command::new("llvm-ar")
                .current_dir(&output_dir)
                .arg("x")
                .arg(
                    archive
                        .canonicalize()
                        .with_context(|| format!("canonicalizing {}", archive.display()))?,
                ),
        )?;

        let mut objects = fs::read_dir(&output_dir)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "o" || extension == "obj")
            })
            .collect::<Vec<_>>();
        objects.sort();
        for object in objects {
            let object_name = format!(
                "{}[{}]",
                archive
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(archive_name),
                object
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("?")
            );
            let disassembly = text(checked(
                Command::new("llvm-objdump")
                    .arg("-dr")
                    .arg("--no-show-raw-insn")
                    .arg(&object),
            )?)?;
            parse_object(&disassembly, &object_name, &mut graph);
        }
    }
    Ok(graph)
}

fn parse_object(disassembly: &str, object: &str, graph: &mut BTreeMap<String, FunctionInfo>) {
    let mut function = None::<String>;
    let mut instructions = Vec::<Instruction>::new();
    for line in disassembly.lines() {
        if line.starts_with("Disassembly of section ") {
            record_control_flow_cycles(function.as_deref(), &instructions, graph);
            function = None;
            instructions.clear();
            continue;
        }
        if let Some(name) = definition_name(line) {
            if !name.starts_with('.') {
                record_control_flow_cycles(function.as_deref(), &instructions, graph);
                instructions.clear();
                function = Some(normalize_symbol(name));
                if let Some(function) = &function {
                    graph
                        .entry(function.clone())
                        .or_default()
                        .objects
                        .insert(object.to_owned());
                }
            }
            continue;
        }

        let Some(caller) = function.as_ref() else {
            continue;
        };
        if let Some(instruction) = parse_instruction(line) {
            instructions.push(instruction);
        }
        if let Some(target) = direct_relocation_target(line) {
            graph
                .entry(caller.clone())
                .or_default()
                .direct
                .insert(target);
        }
        if let Some(site) = indirect_site(line) {
            graph
                .entry(caller.clone())
                .or_default()
                .indirect_sites
                .insert(site);
        }
    }
    record_control_flow_cycles(function.as_deref(), &instructions, graph);
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

fn direct_relocation_target(line: &str) -> Option<String> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let relocation = fields
        .iter()
        .position(|field| matches!(*field, "R_RISCV_CALL" | "R_RISCV_CALL_PLT" | "R_RISCV_JAL"))?;
    let target = *fields.get(relocation + 1)?;
    (!target.starts_with('.')).then(|| normalize_symbol(target))
}

fn indirect_site(line: &str) -> Option<String> {
    if line.contains('<') {
        return None;
    }
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let instruction = fields.get(1)?;
    matches!(*instruction, "jalr" | "jr").then(|| line.trim().to_owned())
}

fn instruction_site_address(site: &str) -> Option<u64> {
    u64::from_str_radix(site.split_whitespace().next()?.trim_end_matches(':'), 16).ok()
}

fn is_pinned_bounded_cycle(function: &str, site: &str) -> bool {
    instruction_site_address(site)
        .is_some_and(|address| PINNED_BOUNDED_CYCLE_SITES.contains(&(function, address)))
}

fn parse_instruction(line: &str) -> Option<Instruction> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let address = u64::from_str_radix(fields.first()?.trim_end_matches(':'), 16).ok()?;
    let mnemonic = *fields.get(1)?;
    if mnemonic.starts_with("R_") {
        return None;
    }
    let has_control_target = mnemonic == "j" || (mnemonic.starts_with('b') && mnemonic != "break");
    let target = has_control_target
        .then(|| {
            fields
                .iter()
                .skip(2)
                .find_map(|field| field.strip_prefix("0x"))
                .and_then(|target| u64::from_str_radix(target.trim_end_matches(','), 16).ok())
        })
        .flatten();
    Some(Instruction {
        address,
        mnemonic: mnemonic.to_owned(),
        target,
        text: line.trim().to_owned(),
    })
}

fn record_control_flow_cycles(
    function: Option<&str>,
    instructions: &[Instruction],
    graph: &mut BTreeMap<String, FunctionInfo>,
) {
    let Some(function) = function else {
        return;
    };
    let positions = instructions
        .iter()
        .enumerate()
        .map(|(index, instruction)| (instruction.address, index))
        .collect::<BTreeMap<_, _>>();
    let mut edges = vec![Vec::<usize>::new(); instructions.len()];

    for (index, instruction) in instructions.iter().enumerate() {
        let conditional =
            instruction.mnemonic.starts_with('b') && !instruction.mnemonic.starts_with("break");
        let unconditional = instruction.mnemonic == "j";
        if conditional || unconditional {
            if let Some(target) = instruction.target.and_then(|target| positions.get(&target)) {
                edges[index].push(*target);
            }
        }
        let terminates =
            unconditional || matches!(instruction.mnemonic.as_str(), "ret" | "jr" | "tail");
        if !terminates && index + 1 < instructions.len() {
            edges[index].push(index + 1);
        }
    }

    for (source, instruction) in instructions.iter().enumerate() {
        let Some(target_address) = instruction.target else {
            continue;
        };
        if target_address > instruction.address {
            continue;
        }
        let Some(&target) = positions.get(&target_address) else {
            continue;
        };
        if is_reachable(target, source, &edges) {
            graph
                .entry(function.to_owned())
                .or_default()
                .control_flow_cycles
                .insert(instruction.text.clone());
        }
    }
}

fn is_reachable(start: usize, target: usize, edges: &[Vec<usize>]) -> bool {
    let mut pending = vec![start];
    let mut visited = BTreeSet::new();
    while let Some(node) = pending.pop() {
        if node == target {
            return true;
        }
        if visited.insert(node) {
            pending.extend(edges[node].iter().copied());
        }
    }
    false
}

fn normalize_symbol(symbol: &str) -> String {
    symbol
        .split(['+', '@'])
        .next()
        .unwrap_or(symbol)
        .trim()
        .to_owned()
}

fn audit_graph(graph: &BTreeMap<String, FunctionInfo>, roots: &[String]) -> BTreeSet<Violation> {
    let forbidden = FORBIDDEN.iter().copied().collect::<BTreeMap<_, _>>();
    let mut violations = BTreeSet::new();
    for root in roots {
        let root = root.as_str();
        if !graph.contains_key(root) {
            violations.insert(Violation::MissingRoot(root.to_owned()));
            continue;
        }

        let mut queue = VecDeque::from([root.to_owned()]);
        let mut predecessor = BTreeMap::<String, String>::new();
        let mut visited = BTreeSet::new();
        while let Some(function) = queue.pop_front() {
            if !visited.insert(function.clone()) {
                continue;
            }
            let path = reconstruct_path(root, &function, &predecessor);
            if let Some(category) = forbidden.get(function.as_str()) {
                violations.insert(Violation::Forbidden {
                    root: root.to_owned(),
                    category,
                    path,
                });
                continue;
            }
            if function != root && WRAPPED_VENDOR_BOUNDARIES.contains(&function.as_str()) {
                continue;
            }
            let Some(info) = graph.get(&function) else {
                continue;
            };
            let pinned_indirect = PINNED_INDIRECT_TARGETS
                .iter()
                .find_map(|(caller, target)| (*caller == function).then_some(*target));
            if pinned_indirect.is_none()
                && !INVARIANT_EXCLUDED_INDIRECTS.contains(&function.as_str())
            {
                for site in &info.indirect_sites {
                    violations.insert(Violation::Indirect {
                        root: root.to_owned(),
                        function: function.clone(),
                        site: site.clone(),
                        path: path.clone(),
                    });
                }
            }
            for site in &info.control_flow_cycles {
                if !is_pinned_bounded_cycle(&function, site) {
                    violations.insert(Violation::ControlFlowCycle {
                        root: root.to_owned(),
                        function: function.clone(),
                        site: site.clone(),
                        path: path.clone(),
                    });
                }
            }
            if let Some(target) = pinned_indirect {
                if !predecessor.contains_key(target) && target != root {
                    predecessor.insert(target.to_owned(), function.clone());
                }
                queue.push_back(target.to_owned());
            }
            for target in &info.direct {
                if !predecessor.contains_key(target) && target != root {
                    predecessor.insert(target.clone(), function.clone());
                }
                queue.push_back(target.clone());
            }
        }
    }
    violations
}

fn reconstruct_path(
    root: &str,
    function: &str,
    predecessor: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut path = vec![function.to_owned()];
    while path.last().is_some_and(|current| current != root) {
        let Some(previous) = path.last().and_then(|current| predecessor.get(current)) else {
            break;
        };
        path.push(previous.clone());
    }
    path.reverse();
    path
}

fn audit_elf(elf: &Path) -> Result<BTreeSet<Violation>> {
    let symbols = text(checked(
        Command::new("llvm-nm").arg("-C").arg("-g").arg(elf),
    )?)?;
    let forbidden = FORBIDDEN.iter().copied().collect::<BTreeMap<_, _>>();
    let direct_heap_wrappers = DIRECT_HEAP_WRAPPERS
        .iter()
        .copied()
        .collect::<BTreeMap<_, _>>();
    let direct_forbidden_wrappers = DIRECT_FORBIDDEN_WRAPPERS
        .iter()
        .copied()
        .collect::<BTreeMap<_, _>>();
    let linked_symbol_kinds = symbols
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let symbol = normalize_symbol(fields.last()?);
            let kind = (*fields.get(fields.len().checked_sub(2)?)?).to_owned();
            Some((symbol, kind))
        })
        .collect::<BTreeMap<_, _>>();
    let mut violations = BTreeSet::new();
    for (_, wrapper) in DIRECT_HEAP_WRAPPERS {
        let violation = match linked_symbol_kinds.get(wrapper) {
            None => Some(Violation::ElfSymbol {
                category: "missing strict direct-heap wrapper",
                symbol: wrapper.to_owned(),
            }),
            Some(kind) if !is_code_symbol_kind(kind) => Some(Violation::ElfSymbol {
                category: "non-code strict direct-heap wrapper",
                symbol: wrapper.to_owned(),
            }),
            Some(_) => None,
        };
        violations.extend(violation);
    }
    for wrapper in REQUIRED_RUNTIME_WRAPPERS {
        let violation = match linked_symbol_kinds.get(*wrapper) {
            None => Some(Violation::ElfSymbol {
                category: "missing strict runtime wrapper",
                symbol: (*wrapper).to_owned(),
            }),
            Some(kind) if !is_code_symbol_kind(kind) => Some(Violation::ElfSymbol {
                category: "non-code strict runtime wrapper",
                symbol: (*wrapper).to_owned(),
            }),
            Some(_) => None,
        };
        violations.extend(violation);
    }
    for line in symbols.lines() {
        let Some(symbol) = line.split_whitespace().last() else {
            continue;
        };
        let symbol = normalize_symbol(symbol);
        if let Some(category) = forbidden.get(symbol.as_str()) {
            let wrapper = if *category == "heap" {
                direct_heap_wrappers.get(symbol.as_str())
            } else {
                direct_forbidden_wrappers.get(symbol.as_str())
            };
            if wrapper
                .and_then(|wrapper| linked_symbol_kinds.get(*wrapper))
                .is_some_and(|kind| is_code_symbol_kind(kind))
            {
                continue;
            }
            violations.insert(Violation::ElfSymbol { category, symbol });
        }
        // Do not reject a replaced entry merely because its symbol exists.
        // Strict wrappers deliberately retain `__real_*` delegation for init,
        // and ROM entries alias their public names to the wrapper while
        // pinning `__real_*` to absolute ROM addresses. Wrapper presence is
        // checked above; runtime reachability is checked from the pinned
        // archive graph. Symbol-table presence alone cannot distinguish an
        // inbound bypass from valid initialization delegation.
    }
    Ok(violations)
}

fn is_code_symbol_kind(kind: &str) -> bool {
    matches!(kind, "T" | "t" | "W" | "w")
}

fn print_report(
    graph: &BTreeMap<String, FunctionInfo>,
    violations: &BTreeSet<Violation>,
    roots: &[String],
    elf: Option<&Path>,
    verbose: bool,
) {
    println!("# ESP32-S31 strict no-wait/no-heap audit\n");
    println!("- roots: {} (`{}`)", roots.len(), roots.join("`, `"));
    println!(
        "- replaced vendor roots: `{}`",
        REPLACED_VENDOR_ROOTS.join("`, `")
    );
    println!("- discovered functions: {}", graph.len());
    println!("- violations: {}", violations.len());
    if let Some(elf) = elf {
        println!("- final ELF: `{}`", elf.display());
    }
    println!(
        "\nAn indirect `jalr`/`jr` and a control-flow cycle are rejected until their target or bound is explicitly proven.\n"
    );

    let mut categories = BTreeMap::<&str, usize>::new();
    let mut roots = BTreeMap::<&str, usize>::new();
    for violation in violations {
        match violation {
            Violation::Forbidden { root, category, .. } => {
                *categories.entry(category).or_default() += 1;
                *roots.entry(root).or_default() += 1;
            }
            Violation::Indirect { root, .. } => {
                *categories.entry("unproven indirect call").or_default() += 1;
                *roots.entry(root).or_default() += 1;
            }
            Violation::ControlFlowCycle { root, .. } => {
                *categories.entry("unproven control-flow cycle").or_default() += 1;
                *roots.entry(root).or_default() += 1;
            }
            Violation::MissingRoot(root) => {
                *categories.entry("missing root").or_default() += 1;
                *roots.entry(root).or_default() += 1;
            }
            Violation::ElfSymbol { category, .. } => {
                *categories.entry(category).or_default() += 1;
            }
        }
    }
    println!("## Summary by category\n");
    for (category, count) in categories {
        println!("- {category}: {count}");
    }
    println!("\n## Summary by root\n");
    for (root, count) in roots {
        println!("- `{root}`: {count}");
    }
    println!("\n## Paths\n");

    let limit = if verbose { usize::MAX } else { 64 };
    for violation in violations.iter().take(limit) {
        match violation {
            Violation::Forbidden {
                root,
                category,
                path,
            } => println!(
                "- FORBIDDEN `{category}` from `{root}`: `{}`",
                path.join(" -> ")
            ),
            Violation::Indirect {
                root,
                function,
                site,
                path,
            } => println!(
                "- INDIRECT from `{root}` at `{function}` (`{site}`): `{}`",
                path.join(" -> ")
            ),
            Violation::ControlFlowCycle {
                root,
                function,
                site,
                path,
            } => println!(
                "- CONTROL-FLOW-CYCLE from `{root}` at `{function}` (`{site}`): `{}`",
                path.join(" -> ")
            ),
            Violation::MissingRoot(root) => println!("- MISSING ROOT `{root}`"),
            Violation::ElfSymbol { category, symbol } => {
                println!("- FINAL ELF `{category}` symbol: `{symbol}`")
            }
        }
    }
    if violations.len() > limit {
        println!(
            "\n- ... {} additional violations omitted; rerun with `--verbose`.",
            violations.len() - limit
        );
    }
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
    use std::collections::BTreeMap;

    use super::{
        definition_name, direct_relocation_target, indirect_site, is_code_symbol_kind,
        is_pinned_bounded_cycle, parse_object,
    };

    #[test]
    fn parses_function_and_call_relocations() {
        assert_eq!(
            definition_name("00000000 <ppProcessTxQ>:"),
            Some("ppProcessTxQ")
        );
        assert_eq!(
            direct_relocation_target("  24: R_RISCV_CALL_PLT ets_delay_us+0"),
            Some("ets_delay_us".to_owned())
        );
        assert!(direct_relocation_target("  24: R_RISCV_BRANCH .L2+0").is_none());
    }

    #[test]
    fn only_unresolved_register_calls_are_indirect() {
        assert!(indirect_site("  18:       jalr a5").is_some());
        assert!(indirect_site("  18:       jalr ra <function+0x4>").is_none());
    }

    #[test]
    fn bounded_cycle_proofs_are_instruction_specific() {
        assert!(is_pinned_bounded_cycle(
            "phy_set_tx_gain_mem_new",
            "aa: bne a5, s8, 0x94 <.L10>"
        ));
        assert!(!is_pinned_bounded_cycle(
            "phy_set_tx_gain_mem_new",
            "ac: j 0xac <.Lassert>"
        ));
        assert!(!is_pinned_bounded_cycle(
            "different_function",
            "aa: bne a5, s8, 0x94 <.L10>"
        ));
    }

    #[test]
    fn absolute_rom_alias_is_not_accepted_as_a_wrapper() {
        assert!(is_code_symbol_kind("T"));
        assert!(is_code_symbol_kind("W"));
        assert!(!is_code_symbol_kind("A"));
    }

    #[test]
    fn distinguishes_cycles_from_backward_layout_edges() {
        let mut graph = BTreeMap::new();
        parse_object(
            "Disassembly of section .text.loop:\n\
             00000000 <looping>:\n\
                    0: li a0, 0x1\n\
                    2: beqz a0, 0x8 <.Lexit>\n\
                    4: addi a0, a0, -0x1\n\
                    6: j 0x2 <.Lloop>\n\
             00000008 <.Lexit>:\n\
                    8: ret\n\
             Disassembly of section .text.layout:\n\
             00000000 <layout>:\n\
                    0: j 0x6 <.Lmerge>\n\
                    2: ret\n\
             00000006 <.Lmerge>:\n\
                    6: beqz a0, 0x2 <.Lreturn>\n\
                    8: ret\n",
            "test.o",
            &mut graph,
        );
        assert_eq!(graph["looping"].control_flow_cycles.len(), 1);
        assert!(graph["layout"].control_flow_cycles.is_empty());
    }

    #[test]
    fn data_immediates_are_not_control_flow_targets() {
        let mut graph = BTreeMap::new();
        parse_object(
            "Disassembly of section .text.no_loop:\n\
             00000000 <no_loop>:\n\
                    0: li a0, 0x0\n\
                    2: lui a1, 0x0\n\
                    4: ret\n",
            "test.o",
            &mut graph,
        );
        assert!(graph["no_loop"].control_flow_cycles.is_empty());
    }
}
