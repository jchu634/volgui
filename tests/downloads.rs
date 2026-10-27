use serde_json::{Value, json};
use std::{fs, sync::atomic::AtomicBool};
use volgui::{
    analyses::{self, AnalysisDraft},
    analysis::{self, downloads},
    artifacts::{ArtifactGroup, OperatingSystem},
    case::{Case, Evidence, Run, RunStatus, now},
    results::{Query, ResultStore},
    settings::Settings,
    volatility::{Installation, Outcome, Plugin, Table},
};

fn fixture() -> (tempfile::TempDir, Case) {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Downloads").unwrap();
    for name in ["capture.raw", "other.raw"] {
        let path = temp.path().join(name);
        fs::write(&path, b"Synthetic memory").unwrap();
        let mut e = Evidence::inspect(&path, &AtomicBool::new(false), |_, _| {}).unwrap();
        e.operating_system = OperatingSystem::Windows;
        case.add_evidence(e).unwrap();
    }
    (temp, case)
}
fn save(case: &mut Case, evidence: usize, plugin: &str, rows: Value) -> Run {
    let run = Run {
        id: uuid::Uuid::new_v4().to_string(),
        evidence_id: case.document.evidence[evidence].id.clone(),
        plugin: plugin.into(),
        arguments: vec![],
        command: vec!["fixture".into()],
        engine_version: "Fixture".into(),
        created_at: now(),
        started_at: None,
        finished_at: None,
        status: RunStatus::Queued,
        exit_code: None,
        row_count: 0,
        message: String::new(),
    };
    case.queue(run.clone()).unwrap();
    case.finish(
        &run.id,
        &Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            message: String::new(),
            table: Some(Table::parse(&rows.to_string()).unwrap()),
        },
    )
    .unwrap();
    run
}
fn complete_sources(case: &mut Case) {
    let missing = analysis::missing_source_inventories(
        &case.document.runs,
        &case.document.evidence[0].id,
        downloads::SOURCES,
        false,
    );
    for plugin in missing {
        save(case, 0, plugin, json!([]));
    }
}
fn ads() -> Value {
    json!([{"Filename":"payload.exe","ADS Filename":"Zone.Identifier","Content":"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.test/tools\r\nHostUrl=https://cdn.example.test/setup.exe.bin\r\n"}])
}
fn execute(case: &mut Case, run: &Run) -> Table {
    let outcome = analysis::execute(
        &case.directory,
        &case.document,
        run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(outcome.status.has_results(), "{}", outcome.message);
    assert!(!outcome.message.contains("Missing source inventories"));
    case.finish(&run.id, &outcome).unwrap();
    outcome.table.unwrap()
}

#[test]
fn download_execution_and_endpoint_chain_retains_each_source_and_survives_reopening() {
    let (_temp, mut case) = fixture();
    let origin = save(&mut case, 0, "windows.mftscan.ADS", ads());
    let process = save(
        &mut case,
        0,
        "windows.pslist.PsList",
        json!([{"PID":100,"ImageFileName":"payload.exe","CreateTime":"2023-09-14T02:00:00Z"}]),
    );
    save(
        &mut case,
        0,
        "windows.cmdline.CmdLine",
        json!([{"PID":100,"Args":"\"C:\\Users\\Alice\\Downloads\\payload.exe\""}]),
    );
    save(
        &mut case,
        0,
        "windows.malware.psxview.PsXView",
        json!([{"PID":100,"Name":"payload.exe","pslist":true}]),
    );
    let net = save(
        &mut case,
        0,
        "windows.netscan.NetScan",
        json!([
            {"PID":100,"ForeignAddr":"192.0.2.10","ForeignPort":4444,"State":"ESTABLISHED"},
            {"PID":null,"ForeignAddr":"192.0.2.99","ForeignPort":9999},
            {"PID":100,"ForeignAddr":"192.0.2.11","ForeignPort":80,"Created":"2022-01-01T00:00:00Z"}
        ]),
    );
    complete_sources(&mut case);
    let run = analysis::prepare(&case.document.evidence[0], analysis::DOWNLOADS, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let table = execute(&mut case, &run);
    let filtered = ResultStore::at(&case.directory)
        .query(&Query {
            runs: vec![run.id.clone()],
            filters: [(
                "Finding".into(),
                ["Download + process candidate + socket".into()].into(),
            )]
            .into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(filtered.ids.len(), 1);
    for column in ["Finding", "Filename", "Remote IP", "Remote port"] {
        assert!(
            !ResultStore::at(&case.directory)
                .filter_values(std::slice::from_ref(&run.id), column)
                .unwrap()
                .is_empty()
        );
    }
    let rows = table
        .rows
        .iter()
        .filter(|r| r.text("PID") == "100")
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    let r = rows[0];
    assert_eq!(r.text("Filename"), "payload.exe");
    assert_eq!(r.text("URL"), "https://cdn.example.test/setup.exe.bin");
    assert_eq!(r.text("Website URL"), "https://example.test/tools");
    assert_eq!(r.text("Remote IP"), "192.0.2.10");
    assert_eq!(r.text("Remote port"), "4444");
    assert!(r.text("Match basis").starts_with("Filename only"));
    assert!(!r.text("Finding").contains("Reverse shell"));
    assert!(r.text("Network evidence").contains("PID-only socket match"));
    let proof = r.text("Sources");
    for id in [&origin.id, &process.id, &net.id] {
        assert!(proof.contains(id));
    }
    let path = case.directory.clone();
    drop(case);
    let case = Case::open(&path).unwrap();
    let result = case.results(&run.id).unwrap();
    assert_eq!(result.rows.len(), table.rows.len());
    assert!(
        result
            .csv(&(0..result.rows.len()).collect::<Vec<_>>())
            .contains("192.0.2.10")
    );
}

#[test]
fn future_other_evidence_and_argument_text_do_not_create_execution_links() {
    let (_temp, mut case) = fixture();
    save(&mut case, 0, "windows.mftscan.ADS", ads());
    save(
        &mut case,
        1,
        "windows.pslist.PsList",
        json!([{"PID":100,"ImageFileName":"payload.exe"}]),
    );
    save(
        &mut case,
        0,
        "windows.pslist.PsList",
        json!([{"PID":200,"ImageFileName":"notepad.exe"}]),
    );
    save(
        &mut case,
        0,
        "windows.cmdline.CmdLine",
        json!([{"PID":200,"Args":"notepad.exe C:\\Downloads\\payload.exe"}]),
    );
    complete_sources(&mut case);
    let run = analysis::prepare(&case.document.evidence[0], analysis::DOWNLOADS, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    save(
        &mut case,
        0,
        "windows.psscan.PsScan",
        json!([{"PID":300,"ImageFileName":"payload.exe"}]),
    );
    let rows = execute(&mut case, &run).rows;
    let origin = rows
        .iter()
        .find(|r| r.text("Filename") == "payload.exe")
        .unwrap();
    assert!(origin.text("PID").is_empty());
    assert!(origin.text("Finding").contains("execution not recovered"));
}

#[test]
fn reused_pids_need_socket_timestamps_and_different_paths_stay_candidates() {
    let (_temp, mut case) = fixture();
    save(&mut case, 0, "windows.mftscan.ADS", ads());
    save(
        &mut case,
        0,
        "windows.pslist.PsList",
        json!([{"PID":100,"ImageFileName":"payload.exe","CreateTime":"2023-01-02T00:00:00Z"}]),
    );
    save(
        &mut case,
        0,
        "windows.psscan.PsScan",
        json!([{"PID":100,"ImageFileName":"payload.exe","CreateTime":"2023-01-01T00:00:00Z","ExitTime":"2023-01-01T01:00:00Z"}]),
    );
    save(
        &mut case,
        0,
        "windows.netscan.NetScan",
        json!([{"PID":100,"ForeignAddr":"192.0.2.10","ForeignPort":4444}]),
    );
    complete_sources(&mut case);
    let run = analysis::prepare(&case.document.evidence[0], analysis::DOWNLOADS, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let table = execute(&mut case, &run);
    assert_eq!(
        table.rows.iter().filter(|r| r.text("PID") == "100").count(),
        2
    );
    assert!(table.rows.iter().all(|r| r.text("Remote IP").is_empty()));
}

#[test]
fn browser_url_leads_stay_distinct_from_recorded_downloads() {
    let (_temp, mut case) = fixture();
    save(
        &mut case,
        0,
        analysis::BROWSER,
        json!([
            {"Kind":"URL","PID":200,"URL":"https://cookiepedia.co.uk/host/.app.onetrust.com"},
            {"Kind":"URL","PID":200,"URL":"https://vimeo.com;https://jiosaavn.com"},
            {"Kind":"URL","PID":200,"URL":"https://vimeo.com;https://example.test/fake.exe"},
            {"Kind":"URL","PID":200,"URL":"https://example.test/unmatched.exe"},
            {"Kind":"URL","PID":200,"URL":"https://example.test/payload.exe"},
            {"Kind":"Download","PID":200,"Filename":"utility.com","Path":"C:\\Downloads\\utility.com","URL":"https://example.test/utility.com"}
        ]),
    );
    save(
        &mut case,
        0,
        "windows.mftscan.ADS",
        json!([
            {"Filename":"renamed.com","ADS Filename":"Zone.Identifier","Content":"[ZoneTransfer]\nHostUrl=https://example.test/renamed.com"}
        ]),
    );
    save(
        &mut case,
        0,
        "windows.pslist.PsList",
        json!([
            {"PID":100,"ImageFileName":"payload.exe"}
        ]),
    );
    complete_sources(&mut case);
    let run = analysis::prepare(&case.document.evidence[0], analysis::DOWNLOADS, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let table = execute(&mut case, &run);
    let findings = table
        .rows
        .iter()
        .filter(|r| r.text("Finding") != "Analysis coverage")
        .collect::<Vec<_>>();
    assert_eq!(findings.len(), 4);
    let unmatched = findings
        .iter()
        .find(|r| r.text("Filename") == "unmatched.exe")
        .unwrap();
    assert_eq!(
        unmatched.text("Finding"),
        "Executable URL lead; download and execution not established"
    );
    assert!(unmatched.text("PID").is_empty());
    let matched = findings
        .iter()
        .find(|r| r.text("Filename") == "payload.exe")
        .unwrap();
    assert_eq!(matched.text("PID"), "100");
    assert!(
        matched
            .text("Finding")
            .starts_with("Executable URL lead + process candidate")
    );
    assert!(
        matched
            .text("Download evidence")
            .contains("download not established")
    );
    for name in ["utility.com", "renamed.com"] {
        let download = findings
            .iter()
            .find(|r| r.text("Filename") == name)
            .unwrap();
        assert_eq!(
            download.text("Finding"),
            "Download origin; execution not recovered"
        );
        assert!(download.text("PID").is_empty());
    }
}

#[test]
fn partial_process_preserves_origin_and_never_claims_matching_socket_ownership() {
    let (_temp, mut case) = fixture();
    let capture = case.document.evidence[0].path.clone();
    let mut bytes = vec![0u8; 0x9000];
    let birth = 133390291766718843u64;
    let mut inventory = Vec::new();
    for i in 0..6 {
        let base = i * 4096;
        let pid = if i == 5 { 12228 } else { 100 + i as u64 * 4 };
        let name = if i == 5 {
            "wbadmin.exe".into()
        } else {
            format!("anchor{i}.exe")
        };
        bytes[base] = if i == 5 { 0x48 } else { 3 };
        for (at, value) in [
            (8, 0xffff800000001008u64),
            (16, 0xffff800000001008),
            (0x28, if i == 5 { 0xe4800000800 } else { 0x123000 }),
            (0x440, pid),
            (0x540, 4),
            (0x468, birth),
            (0x448, 0xffff800000001008),
            (0x450, 0xffff800000001008),
        ] {
            bytes[base + at..base + at + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[base + 0x5a8..base + 0x5a8 + name.len()].copy_from_slice(name.as_bytes());
        if i < 5 {
            inventory.push(
                json!({"PID":pid,"ImageFileName":name,"CreateTime":"2023-09-12T21:52:56.671884Z"}),
            );
        }
    }
    fs::write(&capture, bytes).unwrap();
    let id = case.document.evidence[0].id.clone();
    let mut evidence = Evidence::inspect(&capture, &AtomicBool::new(false), |_, _| {}).unwrap();
    evidence.id = id;
    evidence.operating_system = OperatingSystem::Windows;
    case.document.evidence[0] = evidence;
    case.save().unwrap();
    save(&mut case, 0, "windows.pslist.PsList", inventory.into());
    save(
        &mut case,
        0,
        "windows.mftscan.ADS",
        json!([
            {"Filename":"wbadmin.exe","ADS Filename":"Zone.Identifier","Content":"[ZoneTransfer]\nHostUrl=http://example.test/wbadmin.exe.bin"}
        ]),
    );
    save(
        &mut case,
        0,
        "windows.netscan.NetScan",
        json!([
            {"PID":12228,"ForeignAddr":"192.0.2.9","ForeignPort":4444,"Created":"2023-09-12T21:53:00Z"}
        ]),
    );
    complete_sources(&mut case);
    let run = analysis::prepare(&case.document.evidence[0], analysis::DOWNLOADS, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let table = execute(&mut case, &run);
    let partial = table.rows.iter().find(|r| r.is_partial_match()).unwrap();
    assert_eq!(partial.text("PID"), "12228");
    assert_eq!(partial.text("Acquisition offset"), (5 * 4096).to_string());
    assert!(partial.text("Remote IP").is_empty());
    assert!(
        partial
            .text("Network evidence")
            .contains("sockets were not joined")
    );
    assert!(partial.text("Validation failures").contains("0x48"));
    let store = ResultStore::at(&case.directory);
    let mut query = Query {
        runs: vec![run.id.clone()],
        ..Default::default()
    };
    let strict = store.fetch(&store.query(&query).unwrap().ids).unwrap();
    assert!(strict.iter().all(|r| !r.record.is_partial_match()));
    assert!(
        strict
            .iter()
            .any(|r| r.record.text("Filename") == "wbadmin.exe" && r.record.text("PID").is_empty())
    );
    query.include_partial = true;
    assert_eq!(store.query(&query).unwrap().ids.len(), strict.len() + 1);
    let entries = store
        .partial_process_entries(&query.runs, "wbadmin")
        .unwrap();
    assert_eq!(entries.len(), 1);
    let mut tree = volgui::result_tree::ResultTree::default();
    tree.append_partial_processes(entries);
    assert_eq!(tree.visible[0].1, 0);
    assert!(tree.nodes[0].children.is_empty());
    assert!(tree.nodes[0].label.contains("Partial match"));
    assert!(
        store
            .partial_process_entries(&query.runs, "unrelated")
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .export_csv(&query)
            .unwrap()
            .contains("Validation failures")
    );
}

#[test]
fn chooser_collects_prerequisites_reuses_successes_and_expands_a_single_report_barrier() {
    let (_temp, mut case) = fixture();
    save(&mut case, 0, "windows.pslist.PsList", json!([]));
    let engine = Installation {
        user_memory_dumps: false,
        settings: Settings::default(),
        version: "Fixture".into(),
        plugins: downloads::SOURCES
            .iter()
            .chain(["windows.dumpfiles.DumpFiles"].iter())
            .map(|id| Plugin {
                id: (*id).into(),
                description: String::new(),
            })
            .collect(),
    };
    let e = case.document.evidence[0].clone();
    let mut draft = AnalysisDraft::new(&e);
    draft.selected.insert(analysis::DOWNLOADS.into());
    let runs = draft.prepare_in_case(&engine, &e, &case).unwrap();
    assert!(!runs.iter().any(|r| r.plugin == "windows.pslist.PsList"));
    let report = runs.last().unwrap().clone();
    assert_eq!(report.message, downloads::PENDING);
    case.queue_batch(runs).unwrap();
    assert!(
        analyses::prepare_download_recovery(&case, &engine, &report)
            .unwrap_err()
            .contains("Missing source inventories")
    );
    for r in &mut case.document.runs {
        if r.id != report.id {
            r.status = RunStatus::Completed;
        }
    }
    let expanded = analyses::prepare_download_recovery(&case, &engine, &report).unwrap();
    assert_eq!(expanded.len(), 1);
    assert_eq!(expanded[0].id, report.id);
    assert!(expanded[0].message.is_empty());
    let report_index = case.document.runs.len() - 1;
    case.document.runs[0].status = RunStatus::Running;
    case.document.runs[report_index - 1].status = RunStatus::Completed;
    // A native report cannot run concurrently with an ordinary inventory.
    for r in &mut case.document.runs[1..report_index] {
        r.status = RunStatus::Completed;
    }
    assert!(
        analyses::next_queued_run(&case.document.runs, std::num::NonZeroUsize::new(5).unwrap())
            .is_none()
    );
    assert_eq!(
        ArtifactGroup::for_plugin(analysis::DOWNLOADS),
        ArtifactGroup::Downloads
    );
    assert!(analyses::basic_label("windows.mftscan.ADS").is_some());
    assert_eq!(
        ArtifactGroup::for_plugin("windows.mftscan.ADS"),
        ArtifactGroup::Other
    );
    draft
        .arguments
        .insert(analysis::DOWNLOADS.into(), "--pid 123".into());
    assert!(draft.prepare_in_case(&engine, &e, &case).is_err());
    let store = ResultStore::at(&case.directory);
    assert!(store.query(&Query::default()).is_ok());
}

#[test]
fn cancellation_and_unsupported_custom_options_are_reported() {
    let (_temp, case) = fixture();
    let e = &case.document.evidence[0];
    assert!(analysis::prepare(e, analysis::DOWNLOADS, vec!["--anything".into()]).is_err());
    let run = analysis::prepare(e, analysis::DOWNLOADS, vec![]).unwrap();
    let result = analysis::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(true),
        |_| {},
    );
    assert_eq!(result.status, RunStatus::Cancelled);
}
