use serde_json::{Value, json};
use std::{fs, sync::atomic::AtomicBool};
use volgui::{
    artifacts::OperatingSystem,
    case::{Case, Evidence, Run, RunStatus, now},
    extracted_files::{ContentEncoding, DUMP_FILES, HexPage},
    file_content::database_page,
    investigation::{self, BROWSER, STRINGS, registry, strings},
    results::{Query, ResultStore},
    settings::Settings,
    volatility::{Installation, Outcome, Plugin, Table},
};

fn setup() -> (tempfile::TempDir, Case, Installation) {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Investigation fixture").unwrap();
    for name in ["first.raw", "second.raw"] {
        let path = temp.path().join(name);
        fs::write(&path, b"Synthetic evidence with memory forensics text").unwrap();
        let mut evidence = Evidence::inspect(&path, &AtomicBool::new(false), |_, _| {}).unwrap();
        evidence.operating_system = OperatingSystem::Windows;
        case.add_evidence(evidence).unwrap();
    }
    let engine = Installation {
        settings: Settings::default(),
        version: "Fixture".into(),
        plugins: [
            DUMP_FILES,
            registry::PRINT_KEY,
            "windows.filescan.FileScan",
            "windows.handles.Handles",
        ]
        .into_iter()
        .map(|id| Plugin {
            id: id.into(),
            description: String::new(),
        })
        .collect(),
    };
    (temp, case, engine)
}

fn save(
    case: &mut Case,
    evidence: usize,
    plugin: &str,
    arguments: Vec<String>,
    rows: Value,
) -> Run {
    let run = Run {
        id: uuid::Uuid::new_v4().to_string(),
        evidence_id: case.document.evidence[evidence].id.clone(),
        plugin: plugin.into(),
        arguments,
        command: vec!["synthetic-fixture".into()],
        engine_version: "Fixture".into(),
        created_at: now(),
        started_at: Some(now()),
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
    case.document
        .runs
        .iter()
        .find(|r| r.id == run.id)
        .unwrap()
        .clone()
}

#[test]
fn strings_find_cross_chunk_matches_utf16_at_odd_offsets_and_final_bytes_once() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("memory.raw");
    let mut bytes = vec![0xff; 1024 * 1024 - 4];
    bytes.extend_from_slice(b"Needle");
    let le_offset = bytes.len() + 1;
    bytes.push(0xff);
    bytes.extend("Needle".encode_utf16().flat_map(u16::to_le_bytes));
    bytes.push(0xff);
    let be_offset = bytes.len();
    bytes.extend("Needle".encode_utf16().flat_map(u16::to_be_bytes));
    bytes.push(0xff);
    let final_offset = bytes.len();
    bytes.extend_from_slice(b"Needle");
    fs::write(&path, bytes).unwrap();
    let (table, _) =
        strings::search(&path, &["Needle".into()], &AtomicBool::new(false), &|_| {}).unwrap();
    let hits: Vec<_> = table
        .rows
        .iter()
        .map(|r| (r.fields["Offset"].as_u64().unwrap(), r.text("Encoding")))
        .collect();
    assert_eq!(
        hits,
        vec![
            (1024 * 1024 - 4, "UTF-8".into()),
            (le_offset as u64, "UTF-16LE".into()),
            (be_offset as u64, "UTF-16BE".into()),
            (final_offset as u64, "UTF-8".into())
        ]
    );
    assert!(
        table
            .rows
            .iter()
            .all(|r| r.text("Context").contains("Needle"))
    );
}

#[test]
fn strings_handle_case_cancellation_limits_and_non_ascii_units() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("memory.raw");
    fs::write(&path, b"AbCd abcD").unwrap();
    let (table, _) = strings::search(
        &path,
        &["abcd".into(), "--ignore-ascii-case".into()],
        &AtomicBool::new(false),
        &|_| {},
    )
    .unwrap();
    assert_eq!(table.rows.len(), 2);
    assert!(strings::search(&path, &["abcd".into()], &AtomicBool::new(true), &|_| {}).is_err());
    assert!(strings::validate(&["".into()]).is_err());
    let mut bytes = vec![0xff];
    bytes.extend("Ł".encode_utf16().flat_map(u16::to_le_bytes));
    fs::write(&path, bytes).unwrap();
    let (table, _) = strings::search(
        &path,
        &["š".into(), "--ignore-ascii-case".into()],
        &AtomicBool::new(false),
        &|_| {},
    )
    .unwrap();
    assert!(
        table.rows.is_empty(),
        "ASCII folding must not alter non-ASCII UTF-16 code units"
    );
    fs::write(&path, b"hit ".repeat(strings::MAX_HITS + 2)).unwrap();
    let (table, message) =
        strings::search(&path, &["hit".into()], &AtomicBool::new(false), &|_| {}).unwrap();
    assert_eq!(table.rows.len(), strings::MAX_HITS);
    assert!(message.contains("Stopped at"));
}

fn chrome_database(path: &std::path::Path) {
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER);
        CREATE TABLE keyword_search_terms(keyword_id INTEGER,url_id INTEGER,term TEXT);
        INSERT INTO urls VALUES(1,'https://www.google.com/search?q=memory+forensics%2Btools','Search',11644473601000000);
        INSERT INTO visits VALUES(7,1,11644473600000000);
        INSERT INTO visits VALUES(8,1,11644473601000000);
        INSERT INTO keyword_search_terms VALUES(2,1,'memory forensics+tools');").unwrap();
}

#[test]
fn browser_analysis_parses_history_searches_and_provenance_and_excludes_other_evidence() {
    let (_temp, mut case, _) = setup();
    let scan = save(
        &mut case,
        0,
        "windows.filescan.FileScan",
        vec![],
        json!([{"Offset":4096,"Name":"C:\\Users\\Alice\\Chrome\\User Data\\Default\\History"}]),
    );
    let dump = save(
        &mut case,
        0,
        DUMP_FILES,
        vec!["--virtaddr".into(), "0x1000".into()],
        json!([]),
    );
    let output = case.run_dir(&dump.id);
    fs::create_dir_all(&output).unwrap();
    let path = output.join("cache.dat");
    chrome_database(&path);
    let other = save(&mut case, 1, DUMP_FILES, vec![], json!([]));
    fs::create_dir_all(case.run_dir(&other.id)).unwrap();
    fs::write(
        case.run_dir(&other.id).join("session.json"),
        br#"{"windows":[{"tabs":[{"index":1,"entries":[{"url":"https://excluded.test"}]}]}]}"#,
    )
    .unwrap();
    let before = fs::read(&path).unwrap();
    let run = investigation::prepare(&case.document.evidence[0], BROWSER, vec![]).unwrap();
    case.queue(run.clone()).unwrap();
    let outcome = investigation::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(outcome.status, RunStatus::Completed, "{}", outcome.message);
    let rows = &outcome.table.as_ref().unwrap().rows;
    assert_eq!(
        rows.iter()
            .filter(|r| r.text("Kind") == "Web history")
            .count(),
        2
    );
    assert_eq!(
        rows.iter()
            .filter(|r| r.text("Kind") == "Web search")
            .count(),
        3
    );
    assert!(
        rows.iter()
            .all(|r| r.text("Source run") == dump.id && r.text("Browser") == "Chrome")
    );
    assert!(
        rows.iter()
            .all(|r| r.text("Original path").ends_with("History"))
    );
    assert_eq!(rows[0].text("Time (UTC)"), "1970-01-01T00:00:00+00:00");
    assert!(rows.iter().all(|r| !r.text("URL").contains("excluded")));
    assert_eq!(before, fs::read(&path).unwrap());
    assert!(!path.with_extension("dat-wal").exists());
    case.finish(&run.id, &outcome).unwrap();
    let id = run.id.clone();
    let directory = case.directory.clone();
    drop(case);
    let reopened = Case::open(&directory).unwrap();
    assert_eq!(reopened.results(&id).unwrap().rows.len(), 5);
    assert_eq!(
        Table::read(&reopened.run_dir(&id).join("stdout.json"))
            .unwrap()
            .rows
            .len(),
        5
    );
    assert!(reopened.document.runs.iter().any(|r| r.id == scan.id));
}

#[test]
fn recovery_queues_targeted_unique_files_then_native_analysis_and_reuses_completed_dumps() {
    let (_temp, mut case, engine) = setup();
    save(
        &mut case,
        0,
        "windows.filescan.FileScan",
        vec![],
        json!([
            {"Offset":4096,"Name":"C:\\Chrome\\Default\\History"},
            {"Offset":8192,"Name":"C:\\Firefox\\places.sqlite"},
            {"Offset":12288,"Name":"C:\\Docs\\report.txt"}
        ]),
    );
    save(
        &mut case,
        0,
        "windows.handles.Handles",
        vec![],
        json!([{ "Offset":8192,"Type":"File","PID":42,"Name":"C:\\Firefox\\places.sqlite" }]),
    );
    save(
        &mut case,
        0,
        DUMP_FILES,
        vec!["--virtaddr".into(), "0x1000".into()],
        json!([]),
    );
    save(
        &mut case,
        1,
        "windows.filescan.FileScan",
        vec![],
        json!([{ "Offset":65536,"Name":"C:\\Other\\History" }]),
    );
    let runs = investigation::browser_recovery_runs(
        &case.directory,
        &case.document,
        &case.document.evidence[0],
        &engine,
        false,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].plugin, DUMP_FILES);
    assert_eq!(runs[0].arguments, ["--virtaddr", "0x2000"]);
    assert_eq!(runs[1].plugin, BROWSER);
    assert!(
        runs.iter()
            .all(|r| r.evidence_id == case.document.evidence[0].id)
    );
}

#[test]
fn handles_include_non_file_types_filter_pid_and_page_without_polluting_file_tree() {
    let (_temp, mut case, _) = setup();
    let rows: Vec<_> = (0..205).map(|i| json!({"PID":42,"Type":if i == 0 {"File"} else {"Mutant"},"HandleValue":i,"Name":format!("object-{i}")})).chain(std::iter::once(json!({"PID":43,"Type":"Key","Name":"other PID"}))).collect();
    let run = save(&mut case, 0, "windows.handles.Handles", vec![], json!(rows));
    let store = ResultStore::at(&case.directory);
    let page = store
        .process_handles(vec![run.id.clone()], "42", 100)
        .unwrap();
    assert_eq!(page.total, 205);
    assert_eq!(page.offset, 100);
    assert_eq!(page.records.len(), 100);
    assert!(
        page.records
            .iter()
            .all(|r| r.record.text("Type") == "Mutant")
    );
    let files = store
        .query(&Query {
            runs: vec![run.id],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(files.ids.len(), 1);
}

#[test]
fn registry_navigation_uses_source_evidence_offset_and_relative_key() {
    let (_temp, mut case, engine) = setup();
    let source = save(
        &mut case,
        1,
        "windows.registry.hivelist.HiveList",
        vec![],
        json!([{ "Offset":4096,"FileFullPath":"\\REGISTRY\\USER\\S-1-5-21" }]),
    );
    let record = case.results(&source.id).unwrap().rows.remove(0);
    let requested =
        registry::prepare(&case, &engine, &source, &record, "Software\\Test", true).unwrap();
    assert_eq!(requested.evidence_id, case.document.evidence[1].id);
    assert_eq!(
        requested.arguments,
        ["--offset", "0x1000", "--key", "Software\\Test", "--recurse"]
    );
    let mut source = requested;
    source.arguments.pop();
    let key = Table::parse(r#"[{"Hive Offset":4096,"Type":"Key","Key":"\\REGISTRY\\USER\\S-1-5-21\\Software\\Test","Name":"Child"}]"#).unwrap().rows.remove(0);
    assert_eq!(
        registry::child_key(&source, &key),
        Some("Software\\Test\\Child".into())
    );
}

#[test]
fn sqlite_preview_quotes_names_pages_rows_and_never_changes_database() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("database.sqlite");
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE \"a\"\"b\"(name TEXT, data BLOB); WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<105) INSERT INTO \"a\"\"b\" SELECT 'value '||x, X'001122' FROM n;").unwrap();
    }
    let before = fs::read(&path).unwrap();
    let first = database_page(&path, None, 0).unwrap();
    assert_eq!(first.table, "a\"b");
    assert_eq!(first.rows.len(), 100);
    assert!(first.more);
    assert!(first.rows[0][1].starts_with("BLOB 001122"));
    let last = database_page(&path, Some("a\"b"), 100).unwrap();
    assert_eq!(last.rows.len(), 5);
    assert!(!last.more);
    assert_eq!(before, fs::read(&path).unwrap());
}

#[test]
fn native_search_runs_without_engine_and_remains_exportable() {
    let (_temp, mut case, _) = setup();
    let run = investigation::prepare(
        &case.document.evidence[0],
        STRINGS,
        vec!["memory forensics".into()],
    )
    .unwrap();
    case.queue(run.clone()).unwrap();
    let outcome = investigation::execute(
        &case.directory,
        &case.document,
        &run,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(outcome.status, RunStatus::Completed);
    case.finish(&run.id, &outcome).unwrap();
    let csv = ResultStore::at(&case.directory)
        .export_csv(&Query {
            runs: vec![run.id],
            ..Default::default()
        })
        .unwrap();
    assert!(csv.contains("UTF-8"));
    assert!(csv.contains("memory forensics"));
    let page = HexPage::read(&case.document.evidence[0].path, 0).unwrap();
    assert!(
        page.decoded(ContentEncoding::Utf8)
            .contains("memory forensics")
    );
}
