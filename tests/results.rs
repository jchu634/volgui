use serde_json::json;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    sync::atomic::AtomicBool,
    time::Instant,
};
use volgui_again::{
    artifacts::{ArtifactGroup, OperatingSystem},
    case::{Case, Evidence, Run, RunStatus, now},
    results::{BrowserEntry, DATABASE, Query, ResultStore, process_forest},
    volatility::{Record, Table},
};

fn run(id: &str, plugin: &str) -> Run {
    Run {
        id: id.into(),
        evidence_id: String::new(),
        plugin: plugin.into(),
        arguments: vec![],
        command: vec!["test-engine".into()],
        engine_version: "test".into(),
        created_at: now(),
        started_at: None,
        finished_at: None,
        status: RunStatus::Queued,
        exit_code: None,
        row_count: 0,
        message: String::new(),
    }
}

#[test]
fn sqlite_preserves_rows_and_supports_literal_search_numeric_sort_and_grouped_sources() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let first = run("one", "windows.pslist.PsList");
    let second = run("two", "windows.psscan.PsScan");
    let table=Table::parse(&json!([{"PID":100,"ImageFileName":"parent.exe","__children":[{"PID":9,"ImageFileName":"child.exe","Value":"=x,\"quoted\"","__children":[]}]},{"PID":20,"ImageFileName":"other.exe","__children":[]}]).to_string()).unwrap();
    store.insert(&first, &table).unwrap();
    store
        .insert(
            &second,
            &Table::parse(r#"[{"PID":5,"ImageFileName":"scan.exe"}]"#).unwrap(),
        )
        .unwrap();
    let query = Query {
        runs: vec!["one".into(), "two".into()],
        text: ".EXE".into(),
        sort: Some(("PID".into(), false)),
    };
    let index = store.query(&query).unwrap();
    let rows = store.fetch(&index.ids).unwrap();
    let by_id: std::collections::HashMap<_, _> = rows.iter().map(|r| (r.id, r)).collect();
    assert_eq!(
        index
            .ids
            .iter()
            .map(|id| by_id[id].record.text("PID"))
            .collect::<Vec<_>>(),
        vec!["5", "9", "20", "100"]
    );
    let child = store.record("one", 1).unwrap().unwrap();
    assert_eq!(child.record.depth, 1);
    let original_id = child.id;
    store.insert(&first, &Table::default()).unwrap();
    assert_eq!(store.count("one").unwrap(), 3);
    assert_eq!(store.record("one", 1).unwrap().unwrap().id, original_id);
    for text in ["o", ".e", "child", "=x,\"quoted\"", "\" OR 1=1 --"] {
        let result = store
            .query(&Query {
                runs: vec!["one".into()],
                text: text.into(),
                sort: None,
            })
            .unwrap();
        assert_eq!(
            result.ids.len(),
            table.matching(text, None).len(),
            "literal query {text}"
        );
    }
    assert!(
        store
            .query(&Query {
                runs: vec!["one".into()],
                sort: Some(("not a column; DROP TABLE records".into(), false)),
                text: String::new()
            })
            .is_err()
    );
    let csv = store
        .export_csv(&Query {
            runs: vec!["one".into()],
            text: "child".into(),
            sort: None,
        })
        .unwrap();
    assert!(csv.contains("'=x,"));
    assert!(!csv.contains("parent.exe"));
    assert!(temp.path().join(DATABASE).exists());
}

#[test]
fn failed_import_rolls_back_records_and_search_index() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let db = rusqlite::Connection::open(temp.path().join(DATABASE)).unwrap();
    db.execute_batch("CREATE TRIGGER reject_row BEFORE INSERT ON records WHEN NEW.row_index=1 BEGIN SELECT RAISE(ABORT,'fixture failure'); END;").unwrap();
    let run = run("rollback", "windows.pslist.PsList");
    let table = Table::parse(r#"[{"PID":1},{"PID":2}]"#).unwrap();
    assert!(store.insert(&run, &table).is_err());
    assert!(!store.contains(&run.id).unwrap());
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM records", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM record_search", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    db.execute_batch("DROP TRIGGER reject_row").unwrap();
    store.insert(&run, &table).unwrap();
    assert_eq!(store.count(&run.id).unwrap(), 2);
    let mut cancelled = run.clone();
    cancelled.id = "cancelled-import".into();
    assert!(
        store
            .insert_cancellable(&cancelled, &table, &AtomicBool::new(true))
            .is_err()
    );
    assert!(!store.contains(&cancelled.id).unwrap());
}

#[test]
fn legacy_case_migrates_once_and_reopens_without_json_output() {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Migration").unwrap();
    let image = temp.path().join("image.raw");
    fs::write(&image, b"fixture").unwrap();
    let evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
    let mut run = run(&uuid::Uuid::new_v4().to_string(), "windows.info.Info");
    run.evidence_id = evidence.id.clone();
    case.add_evidence(evidence).unwrap();
    case.queue(run.clone()).unwrap();
    let output = case.run_dir(&run.id);
    fs::create_dir_all(&output).unwrap();
    fs::write(
        output.join("stdout.json"),
        r#"[{"Variable":"Is64Bit","Value":true}]"#,
    )
    .unwrap();
    case.document.runs[0].status = RunStatus::Completed;
    case.document.runs[0].row_count = 1;
    case.save().unwrap();
    drop(case);
    let case = Case::open(&temp.path().join("case")).unwrap();
    assert_eq!(
        case.document.evidence[0].operating_system,
        OperatingSystem::Windows
    );
    case.document
        .migrate_results(&case.directory, &AtomicBool::new(false))
        .unwrap();
    let store = ResultStore::at(&case.directory);
    let id = store.record(&run.id, 0).unwrap().unwrap().id;
    case.document
        .migrate_results(&case.directory, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(store.record(&run.id, 0).unwrap().unwrap().id, id);
    fs::remove_file(output.join("stdout.json")).unwrap();
    assert_eq!(case.results(&run.id).unwrap().rows[0].text("Value"), "true");
    drop(case);
    let reopened = Case::open(&temp.path().join("case")).unwrap();
    assert_eq!(reopened.results(&run.id).unwrap().rows.len(), 1);
}

#[test]
fn artifact_groups_combine_plugins_and_os_filters_allow_common_plugins() {
    for p in [
        "windows.registry.hivelist.HiveList",
        "windows.registry.printkey.PrintKey",
    ] {
        assert_eq!(ArtifactGroup::for_plugin(p), ArtifactGroup::Registry);
    }
    for p in [
        "windows.dlllist.DllList",
        "windows.ldrmodules.LdrModules",
        "linux.lsmod.Lsmod",
    ] {
        assert_eq!(ArtifactGroup::for_plugin(p), ArtifactGroup::Modules);
    }
    assert!(OperatingSystem::Linux.accepts("banners.Banners"));
    assert!(OperatingSystem::Linux.accepts("linux.pslist.PsList"));
    assert!(!OperatingSystem::Linux.accepts("windows.pslist.PsList"));
}

#[test]
fn process_tree_keeps_orphans_breaks_cycles_and_deduplicates_pids() {
    let entries = vec![
        (1, "1", "0"),
        (2, "2", "1"),
        (3, "3", "9"),
        (4, "4", "5"),
        (5, "5", "4"),
        (6, "2", "1"),
    ]
    .into_iter()
    .map(|(id, pid, ppid)| BrowserEntry {
        id,
        title: format!("process {pid}"),
        pid: Some(pid.into()),
        ppid: Some(ppid.into()),
        path: None,
    })
    .collect::<Vec<_>>();
    let forest = process_forest(&entries);
    fn collect(nodes: &[volgui_again::results::ProcessNode], ids: &mut Vec<i64>) {
        for n in nodes {
            ids.push(n.entry.id);
            collect(&n.children, ids);
        }
    }
    let mut ids = vec![];
    collect(&forest, &mut ids);
    assert_eq!(ids.len(), 5);
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 5);
    assert!(forest.iter().any(|n| n.entry.pid.as_deref() == Some("3")));
    assert!(
        forest
            .iter()
            .find(|n| n.entry.pid.as_deref() == Some("1"))
            .unwrap()
            .children
            .iter()
            .any(|n| n.entry.pid.as_deref() == Some("2"))
    );
}

#[test]
fn large_scan_query_returns_lightweight_ids_and_bounded_visible_rows() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let run = run("large", "windows.filescan.FileScan");
    let rows = (0..50_000)
        .map(|i| Record {
            depth: 0,
            fields: BTreeMap::from([
                ("PID".into(), json!(i)),
                (
                    "FileName".into(),
                    json!(format!("C:\\Evidence\\folder-{i}\\artifact-{i}.dat")),
                ),
                (
                    "Details".into(),
                    json!("Recovered file record with additional metadata"),
                ),
            ]),
        })
        .collect();
    let table = Table {
        columns: vec!["PID".into(), "FileName".into(), "Details".into()],
        rows,
    };
    let start = Instant::now();
    store.insert(&run, &table).unwrap();
    let import = start.elapsed();
    let start = Instant::now();
    let all = store
        .query(&Query {
            runs: vec![run.id.clone()],
            ..Default::default()
        })
        .unwrap();
    let index_time = start.elapsed();
    assert_eq!(all.ids.len(), 50_000);
    assert_eq!(std::mem::size_of_val(all.ids.as_slice()), 400_000);
    let start = Instant::now();
    let filtered = store
        .query(&Query {
            runs: vec![run.id],
            text: "artifact-49999".into(),
            sort: None,
        })
        .unwrap();
    let search_time = start.elapsed();
    assert_eq!(filtered.ids.len(), 1);
    assert_eq!(store.fetch(&all.ids[20_000..20_128]).unwrap().len(), 128);
    println!(
        "50k scan: import {import:?}, ID query {index_time:?}, indexed search {search_time:?}; visible fetch bounded to 128 rows"
    );
}
