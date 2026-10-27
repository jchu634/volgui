// Checks results behavior.
use serde_json::json;
use std::{collections::BTreeMap, sync::atomic::AtomicBool, time::Instant};
use volgui::{
    artifacts::ArtifactGroup,
    case::{Run, RunStatus, now},
    results::{DATABASE, Query, ResultStore},
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
fn partial_visibility_is_explicit_and_raw_results_remain_complete() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let scan = run("partial", "windows.psscan.PsScan");
    store
        .insert(
            &scan,
            &Table::parse(
                &json!([
                    {"PID":100,"ImageFileName":"intact.exe"},
                    {"PID":200,"ImageFileName":"damaged.exe","Partial match":true}
                ])
                .to_string(),
            )
            .unwrap(),
        )
        .unwrap();
    let mut query = Query {
        runs: vec![scan.id.clone()],
        ..Default::default()
    };
    assert_eq!(store.query(&query).unwrap().ids.len(), 1);
    assert_eq!(store.tree_entries(&query.runs).unwrap().len(), 1);
    assert_eq!(
        store.filter_values(&query.runs, "PID").unwrap(),
        vec!["100"]
    );
    assert_eq!(store.table(&scan.id).unwrap().rows.len(), 2);
    assert!(!store.export_csv(&query).unwrap().contains("damaged.exe"));
    query.include_partial = true;
    assert_eq!(store.query(&query).unwrap().ids.len(), 2);
    assert_eq!(
        store
            .tree_entries_with_partial(&query.runs, true)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        store
            .filter_values_with_partial(&query.runs, "PID", true)
            .unwrap(),
        vec!["100", "200"]
    );
    assert!(store.export_csv(&query).unwrap().contains("damaged.exe"));
}

#[test]
fn combined_network_endpoint_sort_uses_address_then_numeric_port() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let scan = run("network", "windows.netscan.NetScan");
    let table = Table::parse(
        &json!([
            {"ForeignAddr":"198.51.100.2", "ForeignPort":80},
            {"ForeignAddr":"198.51.100.1", "ForeignPort":443},
            {"ForeignAddr":"198.51.100.1", "ForeignPort":80},
            {"ForeignAddr":"198.51.100.1", "ForeignPort":9},
        ])
        .to_string(),
    )
    .unwrap();
    store.insert(&scan, &table).unwrap();
    let column = volgui::result_table::columns(Some(ArtifactGroup::Network), &table.columns)
        .into_iter()
        .find(|c| c.label == "Target")
        .unwrap();
    for (descending, expected) in [
        (
            false,
            vec![
                "198.51.100.1:9",
                "198.51.100.1:80",
                "198.51.100.1:443",
                "198.51.100.2:80",
            ],
        ),
        (
            true,
            vec![
                "198.51.100.2:80",
                "198.51.100.1:443",
                "198.51.100.1:80",
                "198.51.100.1:9",
            ],
        ),
    ] {
        let index = store
            .query(&Query {
                runs: vec![scan.id.clone()],
                text: String::new(),
                sort: Some((column.key.clone(), descending)),
                ..Default::default()
            })
            .unwrap();
        let rows = store.fetch(&index.ids).unwrap();
        let ordered = index
            .ids
            .iter()
            .map(|id| column.text(&rows.iter().find(|r| r.id == *id).unwrap().record))
            .collect::<Vec<_>>();
        assert_eq!(ordered, expected);
    }
}

#[test]
fn file_name_column_reads_and_sorts_across_plugins_with_different_field_names() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let files = run("files", "windows.filescan.FileScan");
    let handles = run("handles", "windows.handles.Handles");
    store
        .insert(
            &files,
            &Table::parse(r#"[{"FileName":"alpha.txt"}]"#).unwrap(),
        )
        .unwrap();
    store
        .insert(
            &handles,
            &Table::parse(r#"[{"Type":"File","Name":"zulu.txt"},{"Type":"File","Name":null,"FileName":"middle.txt"}]"#)
                .unwrap(),
        )
        .unwrap();
    let query = Query {
        runs: vec![files.id, handles.id],
        text: String::new(),
        sort: Some(("Name".into(), false)),
        ..Default::default()
    };
    let index = store.query(&query).unwrap();
    let columns = volgui::result_table::columns(Some(ArtifactGroup::Files), &index.columns);
    assert_eq!(columns.len(), 1);
    let rows = store.fetch(&index.ids).unwrap();
    let names = index
        .ids
        .iter()
        .map(|id| columns[0].text(&rows.iter().find(|r| r.id == *id).unwrap().record))
        .collect::<Vec<_>>();
    assert_eq!(names, ["alpha.txt", "middle.txt", "zulu.txt"]);
}

#[test]
fn process_relationships_use_saved_rows_and_respect_source_priority() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let list = run("list", "windows.pslist.PsList");
    let scan = run("scan", "windows.psscan.PsScan");
    store.insert(&list,&Table::parse(r#"[{"PID":1,"PPID":0,"ImageFileName":"parent","CreateTime":10},{"PID":2,"PPID":1,"ImageFileName":"selected","CreateTime":20},{"PID":3,"PPID":2,"ImageFileName":"child","CreateTime":30},{"PID":4,"PPID":2,"ImageFileName":"second child","CreateTime":40}]"#).unwrap()).unwrap();
    store
        .insert(
            &scan,
            &Table::parse(
                r#"[{"PID":3,"PPID":2,"ImageFileName":"duplicate child","CreateTime":30}]"#,
            )
            .unwrap(),
        )
        .unwrap();
    let sources = vec!["list".into(), "scan".into()];
    let relations = store.process_relations(&sources, "2").unwrap();
    assert_eq!(relations.parent.unwrap().title, "parent");
    assert_eq!(relations.children.len(), 2);
    assert!(relations.children.iter().any(|r| r.title == "child"));
    assert!(
        !relations
            .children
            .iter()
            .any(|r| r.title == "duplicate child")
    );
    assert_eq!(
        store
            .process_record(&sources, "3")
            .unwrap()
            .unwrap()
            .record
            .title(),
        "child"
    );
    assert!(store.process_record(&sources, "999").unwrap().is_none());
    assert!(
        store
            .process_relations(&sources, "1")
            .unwrap()
            .parent
            .is_none()
    );
    assert!(
        store
            .process_relations(&[], "2")
            .unwrap()
            .children
            .is_empty()
    );
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
        ..Default::default()
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
                ..Default::default()
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
                text: String::new(),
                ..Default::default()
            })
            .is_err()
    );
    let csv = store
        .export_csv(&Query {
            runs: vec!["one".into()],
            text: "child".into(),
            sort: None,
            ..Default::default()
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
    db.execute_batch("CREATE TRIGGER reject_row BEFORE INSERT ON run_observations WHEN NEW.row_index=1 BEGIN SELECT RAISE(ABORT,'fixture failure'); END;").unwrap();
    let run = run("rollback", "windows.pslist.PsList");
    let table = Table::parse(r#"[{"PID":1},{"PID":2}]"#).unwrap();
    assert!(store.insert(&run, &table).is_err());
    assert!(!store.contains(&run.id).unwrap());
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM records", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    for table in [
        "observations",
        "entities",
        "observation_facts",
        "observation_entities",
        "entity_relations",
    ] {
        assert_eq!(
            db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
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
fn legacy_results_database_is_rejected_without_migration() {
    let temp = tempfile::tempdir().unwrap();
    let db = rusqlite::Connection::open(temp.path().join(DATABASE)).unwrap();
    db.execute_batch(
        "CREATE TABLE records(id INTEGER PRIMARY KEY,fields_json TEXT); PRAGMA user_version=1;",
    )
    .unwrap();
    assert!(
        ResultStore::open(temp.path())
            .unwrap_err()
            .contains("Unsupported case format")
    );
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT type FROM sqlite_master WHERE name='records'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "table"
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
        warnings: Vec::new(),
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
            ..Default::default()
        })
        .unwrap();
    let search_time = start.elapsed();
    assert_eq!(filtered.ids.len(), 1);
    assert_eq!(store.fetch(&all.ids[20_000..20_128]).unwrap().len(), 128);
    println!(
        "50k scan: import {import:?}, ID query {index_time:?}, indexed search {search_time:?}; visible fetch bounded to 128 rows"
    );
}

#[test]
fn simultaneous_result_imports_wait_for_the_writer_and_remain_cancellable() {
    use std::{
        sync::{Arc, atomic::Ordering, mpsc},
        time::Duration,
    };
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let writer = rusqlite::Connection::open(temp.path().join(DATABASE)).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let table = Table::parse(r#"[{"Name":"fixture"}]"#).unwrap();
    let (tx, rx) = mpsc::channel();
    let mut workers = Vec::new();
    for id in ["cancelled", "first", "second"] {
        let store = store.clone();
        let table = table.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let tx = tx.clone();
        workers.push((
            cancel,
            std::thread::spawn(move || {
                let result = store.insert_cancellable(
                    &run(id, "windows.pslist.PsList"),
                    &table,
                    &worker_cancel,
                );
                tx.send((id, result)).unwrap();
            }),
        ));
    }
    assert!(
        rx.recv_timeout(Duration::from_millis(150)).is_err(),
        "Imports must wait while another writer owns SQLite"
    );
    workers[0].0.store(true, Ordering::Relaxed);
    let (id, result) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(id, "cancelled");
    assert!(result.unwrap_err().contains("cancelled"));
    writer.execute_batch("COMMIT").unwrap();
    for _ in 0..2 {
        let (_, result) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        result.unwrap();
    }
    for (_, worker) in workers {
        worker.join().unwrap();
    }
    assert!(!store.contains("cancelled").unwrap());
    assert_eq!(store.count("first").unwrap(), 1);
    assert_eq!(store.count("second").unwrap(), 1);
}

#[test]
fn browser_filters_use_derived_domains_and_combine_with_search_and_export() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let scan = run("browser", volgui::analysis::BROWSER);
    let table = Table::parse(&json!([
        {"PID":42,"Browser":"Chrome","Kind":"Web search","URL":"https://www.google.com/search?q=cat","Search terms":"cat"},
        {"PID":43,"Browser":"Firefox","Kind":"Web search","URL":"https://www.google.com/search?q=dog","Search terms":"dog"},
        {"PID":42,"Browser":"Chrome","Kind":"History","Domain":"example.com","URL":"https://example.com/cat"},
        {"Browser":"Chrome","Kind":"Web search","URL":"invalid"}
    ]).to_string()).unwrap();
    store.insert(&scan, &table).unwrap();
    let mut query = Query {
        runs: vec![scan.id],
        ..Default::default()
    };
    assert_eq!(
        store.filter_values(&query.runs, "Domain").unwrap(),
        ["", "example.com", "www.google.com"]
    );
    assert_eq!(
        store.filter_values(&query.runs, "PID").unwrap(),
        ["", "42", "43"]
    );
    query.sort = Some(("Domain".into(), false));
    let sorted = store.query(&query).unwrap();
    let fetched = store.fetch(&sorted.ids).unwrap();
    let domains: Vec<_> = sorted
        .ids
        .iter()
        .map(|id| {
            fetched
                .iter()
                .find(|row| row.id == *id)
                .unwrap()
                .record
                .text("Domain")
        })
        .collect();
    assert_eq!(
        domains,
        ["", "example.com", "www.google.com", "www.google.com"]
    );
    query
        .filters
        .insert("Domain".into(), ["www.google.com".into()].into());
    assert_eq!(store.query(&query).unwrap().ids.len(), 2);
    query.filters.insert("PID".into(), ["42".into()].into());
    let index = store.query(&query).unwrap();
    assert_eq!(index.ids.len(), 1);
    assert_eq!(
        store.fetch(&index.ids).unwrap()[0].record.text("Domain"),
        "www.google.com"
    );
    let csv = store.export_csv(&query).unwrap();
    assert!(csv.contains("cat"));
    assert!(!csv.contains("dog"));
    query.text = "dog".into();
    assert!(store.query(&query).unwrap().ids.is_empty());
    query.text.clear();
    query.filters.insert("PID".into(), Default::default());
    assert!(store.query(&query).unwrap().ids.is_empty());
    query.filters.clear();
    query.filters.insert("PID".into(), ["".into()].into());
    assert_eq!(store.query(&query).unwrap().ids.len(), 1);
}
