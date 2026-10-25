use serde_json::json;
use std::sync::atomic::AtomicBool;
use volgui::{
    case::{Run, RunStatus, now},
    results::{DATABASE, Query, ResultStore},
    volatility::Table,
};

fn run(id: &str, evidence: &str, plugin: &str) -> Run {
    Run {
        id: id.into(),
        evidence_id: evidence.into(),
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

fn insert(store: &ResultStore, id: &str, evidence: &str, plugin: &str, rows: serde_json::Value) {
    store
        .insert(
            &run(id, evidence, plugin),
            &Table::parse(&rows.to_string()).unwrap(),
        )
        .unwrap();
}

fn entity(store: &ResultStore, run: &str, row: usize) -> i64 {
    store
        .entity_for_record(store.record(run, row).unwrap().unwrap().id)
        .unwrap()
        .unwrap()
}

#[test]
fn memory_ranges_remain_searchable_without_expanding_into_fact_and_text_indexes() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "map",
        "capture",
        "windows.memmap.Memmap",
        json!([{"Virtual":4096,"Physical":8192,"Size":4096,"Offset in File":0,"File output":"pid.42.dmp"}]),
    );
    let result = store
        .query(&Query {
            runs: vec!["map".into()],
            text: "8192".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(result.ids.len(), 1);
    assert_eq!(
        store.fetch(&result.ids).unwrap()[0].record.text("Physical"),
        "8192"
    );
    let db = rusqlite::Connection::open(temp.path().join(DATABASE)).unwrap();
    for table in ["observation_facts", "record_search"] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[test]
fn file_object_facts_share_only_explicit_same_space_addresses() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "files",
        "capture",
        "windows.filescan.FileScan",
        json!([{"Offset(V)":"0x1000","Name":"History","Size":4096},{"Offset(P)":"0x1000","Name":"History"}]),
    );
    insert(
        &store,
        "handles",
        "capture",
        "windows.handles.Handles",
        json!([{"Offset":4096,"Type":"File","Name":"History","PID":42,"HandleValue":80}]),
    );
    assert_eq!(entity(&store, "files", 0), entity(&store, "handles", 0));
    assert_ne!(entity(&store, "files", 1), entity(&store, "handles", 0));
    let handle = store.record("handles", 0).unwrap().unwrap();
    assert_eq!(
        store.fetch_enriched(&[handle.id]).unwrap()[0]
            .record
            .text("Size"),
        "4096"
    );
    insert(
        &store,
        "other",
        "another-capture",
        "windows.filescan.FileScan",
        json!([{"Offset(V)":4096,"Name":"History"}]),
    );
    assert_ne!(entity(&store, "other", 0), entity(&store, "files", 0));
}

#[test]
fn reconciliation_failure_rolls_back_new_facts_and_old_memberships_together() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "list",
        "capture",
        "windows.pslist.PsList",
        json!([{"PID":42,"CreateTime":100,"ImageFileName":"process"}]),
    );
    let original = entity(&store, "list", 0);
    let db = rusqlite::Connection::open(temp.path().join(DATABASE)).unwrap();
    db.execute_batch("CREATE TRIGGER fail_reconciliation BEFORE UPDATE ON observation_entities BEGIN SELECT RAISE(ABORT,'fixture reconciliation failure'); END;").unwrap();
    assert!(
        store
            .insert(
                &run("command", "capture", "windows.cmdline.CmdLine"),
                &Table::parse(r#"[{"PID":42,"Args":"command"}]"#).unwrap()
            )
            .is_err()
    );
    assert!(!store.contains("command").unwrap());
    assert_eq!(entity(&store, "list", 0), original);
    assert_eq!(store.entity_observations(original).unwrap().len(), 1);
}

#[test]
fn immutable_findings_share_storage_but_keep_every_run_row_address() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let rows = json!([{"PID":42,"ImageFileName":"browser"},{"PID":42,"ImageFileName":"browser"}]);
    insert(&store, "first", "evidence", "windows.pslist.PsList", rows);
    insert(
        &store,
        "second",
        "evidence",
        "windows.pslist.PsList",
        json!([{"PID":42,"ImageFileName":"browser"}]),
    );
    let first = store.record("first", 0).unwrap().unwrap();
    let duplicate = store.record("first", 1).unwrap().unwrap();
    let second = store.record("second", 0).unwrap().unwrap();
    assert_ne!(first.id, duplicate.id);
    assert_ne!(first.id, second.id);
    let observation = store.observation_for_record(first.id).unwrap().unwrap();
    assert_eq!(
        store.observation_for_record(duplicate.id).unwrap(),
        Some(observation)
    );
    assert_eq!(
        store.observation_for_record(second.id).unwrap(),
        Some(observation)
    );
    let sources = store.observation_provenance(observation).unwrap();
    assert_eq!(
        sources
            .iter()
            .map(|s| (s.run_id.as_str(), s.row))
            .collect::<Vec<_>>(),
        [("first", 0), ("first", 1), ("second", 0)]
    );
    assert_eq!(store.table("first").unwrap().rows.len(), 2);
    assert_eq!(
        store
            .query(&Query {
                runs: vec!["first".into(), "second".into()],
                ..Default::default()
            })
            .unwrap()
            .ids,
        [first.id]
    );
    assert_eq!(
        store
            .tree_entries(&["first".into(), "second".into()])
            .unwrap()
            .len(),
        1
    );
    store
        .insert(
            &run("first", "evidence", "windows.pslist.PsList"),
            &Table::default(),
        )
        .unwrap();
    assert_eq!(store.record("first", 1).unwrap().unwrap().id, duplicate.id);
    let reopened = ResultStore::open(temp.path()).unwrap();
    assert_eq!(reopened.record("second", 0).unwrap().unwrap().id, second.id);
    assert_eq!(
        reopened
            .entity_observations(entity(&store, "first", 0))
            .unwrap()
            .len(),
        1
    );

    let db = rusqlite::Connection::open(temp.path().join(DATABASE)).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT type FROM sqlite_master WHERE name='records'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "view"
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM observations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM record_search", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(
        db.execute("UPDATE observations SET fields_json='{}'", [])
            .is_err()
    );
    assert!(db.execute("DELETE FROM observations", []).is_err());
    assert!(
        db.execute("UPDATE run_observations SET row_index=90", [])
            .is_err()
    );
    assert!(db.execute("DELETE FROM run_observations", []).is_err());
    assert!(
        db.execute("UPDATE observation_facts SET value_json='null'", [])
            .is_err()
    );
}

#[test]
fn process_facts_accumulate_across_plugins_without_hiding_conflicts() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "list",
        "acquisition",
        "windows.pslist.PsList",
        json!([
            {"PID":42,"PPID":1,"ImageFileName":"browser.exe","CreateTime":100,"Offset(V)":"0x1000"}
        ]),
    );
    insert(
        &store,
        "command",
        "acquisition",
        "windows.cmdline.CmdLine",
        json!([
            {"PID":42,"Process":"browser.exe","Args":"browser.exe --first"}
        ]),
    );
    let process = entity(&store, "list", 0);
    assert_eq!(entity(&store, "command", 0), process);
    let original = store.record("list", 0).unwrap().unwrap();
    assert!(!original.record.fields.contains_key("Args"));
    assert_eq!(
        store.fetch_enriched(&[original.id]).unwrap()[0]
            .record
            .text("Args"),
        "browser.exe --first"
    );
    insert(
        &store,
        "conflict",
        "acquisition",
        "windows.cmdline.CmdLine",
        json!([
            {"PID":42,"Process":"browser.exe","Args":"browser.exe --second","CreateTime":100}
        ]),
    );
    assert_eq!(entity(&store, "conflict", 0), process);
    let facts = store.entity_facts(process).unwrap();
    let arguments: Vec<_> = facts.iter().filter(|fact| fact.field == "Args").collect();
    assert_eq!(arguments.len(), 2);
    assert!(arguments.iter().all(|fact| fact.observations.len() == 1));
    assert!(
        !store.fetch_enriched(&[original.id]).unwrap()[0]
            .record
            .fields
            .contains_key("Args")
    );
    assert_eq!(store.entity_observations(process).unwrap().len(), 3);
    insert(
        &store,
        "handles",
        "acquisition",
        "windows.handles.Handles",
        json!([
            {"PID":42,"Process":"browser.exe","Type":"File","Name":"C:\\History","Offset":"0x9999"}
        ]),
    );
    let handle = entity(&store, "handles", 0);
    assert_ne!(process, handle);
    assert!(
        store
            .entity_relations(process)
            .unwrap()
            .iter()
            .any(|relation| relation.predicate == "owns_handle"
                && relation.subject == process
                && relation.object == handle)
    );
    assert!(
        !store
            .entity_facts(process)
            .unwrap()
            .iter()
            .any(|fact| fact.field == "Type")
    );
}

#[test]
fn later_pid_reuse_detaches_uncertain_enrichment_and_handle_ownership() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "command",
        "image",
        "windows.cmdline.CmdLine",
        json!([
            {"PID":7,"Process":"same.exe","Args":"same.exe --unknown-lifetime"}
        ]),
    );
    let command = store.record("command", 0).unwrap().unwrap();
    let command_entity = entity(&store, "command", 0);
    let observation = store.observation_for_record(command.id).unwrap();
    insert(
        &store,
        "original",
        "image",
        "windows.pslist.PsList",
        json!([
            {"PID":7,"ImageFileName":"same.exe","CreateTime":10,"Offset(V)":"0x1234"}
        ]),
    );
    assert_eq!(entity(&store, "command", 0), entity(&store, "original", 0));
    insert(
        &store,
        "handles",
        "image",
        "windows.handles.Handles",
        json!([
            {"PID":7,"Type":"File","Name":"same-path"}
        ]),
    );
    assert!(
        store
            .entity_relations(entity(&store, "original", 0))
            .unwrap()
            .iter()
            .any(|relation| relation.predicate == "owns_handle")
    );
    insert(
        &store,
        "reused",
        "image",
        "windows.psscan.PsScan",
        json!([
            {"PID":7,"ImageFileName":"same.exe","CreateTime":20,"Offset(V)":"0x1234"}
        ]),
    );
    assert_ne!(entity(&store, "original", 0), entity(&store, "reused", 0));
    assert_eq!(entity(&store, "command", 0), command_entity);
    assert_eq!(store.record("command", 0).unwrap().unwrap().id, command.id);
    assert_eq!(
        store.observation_for_record(command.id).unwrap(),
        observation
    );
    assert!(
        !store
            .entity_facts(entity(&store, "original", 0))
            .unwrap()
            .iter()
            .any(|fact| fact.field == "Args")
    );
    assert!(
        store
            .entity_relations(entity(&store, "original", 0))
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .process_record(&["original".into(), "reused".into()], "7")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .process_handles(vec!["handles".into()], "7", 0)
            .unwrap()
            .total,
        0
    );
}

#[test]
fn evidence_plugin_and_depth_are_part_of_finding_identity() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let rows = json!([{"PID":4,"ImageFileName":"same.exe","CreateTime":1}]);
    insert(
        &store,
        "one",
        "image-a",
        "windows.pslist.PsList",
        rows.clone(),
    );
    insert(
        &store,
        "two",
        "image-b",
        "windows.pslist.PsList",
        rows.clone(),
    );
    insert(
        &store,
        "three",
        "image-a",
        "windows.psscan.PsScan",
        rows.clone(),
    );
    let mut nested = Table::parse(&rows.to_string()).unwrap();
    nested.rows[0].depth = 1;
    store
        .insert(&run("nested", "image-a", "windows.pslist.PsList"), &nested)
        .unwrap();
    let findings: std::collections::BTreeSet<_> = ["one", "two", "three", "nested"]
        .iter()
        .map(|run| {
            store
                .observation_for_record(store.record(run, 0).unwrap().unwrap().id)
                .unwrap()
                .unwrap()
        })
        .collect();
    assert_eq!(findings.len(), 4);
    assert_ne!(entity(&store, "one", 0), entity(&store, "two", 0));
    assert_eq!(entity(&store, "one", 0), entity(&store, "three", 0));
    assert_eq!(entity(&store, "one", 0), entity(&store, "nested", 0));
    assert!(
        store
            .process_relations(&["one".into(), "two".into()], "4")
            .unwrap()
            .parent
            .is_none()
    );
    assert!(
        store
            .process_record(&["one".into(), "two".into()], "4")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .query(&Query {
                runs: vec!["one".into(), "two".into(), "three".into(), "nested".into()],
                ..Default::default()
            })
            .unwrap()
            .ids
            .len(),
        4
    );
}

#[test]
fn equal_paths_urls_and_unqualified_pids_do_not_establish_identity() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "files",
        "image",
        "windows.filescan.FileScan",
        json!([
            {"FileName":"C:\\same.txt","Offset":"0x1000"},
            {"FileName":"C:\\same.txt","Offset":"0x2000"}
        ]),
    );
    assert_ne!(entity(&store, "files", 0), entity(&store, "files", 1));
    insert(
        &store,
        "web",
        "image",
        "volgui.browser.Activity",
        json!([
            {"URL":"https://same.example/","Kind":"History","Source run":"a"},
            {"URL":"https://same.example/","Kind":"Memory URL","Source run":"b"}
        ]),
    );
    assert_ne!(entity(&store, "web", 0), entity(&store, "web", 1));
    insert(
        &store,
        "ambiguous",
        "image",
        "windows.pslist.PsList",
        json!([
            {"PID":9,"ImageFileName":"same.exe","Threads":1},
            {"PID":9,"ImageFileName":"same.exe","Threads":2}
        ]),
    );
    insert(
        &store,
        "command",
        "image",
        "windows.cmdline.CmdLine",
        json!([
            {"PID":9,"Process":"same.exe","Args":"same.exe"}
        ]),
    );
    assert_ne!(
        entity(&store, "ambiguous", 0),
        entity(&store, "ambiguous", 1)
    );
    assert_ne!(entity(&store, "command", 0), entity(&store, "ambiguous", 0));
    assert_ne!(entity(&store, "command", 0), entity(&store, "ambiguous", 1));
}

#[test]
fn process_addresses_are_normalized_but_address_spaces_and_lifetimes_stay_distinct() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "list",
        "image",
        "windows.pslist.PsList",
        json!([
            {"PID":8,"Offset(V)":"0x1000","CreateTime":1},
            {"PID":8,"Offset(V)":"0x1000","CreateTime":2}
        ]),
    );
    insert(
        &store,
        "ambiguous-command",
        "image",
        "windows.cmdline.CmdLine",
        json!([
            {"PID":"0x8","EPROCESS":4096,"Args":"unresolved"}
        ]),
    );
    assert_ne!(
        entity(&store, "ambiguous-command", 0),
        entity(&store, "list", 0)
    );
    assert_ne!(
        entity(&store, "ambiguous-command", 0),
        entity(&store, "list", 1)
    );
    insert(
        &store,
        "known-command",
        "image",
        "windows.cmdline.CmdLine",
        json!([
            {"PID":"8","EPROCESS":4096,"CreateTime":1,"Args":"known"}
        ]),
    );
    assert_eq!(
        entity(&store, "known-command", 0),
        entity(&store, "list", 0)
    );
    insert(
        &store,
        "physical",
        "image",
        "windows.psscan.PsScan",
        json!([
            {"PID":8,"Offset(P)":"0x1000"}
        ]),
    );
    assert_ne!(entity(&store, "physical", 0), entity(&store, "list", 0));
    assert_ne!(entity(&store, "physical", 0), entity(&store, "list", 1));
}

#[test]
fn failed_or_cancelled_runs_never_add_provenance_to_shared_findings() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "existing",
        "image",
        "windows.pslist.PsList",
        json!([{"PID":1}]),
    );
    let record = store.record("existing", 0).unwrap().unwrap();
    let observation = store.observation_for_record(record.id).unwrap().unwrap();
    let db = rusqlite::Connection::open(temp.path().join(DATABASE)).unwrap();
    db.execute_batch("CREATE TRIGGER reject_new BEFORE INSERT ON run_observations WHEN NEW.run_id='failed' AND NEW.row_index=1 BEGIN SELECT RAISE(ABORT,'failure'); END;").unwrap();
    let table = Table::parse(r#"[{"PID":1},{"PID":2}]"#).unwrap();
    assert!(
        store
            .insert(&run("failed", "image", "windows.pslist.PsList"), &table)
            .is_err()
    );
    assert!(
        store
            .insert_cancellable(
                &run("cancelled", "image", "windows.pslist.PsList"),
                &table,
                &AtomicBool::new(true)
            )
            .is_err()
    );
    assert!(!store.contains("failed").unwrap());
    assert!(!store.contains("cancelled").unwrap());
    assert_eq!(store.observation_provenance(observation).unwrap().len(), 1);
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM observations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM entities", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(store.record("existing", 0).unwrap().unwrap().id, record.id);
}

#[test]
fn enriched_ui_fields_include_all_observation_and_run_row_sources() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "list",
        "image",
        "windows.pslist.PsList",
        json!([
            {"PID":42,"ImageFileName":"browser.exe","CreateTime":100}
        ]),
    );
    let selected = store.record("list", 0).unwrap().unwrap();
    assert!(
        !store.fetch_enriched(&[selected.id]).unwrap()[0]
            .record
            .fields
            .contains_key("Fact provenance")
    );
    for id in ["command-first", "command-again"] {
        insert(
            &store,
            id,
            "image",
            "windows.cmdline.CmdLine",
            json!([
                {"PID":42,"Process":"browser.exe","Args":"browser.exe --recovered"}
            ]),
        );
    }
    let projected = store.fetch_enriched(&[selected.id]).unwrap().remove(0);
    assert_eq!(projected.run_id, "list");
    assert_eq!(projected.record.text("Args"), "browser.exe --recovered");
    let provenance = &projected.record.fields["Fact provenance"];
    assert_eq!(provenance["Selected run"], "list");
    assert_eq!(provenance["Selected row index"], 0);
    let field = provenance["Fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["Field"] == "Args")
        .unwrap();
    assert_eq!(field["Enriched"], true);
    assert_eq!(field["Conflict"], false);
    assert_eq!(field["Displayed value"], "browser.exe --recovered");
    let observation = store
        .observation_for_record(store.record("command-first", 0).unwrap().unwrap().id)
        .unwrap()
        .unwrap();
    assert_eq!(
        field["Values"][0]["Observations"][0]["Observation ID"],
        observation
    );
    let sources = field["Values"][0]["Observations"][0]["Sources"]
        .as_array()
        .unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0]["Run ID"], "command-first");
    assert_eq!(sources[1]["Run ID"], "command-again");
    for source in sources {
        let source_row = store
            .record(
                source["Run ID"].as_str().unwrap(),
                source["Row index"].as_u64().unwrap() as usize,
            )
            .unwrap()
            .unwrap();
        assert_eq!(source["Record ID"], source_row.id);
    }
    let raw = store.record("list", 0).unwrap().unwrap();
    assert!(!raw.record.fields.contains_key("Args"));
    assert!(!raw.record.fields.contains_key("Fact provenance"));
}

#[test]
fn ui_conflicts_preserve_selected_values_and_attribute_every_alternative() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "list",
        "image",
        "windows.pslist.PsList",
        json!([
            {"PID":42,"ImageFileName":"browser.exe","CreateTime":100}
        ]),
    );
    for (id, args) in [
        ("first", "browser.exe --one"),
        ("second", "browser.exe --two"),
    ] {
        insert(
            &store,
            id,
            "image",
            "windows.cmdline.CmdLine",
            json!([
                {"PID":42,"CreateTime":100,"Args":args,"Fact provenance":"plugin-owned value"}
            ]),
        );
    }
    let selected = store.record("first", 0).unwrap().unwrap();
    let projected = store.fetch_enriched(&[selected.id]).unwrap().remove(0);
    assert_eq!(projected.record.text("Args"), "browser.exe --one");
    assert_eq!(
        projected.record.text("Fact provenance"),
        "plugin-owned value"
    );
    let provenance = &projected.record.fields["Fact provenance (generated)"];
    let field = provenance["Fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["Field"] == "Args")
        .unwrap();
    assert_eq!(field["Enriched"], false);
    assert_eq!(field["Conflict"], true);
    assert_eq!(field["Displayed value"], "browser.exe --one");
    assert_eq!(field["Values"].as_array().unwrap().len(), 2);
    let values: std::collections::BTreeSet<_> = field["Values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
            (
                value["Value"].as_str().unwrap(),
                value["Observations"][0]["Sources"][0]["Run ID"]
                    .as_str()
                    .unwrap(),
            )
        })
        .collect();
    assert_eq!(
        values,
        [
            ("browser.exe --one", "first"),
            ("browser.exe --two", "second")
        ]
        .into()
    );
    let list = store.record("list", 0).unwrap().unwrap();
    let projected = store.fetch_enriched(&[list.id]).unwrap().remove(0);
    assert!(!projected.record.fields.contains_key("Args"));
    let field = projected.record.fields["Fact provenance (generated)"]["Fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["Field"] == "Args")
        .unwrap();
    assert_eq!(field["Conflict"], true);
    assert!(field["Displayed value"].is_null());
}

#[test]
fn nested_object_order_does_not_change_an_exact_finding_but_value_types_do() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    for (id, raw) in [
        (
            "first",
            r#"[{"Detail":{"z":[{"b":2,"a":1}],"a":1},"Count":1}]"#,
        ),
        (
            "reordered",
            r#"[{"Count":1,"Detail":{"a":1,"z":[{"a":1,"b":2}]}}]"#,
        ),
        (
            "different-type",
            r#"[{"Count":"1","Detail":{"a":1,"z":[{"a":1,"b":2}]}}]"#,
        ),
    ] {
        store
            .insert(
                &run(id, "image", "test.findings.Findings"),
                &Table::parse(raw).unwrap(),
            )
            .unwrap();
    }
    let first = store
        .observation_for_record(store.record("first", 0).unwrap().unwrap().id)
        .unwrap();
    let reordered = store
        .observation_for_record(store.record("reordered", 0).unwrap().unwrap().id)
        .unwrap();
    let different_type = store
        .observation_for_record(store.record("different-type", 0).unwrap().unwrap().id)
        .unwrap();
    assert_eq!(first, reordered);
    assert_ne!(first, different_type);
}

#[test]
fn imported_run_identity_cannot_be_reused_for_another_scope_or_plugin() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    let table = Table::parse(r#"[{"PID":1}]"#).unwrap();
    store
        .insert(&run("same-id", "image-a", "windows.pslist.PsList"), &table)
        .unwrap();
    assert!(
        store
            .insert(&run("same-id", "image-b", "windows.pslist.PsList"), &table)
            .is_err()
    );
    assert!(
        store
            .insert(&run("same-id", "image-a", "windows.psscan.PsScan"), &table)
            .is_err()
    );
    let db = volgui::database::connect(temp.path()).unwrap();
    assert!(
        db.execute("DELETE FROM scans WHERE run_id='same-id'", [])
            .is_err()
    );
    assert!(db.execute("DELETE FROM entities", []).is_err());
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
}

#[test]
fn unknown_creation_times_are_not_identity_keys_and_valid_times_normalize() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    for (index, time) in [
        json!(0),
        json!("0"),
        json!("N/A"),
        json!("0x0"),
        json!("2025-unreadable"),
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("unknown-{index}");
        insert(
            &store,
            &id,
            "image",
            "windows.pslist.PsList",
            json!([
                {"PID":4,"ImageFileName":"same.exe","CreateTime":time,"Threads":index}
            ]),
        );
    }
    let entities: std::collections::BTreeSet<_> = (0..5)
        .map(|index| entity(&store, &format!("unknown-{index}"), 0))
        .collect();
    assert_eq!(entities.len(), 5);
    insert(
        &store,
        "known",
        "image",
        "windows.pslist.PsList",
        json!([
            {"PID":99,"CreateTime":"2025-05-03 04:05:06.000000 UTC"}
        ]),
    );
    insert(
        &store,
        "same-time",
        "image",
        "windows.cmdline.CmdLine",
        json!([
            {"PID":99,"CreateTime":"2025-05-03T06:05:06+02:00","Args":"known lifetime"}
        ]),
    );
    assert_eq!(entity(&store, "known", 0), entity(&store, "same-time", 0));
}
