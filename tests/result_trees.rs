// Exercises tree construction against the same saved results used by the UI.
use volgui::{
    case::{Run, RunStatus, now},
    result_tree::ResultTree,
    results::{Query, ResultStore},
    volatility::Table,
};

fn insert(store: &ResultStore, id: &str, plugin: &str, json: &str) {
    let run = Run {
        id: id.into(),
        evidence_id: String::new(),
        plugin: plugin.into(),
        arguments: vec![],
        command: vec![],
        engine_version: "fixture".into(),
        created_at: now(),
        started_at: None,
        finished_at: None,
        status: RunStatus::Completed,
        exit_code: Some(0),
        row_count: 0,
        message: String::new(),
    };
    store.insert(&run, &Table::parse(json).unwrap()).unwrap();
}

fn labels(tree: &ResultTree) -> Vec<(&str, usize)> {
    tree.visible
        .iter()
        .map(|(i, depth)| (tree.nodes[*i].label.as_str(), *depth))
        .collect()
}

#[test]
fn process_search_keeps_ancestors_and_branches_expand_independently() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "list",
        "windows.pslist.PsList",
        r#"[
        {"PID":3,"PPID":2,"ImageFileName":"child"},
        {"PID":2,"PPID":1,"ImageFileName":"parent"},
        {"PID":1,"PPID":0,"ImageFileName":"root"},
        {"PID":4,"PPID":999,"ImageFileName":"orphan"}
    ]"#,
    );
    let mut query = Query {
        runs: vec!["list".into()],
        ..Default::default()
    };
    let entries = store.tree_entries(&query.runs).unwrap();
    let index = store.query(&query).unwrap();
    let mut tree = ResultTree::processes(entries.clone(), &index.ids);
    assert_eq!(
        labels(&tree),
        [("root", 0), ("parent", 1), ("child", 2), ("orphan", 0)]
    );
    let parent = tree.visible[1].0;
    tree.toggle(parent);
    assert_eq!(labels(&tree), [("root", 0), ("parent", 1), ("orphan", 0)]);
    tree.toggle(parent);
    assert_eq!(tree.visible.len(), 4);
    tree.expand_all(false);
    assert_eq!(labels(&tree), [("root", 0), ("orphan", 0)]);
    tree.expand_all(true);
    assert_eq!(tree.visible.len(), 4);
    query.text = "child".into();
    let index = store.query(&query).unwrap();
    let tree = ResultTree::processes(entries, &index.ids);
    assert_eq!(index.ids.len(), 1);
    assert_eq!(labels(&tree), [("root", 0), ("parent", 1), ("child", 2)]);
    let child = tree.nodes[tree.visible[2].0].record_id.unwrap();
    assert_eq!(store.fetch(&[child]).unwrap()[0].record.text("PID"), "3");
}

#[test]
fn process_cycles_self_parents_and_duplicate_pids_do_not_drop_records() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "list",
        "windows.pslist.PsList",
        r#"[
        {"PID":1,"PPID":2},{"PID":2,"PPID":1},{"PID":3,"PPID":3},{"PID":3,"PPID":0}
    ]"#,
    );
    insert(
        &store,
        "scan",
        "windows.psscan.PsScan",
        r#"[
        {"PID":1,"PPID":0},{"PID":2,"PPID":1}
    ]"#,
    );
    let runs = vec!["list".into(), "scan".into()];
    let index = store
        .query(&Query {
            runs: runs.clone(),
            ..Default::default()
        })
        .unwrap();
    let tree = ResultTree::processes(store.tree_entries(&runs).unwrap(), &index.ids);
    let mut visible: Vec<_> = tree
        .visible
        .iter()
        .filter_map(|(i, _)| tree.nodes[*i].record_id)
        .collect();
    visible.sort();
    assert_eq!(visible, index.ids);
    assert_eq!(
        tree.visible.iter().filter(|(_, depth)| *depth == 0).count(),
        4
    );
    // The second scan's child belongs to its own parent, rather than PID 1 in the first scan.
    assert_eq!(tree.visible.last().unwrap().1, 1);
}

#[test]
fn process_tree_uses_engine_nesting_when_ppid_is_absent() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "tree",
        "linux.pstree.PsTree",
        r#"[
        {"PID":1,"COMM":"init","__children":[{"PID":2,"COMM":"shell"}]},
        {"PID":3,"COMM":"other"}
    ]"#,
    );
    let runs = vec!["tree".into()];
    let index = store
        .query(&Query {
            runs: runs.clone(),
            ..Default::default()
        })
        .unwrap();
    let tree = ResultTree::processes(store.tree_entries(&runs).unwrap(), &index.ids);
    assert_eq!(labels(&tree), [("init", 0), ("shell", 1), ("other", 0)]);
}

#[test]
fn files_group_paths_keep_duplicate_records_and_search_with_directory_context() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "files",
        "windows.filescan.FileScan",
        r#"[
        {"FileName":"C:\\Users\\zulu.txt"},
        {"FileName":"C:\\Users\\Docs\\report.txt"},
        {"FileName":"C:\\Users\\Docs\\report.txt"},
        {"FileName":"loose.txt"},
        {"Name":null,"FileName":"","FilePath":"/var/log/syslog"}
    ]"#,
    );
    let runs = vec!["files".into()];
    let entries = store.tree_entries(&runs).unwrap();
    let index = store
        .query(&Query {
            runs: runs.clone(),
            ..Default::default()
        })
        .unwrap();
    let tree = ResultTree::files(entries.clone(), &index.ids);
    assert_eq!(
        labels(&tree),
        [
            ("/var/log/", 0),
            ("syslog", 1),
            ("C:\\Users\\", 0),
            ("Docs\\", 1),
            ("report.txt", 2),
            ("report.txt", 2),
            ("zulu.txt", 1),
            ("loose.txt", 0),
        ]
    );
    assert_eq!(
        tree.visible
            .iter()
            .filter(|(i, _)| tree.nodes[*i].record_id.is_some())
            .count(),
        index.ids.len()
    );
    let index = store
        .query(&Query {
            runs,
            text: "report.txt".into(),
            sort: None,
            ..Default::default()
        })
        .unwrap();
    let tree = ResultTree::files(entries, &index.ids);
    assert_eq!(
        labels(&tree),
        [
            ("C:\\Users\\", 0),
            ("Docs\\", 1),
            ("report.txt", 2),
            ("report.txt", 2)
        ]
    );
    let ids: Vec<_> = tree
        .visible
        .iter()
        .filter_map(|(i, _)| tree.nodes[*i].record_id)
        .collect();
    assert_eq!(store.fetch(&ids).unwrap().len(), 2);
}

#[test]
fn file_roots_distinguish_unc_device_absolute_and_relative_paths() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "files",
        "windows.filescan.FileScan",
        r#"[
        {"Name":"\\\\server\\share\\one.txt"},
        {"Name":"\\Device\\HarddiskVolume1\\two.txt"},
        {"Name":"/etc/three.txt"},
        {"Name":"etc/four.txt"}
    ]"#,
    );
    let runs = vec!["files".into()];
    let index = store
        .query(&Query {
            runs: runs.clone(),
            ..Default::default()
        })
        .unwrap();
    let mut tree = ResultTree::files(store.tree_entries(&runs).unwrap(), &index.ids);
    tree.expand_all(false);
    let roots: Vec<_> = labels(&tree).into_iter().map(|(label, _)| label).collect();
    assert_eq!(
        roots,
        [
            "/etc/",
            "\\\\server\\share\\",
            "\\Device\\HarddiskVolume1\\",
            "etc/"
        ]
    );
}

#[test]
fn single_child_folders_compact_until_a_branch_or_file() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "files",
        "windows.filescan.FileScan",
        r#"[
        {"FileName":"single\\test1\\test2\\test3\\File1.txt"},
        {"FileName":"branch\\test1\\test2\\test3\\File1.txt"},
        {"FileName":"branch\\test1\\test2\\test4\\File2.txt"},
        {"FileName":"mixed\\test1\\File1.txt"},
        {"FileName":"mixed\\test1\\test2\\test3\\File2.txt"}
    ]"#,
    );
    let runs = vec!["files".into()];
    let index = store
        .query(&Query {
            runs: runs.clone(),
            ..Default::default()
        })
        .unwrap();
    let entries = store.tree_entries(&runs).unwrap();
    let mut tree = ResultTree::files(entries.clone(), &index.ids);
    assert_eq!(
        labels(&tree),
        [
            ("branch\\test1\\test2\\", 0),
            ("test3\\", 1),
            ("File1.txt", 2),
            ("test4\\", 1),
            ("File2.txt", 2),
            ("mixed\\test1\\", 0),
            ("test2\\test3\\", 1),
            ("File2.txt", 2),
            ("File1.txt", 1),
            ("single\\test1\\test2\\test3\\", 0),
            ("File1.txt", 1),
        ]
    );
    let single = tree.visible[9].0;
    tree.toggle(single);
    assert_eq!(tree.visible.len(), 10);
    tree.toggle(single);
    assert_eq!(tree.visible.len(), 11);
    tree.expand_all(false);
    assert_eq!(tree.visible.len(), 3);
    tree.expand_all(true);
    let mut ids: Vec<_> = tree
        .visible
        .iter()
        .filter_map(|(i, _)| tree.nodes[*i].record_id)
        .collect();
    ids.sort();
    assert_eq!(ids, index.ids);
    assert_eq!(store.fetch(&ids).unwrap().len(), 5);

    // Filtering keeps the original branch boundary even when only one child matches.
    let index = store
        .query(&Query {
            runs,
            text: "branch\\test1\\test2\\test3".into(),
            sort: None,
            ..Default::default()
        })
        .unwrap();
    let tree = ResultTree::files(entries, &index.ids);
    assert_eq!(
        labels(&tree),
        [
            ("branch\\test1\\test2\\", 0),
            ("test3\\", 1),
            ("File1.txt", 2)
        ]
    );
}

#[test]
fn process_files_join_by_pid_filter_object_types_and_keep_search_context() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "processes",
        "windows.pslist.PsList",
        r#"[
        {"PID":4,"PPID":0,"ImageFileName":"System"},
        {"PID":100,"PPID":4,"ImageFileName":"editor.exe","SessionId":1,"Threads":7,"Path":"C:\\editor.exe","CreateTime":"2026-10-24T07:03:09Z"},
        {"PID":200,"PPID":4,"ImageFileName":"other.exe","SessionId":2,"Threads":3,"Path":"C:\\other.exe"}
    ]"#,
    );
    insert(
        &store,
        "handles",
        "windows.handles.Handles",
        r#"[
        {"PID":100,"Type":"File","Name":"C:\\notes.txt","HandleValue":80,"Offset":4096},
        {"PID":100,"Type":"File","Name":"C:\\notes.txt","HandleValue":84,"Offset":4096},
        {"PID":200,"Type":"File","Name":"C:\\other.txt","Offset":8192},
        {"PID":100,"Type":"Event","Name":"Not a file"},
        {"PID":100,"Type":null,"Name":"Unknown type"},
        {"PID":999,"Type":"File","Name":"Orphan handle"}
    ]"#,
    );
    // Another capture's handle run must never enter the caller's selected runs.
    insert(
        &store,
        "other-capture",
        "windows.handles.Handles",
        r#"[
        {"PID":100,"Type":"File","Name":"Wrong capture"}
    ]"#,
    );
    let processes = store.tree_entries(&["processes".into()]).unwrap();
    let files = store.tree_entries(&["handles".into()]).unwrap();
    assert_eq!(files.len(), 4);
    let mut matches = store
        .query(&Query {
            runs: vec!["processes".into()],
            ..Default::default()
        })
        .unwrap()
        .ids;
    let file_matches = store
        .query(&Query {
            runs: vec!["handles".into()],
            ..Default::default()
        })
        .unwrap()
        .ids;
    assert_eq!(file_matches.len(), 4);
    matches.extend(file_matches);
    let mut tree = ResultTree::processes_with_files(processes.clone(), files.clone(), &matches);
    assert_eq!(
        labels(&tree),
        [
            ("System", 0),
            ("editor.exe", 1),
            ("C:\\notes.txt", 2),
            ("C:\\notes.txt", 2),
            ("other.exe", 1),
            ("C:\\other.txt", 2)
        ]
    );
    let editor = tree.visible[1].0;
    let columns = volgui::result_table::tree_columns(
        volgui::artifacts::ArtifactGroup::Processes,
        &store
            .query(&Query {
                runs: vec!["processes".into()],
                ..Default::default()
            })
            .unwrap()
            .columns,
    );
    for (file_pos, owner_pos) in [(2, 1), (3, 1), (5, 4)] {
        let file = tree.visible[file_pos].0;
        let owner = tree.visible[owner_pos].0;
        let source = tree.detail_node(file);
        assert_eq!(source.record_id, tree.nodes[owner].record_id);
        assert_ne!(source.record_id, tree.nodes[file].record_id);
        let record = store.fetch(&[source.record_id.unwrap()]).unwrap().remove(0);
        let values: Vec<_> = columns
            .iter()
            .map(|column| column.text(&record.record))
            .collect();
        if owner_pos == 1 {
            assert_eq!(
                values,
                [
                    "100",
                    "1",
                    "7",
                    "C:\\editor.exe",
                    "07:03:09 (24-10-2026)(+00:00)"
                ]
            );
        } else {
            assert_eq!(values, ["200", "2", "3", "C:\\other.exe", "N.A."]);
        }
    }
    assert!(matches!(
        tree.nodes[tree.visible[2].0].kind,
        volgui::result_tree::TreeNodeKind::File
    ));
    tree.toggle(editor);
    assert_eq!(
        labels(&tree),
        [
            ("System", 0),
            ("editor.exe", 1),
            ("other.exe", 1),
            ("C:\\other.txt", 2)
        ]
    );
    let matches = store
        .query(&Query {
            runs: vec!["handles".into()],
            text: "notes.txt".into(),
            sort: None,
            ..Default::default()
        })
        .unwrap()
        .ids;
    let tree = ResultTree::processes_with_files(processes.clone(), files.clone(), &matches);
    assert_eq!(
        labels(&tree),
        [
            ("System", 0),
            ("editor.exe", 1),
            ("C:\\notes.txt", 2),
            ("C:\\notes.txt", 2)
        ]
    );
    let selected_id = tree.nodes[tree.visible[2].0].record_id.unwrap();
    let record = store.fetch(&[selected_id]).unwrap().remove(0);
    assert_eq!(record.run_id, "handles");
    assert_eq!(record.record.text("Offset"), "4096");
    // Searching by process name also retains its files.
    let matches = store
        .query(&Query {
            runs: vec!["processes".into()],
            text: "editor.exe".into(),
            sort: None,
            ..Default::default()
        })
        .unwrap()
        .ids;
    assert_eq!(
        labels(&ResultTree::processes_with_files(
            processes, files, &matches
        )),
        labels(&tree)
    );
}

#[test]
fn registry_keys_values_hives_and_search_share_branches() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "hives",
        "windows.registry.hivelist.HiveList",
        r#"[
        {"Offset":4096,"Name":"SYSTEM"},
        {"Offset":8192,"Name":"SOFTWARE"}
    ]"#,
    );
    insert(
        &store,
        "keys",
        "windows.registry.printkey.PrintKey",
        r#"[
        {"Hive Offset":4096,"Key":"SYSTEM","Name":"ControlSet001","Type":"Key"},
        {"Hive Offset":4096,"Key":"SYSTEM\\ControlSet001","Name":"Services","Type":"Key"},
        {"Hive Offset":4096,"Key":"SYSTEM\\ControlSet001\\Services","Name":"Start","Type":"REG_DWORD","Data":2},
        {"Hive Offset":8192,"Key":"SOFTWARE","Name":"Vendor","Type":"Key"}
    ]"#,
    );
    let mut query = Query {
        runs: vec!["hives".into(), "keys".into()],
        ..Default::default()
    };
    let entries = store.registry_entries(&query.runs).unwrap();
    let index = store.query(&query).unwrap();
    let mut tree = ResultTree::registry(entries.clone(), &index.ids);
    assert_eq!(tree.visible.len(), 8);
    let services = tree
        .visible
        .iter()
        .find(|(i, _)| tree.nodes[*i].label == "Services")
        .unwrap()
        .0;
    assert!(tree.nodes[services].record_id.is_some());
    tree.toggle(services);
    assert_eq!(tree.visible.len(), 7);
    tree.expand_all(false);
    assert_eq!(tree.visible.len(), 2);
    query.text = "Start".into();
    let index = store.query(&query).unwrap();
    let tree = ResultTree::registry(entries, &index.ids);
    assert_eq!(
        labels(&tree),
        [
            ("Hive 0x1000 - SYSTEM", 0),
            ("SYSTEM", 1),
            ("ControlSet001", 2),
            ("Services", 3),
            ("Start", 4)
        ]
    );
    let id = tree.nodes[tree.visible[4].0].record_id.unwrap();
    assert_eq!(store.fetch(&[id]).unwrap()[0].record.text("Data"), "2");
}

#[test]
fn modules_group_by_source_process_and_keep_kernel_records_selectable() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "dlls",
        "windows.dlllist.DllList",
        r#"[
        {"PID":100,"Process":"editor.exe","Name":"ntdll.dll","Base":4096},
        {"PID":100,"Process":"editor.exe","Name":"ntdll.dll","Base":8192},
        {"PID":200,"Process":"shell.exe","Name":"kernel32.dll","Base":12288}
    ]"#,
    );
    insert(
        &store,
        "scan",
        "windows.ldrmodules.LdrModules",
        r#"[
        {"PID":100,"Process":"editor.exe","MappedPath":"C:\\Windows\\ntdll.dll","Base":4096}
    ]"#,
    );
    insert(
        &store,
        "kernel",
        "windows.modules.Modules",
        r#"[
        {"Name":"ntoskrnl.exe","Base":65536},
        {"Name":"driver.sys","Base":131072}
    ]"#,
    );
    let runs = vec!["dlls".into(), "scan".into(), "kernel".into()];
    let index = store
        .query(&Query {
            runs: runs.clone(),
            ..Default::default()
        })
        .unwrap();
    let mut tree = ResultTree::modules(store.module_entries(&runs).unwrap(), &index.ids);
    assert_eq!(
        labels(&tree),
        [
            ("editor.exe", 0),
            ("ntdll.dll", 1),
            ("ntdll.dll", 1),
            ("shell.exe", 0),
            ("kernel32.dll", 1),
            ("editor.exe", 0),
            ("ntdll.dll", 1),
            ("Kernel modules", 0),
            ("ntoskrnl.exe", 1),
            ("driver.sys", 1),
        ]
    );
    let mut ids: Vec<_> = tree
        .visible
        .iter()
        .filter_map(|(i, _)| tree.nodes[*i].record_id)
        .collect();
    ids.sort();
    assert_eq!(ids, index.ids);
    assert_eq!(store.fetch(&ids).unwrap().len(), 6);
    let editor = tree.visible[0].0;
    tree.toggle(editor);
    assert_eq!(tree.visible.len(), 8);
    tree.expand_all(false);
    assert_eq!(tree.visible.len(), 4);
    tree.expand_all(true);
    assert_eq!(tree.visible.len(), 10);

    let filtered = store
        .query(&Query {
            runs,
            text: "kernel32".into(),
            ..Default::default()
        })
        .unwrap();
    let tree = ResultTree::modules(
        store
            .module_entries(&["dlls".into(), "scan".into(), "kernel".into()])
            .unwrap(),
        &filtered.ids,
    );
    assert_eq!(labels(&tree), [("shell.exe", 0), ("kernel32.dll", 1)]);
}

#[test]
fn module_names_and_pid_aliases_work_without_a_process_inventory() {
    let temp = tempfile::tempdir().unwrap();
    let store = ResultStore::open(temp.path()).unwrap();
    insert(
        &store,
        "libs",
        "mac.library_list.LibraryList",
        r#"[
        {"ProcessID":42,"Path":"/usr/lib/libSystem.dylib"},
        {"ProcessID":42,"COMM":"terminal","ModuleName":"libobjc.dylib"},
        {"Pid":"43","ImageFileName":"other","FilePath":"/usr/lib/libc.dylib"},
        {"PID":null,"Name":"kernel-extension"},
        {"PID":44,"Name":"","Path":""}
    ]"#,
    );
    insert(
        &store,
        "unrelated",
        "windows.dlllist.DllList",
        r#"[
        {"PID":42,"Process":"wrong-capture.exe","Name":"wrong.dll"}
    ]"#,
    );
    let runs = vec!["libs".into()];
    let index = store
        .query(&Query {
            runs: runs.clone(),
            ..Default::default()
        })
        .unwrap();
    let tree = ResultTree::modules(store.module_entries(&runs).unwrap(), &index.ids);
    assert_eq!(
        labels(&tree),
        [
            ("terminal", 0),
            ("libSystem.dylib", 1),
            ("libobjc.dylib", 1),
            ("other", 0),
            ("libc.dylib", 1),
            ("Kernel modules", 0),
            ("kernel-extension", 1),
            ("PID 44", 0),
            ("Unnamed module", 1),
        ]
    );
    assert_eq!(tree.nodes[tree.visible[0].0].pid.as_deref(), Some("42"));
    assert_eq!(tree.nodes[tree.visible[3].0].pid.as_deref(), Some("43"));
    assert!(store.module_entries(&[]).unwrap().is_empty());
}
