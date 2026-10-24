use std::{fs, sync::atomic::AtomicBool};
use volgui_again::{
    analyses::{AnalysisDraft, basic_label, chooser_plugins},
    artifacts::OperatingSystem,
    case::{Case, Evidence, MANIFEST},
    settings::Settings,
    volatility::{Installation, Plugin},
};

fn plugin(id: &str) -> Plugin {
    Plugin {
        id: id.into(),
        description: "Test plugin".into(),
    }
}

#[test]
fn shift_selection_uses_visible_order_in_both_directions_and_can_clear_ranges() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("image.raw");
    fs::write(&image, b"synthetic selection fixture").unwrap();
    let evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
    let mut draft = AnalysisDraft::new(&evidence);
    let visible: Vec<String> = ["d", "b", "a", "c", "e"].map(String::from).into();

    draft.select("d", true, false, &visible);
    draft.select("b", true, false, &visible);
    draft.select("c", true, true, &visible);
    assert_eq!(
        draft.selected,
        ["a", "b", "c", "d"].map(String::from).into()
    );
    draft.select("a", false, true, &visible);
    assert_eq!(draft.selected, ["c", "d"].map(String::from).into());

    draft.select("e", true, false, &visible);
    draft.select("a", true, true, &visible);
    assert_eq!(
        draft.selected,
        ["a", "c", "d", "e"].map(String::from).into()
    );
}

#[test]
fn shift_selection_respects_filters_and_separate_evidence_drafts() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("image.raw");
    fs::write(&image, b"synthetic selection fixture").unwrap();
    let evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
    let mut draft = AnalysisDraft::new(&evidence);
    let all = ["a", "b", "c", "d"].map(String::from);
    let filtered = ["b", "d"].map(String::from);
    draft.select("b", true, false, &all);
    draft.select("d", true, true, &filtered);
    assert_eq!(draft.selected, ["b", "d"].map(String::from).into());

    let mut other = AnalysisDraft::new(&evidence);
    other.select("d", true, true, &all);
    assert_eq!(other.selected, [String::from("d")].into());

    // A hidden anchor falls back to the clicked checkbox, without touching hidden rows.
    draft.select("a", true, false, &all);
    draft.select("d", false, true, &filtered);
    assert_eq!(draft.selected, ["a", "b"].map(String::from).into());
}

#[test]
fn basic_catalog_includes_the_requested_tasks_and_sorts_before_advanced() {
    let requested = [
        "windows.info.Info",
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.psscan.PsScan",
        "windows.cmdline.CmdLine",
        "windows.netscan.NetScan",
        "windows.dlllist.DllList",
        "windows.filescan.FileScan",
        "windows.registry.hivelist.HiveList",
        "linux.pslist.PsList",
        "linux.pstree.PsTree",
        "linux.bash.Bash",
        "mac.pslist.PsList",
        "mac.bash.Bash",
    ];
    assert!(requested.iter().all(|id| basic_label(id).is_some()));
    let mut plugins: Vec<_> = requested.iter().map(|id| plugin(id)).collect();
    plugins.push(plugin("frameworkinfo.FrameworkInfo"));
    plugins.push(plugin("windows.registry.printkey.PrintKey"));
    let basic = chooser_plugins(&plugins, OperatingSystem::Windows, false, "");
    assert_eq!(basic.len(), 9);
    assert!(basic.iter().all(|p| p.id.starts_with("windows.")));
    let full = chooser_plugins(&plugins, OperatingSystem::Windows, true, "");
    assert_eq!(full.len(), 11);
    assert!(full[..9].iter().all(|p| basic_label(&p.id).is_some()));
    assert!(full[9..].iter().all(|p| basic_label(&p.id).is_none()));
    assert_eq!(
        chooser_plugins(&plugins, OperatingSystem::Windows, false, "registry hives").len(),
        1
    );
    assert_eq!(
        chooser_plugins(&plugins, OperatingSystem::Windows, false, "FrameworkInfo").len(),
        0
    );
}

#[test]
fn batch_selection_preserves_individual_options_and_is_saved_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("image.raw");
    fs::write(&image, b"synthetic test evidence").unwrap();
    let evidence = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Batch test").unwrap();
    case.add_evidence(evidence.clone()).unwrap();
    let engine = Installation {
        settings: Settings::default(),
        version: "fixture".into(),
        plugins: vec![
            plugin("windows.pslist.PsList"),
            plugin("windows.cmdline.CmdLine"),
            plugin("linux.pslist.PsList"),
            plugin("frameworkinfo.FrameworkInfo"),
        ],
    };
    let mut draft = AnalysisDraft::new(&evidence);
    draft.selected.extend([
        "windows.pslist.PsList".into(),
        "windows.cmdline.CmdLine".into(),
    ]);
    draft
        .arguments
        .insert("windows.pslist.PsList".into(), "--pid 40".into());
    draft
        .arguments
        .insert("windows.cmdline.CmdLine".into(), "--pid 80".into());
    let runs = draft
        .prepare(&engine, &evidence, &case.directory.join("analyses"))
        .unwrap();
    assert_eq!(runs.len(), 2);
    assert!(
        runs.iter()
            .any(|r| r.plugin == "windows.pslist.PsList" && r.arguments == ["--pid", "40"])
    );
    assert!(
        runs.iter()
            .any(|r| r.plugin == "windows.cmdline.CmdLine" && r.arguments == ["--pid", "80"])
    );
    let mut invalid = runs.clone();
    invalid[1].id = invalid[0].id.clone();
    assert!(case.queue_batch(invalid).is_err());
    assert!(case.document.runs.is_empty());
    assert!(case.queue_batch(Vec::new()).is_err());
    let manifest = case.directory.join(MANIFEST);
    let saved = fs::read(&manifest).unwrap();
    fs::remove_file(&manifest).unwrap();
    fs::create_dir(&manifest).unwrap();
    assert!(case.queue_batch(runs.clone()).is_err());
    assert!(case.document.runs.is_empty());
    fs::remove_dir(&manifest).unwrap();
    fs::write(&manifest, saved).unwrap();
    case.queue_batch(runs).unwrap();
    let directory = case.directory.clone();
    drop(case);
    assert_eq!(Case::open(&directory).unwrap().document.runs.len(), 2);

    draft.selected.insert("frameworkinfo.FrameworkInfo".into());
    draft.set_os(OperatingSystem::Linux);
    assert_eq!(
        draft.selected.iter().cloned().collect::<Vec<_>>(),
        vec!["frameworkinfo.FrameworkInfo"]
    );
    draft.selected.insert("linux.pslist.PsList".into());
    draft
        .arguments
        .insert("linux.pslist.PsList".into(), "--pid \"unterminated".into());
    assert!(
        draft
            .prepare(&engine, &evidence, &directory.join("analyses"))
            .is_err()
    );
    draft.arguments.remove("linux.pslist.PsList");
    draft.selected.insert("windows.pslist.PsList".into());
    assert!(
        draft
            .prepare(&engine, &evidence, &directory.join("analyses"))
            .is_err()
    );
}
