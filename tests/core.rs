// Checks core behavior.
use serde_json::json;
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};
use volgui::{
    case::{Case, Evidence, RunStatus},
    settings::Settings,
    volatility::{Installation, Table, format_arguments, parse_arguments, parse_plugins},
};

fn evidence(path: &std::path::Path) -> Evidence {
    fs::write(path, b"memory acquisition fixture").unwrap();
    Evidence::inspect(path, &AtomicBool::new(false), |_, _| {}).unwrap()
}

#[test]
fn preserves_json_hierarchy_types_nulls_and_original_row_identity() {
    let table = Table::parse(
        &json!([
            {"PID":100,"ImageFileName":"parent.exe","Address":18446744073709551615u64,"__children":[
                {"PID":9,"ImageFileName":"child.exe","Missing":null,"__children":[]}
            ]},
            {"PID":20,"ImageFileName":"other.exe","__children":[]}
        ])
        .to_string(),
    )
    .unwrap();
    assert_eq!(table.rows.len(), 3);
    assert_eq!(table.rows[1].depth, 1);
    assert_eq!(table.rows[0].text("Address"), "18446744073709551615");
    assert_eq!(table.rows[1].text("Missing"), "N/A");
    assert_eq!(table.matching("EXE", Some(("PID", false))), vec![1, 2, 0]);
    assert_eq!(table.matching("CHILD", None), vec![1]);
    assert!(Table::parse("{}").is_err());
    assert!(Table::parse(r#"[{"__children":{}}]"#).is_err());
    assert!(Table::parse("[]").unwrap().rows.is_empty());
}

#[test]
fn arguments_are_literal_and_preserve_windows_paths() {
    assert_eq!(parse_arguments(r#"--pid 3488 --path "D:\Evidence Files\workstation.raw" --key 'A B' --empty "" --literal $(echo);x"#).unwrap(),
        vec!["--pid","3488","--path",r"D:\Evidence Files\workstation.raw","--key","A B","--empty","","--literal","$(echo);x"]);
    assert!(parse_arguments("--name 'unfinished").is_err());
    let arguments = vec![
        r"\\server\share\folder\".into(),
        r"D:\path with spaces\".into(),
        "quote \" in text".into(),
        "".into(),
        "'single quote'".into(),
        "$(literal); &".into(),
    ];
    assert_eq!(
        parse_arguments(&format_arguments(&arguments)).unwrap(),
        arguments
    );
}

#[test]
fn discovery_handles_wrapped_help_without_confusing_descriptions_for_plugins() {
    let plugins = parse_plugins(
        "usage: vol [-h]\nPlugins:\n  PLUGIN\n    windows.pslist.PsList\n                        Lists processes.\n                        AmCache.\n                        data.with.dots\n    linux.pslist.PsList  Lists linux tasks\n                        in order.\n",
    );
    assert_eq!(plugins.len(), 2);
    assert_eq!(plugins[0].description, "Lists linux tasks in order.");
    assert_eq!(plugins[1].id, "windows.pslist.PsList");
}

#[test]
fn csv_quotes_fields_and_neutralizes_spreadsheet_formulas() {
    let table = Table::parse(
        &json!([{"Text":"=HYPERLINK(\"http://invalid\")","Multiline":"a,\"b\"\nc","Number":-5}])
            .to_string(),
    )
    .unwrap();
    let csv = table.csv(&[0]);
    assert!(csv.contains("\"'=HYPERLINK(\"\"http://invalid\"\")\""));
    assert!(csv.contains("\"a,\"\"b\"\"\nc\""));
    assert!(csv.contains("\"-5\""));
    assert!(!csv.contains("'-5"));
}

#[test]
fn hashing_detects_modification_and_supports_cancellation() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("host.raw");
    let original = evidence(&image);
    assert_eq!(original.sha256.len(), 64);
    assert!(original.check_metadata().is_ok());
    fs::write(&image, b"changed evidence").unwrap();
    assert!(original.check_metadata().is_err());
    assert!(Evidence::inspect(&image, &AtomicBool::new(true), |_, _| {}).is_err());
}

#[test]
fn cases_lock_atomically_save_and_preserve_integrity_failures() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("Case 42");
    let mut case = Case::create(&directory, "Investigation <script>").unwrap();
    assert!(
        Case::open(&directory).is_err(),
        "second writer must not overwrite the first"
    );
    let image = temp.path().join("image.raw");
    let original = evidence(&image);
    let id = original.id.clone();
    case.add_evidence(original).unwrap();
    fs::write(&image, b"different image").unwrap();
    let current = Evidence::inspect(&image, &AtomicBool::new(false), |_, _| {}).unwrap();
    assert!(!case.record_verification(&id, &current).unwrap());
    assert!(
        case.document.evidence[0]
            .check_metadata()
            .unwrap_err()
            .contains("failed its last integrity check")
    );
    let report = case.report().unwrap();
    assert!(report.contains("Investigation &lt;script&gt;"));
    assert!(!report.contains("<script>"));
    assert!(report.contains("MISMATCH"));
    assert!(
        case.document
            .export(&case.directory, &image, b"must not overwrite evidence")
            .is_err()
    );
    assert!(
        case.document
            .export(
                &case.directory,
                &directory.join("case.volgui.json"),
                b"must not overwrite manifest"
            )
            .is_err()
    );
    case.document
        .export(
            &case.directory,
            &directory.join("report.html"),
            report.as_bytes(),
        )
        .unwrap();
    assert!(
        fs::read_to_string(directory.join("report.html"))
            .unwrap()
            .contains("MISMATCH")
    );
    drop(case);
    let reopened = Case::open(&directory).unwrap();
    assert_eq!(
        reopened.document.evidence[0]
            .verification
            .as_ref()
            .unwrap()
            .sha256,
        current.sha256
    );
    assert!(Case::create(&directory, "overwrite").is_err());
}

fn engine(path: PathBuf) -> Installation {
    Installation::discover(
        Settings {
            executable: path,
            offline: true,
            ..Default::default()
        },
        &AtomicBool::new(false),
    )
    .unwrap()
}

#[test]
#[ignore = "Requires VOLGUI_TEST_VOLATILITY pointing to a separately installed engine"]
fn supplied_volatility_build_can_discover_and_run_without_a_capture() {
    let path = std::env::var_os("VOLGUI_TEST_VOLATILITY")
        .expect("Set VOLGUI_TEST_VOLATILITY to an external Volatility executable");
    let engine = engine(path.into());
    assert!(engine.version.starts_with("Volatility 3 Framework"));
    assert!(
        engine
            .plugins
            .iter()
            .any(|p| p.id == "windows.pslist.PsList")
    );
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Engine integration").unwrap();
    let image = evidence(&temp.path().join("placeholder.raw"));
    case.add_evidence(image.clone()).unwrap();
    // FrameworkInfo requires no memory layer; this verifies the actual packaged engine protocol.
    let run = engine
        .prepare(
            &image,
            "frameworkinfo.FrameworkInfo",
            vec![],
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(run.clone()).unwrap();
    let result = engine.execute(&run, &case.run_dir(&run.id), &AtomicBool::new(false));
    assert_eq!(result.status, RunStatus::Completed, "{}", result.message);
    assert!(result.table.as_ref().unwrap().rows.len() > 20);
    case.finish(&run.id, &result).unwrap();
    let count = result.table.as_ref().unwrap().rows.len();
    drop(case);
    let reopened = Case::open(&temp.path().join("case")).unwrap();
    assert_eq!(reopened.results(&run.id).unwrap().rows.len(), count);
    println!(
        "Actual engine verified: {} · {} plugins · {} records",
        engine.version,
        engine.plugins.len(),
        count
    );
}

#[cfg(feature = "test-engine")]
mod process_tests {
    use super::*;
    use std::{
        sync::{Arc, atomic::Ordering},
        time::{Duration, Instant},
    };

    #[test]
    fn run_lifecycle_captures_large_stderr_literal_args_generated_files_and_annotations() {
        let engine = engine(PathBuf::from(env!("CARGO_BIN_EXE_volgui-test-engine")));
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("Case with spaces");
        let mut case = Case::create(&directory, "Lifecycle").unwrap();
        let image = evidence(&temp.path().join("image with spaces.raw"));
        case.add_evidence(image.clone()).unwrap();
        let args = vec!["--name".into(), "literal $(whoami); & value".into()];
        let run = engine
            .prepare(
                &image,
                "test.echo.Echo",
                args,
                &case.directory.join("analyses"),
            )
            .unwrap();
        case.queue(run.clone()).unwrap();
        let output = case.run_dir(&run.id);
        let result = engine.execute(&run, &output, &AtomicBool::new(false));
        assert_eq!(result.status, RunStatus::Completed, "{}", result.message);
        assert_eq!(result.table.as_ref().unwrap().rows.len(), 2);
        assert!(fs::metadata(output.join("stderr.log")).unwrap().len() > 1024 * 1024);
        assert!(result.message.len() <= 16 * 1024);
        assert!(output.join("artifact.txt").exists());
        assert!(
            result.table.as_ref().unwrap().rows[0]
                .text("Arguments")
                .contains("literal $(whoami); & value")
        );
        case.finish(&run.id, &result).unwrap();
        case.annotate(&run.id, 1, true, "Check <this> & compare".into())
            .unwrap();
        assert!(case.annotate(&run.id, 9, true, "invalid".into()).is_err());
        let report = case.report().unwrap();
        assert!(report.contains("Check &lt;this&gt; &amp; compare"));
        drop(case);
        let reopened = Case::open(&directory).unwrap();
        assert_eq!(
            reopened.annotation(&run.id, 1).unwrap().note,
            "Check <this> & compare"
        );
        assert_eq!(reopened.results(&run.id).unwrap().rows[1].title(), "child");
    }

    #[test]
    fn distinguishes_nonzero_exit_invalid_json_and_cancellation() {
        let engine = engine(PathBuf::from(env!("CARGO_BIN_EXE_volgui-test-engine")));
        let temp = tempfile::tempdir().unwrap();
        let image = evidence(&temp.path().join("image.raw"));
        for plugin in ["test.fail.Fail", "test.bad.Bad"] {
            let run = engine.prepare(&image, plugin, vec![], temp.path()).unwrap();
            let outcome = engine.execute(&run, &temp.path().join(&run.id), &AtomicBool::new(false));
            assert_eq!(outcome.status, RunStatus::Failed);
            if plugin == "test.fail.Fail" {
                assert_eq!(outcome.exit_code, Some(7));
                assert!(outcome.message.contains("symbol_table_name"));
            } else {
                assert_eq!(outcome.exit_code, Some(0));
                assert!(outcome.message.contains("JSON"));
            }
        }
        let run = engine
            .prepare(&image, "test.slow.Slow", vec![], temp.path())
            .unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let output = temp.path().join(&run.id);
        let start = Instant::now();
        let worker = std::thread::spawn(move || engine.execute(&run, &output, &worker_cancel));
        std::thread::sleep(Duration::from_millis(250));
        cancel.store(true, Ordering::Relaxed);
        assert_eq!(worker.join().unwrap().status, RunStatus::Cancelled);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn reopening_recovers_unfinished_jobs_without_restarting_them() {
        let engine = engine(PathBuf::from(env!("CARGO_BIN_EXE_volgui-test-engine")));
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("case");
        let image = evidence(&temp.path().join("image.raw"));
        let mut case = Case::create(&directory, "Recovery").unwrap();
        case.add_evidence(image.clone()).unwrap();
        let run = engine
            .prepare(
                &image,
                "test.echo.Echo",
                vec![],
                &directory.join("analyses"),
            )
            .unwrap();
        case.queue(run.clone()).unwrap();
        drop(case);
        let recovered = Case::open(&directory).unwrap();
        assert_eq!(recovered.document.runs[0].status, RunStatus::Interrupted);
        assert!(recovered.document.runs[0].finished_at.is_some());
        assert!(!recovered.run_dir(&run.id).exists());
    }
}
