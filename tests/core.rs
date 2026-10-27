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

#[cfg(feature = "test-engine")]
#[test]
fn discovery_probes_user_memory_support_instead_of_assuming_a_version() {
    let temp = tempfile::tempdir().unwrap();
    for (name, supported) in [("vol-rs-legacy", false), ("vol-rs-user-memory", true)] {
        let path = temp
            .path()
            .join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
        fs::copy(env!("CARGO_BIN_EXE_volgui-test-engine"), &path).unwrap();
        let installation = engine(path);
        assert_eq!(installation.version, "vol-rs 1.0.2");
        assert_eq!(installation.user_memory_dumps, supported);
    }
    let installation = engine(env!("CARGO_BIN_EXE_volgui-test-engine").into());
    assert!(!installation.user_memory_dumps);
}

#[test]
fn engine_commands_leave_default_cache_and_symbols_to_the_engine() {
    let temp = tempfile::tempdir().unwrap();
    let image = evidence(&temp.path().join("image.raw"));
    let mut engine = Installation {
        user_memory_dumps: false,
        settings: Settings::default(),
        version: "vol-rs 1.0.2".into(),
        plugins: vec![volgui::volatility::Plugin {
            id: "windows.pslist.PsList".into(),
            description: String::new(),
        }],
    };
    let run = engine
        .prepare(&image, "windows.pslist.PsList", vec![], temp.path())
        .unwrap();
    assert!(
        !run.command
            .iter()
            .any(|arg| arg == "--cache-path" || arg == "-s")
    );
    engine.settings.symbols = temp.path().to_path_buf();
    let custom = engine
        .prepare(&image, "windows.pslist.PsList", vec![], temp.path())
        .unwrap();
    assert_eq!(custom.command.iter().filter(|arg| *arg == "-s").count(), 1);
    assert!(
        custom
            .command
            .windows(2)
            .any(|pair| pair[0] == "-s" && pair[1] == temp.path().display().to_string())
    );
    engine.version = "Volatility 3 Framework 2.28.3".into();
    engine.settings.symbols.clear();
    let original = engine
        .prepare(&image, "windows.pslist.PsList", vec![], temp.path())
        .unwrap();
    assert!(
        !original
            .command
            .iter()
            .any(|arg| arg == "--cache-path" || arg == "-s")
    );
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
                &directory.join("case.sqlite"),
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
    assert!(
        engine.version.starts_with("Volatility 3 Framework")
            || engine.version.starts_with("vol-rs ")
    );
    assert!(
        engine
            .plugins
            .iter()
            .any(|p| p.id == "windows.pslist.PsList")
    );
    let help = engine
        .help("windows.pslist.PsList", &AtomicBool::new(false))
        .unwrap();
    assert!(help.contains("--pid"));
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
    fn missing_offline_symbols_explain_recovery_and_retain_diagnostics() {
        let engine = engine(PathBuf::from(env!("CARGO_BIN_EXE_volgui-test-engine")));
        let temp = tempfile::tempdir().unwrap();
        let image = evidence(&temp.path().join("image.raw"));
        let run = engine
            .prepare(
                &image,
                "test.fail.Fail",
                vec!["--missing-symbols".into()],
                temp.path(),
            )
            .unwrap();
        let output = temp.path().join(&run.id);
        let result = engine.execute(&run, &output, &AtomicBool::new(false));
        assert_eq!(result.status, RunStatus::Failed);
        assert!(result.message.starts_with("Kernel symbols are missing"));
        assert!(result.message.contains("Validate and save"));
        assert!(result.message.contains("Symbols directory"));
        assert!(
            result
                .message
                .contains("plugins.Fail.kernel.symbol_table_name")
        );
        let raw = fs::read_to_string(output.join("stderr.log")).unwrap();
        assert!(raw.contains("Symbols are not available offline"));
        assert!(!raw.contains("Validate and save"));
    }

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
    fn concurrent_cli_jobs_have_distinct_processes_and_independent_cancellation() {
        use volgui::analyses::next_queued_run;
        let engine = engine(PathBuf::from(env!("CARGO_BIN_EXE_volgui-test-engine")));
        let temp = tempfile::tempdir().unwrap();
        let mut case = Case::create(&temp.path().join("case"), "Concurrent CLI").unwrap();
        let image = evidence(&temp.path().join("image.raw"));
        case.add_evidence(image.clone()).unwrap();
        let runs: Vec<_> = ["test.gated.Gated", "test.gated.Gated", "test.echo.Echo"]
            .into_iter()
            .map(|plugin| {
                engine
                    .prepare(&image, plugin, vec![], &case.directory.join("analyses"))
                    .unwrap()
            })
            .collect();
        case.queue_batch(runs.clone()).unwrap();
        let limit = Settings::default().max_concurrent_jobs;
        let mut workers = Vec::new();
        for expected in 0..2 {
            let index = next_queued_run(&case.document.runs, limit).unwrap();
            assert_eq!(index, expected);
            case.document.runs[index].status = RunStatus::Running;
            let run = runs[index].clone();
            let engine = engine.clone();
            let output = case.run_dir(&run.id);
            let cancel = Arc::new(AtomicBool::new(false));
            let worker_cancel = cancel.clone();
            workers.push((
                cancel,
                std::thread::spawn(move || engine.execute(&run, &output, &worker_cancel)),
            ));
        }
        assert_eq!(next_queued_run(&case.document.runs, limit), None);
        assert!(!case.run_dir(&runs[2].id).exists());
        let deadline = Instant::now() + Duration::from_secs(5);
        while !runs[..2]
            .iter()
            .all(|run| case.run_dir(&run.id).join("ready").exists())
        {
            assert!(
                Instant::now() < deadline,
                "Both CLI instances must be alive together"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let pids: Vec<_> = runs[..2]
            .iter()
            .map(|run| fs::read_to_string(case.run_dir(&run.id).join("ready")).unwrap())
            .collect();
        assert_ne!(pids[0], pids[1]);
        let (cancel, first) = workers.remove(0);
        cancel.store(true, Ordering::Relaxed);
        let outcome = first.join().unwrap();
        assert_eq!(outcome.status, RunStatus::Cancelled);
        case.finish(&runs[0].id, &outcome).unwrap();
        assert!(
            !workers[0].1.is_finished(),
            "Cancelling one CLI must leave the other running"
        );
        assert_eq!(next_queued_run(&case.document.runs, limit), Some(2));
        case.document.runs[2].status = RunStatus::Running;
        let outcome = engine.execute(
            &runs[2],
            &case.run_dir(&runs[2].id),
            &AtomicBool::new(false),
        );
        assert_eq!(outcome.status, RunStatus::Completed, "{}", outcome.message);
        case.finish(&runs[2].id, &outcome).unwrap();
        fs::write(case.run_dir(&runs[1].id).join("release"), b"").unwrap();
        let (_, second) = workers.remove(0);
        let outcome = second.join().unwrap();
        assert_eq!(outcome.status, RunStatus::Completed, "{}", outcome.message);
        case.finish(&runs[1].id, &outcome).unwrap();
        assert!(volgui::object_store::exists(
            &case.run_dir(&runs[1].id).join("artifact.txt")
        ));
        assert!(volgui::object_store::exists(
            &case.run_dir(&runs[2].id).join("artifact.txt")
        ));
        drop(case);
        let reopened = Case::open(&temp.path().join("case")).unwrap();
        assert_eq!(reopened.document.runs[0].status, RunStatus::Cancelled);
        for run in &runs[1..] {
            assert_eq!(reopened.results(&run.id).unwrap().rows.len(), 2);
        }
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

#[test]
fn result_reader_accepts_output_larger_than_the_text_viewer_limit() {
    use std::io::{Read, Write};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("stdout.json");
    let mut file = std::fs::File::create(&path).unwrap();
    // Large whitespace keeps the regression test's memory use small.
    std::io::copy(
        &mut std::io::repeat(b' ').take(128 * 1024 * 1024 + 1),
        &mut file,
    )
    .unwrap();
    file.write_all(br#"[{"Name":"Registry value","__children":[{"Data":"value"}]}]"#)
        .unwrap();
    drop(file);
    let table = volgui::volatility::Table::read(&path).unwrap();
    assert_eq!(table.rows.len(), 2);
    assert_eq!(table.rows[1].depth, 1);
    assert_eq!(table.rows[1].text("Data"), "value");
}

#[test]
fn result_reader_accepts_banner_and_bom_and_rejects_trailing_json() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("stdout.json");
    std::fs::write(
        &path,
        "\u{feff} \nVolatility 3 Framework 2.0\n[{\"Name\":\"key\"}]",
    )
    .unwrap();
    let table = volgui::volatility::Table::read(&path).unwrap();
    assert_eq!(table.rows[0].text("Name"), "key");
    std::fs::write(&path, "[] trailing").unwrap();
    assert!(volgui::volatility::Table::read(&path).is_err());
}
