//! A benign synthetic case for checking the quarantine view in the native app.
use serde_json::{Value, json};
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};
use volgui::{
    analysis,
    artifacts::OperatingSystem,
    case::{Case, Evidence, Run, RunStatus, now},
    extracted_files,
    volatility::{Outcome, Table},
};

fn save(
    case: &mut Case,
    plugin: &str,
    arguments: Vec<String>,
    rows: Value,
    metadata: bool,
) -> Result<Run, String> {
    let run = Run {
        id: uuid::Uuid::new_v4().to_string(),
        evidence_id: case.document.evidence[0].id.clone(),
        plugin: plugin.into(),
        arguments,
        command: vec!["synthetic-fixture".into()],
        engine_version: "Synthetic quarantine fixture".into(),
        created_at: now(),
        started_at: None,
        finished_at: None,
        status: RunStatus::Queued,
        exit_code: None,
        row_count: 0,
        message: String::new(),
    };
    case.queue(run.clone())?;
    if metadata {
        let directory = case.run_dir(&run.id);
        fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        fs::write(
            directory.join("file.metadata.dat"),
            include_bytes!("../tests/fixtures/defender-entry.bin"),
        )
        .map_err(|e| e.to_string())?;
        fs::write(directory.join("stdout.json"), rows.to_string()).map_err(|e| e.to_string())?;
    }
    case.finish(
        &run.id,
        &Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            message: "Synthetic fixture; contains no malware".into(),
            table: Some(Table::parse(&rows.to_string())?),
        },
    )?;
    Ok(run)
}

fn main() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let path = PathBuf::from(
        arguments
            .next()
            .ok_or("Usage: seed_quarantine <new-case-directory> [--passive-only]")?,
    );
    let passive_only = arguments.next().is_some_and(|a| a == "--passive-only");
    let mut case = Case::create(&path, "Synthetic quarantine investigation")?;
    let acquisition = case.directory.join("fixture.raw");
    fs::write(
        &acquisition,
        b"Synthetic fixture, not a memory acquisition. Contains no malware.",
    )
    .map_err(|e| e.to_string())?;
    let mut evidence = Evidence::inspect(&acquisition, &AtomicBool::new(false), |_, _| {})?;
    evidence.operating_system = OperatingSystem::Windows;
    case.add_evidence(evidence)?;
    save(
        &mut case,
        "windows.filescan.FileScan",
        vec![],
        json!([
            {"Name":r"C:\ProgramData\Microsoft\Windows Defender\Quarantine\Entries\{fixture}","Offset(V)":4096},
            {"Name":r"C:\Users\Alice\Downloads\payload.exe","Offset(V)":8192},
            {"Name":r"C:\ProgramData\Microsoft\Windows Defender\Quarantine\ResourceData\AA\opaque","Offset(V)":12288},
            {"Name":r"C:\ProgramData\Malwarebytes\MBAMService\Quarantine\opaque","Offset(V)":16384}
        ]),
        false,
    )?;
    save(
        &mut case,
        "windows.pslist.PsList",
        vec![],
        json!([
            {"PID":100,"ImageFileName":"payload.exe","CreateTime":"2022-06-18T04:00:00Z","ExitTime":null}
        ]),
        false,
    )?;
    save(
        &mut case,
        "windows.cmdline.CmdLine",
        vec![],
        json!([
            {"PID":100,"Args":r"C:\Users\Alice\Downloads\payload.exe --synthetic"}
        ]),
        false,
    )?;
    save(
        &mut case,
        "windows.mftscan.ADS",
        vec![],
        json!([
            {"Filename":r"C:\Users\Alice\Downloads\payload.exe","ADS Filename":"Zone.Identifier",
                "Content":"[ZoneTransfer]\r\nHostUrl=https://cdn.example.test/setup.exe\r\nReferrerUrl=https://example.test/downloads\r\n"}
        ]),
        false,
    )?;
    save(
        &mut case,
        extracted_files::DUMP_FILES,
        vec!["--virtaddr".into(), "0x1000".into()],
        json!([{"File output":"file.metadata.dat"}]),
        true,
    )?;
    let local = save(
        &mut case,
        extracted_files::DUMP_FILES,
        vec!["--virtaddr".into(), "0x2000".into()],
        json!([]),
        false,
    )?;
    extracted_files::block_artifact(
        &case.run_dir(&local.id).join("file.unavailable.dat"),
        "Synthetic unavailable output. Antivirus involvement is unconfirmed.",
    )?;
    if !passive_only {
        let report = analysis::prepare(&case.document.evidence[0], analysis::QUARANTINE, vec![])?;
        case.queue(report.clone())?;
        let outcome = analysis::execute(
            &case.directory,
            &case.document,
            &report,
            &AtomicBool::new(false),
            |_| {},
        );
        if outcome.status != RunStatus::Completed {
            return Err(outcome.message);
        }
        case.finish(&report.id, &outcome)?;
    }
    println!("Synthetic quarantine case: {}", case.directory.display());
    Ok(())
}
