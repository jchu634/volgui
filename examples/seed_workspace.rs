//! Generate synthetic scan data for UI/performance checks. No acquisition or CLI is used.
use serde_json::json;
use std::{collections::BTreeMap, fs, path::PathBuf, sync::atomic::AtomicBool};
use volgui_again::{
    artifacts::OperatingSystem,
    case::{Case, Evidence, Run, RunStatus, now},
    volatility::{Outcome, Record, Table},
};

fn main() -> Result<(), String> {
    let directory = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("Usage: seed_workspace <new-case-directory>")?,
    );
    let mut case = Case::create(&directory, "Synthetic UI fixture")?;
    let path = case.directory.join("fixture.raw");
    fs::write(&path, b"Synthetic UI fixture, not a memory acquisition.")
        .map_err(|e| e.to_string())?;
    let mut evidence = Evidence::inspect(&path, &AtomicBool::new(false), |_, _| {})?;
    evidence.operating_system = OperatingSystem::Windows;
    let evidence_id = evidence.id.clone();
    case.add_evidence(evidence)?;
    fn save(
        case: &mut Case,
        evidence: &str,
        plugin: &str,
        rows: Vec<Record>,
    ) -> Result<(), String> {
        let columns = rows
            .first()
            .map(|r| r.fields.keys().cloned().collect())
            .unwrap_or_default();
        let run = Run {
            id: uuid::Uuid::new_v4().to_string(),
            evidence_id: evidence.into(),
            plugin: plugin.into(),
            arguments: vec![],
            command: vec!["synthetic-fixture".into()],
            engine_version: "Synthetic UI fixture".into(),
            created_at: now(),
            started_at: Some(now()),
            finished_at: None,
            status: RunStatus::Queued,
            exit_code: None,
            row_count: 0,
            message: String::new(),
        };
        case.queue(run.clone())?;
        case.finish(
            &run.id,
            &Outcome {
                status: RunStatus::Completed,
                exit_code: Some(0),
                message: "Synthetic records for UI verification".into(),
                table: Some(Table { columns, rows }),
            },
        )?;
        Ok(())
    }
    let processes = (0..5000)
        .map(|i| Record {
            depth: 0,
            fields: BTreeMap::from([
                ("PID".into(), json!(i + 1)),
                (
                    "PPID".into(),
                    json!(if i == 0 { 0 } else { (i - 1) / 8 + 1 }),
                ),
                (
                    "ImageFileName".into(),
                    json!(if i == 4999 {
                        "longest-process-name-outside-the-initial-row-cache.exe".into()
                    } else {
                        format!("test-process-{i}.exe")
                    }),
                ),
                (
                    "CreateTime".into(),
                    json!("2026-10-24T18:03:09.123456+11:00"),
                ),
                ("ExitTime".into(), json!("N/A")),
                ("Threads".into(), json!(14)),
                ("SessionId".into(), json!(1)),
                ("Audit".into(), json!("Synthetic audit data")),
                ("Cmd".into(), json!("synthetic-process --fixture")),
                ("File output".into(), json!("Disabled")),
                ("Handles".into(), json!("N/A")),
                ("Offset(V)".into(), json!(156735441006912_u64 + i)),
                ("Wow64".into(), json!(false)),
            ]),
        })
        .collect();
    save(&mut case, &evidence_id, "windows.pslist.PsList", processes)?;
    let network = (0..10_000)
        .map(|i| Record {
            depth: 0,
            fields: BTreeMap::from([
                ("PID".into(), json!(i % 5000 + 1)),
                (
                    "LocalAddr".into(),
                    json!(format!("192.0.2.{}", i % 250 + 1)),
                ),
                ("ForeignAddr".into(), json!("198.51.100.1")),
                ("State".into(), json!("ESTABLISHED")),
            ]),
        })
        .collect();
    save(&mut case, &evidence_id, "windows.netscan.NetScan", network)?;
    let files = (0..50_000)
        .map(|i| Record {
            depth: 0,
            fields: BTreeMap::from([
                (
                    "FileName".into(),
                    json!(format!("C:\\Fixture\\folder-{}\\document-{i}.txt", i / 100)),
                ),
                ("Offset".into(), json!(i * 4096)),
            ]),
        })
        .collect();
    save(&mut case, &evidence_id, "windows.filescan.FileScan", files)?;
    for plugin in [
        "windows.registry.hivelist.HiveList",
        "windows.registry.printkey.PrintKey",
    ] {
        save(
            &mut case,
            &evidence_id,
            plugin,
            vec![Record {
                depth: 0,
                fields: BTreeMap::from([("Name".into(), json!("Fixture registry record"))]),
            }],
        )?;
    }
    println!("Synthetic case: {}", case.directory.display());
    Ok(())
}
