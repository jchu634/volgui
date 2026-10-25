// Demonstrates seed workspace.
//! Generate synthetic scan data for UI/performance checks. No acquisition or CLI is used.
use serde_json::json;
use std::{collections::BTreeMap, fs, path::PathBuf, sync::atomic::AtomicBool};
use volgui::{
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
    ) -> Result<String, String> {
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
        Ok(run.id)
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
    let mut files: Vec<_> = (0..50_000)
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
    files.push(Table::parse(r#"[{"FileName":"C:\\Users\\Fixture\\Chrome\\User Data\\Default\\History","Offset":267309056}]"#)?.rows.remove(0));
    save(&mut case, &evidence_id, "windows.filescan.FileScan", files)?;
    let mut handles: Vec<_> = (0..500)
        .map(|i| Record {
            depth: 0,
            fields: BTreeMap::from([
                ("PID".into(), json!(i + 1)),
                ("Type".into(), json!("File")),
                (
                    "Name".into(),
                    json!(format!("C:\\Fixture\\folder-0\\document-{}.txt", i + 1)),
                ),
                ("Offset".into(), json!((i + 1) * 4096)),
                ("HandleValue".into(), json!(80)),
            ]),
        })
        .collect();
    handles.extend(Table::parse(r#"[
        {"PID":1,"Type":"Key","HandleValue":84,"GrantedAccess":131097,"Name":"\\REGISTRY\\MACHINE\\SOFTWARE"},
        {"PID":1,"Type":"Mutant","HandleValue":88,"GrantedAccess":2031617,"Name":"Fixture mutex"},
        {"PID":1,"Type":"Event","HandleValue":92,"Name":"Fixture event"},
        {"PID":1,"Type":"File","HandleValue":96,"Name":"C:\\Users\\Fixture\\Chrome\\User Data\\Default\\History","Offset":267309056}
    ]"#)?.rows);
    save(&mut case, &evidence_id, "windows.handles.Handles", handles)?;
    let dump = save(
        &mut case,
        &evidence_id,
        "windows.dumpfiles.DumpFiles",
        vec![Record {
            depth: 0,
            fields: BTreeMap::from([("Result".into(), json!("file.0x1000.dat"))]),
        }],
    )?;
    case.document.runs.last_mut().unwrap().arguments = vec!["--virtaddr".into(), "0x1000".into()];
    case.save()?;
    fs::create_dir_all(case.run_dir(&dump)).map_err(|e| e.to_string())?;
    fs::write(
        case.run_dir(&dump).join("file.0x1000.dat"),
        (0..1024).map(|i| i as u8).collect::<Vec<_>>(),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        case.run_dir(&dump).join("file.0x1000.img"),
        b"Synthetic second cache variant.\n",
    )
    .map_err(|e| e.to_string())?;
    save(
        &mut case,
        &evidence_id,
        "windows.registry.hivelist.HiveList",
        Table::parse(r#"[{"Offset":12288,"FileFullPath":"\\REGISTRY\\MACHINE\\SOFTWARE"}]"#)?.rows,
    )?;
    save(&mut case,&evidence_id,"windows.registry.printkey.PrintKey",Table::parse(r#"[
        {"Hive Offset":12288,"Type":"Key","Key":"\\REGISTRY\\MACHINE\\SOFTWARE","Name":"Microsoft","Data":null},
        {"Hive Offset":12288,"Type":"REG_SZ","Key":"\\REGISTRY\\MACHINE\\SOFTWARE","Name":"Fixture value","Data":"Synthetic registry contents"}
    ]"#)?.rows)?;
    case.document.runs.last_mut().unwrap().arguments = vec!["--offset".into(), "0x3000".into()];
    save(&mut case,&evidence_id,"windows.registry.printkey.PrintKey",Table::parse(r#"[{"Hive Offset":12288,"Type":"REG_SZ","Key":"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft","Name":"Fixture child value","Data":"Subkey contents"}]"#)?.rows)?;
    case.document.runs.last_mut().unwrap().arguments = vec![
        "--offset".into(),
        "0x3000".into(),
        "--key".into(),
        "Microsoft".into(),
    ];
    let browser_dump = save(
        &mut case,
        &evidence_id,
        "windows.dumpfiles.DumpFiles",
        Table::parse(r#"[{"Result":"browser-history.dat"}]"#)?.rows,
    )?;
    case.document.runs.last_mut().unwrap().arguments =
        vec!["--virtaddr".into(), "0xfeed000".into()];
    fs::create_dir_all(case.run_dir(&browser_dump)).map_err(|e| e.to_string())?;
    {
        let db =
            rusqlite::Connection::open(case.run_dir(&browser_dump).join("browser-history.dat"))
                .map_err(|e| e.to_string())?;
        db.execute_batch("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER);
            CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER);
            INSERT INTO urls VALUES(1,'https://www.google.com/search?q=memory+forensics','Search',13437360000000000);
            INSERT INTO urls VALUES(2,'https://example.test/fixture','Fixture page',13437360001000000);
            INSERT INTO visits VALUES(1,1,13437360000000000);
            INSERT INTO visits VALUES(2,2,13437360001000000);").map_err(|e| e.to_string())?;
    }
    fs::write(case.run_dir(&browser_dump).join("session.json"),br#"{"windows":[{"tabs":[{"index":1,"entries":[{"url":"https://example.test/open-tab","title":"Saved session fixture"}]}]}]}"#).map_err(|e| e.to_string())?;
    case.save()?;
    let browser = volgui::analysis::prepare(
        &case.document.evidence[0],
        volgui::analysis::BROWSER,
        vec![],
    )?;
    case.queue(browser.clone())?;
    let outcome = volgui::analysis::execute(
        &case.directory,
        &case.document,
        &browser,
        &AtomicBool::new(false),
        |_| {},
    );
    case.finish(&browser.id, &outcome)?;
    // A sparse dump exercises virtual scrolling without writing a GiB of fixture data.
    let memory = save(
        &mut case,
        &evidence_id,
        "windows.memmap.Memmap",
        Table::parse(
            r#"[{"Virtual":4194304,"Physical":4096,"Size":1073741831,"Offset in File":0}]"#,
        )?
        .rows,
    )?;
    case.document.runs.last_mut().unwrap().arguments =
        vec!["--pid".into(), "4242".into(), "--dump".into()];
    fs::create_dir_all(case.run_dir(&memory)).map_err(|e| e.to_string())?;
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut dump = fs::File::create(case.run_dir(&memory).join("pid.4242.dmp"))
            .map_err(|e| e.to_string())?;
        dump.set_len(1024 * 1024 * 1024 + 7)
            .map_err(|e| e.to_string())?;
        dump.write_all(b"Synthetic process memory for the hex editor.\r\n")
            .map_err(|e| e.to_string())?;
        dump.seek(SeekFrom::Start(4093))
            .map_err(|e| e.to_string())?;
        dump.write_all(b"Cross-block UTF-8 selection: hello!")
            .map_err(|e| e.to_string())?;
        dump.seek(SeekFrom::Start(8191))
            .map_err(|e| e.to_string())?;
        let utf16 = "Odd-offset UTF-16 selection"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        dump.write_all(&utf16).map_err(|e| e.to_string())?;
        dump.seek(SeekFrom::End(-7)).map_err(|e| e.to_string())?;
        dump.write_all(b"THE END").map_err(|e| e.to_string())?;
    }
    save(&mut case, &evidence_id, volgui::analysis::APPLICATION, Table::parse(&json!([
        {"PID":4242,"Process":"fixture-editor.exe","Source run":memory,"Dump offset":4093,"Byte length":34,"Encoding":"UTF-8","Text":"Cross-block UTF-8 selection: hello!"},
        {"PID":4242,"Process":"fixture-editor.exe","Source run":memory,"Dump offset":8191,"Byte length":52,"Encoding":"UTF-16LE","Text":"Odd-offset UTF-16 selection"}
    ]).to_string())?.rows)?;
    case.document.runs.last_mut().unwrap().arguments = vec!["--pid".into(), "4242".into()];
    case.save()?;
    println!("Synthetic case: {}", case.directory.display());
    Ok(())
}
