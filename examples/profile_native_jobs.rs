//! Profile native parsing, production serialization, archiving and import in isolated cases.
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell, collections::BTreeMap, fs, path::PathBuf, sync::atomic::AtomicBool,
    time::Instant,
};
use volgui::{
    analysis,
    case::{Case, CaseSnapshot, Run, RunStatus},
    object_store::ObjectStore,
    results::ResultStore,
};

#[cfg(windows)]
fn cpu_seconds() -> Option<f64> {
    use windows_sys::Win32::{
        Foundation::FILETIME,
        System::Threading::{GetCurrentProcess, GetProcessTimes},
    };
    let mut created = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exited = created;
    let mut kernel = created;
    let mut user = created;
    // GetCurrentProcess returns a pseudo-handle; the output pointers are valid
    // for this call and the handle must not be closed.
    if unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return None;
    }
    let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
    Some((ticks(kernel) + ticks(user)) as f64 / 10_000_000.0)
}

#[cfg(not(windows))]
fn cpu_seconds() -> Option<f64> {
    None
}

fn clone_files(
    source: &std::path::Path,
    target: &std::path::Path,
    link: bool,
) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|e| e.to_string())?;
    if !source.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(source).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let destination = target.join(entry.file_name());
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            clone_files(&entry.path(), &destination, link)?;
        } else if link {
            fs::hard_link(entry.path(), destination).map_err(|e| e.to_string())?;
        } else {
            fs::copy(entry.path(), destination).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let source=PathBuf::from(args.next().ok_or("Usage: profile_native_jobs <source-case> <output-json> <attribution-run-json> [repeats] [plugin-filter]")?);
    let output = PathBuf::from(args.next().ok_or("Specify output JSON")?);
    let extra = PathBuf::from(
        args.next()
            .ok_or("Specify a prepared attribution run JSON")?,
    );
    let repeats: usize = args
        .next()
        .map(|s| s.to_string_lossy().parse())
        .transpose()
        .map_err(|_| "Invalid repeats")?
        .unwrap_or(3);
    if repeats == 0 {
        return Err("Repeats must be positive".into());
    }
    let filter = args
        .next()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let discovery_replay = args.next().map(PathBuf::from);
    let cancel = AtomicBool::new(false);
    // Readers may persist availability diagnostics. Give them a separate catalog
    // and capture tree. Immutable archived object bytes are only read here.
    let input = tempfile::tempdir_in(source.parent().ok_or("Source case needs a parent")?)
        .map_err(|e| e.to_string())?;
    let isolated = input.path().join("inputs");
    fs::create_dir_all(&isolated).map_err(|e| e.to_string())?;
    let database = rusqlite::Connection::open_with_flags(
        source.join("case.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| e.to_string())?;
    // Hold one WAL read snapshot. Otherwise each live case write can restart
    // SQLite's backup and prevent a large input catalog from ever finishing.
    database
        .execute_batch("BEGIN; SELECT id FROM case_meta;")
        .map_err(|e| e.to_string())?;
    eprintln!("Backing up input catalog");
    database
        .backup("main", isolated.join("case.sqlite"), None)
        .map_err(|e| e.to_string())?;
    database
        .execute_batch("ROLLBACK;")
        .map_err(|e| e.to_string())?;
    drop(database);
    eprintln!("Preparing isolated output references");
    clone_files(&source.join("objects"), &isolated.join("objects"), true)?;
    clone_files(&source.join("analyses"), &isolated.join("analyses"), false)?;
    let source = isolated;
    let mut document = CaseSnapshot::load(&source)?;
    let mut extra: Run = serde_json::from_slice(&fs::read(extra).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if let Some(path) = &discovery_replay {
        let replay: serde_json::Value =
            serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let mut discovery: Run =
            serde_json::from_value(replay["run"].clone()).map_err(|e| e.to_string())?;
        let observations =
            volgui::volatility::Table::read(&path.with_extension("observations.json"))?;
        discovery.status = RunStatus::Completed;
        discovery.row_count = observations.rows.len();
        // These benchmark inputs exist only in the isolated catalog and snapshot.
        ResultStore::at(&source).insert(&discovery, &observations)?;
        document.runs.push(discovery.clone());
        let evidence = document
            .evidence
            .iter()
            .find(|e| e.id == discovery.evidence_id)
            .ok_or("Missing discovery evidence")?;
        let engine = volgui::volatility::Installation {
            settings: volgui::settings::Settings::load()?,
            version: discovery.engine_version.clone(),
            user_memory_dumps: true,
            plugins: [
                analysis::application::MEMMAP,
                analysis::application::VADINFO,
                analysis::network_attribution::DISCOVERY,
            ]
            .map(|id| volgui::volatility::Plugin {
                id: id.into(),
                description: String::new(),
            })
            .into(),
        };
        let prepared = analysis::network_attribution::recovery_runs(
            &source,
            &document,
            evidence,
            &engine,
            &[],
            &cancel,
        )?;
        if prepared.len() != 1 {
            return Err("Discovery replay still requires missing engine collections".into());
        }
        extra = prepared.into_iter().next().unwrap();
    }
    document.runs.push(extra.clone());
    let mut runs: BTreeMap<_, _> = document
        .runs
        .iter()
        .filter(|r| analysis::is_native(&r.plugin) && r.status == RunStatus::Completed)
        .map(|r| (r.plugin.clone(), r.clone()))
        .collect();
    runs.insert(extra.plugin.clone(), extra);
    let evidence = document.evidence.first().ok_or("Missing evidence")?.clone();
    // File recovery's parser can be profiled without starting extraction jobs.
    if !runs.contains_key(analysis::FILES) {
        let run = analysis::prepare(&evidence, analysis::FILES, vec![])?;
        document.runs.push(run.clone());
        runs.insert(run.plugin.clone(), run);
    }
    fs::create_dir_all(output.parent().ok_or("Output needs a parent directory")?)
        .map_err(|e| e.to_string())?;
    let mut measurements = Vec::new();
    for (plugin, run) in runs.into_iter().filter(|(p, _)| p.contains(&filter)) {
        for iteration in 1..=repeats {
            eprintln!("{plugin}, sample {iteration}/{repeats}");
            let progress = RefCell::new(Vec::new());
            let cpu_started = cpu_seconds();
            let started = Instant::now();
            let (table, message) = analysis::analyze(
                &source,
                &document,
                &run,
                &cancel,
                |message| {
                    if message.starts_with("Network process attribution: ") {
                        eprintln!("{:.3}s: {message}", started.elapsed().as_secs_f64());
                    }
                    progress.borrow_mut().push(serde_json::json!({
                        "seconds": started.elapsed().as_secs_f64(), "message": message,
                        "cpu_seconds": cpu_seconds().zip(cpu_started).map(|(end, start)| end - start),
                    }));
                },
            )?;
            let parse = started.elapsed().as_secs_f64();
            let parse_cpu = cpu_seconds()
                .zip(cpu_started)
                .map(|(end, start)| end - start);
            let temp = tempfile::tempdir_in(output.parent().unwrap()).map_err(|e| e.to_string())?;
            let mut case = Case::create(&temp.path().join("case"), "Native job profile")?;
            case.add_evidence(evidence.clone())?;
            let mut imported = run.clone();
            imported.status = RunStatus::Queued;
            case.queue(imported.clone())?;
            let started = Instant::now();
            analysis::save_results(&case.directory, &imported, &table, &message)?;
            let serialize = started.elapsed().as_secs_f64();
            let bytes =
                fs::read(case.run_dir(&run.id).join("stdout.json")).map_err(|e| e.to_string())?;
            let digest = format!("{:x}", Sha256::digest(&bytes));
            // Compare both writers on exactly the same parsed findings.
            let baseline = temp.path().join("unbuffered.json");
            let values: Vec<_> = table.rows.iter().map(|r| &r.fields).collect();
            let started = Instant::now();
            serde_json::to_writer(
                fs::File::create(&baseline).map_err(|e| e.to_string())?,
                &values,
            )
            .map_err(|e| e.to_string())?;
            let unbuffered = started.elapsed().as_secs_f64();
            if fs::read(&baseline).map_err(|e| e.to_string())? != bytes {
                return Err(format!(
                    "Buffered and unbuffered output differs for {plugin}"
                ));
            }
            let started = Instant::now();
            ObjectStore::at(&case.directory).capture_run(&run.id, &cancel)?;
            let archive = started.elapsed().as_secs_f64();
            let started = Instant::now();
            ResultStore::at(&case.directory).insert_cancellable(&imported, &table, &cancel)?;
            let import = started.elapsed().as_secs_f64();
            let stored = ResultStore::at(&case.directory).table(&run.id)?;
            if stored.rows.len() != table.rows.len()
                || stored
                    .rows
                    .iter()
                    .zip(&table.rows)
                    .any(|(a, b)| a.fields != b.fields || a.depth != b.depth)
            {
                return Err(format!("Stored rows differ for {plugin}"));
            }
            measurements.push(serde_json::json!({"plugin":plugin,"iteration":iteration,"rows":table.rows.len(),"output_bytes":bytes.len(),"output_sha256":digest,"parse_seconds":parse,"parse_cpu_seconds":parse_cpu,"serialize_seconds":serialize,"unbuffered_serialize_seconds":unbuffered,"archive_seconds":archive,"import_seconds":import,"total_seconds":parse+serialize+archive+import,"progress":progress.into_inner(),"message":message}));
            if discovery_replay.is_some() && iteration == 1 {
                fs::write(
                    output.with_extension(format!("{plugin}.findings.json")),
                    &bytes,
                )
                .map_err(|e| e.to_string())?;
            }
            fs::write(
                &output,
                serde_json::to_vec_pretty(&measurements).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            println!(
                "{plugin}, sample {iteration}: {:.3}s, {} rows",
                parse + serialize + archive + import,
                table.rows.len()
            );
        }
    }
    Ok(())
}
