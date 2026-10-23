//! Produce a reviewable engine smoke case, optionally using one plugin on a real acquisition.
use std::{path::PathBuf, sync::atomic::AtomicBool};
use volgui_again::{
    case::{Case, Evidence, RunStatus, now},
    settings::Settings,
    volatility::Installation,
};

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let executable = PathBuf::from(
        args.next()
            .ok_or("Usage: validate_engine <vol-executable> <new-output-directory>")?,
    );
    let output = PathBuf::from(args.next().ok_or("Specify a new output directory")?);
    let capture = args.next().map(PathBuf::from);
    let plugin = args
        .next()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            if capture.is_some() {
                "banners.Banners".into()
            } else {
                "frameworkinfo.FrameworkInfo".into()
            }
        });
    let mut case = Case::create(
        &output,
        if capture.is_some() {
            "Focused capture validation"
        } else {
            "CLI validation - no memory capture"
        },
    )?;
    let image_path = if let Some(path) = capture {
        path
    } else {
        let path = case.directory.join("protocol-test.raw");
        std::fs::write(
            &path,
            b"Protocol fixture. This is not a memory acquisition.",
        )
        .map_err(|e| e.to_string())?;
        path
    };
    let cancel = AtomicBool::new(false);
    let mut last = std::time::Instant::now();
    let image = Evidence::inspect(&image_path, &cancel, |bytes, total| {
        if last.elapsed().as_secs() >= 5 {
            eprintln!("Hashing {:.0}%", bytes as f64 / total as f64 * 100.);
            last = std::time::Instant::now();
        }
    })?;
    case.add_evidence(image.clone())?;
    let engine = Installation::discover(
        Settings {
            executable,
            offline: true,
            ..Default::default()
        },
        &cancel,
    )?;
    let run = engine.prepare(&image, &plugin, vec![], &case.directory.join("analyses"))?;
    case.queue(run.clone())?;
    case.document.runs[0].status = RunStatus::Running;
    case.document.runs[0].started_at = Some(now());
    case.save()?;
    let outcome = engine.execute(&run, &case.run_dir(&run.id), &cancel);
    case.finish(&run.id, &outcome)?;
    if outcome.status != RunStatus::Completed {
        return Err(outcome.message);
    }
    if !outcome.table.as_ref().unwrap().rows.is_empty() {
        case.annotate(
            &run.id,
            0,
            true,
            format!("Focused validation of {plugin} using the external engine."),
        )?;
    }
    let table = outcome.table.unwrap();
    std::fs::write(
        case.directory.join("results.csv"),
        table.csv(&(0..table.rows.len()).collect::<Vec<_>>()),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(case.directory.join("case-report.html"), case.report()?)
        .map_err(|e| e.to_string())?;
    println!(
        "{}\n{} plugins\n{} records\nCase: {}",
        engine.version,
        engine.plugins.len(),
        table.rows.len(),
        case.directory.display()
    );
    Ok(())
}
