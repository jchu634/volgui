//! Reparse saved inventories and acquisition bytes without changing the source case.
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};
use volgui::{analysis, case::CaseSnapshot};

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let input = PathBuf::from(
        args.next()
            .ok_or("Usage: reparse_network <case-directory> <output-directory>")?,
    );
    let output = PathBuf::from(args.next().ok_or("Specify an output directory")?);
    let mut document = CaseSnapshot::load(&input)?;
    let evidence = document
        .evidence
        .first()
        .ok_or("Case has no evidence")?
        .clone();
    let run = analysis::prepare(&evidence, analysis::NETWORK, vec![])?;
    document.runs.push(run.clone());
    let (table, message) =
        analysis::network::analyze(&input, &document, &run, &AtomicBool::new(false), &|_| {})?;
    fs::create_dir_all(&output).map_err(|e| e.to_string())?;
    let findings: Vec<_> = table.rows.iter().map(|r| &r.fields).collect();
    fs::write(
        output.join("findings.json"),
        serde_json::to_vec_pretty(&findings).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        output.join("network.csv"),
        table.csv(&(0..table.rows.len()).collect::<Vec<_>>()),
    )
    .map_err(|e| e.to_string())?;
    for row in &table.rows {
        if row.text("Finding") == "Meterpreter TCP configuration" {
            println!(
                "{}:{} at {}",
                row.text("IP"),
                row.text("Port"),
                row.text("Configuration offset")
            );
        }
    }
    println!("{message}");
    Ok(())
}
