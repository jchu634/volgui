//! Reparse saved inventories and acquisition bytes without changing the source case.
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};
use volgui::{
    analysis,
    case::{Case, CaseSnapshot, RunStatus},
    volatility::Outcome,
};

fn main() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let input = PathBuf::from(
        args.next()
            .ok_or("Usage: reparse_network <case-directory> <output-directory> [--save-case]")?,
    );
    let output = PathBuf::from(args.next().ok_or("Specify an output directory")?);
    let save_case = match args.next() {
        None => false,
        Some(flag) if flag == "--save-case" => true,
        _ => return Err("Expected --save-case".into()),
    };
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
    if save_case {
        let mut case = Case::create(&output.join("case"), "Network configuration validation")?;
        case.add_evidence(evidence)?;
        case.queue(run.clone())?;
        case.finish(
            &run.id,
            &Outcome {
                status: RunStatus::Completed,
                exit_code: Some(0),
                message: message.clone(),
                table: Some(table.clone()),
            },
        )?;
    }
    fs::write(
        output.join("network.csv"),
        table.csv(&(0..table.rows.len()).collect::<Vec<_>>()),
    )
    .map_err(|e| e.to_string())?;
    for row in &table.rows {
        if row.text("Finding").contains("Meterpreter") {
            println!(
                "{}:{} at {} | {} | payload {}",
                row.text("IP"),
                row.text("Port"),
                row.text("Configuration offset"),
                row.text("Finding"),
                row.text("Payload UUID")
            );
        }
    }
    println!("{message}");
    Ok(())
}
