//! Test-only CLI fixture. Never included in a normal application build.
use std::{io::Write, time::Duration};

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    eprintln!("Volatility 3 Framework test-fixture");
    if args == ["--help"] {
        println!(
            "Plugins:\n\n  PLUGIN\n    test.echo.Echo     Echo literal arguments and create an output artifact.\n    test.slow.Slow     Wait for cancellation.\n    test.fail.Fail     Emit a nonzero status.\n    test.bad.Bad       Emit malformed JSON."
        );
        return;
    }
    if args.last().is_some_and(|a| a == "--help") {
        println!("Plugin options:\n  --pid PID\n  --name NAME");
        return;
    }
    if args.iter().any(|a| a == "test.slow.Slow") {
        std::thread::sleep(Duration::from_secs(30));
    }
    if args.iter().any(|a| a == "test.fail.Fail") {
        eprintln!("Unsatisfied requirement plugins.Fail.kernel.symbol_table_name");
        std::process::exit(7);
    }
    if args.iter().any(|a| a == "test.bad.Bad") {
        println!("this is not JSON");
        return;
    }
    let mut stderr = std::io::stderr().lock();
    for _ in 0..160 {
        stderr.write_all(&vec![b'x'; 8192]).unwrap();
    }
    drop(stderr);
    if let Some(index) = args.iter().position(|a| a == "-o") {
        std::fs::write(
            std::path::Path::new(&args[index + 1]).join("artifact.txt"),
            "extracted fixture",
        )
        .unwrap();
    }
    println!(
        "{}",
        serde_json::json!([{ "Name": "fixture", "Arguments": args, "__children": [{ "Name": "child", "__children": [] }] }])
    );
}
