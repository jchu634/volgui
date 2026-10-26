// Provides the test Volatility engine.
//! Test-only CLI fixture. Never included in a normal application build.
use std::{io::Write, time::Duration};

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let executable = std::env::current_exe().unwrap();
    let name = executable.file_stem().unwrap().to_string_lossy();
    let vol_rs = name.starts_with("vol-rs-");
    if !vol_rs {
        eprintln!("Volatility 3 Framework test-fixture");
    }
    if vol_rs && args == ["--version"] {
        println!("vol-rs 1.0.2");
        return;
    }
    if args == ["--help"] {
        println!(
            "Plugins:\n\n  PLUGIN\n    test.echo.Echo     Echo literal arguments and create an output artifact.\n    test.gated.Gated     Wait for an explicit release file.\n    test.slow.Slow     Wait for cancellation.\n    test.fail.Fail     Emit a nonzero status.\n    test.bad.Bad       Emit malformed JSON.\n    windows.dumpfiles.DumpFiles     Extract a single synthetic file object."
        );
        if vol_rs {
            println!("    windows.memmap.Memmap     Process memory map");
        }
        return;
    }
    if args.last().is_some_and(|a| a == "--help") {
        println!("Plugin options:\n  --pid PID\n  --name NAME");
        if vol_rs && name.contains("user-memory") {
            println!("  --user-memory     Omit kernel memory");
        }
        return;
    }
    if args.iter().any(|a| a == "test.slow.Slow") {
        std::thread::sleep(Duration::from_secs(30));
    }
    if args.iter().any(|a| a == "test.gated.Gated") {
        let output = std::path::Path::new(&args[args.iter().position(|a| a == "-o").unwrap() + 1]);
        std::fs::write(output.join("ready"), std::process::id().to_string()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !output.join("release").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "Test did not release the CLI"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if args.iter().any(|a| a == "test.fail.Fail") {
        if args.iter().any(|a| a == "--missing-symbols") {
            eprintln!("[WARN] Symbols are not available offline");
        }
        eprintln!("Unsatisfied requirement plugins.Fail.kernel.symbol_table_name");
        std::process::exit(7);
    }
    if args.iter().any(|a| a == "test.bad.Bad") {
        println!("this is not JSON");
        return;
    }
    if args.iter().any(|a| a == "windows.dumpfiles.DumpFiles") {
        let plugin = args
            .iter()
            .position(|a| a == "windows.dumpfiles.DumpFiles")
            .unwrap();
        let options = &args[plugin + 1..];
        assert_eq!(
            options.len(),
            2,
            "A per-file dump must select exactly one address"
        );
        assert!(matches!(options[0].as_str(), "--virtaddr" | "--physaddr"));
        let address = u64::from_str_radix(options[1].strip_prefix("0x").unwrap(), 16).unwrap();
        if address == 1 {
            println!("[]");
            return;
        }
        let output = std::path::Path::new(&args[args.iter().position(|a| a == "-o").unwrap() + 1]);
        let rows: Vec<_> = ["dat", "img"]
            .into_iter()
            .map(|extension| {
                let name = format!("file.{address:#x}.{extension}");
                std::fs::write(output.join(&name), format!("{} {address:#x}", options[0])).unwrap();
                serde_json::json!({"FileObject": address, "Result": name, "__children": []})
            })
            .collect();
        println!("{}", serde_json::json!(rows));
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
