use serde_json::json;
use std::{fs, sync::atomic::AtomicBool};
use volgui::{
    case::{Case, Evidence, Run, RunStatus},
    memory_scan::{self, Address, Content, MEMMAP},
    results::StoredRecord,
    settings::Settings,
    volatility::{Installation, Outcome, Plugin, Record, Table},
};

const PSXVIEW: &str = "windows.malware.psxview.PsXView";

fn record(fields: serde_json::Value) -> Record {
    Table::parse(&json!([fields]).to_string())
        .unwrap()
        .rows
        .remove(0)
}

fn save(
    case: &mut Case,
    evidence: usize,
    plugin: &str,
    args: Vec<String>,
    rows: serde_json::Value,
) -> Run {
    let engine = Installation {
        settings: Settings::default(),
        version: "fixture".into(),
        user_memory_dumps: false,
        plugins: vec![Plugin {
            id: plugin.into(),
            description: String::new(),
        }],
    };
    let run = engine
        .prepare(
            &case.document.evidence[evidence],
            plugin,
            args,
            &case.directory.join("analyses"),
        )
        .unwrap();
    case.queue(run.clone()).unwrap();
    case.finish(
        &run.id,
        &Outcome {
            status: RunStatus::Completed,
            exit_code: Some(0),
            message: String::new(),
            table: Some(Table::parse(&rows.to_string()).unwrap()),
        },
    )
    .unwrap();
    run
}

fn fixture() -> (tempfile::TempDir, Case, StoredRecord) {
    let temp = tempfile::tempdir().unwrap();
    let mut case = Case::create(&temp.path().join("case"), "Memory scan").unwrap();
    for name in ["source.raw", "other.raw"] {
        let path = temp.path().join(name);
        fs::write(&path, vec![0; 8192]).unwrap();
        case.add_evidence(Evidence::inspect(&path, &AtomicBool::new(false), |_, _| {}).unwrap())
            .unwrap();
    }
    let fields = json!({"Offset(Virtual)":"0xffff800000001123", "PID":42, "Name":"test.exe"});
    let run = save(&mut case, 0, PSXVIEW, vec![], json!([fields]));
    let selected = StoredRecord {
        id: 1,
        run_id: run.id,
        row: 0,
        record: record(fields),
    };
    (temp, case, selected)
}

fn dump(case: &mut Case, evidence: usize, args: Vec<String>, rows: serde_json::Value) {
    let run = save(case, evidence, MEMMAP, args, rows);
    let directory = case.run_dir(&run.id);
    fs::create_dir_all(&directory).unwrap();
    let mut bytes = vec![0; 8192];
    bytes[0x1123] = 0xab;
    fs::write(directory.join("pid.42.dmp"), bytes).unwrap();
}

fn args() -> Vec<String> {
    ["--pid", "42", "--dump"].map(str::to_owned).to_vec()
}

#[test]
fn addresses_preserve_their_space_and_reject_ambiguous_or_invalid_values() {
    for name in ["Offset(V)", "Offset(Virtual)", "Virtual address"] {
        assert_eq!(
            Address::from_record(PSXVIEW, &record(json!({name:"0X1234", "PID":"42"}))),
            Some(Address::Virtual {
                pid: 42,
                offset: 0x1234
            })
        );
    }
    assert_eq!(
        Address::from_record(PSXVIEW, &record(json!({"Offset(Physical)":1234,"PID":42}))),
        Some(Address::Physical {
            pid: 42,
            offset: 1234
        })
    );
    assert_eq!(
        Address::from_record(
            "windows.malware.malfind.Malfind",
            &record(json!({"Start VPN":4096,"PID":42}))
        ),
        Some(Address::Virtual {
            pid: 42,
            offset: 4096
        })
    );
    assert_eq!(
        Address::from_record(
            "windows.vadyarascan.VadYaraScan",
            &record(json!({"Offset":0,"PID":42}))
        ),
        Some(Address::Virtual { pid: 42, offset: 0 })
    );
    for fields in [
        json!({"Offset":4096,"PID":42}),
        json!({"Offset(Virtual)":4096}),
        json!({"Offset(Virtual)":-1,"PID":42}),
        json!({"Offset(Virtual)":"0x1000 --pid 4","PID":42}),
        json!({"Offset(Virtual)":"18446744073709551616","PID":42}),
    ] {
        assert!(Address::from_record(PSXVIEW, &record(fields)).is_none());
    }
}

#[test]
fn scan_bytes_use_the_source_capture_and_translate_kernel_and_physical_addresses() {
    let (_temp, mut case, mut selected) = fixture();
    let rows = json!([{"Virtual":"0x800000001000", "Physical":0x9000,
        "Offset in File":0x1000,"Size":4096,"File output":"pid.42.dmp"}]);
    // An identical PID and virtual address in another capture cannot supply the bytes.
    dump(&mut case, 1, args(), rows.clone());
    match memory_scan::content(&case.directory, &case.document, &selected).unwrap() {
        Content::NeedsDump { evidence_id, pid } => {
            assert_eq!(evidence_id, case.document.evidence[0].id);
            assert_eq!(pid, 42);
        }
        _ => panic!("Must collect memory from the scan's capture"),
    }
    dump(&mut case, 0, args(), rows);
    // Also resolve after reopening, when the mappings come from the saved result store.
    let directory = case.directory.clone();
    drop(case);
    let case = Case::open(&directory).unwrap();
    for fields in [
        json!({"Offset(Virtual)":"0xffff800000001123", "PID":42}),
        json!({"Offset(Physical)":"0x9123", "PID":42}),
    ] {
        selected.record = record(fields);
        match memory_scan::content(&case.directory, &case.document, &selected).unwrap() {
            Content::Ready(path, offset) => {
                assert_eq!(offset, 0x1123);
                assert_eq!(fs::read(path).unwrap()[offset as usize], 0xab);
            }
            _ => panic!("Expected mapped bytes"),
        }
    }
    selected.record = record(json!({"Offset(Virtual)":"0xffff800000002000","PID":42}));
    assert!(memory_scan::content(&case.directory, &case.document, &selected).is_err());
}

#[test]
fn user_only_dumps_are_not_reused_and_truncated_ranges_are_rejected() {
    let (_temp, mut case, selected) = fixture();
    let rows = json!([{"Virtual":"0x800000001000", "Offset in File":0x1000,
        "Size":8192,"File output":"pid.42.dmp"}]);
    let mut user_args = args();
    user_args.push("--user-memory".into());
    dump(&mut case, 0, user_args, rows.clone());
    assert!(matches!(
        memory_scan::content(&case.directory, &case.document, &selected).unwrap(),
        Content::NeedsDump { .. }
    ));
    dump(&mut case, 0, args(), rows);
    assert!(memory_scan::content(&case.directory, &case.document, &selected).is_err());
}
