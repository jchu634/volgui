use std::fs;

#[test]
fn lists_nested_dumps_but_excludes_engine_logs() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("nested")).unwrap();
    for name in [
        "stdout.json",
        "stderr.log",
        "process.dmp",
        "nested/file.dat",
    ] {
        fs::write(directory.path().join(name), b"dump").unwrap();
    }
    assert_eq!(
        volgui::extracted_files::list(directory.path()).unwrap(),
        vec![
            directory.path().join("nested/file.dat"),
            directory.path().join("process.dmp")
        ]
    );
}

#[test]
fn missing_output_directory_reports_an_error() {
    let directory = tempfile::tempdir().unwrap();
    assert!(volgui::extracted_files::list(&directory.path().join("missing")).is_err());
}
