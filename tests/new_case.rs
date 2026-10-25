// Checks case creation validation and the folder-per-case layout.
use std::{fs, path::Path};
use volgui::case::{Case, DATABASE};

fn rejects(parent: &Path, name: &str) {
    assert!(
        Case::create_named(parent, name).is_err(),
        "case name {name:?} must be rejected"
    );
}

#[test]
fn rejects_empty_blank_and_whitespace_only_names() {
    let parent = tempfile::tempdir().unwrap();
    for name in ["", " ", "   ", "\t", "\n", " \t "] {
        rejects(parent.path(), name);
    }
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn rejects_relative_component_and_separator_names() {
    let parent = tempfile::tempdir().unwrap();
    for name in [".", "..", "a/b", "a\\b", "a/b/c", "name/"] {
        rejects(parent.path(), name);
    }
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn rejects_windows_reserved_device_names() {
    let parent = tempfile::tempdir().unwrap();
    for name in [
        "CON", "con", "Nul", "PRN", "Aux", "NUL", "COM1", "com9", "LPT4", "lpt1",
    ] {
        rejects(parent.path(), name);
    }
}

#[test]
fn creates_case_folder_and_database_and_rejects_existing_paths() {
    let parent = tempfile::tempdir().unwrap();
    let case = Case::create_named(parent.path(), "Investigation A").unwrap();
    assert_eq!(
        case.directory.file_name().unwrap().to_string_lossy(),
        "Investigation A"
    );
    assert!(case.directory.join(DATABASE).is_file());
    drop(case);
    // Exclusive: the same folder cannot be claimed as a new case.
    assert!(Case::create_named(parent.path(), "Investigation A").is_err());
    // Existing folders are never replaced.
    fs::create_dir(parent.path().join("taken")).unwrap();
    assert!(Case::create_named(parent.path(), "taken").is_err());
    assert!(!parent.path().join("taken").join(DATABASE).exists());
}

#[test]
fn creates_missing_parent_directories() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("collections").join("2024");
    let case = Case::create_named(&parent, "Case").unwrap();
    assert!(case.directory.join(DATABASE).is_file());
}

#[test]
fn open_accepts_case_folder_or_database_and_rejects_legacy_manifest() {
    let parent = tempfile::tempdir().unwrap();
    let case = Case::create_named(parent.path(), "Reopen").unwrap();
    let directory = case.directory.clone();
    drop(case);

    assert!(Case::open(&directory).is_ok());
    assert!(Case::open(&directory.join(DATABASE)).is_ok());

    // A folder holding only the legacy JSON manifest is not a case.
    let legacy = parent.path().join("legacy");
    fs::create_dir(&legacy).unwrap();
    fs::write(legacy.join("case.volgui.json"), "{}").unwrap();
    assert!(Case::open(&legacy).is_err());
    assert!(Case::open(&legacy.join("case.volgui.json")).is_err());
    assert!(legacy.join("case.volgui.json").is_file());
}
