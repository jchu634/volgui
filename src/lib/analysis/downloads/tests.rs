use super::*;

#[test]
fn zone_stream_decodes_hex_and_preserves_the_local_name_and_referrer() {
    let bytes=b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://cdn.example.test/original.exe.bin\r\nReferrerUrl=https://example.test/start\r\n";
    let row = record(
        json!({"Filename":"renamed.exe","ADS Filename":"Zone.Identifier","Hexdump":bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")}),
    );
    let origin = zone_origin(&row).unwrap();
    assert_eq!(origin.text("Filename"), "renamed.exe");
    assert_eq!(origin.text("Website URL"), "https://example.test/start");
    assert_eq!(
        origin.text("URL"),
        "https://cdn.example.test/original.exe.bin"
    );
    for row in [
        record(
            json!({"Filename":"bad.exe","ADS Filename":"other","Content":String::from_utf8_lossy(bytes)}),
        ),
        record(
            json!({"Filename":"bad.exe","ADS Filename":"Zone.Identifier","Hexdump":"00 broken"}),
        ),
        record(
            json!({"Filename":"bad.exe","ADS Filename":"Zone.Identifier","Content":"[ZoneTransfer]\nHostUrl=javascript:alert(1)"}),
        ),
    ] {
        assert!(zone_origin(&row).is_none());
    }
}

#[test]
fn chromium_downloads_keep_redirects_target_path_state_and_optional_columns() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(r"CREATE TABLE downloads(id INTEGER,target_path TEXT,current_path TEXT,start_time INTEGER,end_time INTEGER,state INTEGER,opened INTEGER,tab_url TEXT,referrer TEXT);CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT);INSERT INTO downloads VALUES(7,'C:\Downloads\renamed.exe','C:\Downloads\partial.crdownload',13339000000000000,0,1,1,'https://example.test/tools','https://example.test/');INSERT INTO downloads_url_chains VALUES(7,1,'https://cdn.example.test/file.exe.bin'),(7,0,'https://example.test/get');").unwrap();
    let mut rows = Vec::new();
    chromium_downloads(&db, &mut rows, &AtomicBool::new(false)).unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.text("Filename"), "renamed.exe");
    assert_eq!(row.text("URL"), "https://cdn.example.test/file.exe.bin");
    assert_eq!(row.text("Website URL"), "https://example.test/tools");
    assert_eq!(row.fields["URL chain"][0][1], "https://example.test/get");
    assert_eq!(row.fields["Opened"], 1);
    assert!(!row.fields.contains_key("PID"));
    assert!(
        row.text("Interpretation")
            .contains("not an operating-system execution")
    );
    let old = Connection::open_in_memory().unwrap();
    old.execute_batch(r"CREATE TABLE downloads(id INTEGER,full_path TEXT,url TEXT,start_time INTEGER);INSERT INTO downloads VALUES(1,'C:\Downloads\old.exe','https://example.test/old.exe',1694657100);").unwrap();
    let mut rows = Vec::new();
    chromium_downloads(&old, &mut rows, &AtomicBool::new(false)).unwrap();
    assert!(rows[0].text("Time (UTC)").starts_with("2023-"));
    assert_eq!(rows[0].text("Filename"), "old.exe");
}

#[test]
fn executable_url_names_decode_without_changing_plus_or_matching_an_argument() {
    assert_eq!(
        executable_url("https://example.test/a%20b+1.exe?token=x"),
        Some("a b+1.exe".into())
    );
    assert_eq!(
        command_executable("\"C:\\Downloads\\payload.exe\" --file good.exe"),
        r"C:\Downloads\payload.exe"
    );
    assert_eq!(
        command_executable("notepad.exe C:\\Downloads\\payload.exe"),
        "notepad.exe"
    );
    assert!(executable_url("https://example.test/path.html?file=payload.exe").is_none());
    assert!(executable_url("https://example.test/x%2Fy.exe").is_none());
}

#[test]
fn website_names_and_url_lists_are_not_executable_url_leads() {
    for address in [
        "https://cookiepedia.co.uk/host/.app.onetrust.com?_ga=123",
        "https://cookiepedia.co.uk/host/app.onetrust.com",
        "https://deezer.com;https://liveone.com;https://jiosaavn.com",
        "https://vimeo.com;https://example.test/payload.exe",
        "https://vimeo.com;HTTPS://example.test/payload.exe",
        "https://example.test/sites/https%3A%2F%2Fother.test%2Fpayload.exe",
        "https://example.test/user-sync%3Fbea4%3D%23%7Buser.id%7D%26done%3Dexample.com",
        "ftp://example.test/payload.exe",
        "file:///C:/Downloads/payload.exe",
    ] {
        assert!(executable_url(address).is_none(), "{address}");
    }
    for address in [
        "https://www.autohotkey.com/download/ahk-v2.exe",
        "http://www.juno.it/wbadmin.exe.bin",
        "https://example.test/installer.MSI?ref=https://example.test/start",
    ] {
        assert!(executable_url(address).is_some(), "{address}");
    }
}

#[test]
fn unrelated_downloads_schema_does_not_produce_empty_downloads() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE downloads(id INTEGER,name TEXT,source TEXT,target TEXT);INSERT INTO downloads VALUES(1,'other','https://example.test/a','file:///C:/a');").unwrap();
    let mut rows = Vec::new();
    chromium_downloads(&db, &mut rows, &AtomicBool::new(false)).unwrap();
    assert!(rows.is_empty());
}
