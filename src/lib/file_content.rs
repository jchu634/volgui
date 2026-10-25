//! Bounded, read-only inspection of recovered SQLite files.
use rusqlite::{Connection, OpenFlags, types::ValueRef};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct DatabasePage {
    pub path: PathBuf,
    pub tables: Vec<String>,
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub offset: usize,
    pub more: bool,
}

pub struct OpenDatabase {
    connection: Connection,
    _lease: Option<tempfile::NamedTempFile>,
}
impl std::ops::Deref for OpenDatabase {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

pub fn open_database(path: &Path) -> Result<OpenDatabase, String> {
    let _ = crate::extracted_files::open_artifact(path)?;
    let lease = if crate::object_store::stored_hash(path)?.is_some() {
        Some(crate::object_store::materialize(path)?)
    } else {
        None
    };
    let physical = lease.as_ref().map_or(path, |f| f.path());
    let mut uri = url::Url::from_file_path(physical).map_err(|_| "File path must be absolute")?;
    uri.set_query(Some("immutable=1"));
    Connection::open_with_flags(
        uri.as_str(),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map(|connection| OpenDatabase {
        connection,
        _lease: lease,
    })
    .map_err(|e| e.to_string())
}

pub fn database_page(
    path: &Path,
    selected: Option<&str>,
    offset: usize,
) -> Result<DatabasePage, String> {
    let db = open_database(path)?;
    // Bound work even for damaged or adversarial schemas. No views, triggers or user SQL run here.
    let mut budget = 0usize;
    db.progress_handler(
        1000,
        Some(move || {
            budget += 1000;
            budget > 2_000_000
        }),
    )
    .map_err(|e| e.to_string())?;
    let mut statement = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 101").map_err(|e| e.to_string())?;
    let tables = statement
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if tables.len() > 100 {
        return Err(
            "Database contains more than 100 tables. Export it for a full database inspection."
                .into(),
        );
    }
    let table = selected
        .and_then(|s| tables.iter().find(|t| t.as_str() == s))
        .or_else(|| tables.first())
        .ok_or("Database contains no ordinary tables")?
        .clone();
    let quote = |identifier: &str| format!("\"{}\"", identifier.replace('"', "\"\""));
    let metadata = db
        .prepare(&format!("SELECT * FROM {} LIMIT 0", quote(&table)))
        .map_err(|e| e.to_string())?;
    let columns: Vec<_> = metadata
        .column_names()
        .into_iter()
        .take(64)
        .map(str::to_owned)
        .collect();
    if metadata.column_count() > 64 {
        return Err(
            "Table has more than 64 columns. Export it for a full database inspection.".into(),
        );
    }
    // Read at most 1024 bytes per cell. SQLite applies substr before returning values to Rust.
    let fields = columns
        .iter()
        .map(|c| {
            let name = quote(c);
            format!("substr({name},1,1024)")
        })
        .collect::<Vec<_>>()
        .join(",");
    let mut statement = db
        .prepare(&format!(
            "SELECT {fields} FROM {} LIMIT 101 OFFSET ?1",
            quote(&table)
        ))
        .map_err(|e| e.to_string())?;
    let mut query = statement
        .query([i64::try_from(offset).map_err(|_| "Row offset is too large")?])
        .map_err(|e| e.to_string())?;
    let mut rows = Vec::new();
    while let Some(row) = query
        .next()
        .map_err(|e| format!("Cannot read database pages: {e}"))?
    {
        let mut cells = Vec::new();
        for index in 0..columns.len() {
            let cell = match row.get_ref(index).map_err(|e| e.to_string())? {
                ValueRef::Null => "NULL".into(),
                ValueRef::Integer(n) => n.to_string(),
                ValueRef::Real(n) => n.to_string(),
                ValueRef::Text(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                ValueRef::Blob(bytes) => format!(
                    "BLOB {}{}",
                    bytes
                        .iter()
                        .take(128)
                        .map(|b| format!("{b:02X}"))
                        .collect::<String>(),
                    if bytes.len() > 128 { "..." } else { "" }
                ),
            };
            cells.push(cell);
        }
        rows.push(cells);
    }
    let more = rows.len() > 100;
    rows.truncate(100);
    Ok(DatabasePage {
        path: path.into(),
        tables,
        table,
        columns,
        rows,
        offset,
        more,
    })
}

impl DatabasePage {
    pub fn text(&self) -> String {
        let mut text = String::new();
        for (i, row) in self.rows.iter().enumerate() {
            text.push_str(&format!("Row {}\n", self.offset + i + 1));
            for (column, value) in self.columns.iter().zip(row) {
                text.push_str(&format!("{column}: {value}\n"));
            }
            text.push('\n');
        }
        text
    }
}
