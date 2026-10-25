// Stores and queries analysis results in SQLite.
//! SQLite owns completed records. UI queries return IDs and fetch only visible fields.
use rusqlite::{Connection, OptionalExtension, params, params_from_iter, types::Value as SqlValue};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use crate::{
    artifacts::ArtifactGroup,
    case::{Result, Run},
    volatility::{Record, Table, display_value},
};

pub const DATABASE: &str = "case.sqlite";
#[derive(Clone, Debug)]
pub struct ResultStore {
    path: PathBuf,
}
#[derive(Clone, Debug)]
pub struct StoredRecord {
    pub id: i64,
    pub run_id: String,
    pub row: usize,
    pub record: Record,
}
#[derive(Clone, Debug, Default)]
pub struct Query {
    pub filters: std::collections::BTreeMap<String, BTreeSet<String>>,
    pub runs: Vec<String>,
    pub text: String,
    pub sort: Option<(String, bool)>,
}
#[derive(Clone, Debug, Default)]
pub struct ResultIndex {
    pub columns: Vec<String>,
    pub ids: Vec<i64>,
}
#[derive(Clone, Debug)]
pub struct BrowserEntry {
    pub id: i64,
    pub title: String,
    pub pid: Option<String>,
    pub ppid: Option<String>,
    pub path: Option<String>,
}
#[derive(Clone, Debug, Default)]
pub struct ProcessRelations {
    pub parent: Option<BrowserEntry>,
    pub children: Vec<BrowserEntry>,
}
#[derive(Clone, Debug, Default)]
pub struct HandlePage {
    pub total: usize,
    pub offset: usize,
    pub records: Vec<StoredRecord>,
}

impl ResultStore {
    pub fn open(directory: &Path) -> Result<Self> {
        let store = Self {
            path: directory.join(DATABASE),
        };
        let db = store.connect()?;
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|e| e.to_string())?;
        if version > 1 {
            return Err("This case database uses a newer format".into());
        }
        db.execute_batch("PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS scans(run_id TEXT PRIMARY KEY,plugin TEXT NOT NULL,columns_json TEXT NOT NULL,row_count INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY,run_id TEXT NOT NULL REFERENCES scans(run_id) ON DELETE CASCADE,row_index INTEGER NOT NULL,depth INTEGER NOT NULL,fields_json TEXT NOT NULL,title TEXT NOT NULL,pid TEXT,ppid TEXT,path TEXT,search_text TEXT NOT NULL,UNIQUE(run_id,row_index));
            CREATE INDEX IF NOT EXISTS records_run ON records(run_id,row_index);
            CREATE INDEX IF NOT EXISTS records_pid ON records(run_id,pid);
            CREATE INDEX IF NOT EXISTS records_ppid ON records(run_id,ppid);
            CREATE VIRTUAL TABLE IF NOT EXISTS record_search USING fts5(search_text,tokenize='trigram');
            PRAGMA user_version=1;") .map_err(|e|format!("Cannot initialize results database: {e}"))?;
        Ok(store)
    }
    pub fn at(directory: &Path) -> Self {
        Self {
            path: directory.join(DATABASE),
        }
    }
    fn connect(&self) -> Result<Connection> {
        let db = Connection::open(&self.path).map_err(|e| e.to_string())?;
        db.busy_timeout(Duration::from_secs(10))
            .map_err(|e| e.to_string())?;
        db.pragma_update(None, "foreign_keys", true)
            .map_err(|e| e.to_string())?;
        db.create_scalar_function(
            "browser_domain",
            1,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                let value: Option<String> = ctx.get(0)?;
                Ok(value
                    .and_then(|value| url::Url::parse(&value).ok())
                    .and_then(|url| url.host_str().map(str::to_owned))
                    .unwrap_or_default())
            },
        )
        .map_err(|e| e.to_string())?;
        Ok(db)
    }
    pub fn contains(&self, run: &str) -> Result<bool> {
        self.connect()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM scans WHERE run_id=?1)",
                [run],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())
    }
    pub fn count(&self, run: &str) -> Result<usize> {
        self.connect()?
            .query_row("SELECT row_count FROM scans WHERE run_id=?1", [run], |r| {
                r.get::<_, i64>(0)
            })
            .optional()
            .map(|n| n.unwrap_or(0) as usize)
            .map_err(|e| e.to_string())
    }
    pub fn insert(&self, run: &Run, table: &Table) -> Result<()> {
        self.insert_cancellable(run, table, &AtomicBool::new(false))
    }
    pub fn insert_cancellable(&self, run: &Run, table: &Table, cancel: &AtomicBool) -> Result<()> {
        if cancel.load(Ordering::Relaxed) {
            return Err("Saving scan cancelled".into());
        }
        let db = self.connect()?;
        // Acquire the writer before reading, so simultaneous imports cannot try to
        // upgrade stale WAL snapshots. Keep lock waits cancellable for large scans.
        db.busy_timeout(Duration::from_millis(50))
            .map_err(|e| e.to_string())?;
        let tx = loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("Saving scan cancelled".into());
            }
            match rusqlite::Transaction::new_unchecked(
                &db,
                rusqlite::TransactionBehavior::Immediate,
            ) {
                Ok(tx) => break tx,
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.code == rusqlite::ErrorCode::DatabaseBusy => {}
                Err(error) => return Err(error.to_string()),
            }
        };
        // A run is immutable once imported. Repeating migration cannot change bookmark identities.
        if tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM scans WHERE run_id=?1)",
                [&run.id],
                |r| r.get::<_, bool>(0),
            )
            .map_err(|e| e.to_string())?
        {
            return Ok(());
        }
        tx.execute(
            "INSERT INTO scans VALUES(?1,?2,?3,?4)",
            params![
                run.id,
                run.plugin,
                serde_json::to_string(&table.columns).map_err(|e| e.to_string())?,
                table.rows.len() as i64
            ],
        )
        .map_err(|e| e.to_string())?;
        {
            let mut insert=tx.prepare("INSERT INTO records(run_id,row_index,depth,fields_json,title,pid,ppid,path,search_text) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)").map_err(|e|e.to_string())?;
            let mut search = tx
                .prepare("INSERT INTO record_search(rowid,search_text) VALUES(?1,?2)")
                .map_err(|e| e.to_string())?;
            for (index, row) in table.rows.iter().enumerate() {
                if index % 256 == 0 && cancel.load(Ordering::Relaxed) {
                    return Err("Saving scan cancelled".into());
                }
                let text = row
                    .fields
                    .values()
                    .map(display_value)
                    .collect::<Vec<_>>()
                    .join("\u{1f}")
                    .to_lowercase();
                let get = |names: &[&str]| {
                    names.iter().find_map(|n| {
                        row.fields
                            .get(*n)
                            .filter(|v| !v.is_null())
                            .map(display_value)
                    })
                };
                let title = match ArtifactGroup::for_plugin(&run.plugin) {
                    ArtifactGroup::Network => format!(
                        "{}:{} → {}:{}",
                        get(&["LocalAddr", "LocalAddress", "LocalIP"])
                            .unwrap_or_else(|| "?".into()),
                        get(&["LocalPort"]).unwrap_or_default(),
                        get(&[
                            "ForeignAddr",
                            "RemoteAddr",
                            "ForeignAddress",
                            "RemoteAddress"
                        ])
                        .unwrap_or_else(|| "?".into()),
                        get(&["ForeignPort", "RemotePort"]).unwrap_or_default()
                    ),
                    ArtifactGroup::Files => get(&["FileName", "Path", "FullPath", "Name"])
                        .unwrap_or_else(|| row.title()),
                    _ => row.title(),
                };
                insert
                    .execute(params![
                        run.id,
                        index as i64,
                        row.depth as i64,
                        serde_json::to_string(&row.fields).map_err(|e| e.to_string())?,
                        title,
                        get(&["PID", "Pid", "pid"]),
                        get(&["PPID", "PPid", "ppid"]),
                        get(&["FileName", "Path", "FullPath", "Name"]),
                        text
                    ])
                    .map_err(|e| e.to_string())?;
                search
                    .execute(params![tx.last_insert_rowid(), text])
                    .map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())
    }
    pub fn filter_values(&self, runs: &[String], column: &str) -> Result<Vec<String>> {
        if runs.is_empty() {
            return Ok(vec![]);
        }
        let expression = filter_expression(column)?;
        let db = self.connect()?;
        let marks = std::iter::repeat_n("?", runs.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut stmt = db.prepare(&format!("SELECT DISTINCT {expression} AS value FROM records r WHERE r.run_id IN ({marks}) ORDER BY value COLLATE NOCASE")).map_err(|e| e.to_string())?;
        stmt.query_map(params_from_iter(runs), |row| row.get(0))
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<Vec<String>>>()
            .map_err(|e| e.to_string())
    }
    pub fn query(&self, query: &Query) -> Result<ResultIndex> {
        self.query_filtered(query, None, false)
    }
    fn query_filtered(
        &self,
        query: &Query,
        pid: Option<&str>,
        all_handles: bool,
    ) -> Result<ResultIndex> {
        if query.runs.is_empty() {
            return Ok(ResultIndex::default());
        }
        let db = self.connect()?;
        let mut columns = BTreeSet::new();
        let mut groups = HashSet::new();
        for run in &query.runs {
            if let Some((json, plugin)) = db
                .query_row(
                    "SELECT columns_json,plugin FROM scans WHERE run_id=?1",
                    [run],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|e| e.to_string())?
            {
                columns
                    .extend(serde_json::from_str::<Vec<String>>(&json).map_err(|e| e.to_string())?);
                groups.insert(ArtifactGroup::for_plugin(&plugin));
            }
        }
        if groups.len() == 1 && groups.contains(&ArtifactGroup::Web) && columns.contains("URL") {
            columns.insert("Domain".into());
        }
        let mut columns: Vec<_> = columns.into_iter().collect();
        let preferred = [
            "ImageFileName",
            "COMM",
            "PID",
            "PPID",
            "Name",
            "Variable",
            "Value",
            "Data",
        ];
        columns.sort_by_key(|s| {
            preferred
                .iter()
                .position(|p| p == s)
                .unwrap_or(preferred.len())
        });
        let marks = std::iter::repeat_n("?", query.runs.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut sql = format!("SELECT r.id FROM records r WHERE r.run_id IN ({marks})");
        if !all_handles && groups.len() == 1 && groups.contains(&ArtifactGroup::Files) {
            sql.push_str(" AND (r.run_id NOT IN (SELECT run_id FROM scans WHERE plugin='windows.handles.Handles') OR json_extract(r.fields_json,'$.Type')='File')");
        }
        let mut values: Vec<SqlValue> = query.runs.iter().cloned().map(SqlValue::Text).collect();
        if let Some(pid) = pid {
            sql.push_str(" AND r.pid=?");
            values.push(SqlValue::Text(pid.into()));
        }
        for (column, selected) in &query.filters {
            let expression = filter_expression(column)?;
            if selected.is_empty() {
                sql.push_str(" AND 0");
            } else {
                let marks = std::iter::repeat_n("?", selected.len())
                    .collect::<Vec<_>>()
                    .join(",");
                sql.push_str(&format!(" AND {expression} IN ({marks})"));
                values.extend(selected.iter().cloned().map(SqlValue::Text));
            }
        }
        let text = query.text.to_lowercase();
        if !text.is_empty() {
            if text.chars().count() >= 3 {
                sql.push_str(
                    " AND r.id IN (SELECT rowid FROM record_search WHERE record_search MATCH ?)",
                );
                values.push(SqlValue::Text(format!("\"{}\"", text.replace('"', "\"\""))));
            }
            sql.push_str(" AND instr(r.search_text,?)>0");
            values.push(SqlValue::Text(text));
        }
        if let Some((column, descending)) = &query.sort {
            if !columns.contains(column) {
                return Err("Unknown sort column".into());
            }
            let direction = if *descending { "DESC" } else { "ASC" };
            sql.push_str(" ORDER BY ");
            let group = (groups.len() == 1)
                .then(|| groups.iter().next().copied())
                .flatten();
            let displayed = crate::result_table::columns(group, &columns);
            let sort_fields: Vec<_> = displayed
                .iter()
                .find(|c| &c.key == column)
                .map(|c| c.sort_fields().collect())
                .unwrap_or_else(|| vec![std::slice::from_ref(column)]);
            for (i, fields) in sort_fields.iter().enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                if fields.len() > 1 {
                    sql.push_str("COALESCE(");
                }
                for (j, field) in fields.iter().enumerate() {
                    if j > 0 {
                        sql.push(',');
                    }
                    if field == "Domain" && group == Some(ArtifactGroup::Web) {
                        sql.push_str(&filter_expression("Domain")?);
                        continue;
                    }
                    sql.push_str(if fields.len() > 1 {
                        "NULLIF(json_extract(r.fields_json,?),'')"
                    } else {
                        "json_extract(r.fields_json,?)"
                    });
                    values.push(SqlValue::Text(format!(
                        "$.{}",
                        serde_json::to_string(field).map_err(|e| e.to_string())?
                    )));
                }
                if fields.len() > 1 {
                    sql.push(')');
                }
                sql.push_str(&format!(" {direction}"));
            }
            sql.push_str(",r.id");
        } else {
            sql.push_str(" ORDER BY r.id");
        }
        let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
        let ids = stmt
            .query_map(params_from_iter(values), |r| r.get(0))
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<Vec<i64>>>()
            .map_err(|e| e.to_string())?;
        Ok(ResultIndex { columns, ids })
    }
    /// Handles are not restricted to the File objects used by file trees.
    pub fn process_handles(
        &self,
        runs: Vec<String>,
        pid: &str,
        offset: usize,
    ) -> Result<HandlePage> {
        let index = self.query_filtered(
            &Query {
                runs,
                ..Default::default()
            },
            Some(pid),
            true,
        )?;
        let offset = offset.min(index.ids.len().saturating_sub(1)) / 100 * 100;
        let records = self.fetch(&index.ids[offset..(offset + 100).min(index.ids.len())])?;
        Ok(HandlePage {
            total: index.ids.len(),
            offset,
            records,
        })
    }
    pub fn fetch(&self, ids: &[i64]) -> Result<Vec<StoredRecord>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let db = self.connect()?;
        let marks = std::iter::repeat_n("?", ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut stmt = db
            .prepare(&format!(
                "SELECT id,run_id,row_index,depth,fields_json FROM records WHERE id IN ({marks})"
            ))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params_from_iter(ids), |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? as usize,
                    r.get::<_, i64>(3)? as usize,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.map(|row| {
            let (id, run_id, row, depth, json) = row.map_err(|e| e.to_string())?;
            let fields = serde_json::from_str(&json).map_err(|e| e.to_string())?;
            let mut record = Record { fields, depth };
            crate::result_table::populate_domain(&mut record);
            Ok(StoredRecord {
                id,
                run_id,
                row,
                record,
            })
        })
        .collect()
    }
    /// Tree construction needs only hierarchy fields, even for large file scans.
    pub fn tree_entries(&self, runs: &[String]) -> Result<Vec<crate::result_tree::TreeEntry>> {
        if runs.is_empty() {
            return Ok(vec![]);
        }
        let db = self.connect()?;
        let marks = std::iter::repeat_n("?", runs.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut stmt = db.prepare(&format!(
            "SELECT id,run_id,depth,title,pid,ppid,COALESCE(NULLIF(json_extract(fields_json,'$.Name'),''),NULLIF(json_extract(fields_json,'$.FileName'),''),NULLIF(json_extract(fields_json,'$.Path'),''),NULLIF(json_extract(fields_json,'$.FilePath'),''),NULLIF(json_extract(fields_json,'$.FullPath'),''),path) FROM records WHERE run_id IN ({marks}) AND (run_id NOT IN (SELECT run_id FROM scans WHERE plugin='windows.handles.Handles') OR json_extract(fields_json,'$.Type')='File') ORDER BY id"
        )).map_err(|e| e.to_string())?;
        stmt.query_map(params_from_iter(runs), |r| {
            Ok(crate::result_tree::TreeEntry {
                id: r.get(0)?,
                run_id: r.get(1)?,
                depth: r.get::<_, i64>(2)? as usize,
                title: r.get(3)?,
                pid: r.get(4)?,
                ppid: r.get(5)?,
                path: r.get(6)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())
    }
    pub fn registry_entries(
        &self,
        runs: &[String],
    ) -> Result<Vec<crate::result_tree::RegistryEntry>> {
        if runs.is_empty() {
            return Ok(vec![]);
        }
        let db = self.connect()?;
        let marks = std::iter::repeat_n("?", runs.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut stmt = db
            .prepare(&format!(
                "SELECT id, fields_json FROM records WHERE run_id IN ({marks}) ORDER BY id"
            ))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params_from_iter(runs), |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        rows.map(|row| {
            let (id, json) = row.map_err(|e| e.to_string())?;
            let record = Record {
                fields: serde_json::from_str(&json).map_err(|e| e.to_string())?,
                depth: 0,
            };
            let offset = crate::investigation::registry::hive_offset(&record);
            let value_type = record.text("Type");
            Ok(crate::result_tree::RegistryEntry {
                id,
                hive: offset
                    .map(|offset| format!("Hive {offset:#x}"))
                    .unwrap_or_else(|| "Registry artifacts".into()),
                path: record.text("Key"),
                name: record.text("Name"),
                value_type: if value_type.is_empty() {
                    "Hive".into()
                } else {
                    value_type
                },
            })
        })
        .collect()
    }

    pub fn record(&self, run: &str, row: usize) -> Result<Option<StoredRecord>> {
        let id = self
            .connect()?
            .query_row(
                "SELECT id FROM records WHERE run_id=?1 AND row_index=?2",
                params![run, row as i64],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        id.map(|id| self.fetch(&[id]).map(|mut rows| rows.pop()))
            .transpose()
            .map(Option::flatten)
    }
    pub fn process_record(&self, runs: &[String], pid: &str) -> Result<Option<StoredRecord>> {
        let db = self.connect()?;
        for run in runs {
            let id = db
                .query_row(
                    "SELECT id FROM records WHERE run_id=?1 AND pid=?2 ORDER BY row_index LIMIT 1",
                    params![run, pid],
                    |r| r.get::<_, i64>(0),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            if let Some(id) = id {
                return self.fetch(&[id]).map(|mut records| records.pop());
            }
        }
        Ok(None)
    }
    pub fn process_relations(&self, runs: &[String], pid: &str) -> Result<ProcessRelations> {
        if runs.is_empty() || pid.is_empty() {
            return Ok(ProcessRelations::default());
        }
        let db = self.connect()?;
        let find = |field: &str, value: &str| -> Result<Vec<BrowserEntry>> {
            let marks = std::iter::repeat_n("?", runs.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut sql = format!(
                "SELECT id,title,pid,ppid,path FROM records WHERE run_id IN ({marks}) AND {field}=? ORDER BY CASE run_id "
            );
            let mut values: Vec<_> = runs.iter().cloned().map(SqlValue::Text).collect();
            values.push(SqlValue::Text(value.into()));
            for (i, run) in runs.iter().enumerate() {
                sql.push_str(&format!("WHEN ? THEN {i} "));
                values.push(SqlValue::Text(run.clone()));
            }
            sql.push_str("END,row_index");
            let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
            stmt.query_map(params_from_iter(values), |r| {
                Ok(BrowserEntry {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    pid: r.get(2)?,
                    ppid: r.get(3)?,
                    path: r.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())
        };
        let current = find("pid", pid)?.into_iter().next();
        let parent = match current.and_then(|r| r.ppid).filter(|p| p != pid) {
            Some(ppid) => find("pid", &ppid)?.into_iter().next(),
            None => None,
        };
        let mut seen = HashSet::new();
        let children = find("ppid", pid)?
            .into_iter()
            .filter(|r| {
                r.pid.as_deref() != Some(pid)
                    && r.pid.as_ref().is_some_and(|p| seen.insert(p.clone()))
            })
            .collect();
        Ok(ProcessRelations { parent, children })
    }
    pub fn table(&self, run: &str) -> Result<Table> {
        let index = self.query(&Query {
            runs: vec![run.into()],
            ..Default::default()
        })?;
        let mut rows = vec![];
        for chunk in index.ids.chunks(256) {
            let mut fetched = self.fetch(chunk)?;
            fetched.sort_by_key(|r| r.row);
            rows.extend(fetched.into_iter().map(|r| r.record));
        }
        Ok(Table {
            columns: index.columns,
            rows,
        })
    }
    pub fn export_csv(&self, query: &Query) -> Result<String> {
        let index = self.query(query)?;
        let mut output = Table {
            columns: index.columns.clone(),
            rows: vec![],
        }
        .csv(&[]);
        for chunk in index.ids.chunks(256) {
            let mut rows: HashMap<_, _> = self
                .fetch(chunk)?
                .into_iter()
                .map(|r| (r.id, r.record))
                .collect();
            let table = Table {
                columns: index.columns.clone(),
                rows: chunk.iter().filter_map(|id| rows.remove(id)).collect(),
            };
            let csv = table.csv(&(0..table.rows.len()).collect::<Vec<_>>());
            if let Some((_, body)) = csv.split_once("\r\n") {
                output.push_str(body);
            }
        }
        Ok(output)
    }
}

fn filter_expression(column: &str) -> Result<String> {
    match column {
        "Domain" => Ok("COALESCE(NULLIF(json_extract(r.fields_json,'$.Domain'),''),browser_domain(json_extract(r.fields_json,'$.URL')))".into()),
        "PID" | "Browser" | "Kind" => Ok(format!("COALESCE(CAST(json_extract(r.fields_json,'$.{column}') AS TEXT),'')")),
        _ => Err("Unknown filter column".into()),
    }
}
