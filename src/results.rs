//! SQLite owns completed records. UI queries return IDs and fetch only visible fields.
use rusqlite::{Connection, OptionalExtension, params, params_from_iter, types::Value as SqlValue};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
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
#[derive(Clone, Debug)]
pub struct ProcessNode {
    pub entry: BrowserEntry,
    pub children: Vec<ProcessNode>,
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
        let mut db = self.connect()?;
        let tx = db.transaction().map_err(|e| e.to_string())?;
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
    pub fn query(&self, query: &Query) -> Result<ResultIndex> {
        if query.runs.is_empty() {
            return Ok(ResultIndex::default());
        }
        let db = self.connect()?;
        let mut columns = BTreeSet::new();
        for run in &query.runs {
            if let Some(json) = db
                .query_row(
                    "SELECT columns_json FROM scans WHERE run_id=?1",
                    [run],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
            {
                columns
                    .extend(serde_json::from_str::<Vec<String>>(&json).map_err(|e| e.to_string())?);
            }
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
        let mut values: Vec<SqlValue> = query.runs.iter().cloned().map(SqlValue::Text).collect();
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
            sql.push_str(if *descending {
                " ORDER BY json_extract(r.fields_json,?) DESC,r.id"
            } else {
                " ORDER BY json_extract(r.fields_json,?) ASC,r.id"
            });
            values.push(SqlValue::Text(format!(
                "$.{}",
                serde_json::to_string(column).map_err(|e| e.to_string())?
            )));
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
            Ok(StoredRecord {
                id,
                run_id,
                row,
                record: Record { fields, depth },
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
    pub fn navigation(&self, query: &Query) -> Result<Vec<BrowserEntry>> {
        if query.runs.is_empty() {
            return Ok(vec![]);
        }
        let db = self.connect()?;
        let marks = std::iter::repeat_n("?", query.runs.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut values: Vec<SqlValue> = query.runs.iter().cloned().map(SqlValue::Text).collect();
        let mut sql =
            format!("SELECT id,title,pid,ppid,path FROM records WHERE run_id IN ({marks})");
        if !query.text.is_empty() {
            sql.push_str(" AND instr(search_text,?)>0");
            values.push(SqlValue::Text(query.text.to_lowercase()));
        }
        sql.push_str(" ORDER BY CASE run_id ");
        for (i, run) in query.runs.iter().enumerate() {
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

/// Each process appears once. Cycles and missing parents become roots instead of disappearing.
pub fn process_forest(entries: &[BrowserEntry]) -> Vec<ProcessNode> {
    let mut chosen = BTreeMap::new();
    let mut loose = vec![];
    for e in entries {
        if let Some(pid) = &e.pid {
            chosen.entry(pid.clone()).or_insert_with(|| e.clone());
        } else {
            loose.push(e.clone());
        }
    }
    let mut parents: HashMap<String, String> = chosen
        .iter()
        .filter_map(|(pid, e)| {
            e.ppid
                .as_ref()
                .filter(|ppid| *ppid != pid && chosen.contains_key(*ppid))
                .map(|p| (pid.clone(), p.clone()))
        })
        .collect();
    for pid in chosen.keys() {
        let mut seen = HashSet::new();
        let mut cursor = pid.clone();
        while let Some(p) = parents.get(&cursor) {
            if !seen.insert(cursor.clone()) || seen.len() >= 100 {
                parents.remove(&cursor);
                break;
            }
            cursor = p.clone();
        }
    }
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    for (pid, parent) in &parents {
        children
            .entry(parent.clone())
            .or_default()
            .push(pid.clone());
    }
    fn build(
        pid: &str,
        chosen: &BTreeMap<String, BrowserEntry>,
        children: &HashMap<String, Vec<String>>,
        depth: usize,
    ) -> ProcessNode {
        let mut nested = if depth < 100 {
            children
                .get(pid)
                .into_iter()
                .flatten()
                .map(|id| build(id, chosen, children, depth + 1))
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        nested.sort_by(|a, b| a.entry.title.cmp(&b.entry.title));
        ProcessNode {
            entry: chosen[pid].clone(),
            children: nested,
        }
    }
    let mut roots = chosen
        .keys()
        .filter(|id| !parents.contains_key(*id))
        .map(|id| build(id, &chosen, &children, 0))
        .collect::<Vec<_>>();
    roots.extend(loose.into_iter().map(|entry| ProcessNode {
        entry,
        children: vec![],
    }));
    roots.sort_by(|a, b| a.entry.title.cmp(&b.entry.title));
    roots
}
