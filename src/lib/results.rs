// Stores and queries analysis results in SQLite.
//! SQLite owns completed records. UI queries return IDs and fetch only visible fields.
use rusqlite::{Connection, OptionalExtension, params, params_from_iter, types::Value as SqlValue};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    artifacts::ArtifactGroup,
    case::{Result, Run},
    volatility::{Record, Table, display_value},
};

#[path = "identity.rs"]
mod identity;

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
/// An immutable finding may have several stable run/row occurrences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationProvenance {
    pub record_id: i64,
    pub run_id: String,
    pub row: usize,
}
#[derive(Clone, Debug)]
pub struct EntityObservation {
    pub observation_id: i64,
    pub evidence_id: String,
    pub plugin: String,
    pub record: Record,
    pub provenance: Vec<ObservationProvenance>,
}
/// Conflicting values are separate facts; sources identify immutable observations.
#[derive(Clone, Debug)]
pub struct EntityFact {
    pub field: String,
    pub value: serde_json::Value,
    pub observations: Vec<i64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityRelation {
    pub subject: i64,
    pub predicate: String,
    pub object: i64,
    pub observation_id: i64,
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
    /// Every run/row occurrence in the requested network scope, including repeated findings.
    /// Unlike the general result browser, an endpoint investigation must not collapse runs.
    pub fn network_ids(&self, runs: &[String]) -> Result<Vec<i64>> {
        if runs.is_empty() {
            return Ok(Vec::new());
        }
        let db = self.connect()?;
        let marks = std::iter::repeat_n("?", runs.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut statement = db
            .prepare(&format!(
                "SELECT r.id FROM records r JOIN scans s USING(run_id) WHERE r.run_id IN ({marks})
                 AND (s.plugin != ? OR json_extract(r.fields_json,'$.Finding') = ?)
                 ORDER BY r.run_id,r.row_index,r.id"
            ))
            .map_err(|e| e.to_string())?;
        let mut values = runs.to_vec();
        values.push(crate::analysis::DOWNLOADS.into());
        values.push("Meterpreter TCP configuration".into());
        statement
            .query_map(params_from_iter(values), |r| r.get(0))
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())
    }
    pub fn open(directory: &Path) -> Result<Self> {
        let store = Self {
            path: directory.join(DATABASE),
        };
        let db = crate::database::initialize(directory)?;
        db.execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS scans(run_id TEXT PRIMARY KEY,evidence_id TEXT NOT NULL,plugin TEXT NOT NULL,columns_json TEXT NOT NULL,row_count INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS entities(
                id INTEGER PRIMARY KEY,evidence_id TEXT NOT NULL,kind TEXT NOT NULL,
                identity_key TEXT NOT NULL,UNIQUE(evidence_id,identity_key));
            CREATE TABLE IF NOT EXISTS observations(
                id INTEGER PRIMARY KEY,evidence_id TEXT NOT NULL,plugin TEXT NOT NULL,
                fields_sha256 BLOB NOT NULL CHECK(length(fields_sha256)=32),
                depth INTEGER NOT NULL CHECK(depth>=0),fields_json TEXT NOT NULL,
                base_entity_id INTEGER NOT NULL REFERENCES entities(id),
                title TEXT NOT NULL,pid TEXT,ppid TEXT,path TEXT,search_text TEXT NOT NULL,
                process_role TEXT NOT NULL,process_identity_json TEXT,
                UNIQUE(evidence_id,plugin,fields_sha256,depth));
            CREATE INDEX IF NOT EXISTS observations_pid ON observations(evidence_id,pid) WHERE pid IS NOT NULL;
            CREATE INDEX IF NOT EXISTS observations_ppid ON observations(evidence_id,ppid) WHERE ppid IS NOT NULL;
            CREATE INDEX IF NOT EXISTS observations_process_scope ON observations(evidence_id,id) WHERE process_role!='none';
            CREATE TABLE IF NOT EXISTS run_observations(
                id INTEGER PRIMARY KEY,run_id TEXT NOT NULL REFERENCES scans(run_id),
                row_index INTEGER NOT NULL CHECK(row_index>=0),
                observation_id INTEGER NOT NULL REFERENCES observations(id),UNIQUE(run_id,row_index));
            CREATE INDEX IF NOT EXISTS run_observations_finding ON run_observations(observation_id,run_id);
            CREATE TABLE IF NOT EXISTS observation_entities(
                observation_id INTEGER PRIMARY KEY REFERENCES observations(id),
                entity_id INTEGER NOT NULL REFERENCES entities(id));
            CREATE INDEX IF NOT EXISTS observation_entities_entity ON observation_entities(entity_id,observation_id);
            CREATE TABLE IF NOT EXISTS observation_facts(
                observation_id INTEGER NOT NULL REFERENCES observations(id),field TEXT NOT NULL,
                value_json TEXT NOT NULL,PRIMARY KEY(observation_id,field)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS entity_relations(
                subject INTEGER NOT NULL REFERENCES entities(id),predicate TEXT NOT NULL,
                object INTEGER NOT NULL REFERENCES entities(id),
                observation_id INTEGER NOT NULL REFERENCES observations(id),
                PRIMARY KEY(subject,predicate,object,observation_id)) WITHOUT ROWID;
            CREATE VIEW IF NOT EXISTS entity_facts AS
                SELECT e.entity_id,f.observation_id,f.field,f.value_json
                FROM observation_entities e JOIN observation_facts f USING(observation_id);
            CREATE VIEW IF NOT EXISTS records AS
                SELECT r.id,r.run_id,r.row_index,r.observation_id,e.entity_id,
                    o.depth,o.fields_json,o.title,o.pid,o.ppid,o.path,o.search_text
                FROM run_observations r JOIN observations o ON o.id=r.observation_id
                JOIN observation_entities e ON e.observation_id=o.id;
            CREATE VIRTUAL TABLE IF NOT EXISTS record_search USING fts5(search_text,tokenize='trigram');
            CREATE TRIGGER IF NOT EXISTS observations_immutable_update BEFORE UPDATE ON observations
                BEGIN SELECT RAISE(ABORT,'Observations are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS observations_immutable_delete BEFORE DELETE ON observations
                BEGIN SELECT RAISE(ABORT,'Observations are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS run_observations_immutable_update BEFORE UPDATE ON run_observations
                BEGIN SELECT RAISE(ABORT,'Run observations are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS run_observations_immutable_delete BEFORE DELETE ON run_observations
                BEGIN SELECT RAISE(ABORT,'Run observations are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS observation_facts_immutable_update BEFORE UPDATE ON observation_facts
                BEGIN SELECT RAISE(ABORT,'Observation facts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS observation_facts_immutable_delete BEFORE DELETE ON observation_facts
                BEGIN SELECT RAISE(ABORT,'Observation facts are immutable'); END;
            COMMIT;") .map_err(|e|format!("Cannot initialize results database: {e}"))?;
        Ok(store)
    }
    pub fn at(directory: &Path) -> Self {
        Self {
            path: directory.join(DATABASE),
        }
    }
    fn connect(&self) -> Result<Connection> {
        let db = crate::database::connect(self.path.parent().ok_or("Missing case directory")?)?;
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
        let tx = crate::database::write_transaction(&db, cancel)?;
        // A run is immutable once imported. Retrying cannot change bookmark identities.
        if let Some((evidence, plugin)) = tx
            .query_row(
                "SELECT evidence_id,plugin FROM scans WHERE run_id=?1",
                [&run.id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?
        {
            if evidence != run.evidence_id || plugin != run.plugin {
                return Err("Imported run identity belongs to another evidence or plugin".into());
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO scans(run_id,evidence_id,plugin,columns_json,row_count) VALUES(?1,?2,?3,?4,?5)",
            params![
                run.id,
                run.evidence_id,
                run.plugin,
                serde_json::to_string(&table.columns).map_err(|e| e.to_string())?,
                table.rows.len() as i64
            ],
        )
        .map_err(|e| e.to_string())?;
        {
            let mut find = tx.prepare_cached("SELECT id,fields_json FROM observations WHERE evidence_id=?1 AND plugin=?2 AND fields_sha256=?3 AND depth=?4").map_err(|e| e.to_string())?;
            let mut entity = tx
                .prepare_cached(
                    "INSERT OR IGNORE INTO entities(evidence_id,kind,identity_key) VALUES(?1,?2,?3)",
                )
                .map_err(|e| e.to_string())?;
            let mut insert = tx.prepare_cached("INSERT INTO observations(evidence_id,plugin,fields_sha256,depth,fields_json,base_entity_id,title,pid,ppid,path,search_text,process_role,process_identity_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)").map_err(|e| e.to_string())?;
            let mut occurrence = tx.prepare_cached("INSERT INTO run_observations(run_id,row_index,observation_id) VALUES(?1,?2,?3)").map_err(|e| e.to_string())?;
            let mut membership = tx
                .prepare_cached(
                    "INSERT INTO observation_entities(observation_id,entity_id) VALUES(?1,?2)",
                )
                .map_err(|e| e.to_string())?;
            let mut fact = tx.prepare_cached("INSERT INTO observation_facts(observation_id,field,value_json) VALUES(?1,?2,?3)").map_err(|e| e.to_string())?;
            let mut search = tx
                .prepare("INSERT INTO record_search(rowid,search_text) VALUES(?1,?2)")
                .map_err(|e| e.to_string())?;
            for (index, row) in table.rows.iter().enumerate() {
                if index % 256 == 0 && cancel.load(Ordering::Relaxed) {
                    return Err("Saving scan cancelled".into());
                }
                let mut fields = serde_json::to_value(&row.fields).map_err(|e| e.to_string())?;
                canonicalize(&mut fields);
                let json = serde_json::to_string(&fields).map_err(|e| e.to_string())?;
                let hash = Sha256::digest(json.as_bytes());
                let existing = find
                    .query_row(
                        params![
                            run.evidence_id,
                            run.plugin,
                            hash.as_slice(),
                            row.depth as i64
                        ],
                        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
                    )
                    .optional()
                    .map_err(|e| e.to_string())?;
                if let Some((observation_id, original)) = existing {
                    if original != json {
                        return Err("Observation SHA-256 collision or corrupt stored fields".into());
                    }
                    occurrence
                        .execute(params![run.id, index as i64, observation_id])
                        .map_err(|e| e.to_string())?;
                    continue;
                }
                let text = fields
                    .as_object()
                    .ok_or("Invalid observation fields")?
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
                let process = identity::describe(&run.plugin, row);
                let file_key = identity::file_key(&run.plugin, row);
                let kind = if file_key.is_some() {
                    "file_object"
                } else if process.role == "inventory" || process.role == "command" {
                    "process"
                } else if process.role == "handle" {
                    "handle"
                } else {
                    "finding"
                };
                let key =
                    file_key.unwrap_or_else(|| format!("{}:{}:{hash:x}", run.plugin, row.depth));
                let added = entity
                    .execute(params![run.evidence_id, kind, key])
                    .map_err(|e| e.to_string())?;
                let entity_id = if added == 0 {
                    tx.query_row(
                        "SELECT id FROM entities WHERE evidence_id=?1 AND identity_key=?2",
                        params![run.evidence_id, key],
                        |r| r.get(0),
                    )
                    .map_err(|e| e.to_string())?
                } else {
                    tx.last_insert_rowid()
                };
                insert
                    .execute(params![
                        run.evidence_id,
                        run.plugin,
                        hash.as_slice(),
                        row.depth as i64,
                        json,
                        entity_id,
                        title,
                        identity::number(row, &["PID", "Pid", "pid"]),
                        identity::number(row, &["PPID", "PPid", "ppid"]),
                        get(&["FileName", "Path", "FullPath", "Name"]),
                        text,
                        process.role,
                        serde_json::to_string(&process).map_err(|e| e.to_string())?
                    ])
                    .map_err(|e| e.to_string())?;
                let observation_id = tx.last_insert_rowid();
                membership
                    .execute(params![observation_id, entity_id])
                    .map_err(|e| e.to_string())?;
                // Numeric mapping rows already retain their immutable fields.
                // Expanding millions of ranges into EAV facts and trigram postings
                // adds no entity enrichment and dominates the case database.
                if run.plugin != "windows.memmap.Memmap" {
                    for (field, value) in fields.as_object().ok_or("Invalid observation fields")? {
                        fact.execute(params![
                            observation_id,
                            field,
                            serde_json::to_string(value).map_err(|e| e.to_string())?
                        ])
                        .map_err(|e| e.to_string())?;
                    }
                    search
                        .execute(params![observation_id, text])
                        .map_err(|e| e.to_string())?;
                }
                occurrence
                    .execute(params![run.id, index as i64, observation_id])
                    .map_err(|e| e.to_string())?;
            }
        }
        identity::reconcile(&tx, &run.evidence_id, cancel)?;
        if cancel.load(Ordering::Relaxed) {
            return Err("Saving scan cancelled".into());
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
        let mut values: Vec<SqlValue> = query.runs.iter().cloned().map(SqlValue::Text).collect();
        append_representatives(&mut sql, &mut values, &query.runs, "r");
        if groups.len() == 1 && groups.contains(&ArtifactGroup::Downloads) {
            // Older download reports kept payload configuration alongside download findings.
            // Keep the immutable source row, but present it through Network instead.
            sql.push_str(" AND COALESCE(json_extract(r.fields_json,'$.Finding'),'') != 'Meterpreter TCP configuration'");
        }
        if !all_handles && groups.len() == 1 && groups.contains(&ArtifactGroup::Files) {
            sql.push_str(" AND (r.run_id NOT IN (SELECT run_id FROM scans WHERE plugin='windows.handles.Handles') OR json_extract(r.fields_json,'$.Type')='File')");
        }
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
                    " AND (r.observation_id IN (SELECT rowid FROM record_search WHERE record_search MATCH ?) OR r.run_id IN (SELECT run_id FROM scans WHERE plugin='windows.memmap.Memmap'))",
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
        let db = self.connect()?;
        let Some(evidence) = single_evidence(&db, &runs)? else {
            return Ok(HandlePage::default());
        };
        if inventory_entities(&db, &evidence, pid)?.len() > 1 {
            return Ok(HandlePage::default());
        }
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
        fetch_records(&self.connect()?, ids)
    }
    /// The default fetch preserves the original finding. This opt-in projection
    /// fills absent fields only when the entity has one non-null value for them.
    /// Generated fact provenance attributes additions and conflicts to their
    /// original observations and run rows, rather than to the selected run.
    pub fn fetch_enriched(&self, ids: &[i64]) -> Result<Vec<StoredRecord>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let mut db = self.connect()?;
        let tx = db.transaction().map_err(|e| e.to_string())?;
        let mut records = fetch_records(&tx, ids)?;
        let marks = std::iter::repeat_n("?", ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut statement = tx
            .prepare(&format!(
                "SELECT id,entity_id FROM records WHERE id IN ({marks})"
            ))
            .map_err(|e| e.to_string())?;
        let memberships = statement
            .query_map(params_from_iter(ids), |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<HashMap<_, _>>>()
            .map_err(|e| e.to_string())?;
        let entities: Vec<_> = memberships
            .values()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let facts = entity_facts_for(&tx, &entities)?;
        let sources = entity_sources(&tx, &entities)?;
        for record in &mut records {
            let Some(entity) = memberships.get(&record.id) else {
                continue;
            };
            let mut fields = BTreeMap::<&str, Vec<&EntityFact>>::new();
            for fact in facts.get(entity).into_iter().flatten() {
                fields.entry(&fact.field).or_default().push(fact);
            }
            let mut attribution = Vec::new();
            for (field, facts) in fields {
                let values: Vec<_> = facts.iter().filter(|fact| !fact.value.is_null()).collect();
                let original = record.record.fields.get(field);
                let enriched = original.is_none() && values.len() == 1;
                let conflict = values.len() > 1
                    || original
                        .is_some_and(|original| values.iter().any(|fact| &fact.value != original));
                if enriched {
                    record
                        .record
                        .fields
                        .insert(field.into(), values[0].value.clone());
                }
                if !enriched && !conflict {
                    continue;
                }
                let alternatives: Vec<_> = facts.iter().map(|fact| {
                    let observations: Vec<_> = fact.observations.iter().map(|observation| {
                        let provenance: Vec<_> = sources.get(observation).into_iter().flatten().map(|source|
                            serde_json::json!({"Run ID":source.run_id,"Row index":source.row,"Record ID":source.record_id})
                        ).collect();
                        serde_json::json!({"Observation ID":observation,"Sources":provenance})
                    }).collect();
                    serde_json::json!({"Value":fact.value,"Observations":observations})
                }).collect();
                attribution.push(serde_json::json!({
                    "Field":field,"Displayed value":record.record.fields.get(field),
                    "Enriched":enriched,"Conflict":conflict,"Values":alternatives,
                }));
            }
            if !attribution.is_empty() {
                let mut label = "Fact provenance".to_owned();
                // Preserve even a plugin field that uses our display label.
                while record.record.fields.contains_key(&label) {
                    label.push_str(" (generated)");
                }
                record.record.fields.insert(
                    label,
                    serde_json::json!({
                        "Entity ID":entity,"Selected run":record.run_id,
                        "Selected row index":record.row,"Fields":attribution,
                    }),
                );
            }
        }
        Ok(records)
    }
    pub fn entity_for_record(&self, record_id: i64) -> Result<Option<i64>> {
        self.connect()?
            .query_row(
                "SELECT entity_id FROM records WHERE id=?1",
                [record_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    }
    pub fn observation_for_record(&self, record_id: i64) -> Result<Option<i64>> {
        self.connect()?
            .query_row(
                "SELECT observation_id FROM run_observations WHERE id=?1",
                [record_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    }
    pub fn observation_provenance(
        &self,
        observation_id: i64,
    ) -> Result<Vec<ObservationProvenance>> {
        provenance(&self.connect()?, observation_id)
    }
    pub fn entity_observations(&self, entity_id: i64) -> Result<Vec<EntityObservation>> {
        let db = self.connect()?;
        let mut statement = db
            .prepare(
                "SELECT o.id,o.evidence_id,o.plugin,o.depth,o.fields_json
            FROM observation_entities e JOIN observations o ON o.id=e.observation_id
            WHERE e.entity_id=?1 ORDER BY o.id",
            )
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([entity_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.map(|row| {
            let (observation_id, evidence_id, plugin, depth, json) =
                row.map_err(|e| e.to_string())?;
            Ok(EntityObservation {
                observation_id,
                evidence_id,
                plugin,
                record: Record {
                    depth: depth as usize,
                    fields: serde_json::from_str(&json).map_err(|e| e.to_string())?,
                },
                provenance: provenance(&db, observation_id)?,
            })
        })
        .collect()
    }
    pub fn entity_facts(&self, entity_id: i64) -> Result<Vec<EntityFact>> {
        Ok(entity_facts_for(&self.connect()?, &[entity_id])?
            .remove(&entity_id)
            .unwrap_or_default())
    }
    pub fn entity_relations(&self, entity_id: i64) -> Result<Vec<EntityRelation>> {
        let db = self.connect()?;
        let mut statement = db
            .prepare(
                "SELECT subject,predicate,object,observation_id FROM entity_relations
            WHERE subject=?1 OR object=?1 ORDER BY subject,predicate,object,observation_id",
            )
            .map_err(|e| e.to_string())?;
        statement
            .query_map([entity_id], |r| {
                Ok(EntityRelation {
                    subject: r.get(0)?,
                    predicate: r.get(1)?,
                    object: r.get(2)?,
                    observation_id: r.get(3)?,
                })
            })
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())
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
        let mut sql = format!(
            "SELECT id,run_id,depth,title,pid,ppid,COALESCE(NULLIF(json_extract(fields_json,'$.Name'),''),NULLIF(json_extract(fields_json,'$.FileName'),''),NULLIF(json_extract(fields_json,'$.Path'),''),NULLIF(json_extract(fields_json,'$.FilePath'),''),NULLIF(json_extract(fields_json,'$.FullPath'),''),path) FROM records r WHERE run_id IN ({marks}) AND (run_id NOT IN (SELECT run_id FROM scans WHERE plugin='windows.handles.Handles') OR json_extract(fields_json,'$.Type')='File')"
        );
        let mut values = runs.iter().cloned().map(SqlValue::Text).collect();
        append_representatives(&mut sql, &mut values, runs, "r");
        sql.push_str(" ORDER BY id");
        let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
        stmt.query_map(params_from_iter(values), |r| {
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
    /// Load module hierarchy fields without materializing every module's details.
    pub fn module_entries(&self, runs: &[String]) -> Result<Vec<crate::result_tree::ModuleEntry>> {
        if runs.is_empty() {
            return Ok(vec![]);
        }
        let db = self.connect()?;
        let marks = std::iter::repeat_n("?", runs.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut sql = format!(
            "SELECT id,run_id,
             CAST(COALESCE(json_extract(fields_json,'$.PID'),json_extract(fields_json,'$.ProcessID'),json_extract(fields_json,'$.Pid')) AS TEXT),
             COALESCE(NULLIF(json_extract(fields_json,'$.Process'),''),NULLIF(json_extract(fields_json,'$.ImageFileName'),''),json_extract(fields_json,'$.COMM'),''),
             COALESCE(NULLIF(json_extract(fields_json,'$.Name'),''),NULLIF(json_extract(fields_json,'$.ModuleName'),''),NULLIF(json_extract(fields_json,'$.Module'),''),''),
             COALESCE(NULLIF(json_extract(fields_json,'$.Path'),''),NULLIF(json_extract(fields_json,'$.MappedPath'),''),NULLIF(json_extract(fields_json,'$.FilePath'),''),'')
             FROM records r WHERE run_id IN ({marks})"
        );
        let mut values = runs.iter().cloned().map(SqlValue::Text).collect();
        append_representatives(&mut sql, &mut values, runs, "r");
        sql.push_str(" ORDER BY id");
        let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
        stmt.query_map(params_from_iter(values), |r| {
            let name: String = r.get(4)?;
            let path: String = r.get(5)?;
            Ok(crate::result_tree::ModuleEntry {
                id: r.get(0)?,
                run_id: r.get(1)?,
                pid: r.get::<_, Option<String>>(2)?.filter(|pid| !pid.is_empty()),
                process: r.get(3)?,
                name: if !name.is_empty() {
                    name
                } else {
                    path.rsplit(['/', '\\'])
                        .find(|part| !part.is_empty())
                        .unwrap_or("Unnamed module")
                        .to_owned()
                },
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
        let mut sql = format!("SELECT id,fields_json FROM records r WHERE run_id IN ({marks})");
        let mut values = runs.iter().cloned().map(SqlValue::Text).collect();
        append_representatives(&mut sql, &mut values, runs, "r");
        sql.push_str(" ORDER BY id");
        let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params_from_iter(values), |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        rows.map(|row| {
            let (id, json) = row.map_err(|e| e.to_string())?;
            let record = Record {
                fields: serde_json::from_str(&json).map_err(|e| e.to_string())?,
                depth: 0,
            };
            let offset = crate::analysis::registry::hive_offset(&record);
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
        let Some(evidence) = single_evidence(&db, runs)? else {
            return Ok(None);
        };
        if inventory_entities(&db, &evidence, pid)?.len() > 1 {
            return Ok(None);
        }
        for run in runs {
            let id = db
                .query_row(
                    "SELECT r.id FROM records r JOIN observations o ON o.id=r.observation_id
                     WHERE r.run_id=?1 AND r.pid=?2 AND o.process_role IN ('inventory','command')
                     ORDER BY r.row_index LIMIT 1",
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
        let Some(current) = self.process_record(runs, pid)? else {
            return Ok(ProcessRelations::default());
        };
        let Some(entity) = self.entity_for_record(current.id)? else {
            return Ok(ProcessRelations::default());
        };
        let db = self.connect()?;
        let find = |entity: i64| -> Result<Option<BrowserEntry>> {
            let marks = std::iter::repeat_n("?", runs.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut sql = format!(
                "SELECT r.id,r.title,r.pid,r.ppid,r.path FROM records r JOIN observations o ON o.id=r.observation_id
                 WHERE r.run_id IN ({marks}) AND r.entity_id=? AND o.process_role IN ('inventory','command') ORDER BY CASE r.run_id "
            );
            let mut values: Vec<_> = runs.iter().cloned().map(SqlValue::Text).collect();
            values.push(SqlValue::Integer(entity));
            for (i, run) in runs.iter().enumerate() {
                sql.push_str(&format!("WHEN ? THEN {i} "));
                values.push(SqlValue::Text(run.clone()));
            }
            sql.push_str("END,r.row_index LIMIT 1");
            let mut stmt = db.prepare(&sql).map_err(|e| e.to_string())?;
            stmt.query_row(params_from_iter(values), |r| {
                Ok(BrowserEntry {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    pid: r.get(2)?,
                    ppid: r.get(3)?,
                    path: r.get(4)?,
                })
            })
            .optional()
            .map_err(|e| e.to_string())
        };
        let mut parents = BTreeSet::new();
        let mut child_entities = BTreeSet::new();
        for relation in self.entity_relations(entity)? {
            if relation.predicate != "parent_of" {
                continue;
            }
            if relation.object == entity {
                parents.insert(relation.subject);
            }
            if relation.subject == entity {
                child_entities.insert(relation.object);
            }
        }
        let parent = if parents.len() == 1 {
            find(*parents.first().unwrap())?
        } else {
            None
        };
        let children = child_entities
            .into_iter()
            .map(find)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
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

fn fetch_records(db: &Connection, ids: &[i64]) -> Result<Vec<StoredRecord>> {
    if ids.is_empty() {
        return Ok(vec![]);
    }
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

fn canonicalize(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(fields) => {
            fields.sort_keys();
            for value in fields.values_mut() {
                canonicalize(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                canonicalize(value);
            }
        }
        _ => {}
    }
}

fn entity_facts_for(db: &Connection, entities: &[i64]) -> Result<HashMap<i64, Vec<EntityFact>>> {
    if entities.is_empty() {
        return Ok(HashMap::new());
    }
    let marks = std::iter::repeat_n("?", entities.len())
        .collect::<Vec<_>>()
        .join(",");
    let mut statement = db
        .prepare(&format!(
            "SELECT entity_id,field,value_json,observation_id FROM entity_facts
        WHERE entity_id IN ({marks}) ORDER BY entity_id,field,value_json,observation_id"
        ))
        .map_err(|e| e.to_string())?;
    let rows = statement
        .query_map(params_from_iter(entities), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut facts = BTreeMap::<(i64, String, String), Vec<i64>>::new();
    for row in rows {
        let (entity, field, value, observation) = row.map_err(|e| e.to_string())?;
        facts
            .entry((entity, field, value))
            .or_default()
            .push(observation);
    }
    let mut result = HashMap::<i64, Vec<EntityFact>>::new();
    for ((entity, field, value), observations) in facts {
        result.entry(entity).or_default().push(EntityFact {
            field,
            value: serde_json::from_str(&value).map_err(|e| e.to_string())?,
            observations,
        });
    }
    Ok(result)
}

fn entity_sources(
    db: &Connection,
    entities: &[i64],
) -> Result<HashMap<i64, Vec<ObservationProvenance>>> {
    if entities.is_empty() {
        return Ok(HashMap::new());
    }
    let marks = std::iter::repeat_n("?", entities.len())
        .collect::<Vec<_>>()
        .join(",");
    let mut statement = db
        .prepare(&format!(
            "SELECT r.observation_id,r.id,r.run_id,r.row_index
        FROM observation_entities e JOIN run_observations r ON r.observation_id=e.observation_id
        WHERE e.entity_id IN ({marks}) ORDER BY r.observation_id,r.id"
        ))
        .map_err(|e| e.to_string())?;
    let rows = statement
        .query_map(params_from_iter(entities), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                ObservationProvenance {
                    record_id: r.get(1)?,
                    run_id: r.get(2)?,
                    row: r.get::<_, i64>(3)? as usize,
                },
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut sources = HashMap::<i64, Vec<ObservationProvenance>>::new();
    for row in rows {
        let (observation, source) = row.map_err(|e| e.to_string())?;
        sources.entry(observation).or_default().push(source);
    }
    Ok(sources)
}

fn provenance(db: &Connection, observation_id: i64) -> Result<Vec<ObservationProvenance>> {
    let mut statement = db
        .prepare(
            "SELECT id,run_id,row_index FROM run_observations WHERE observation_id=?1 ORDER BY id",
        )
        .map_err(|e| e.to_string())?;
    statement
        .query_map([observation_id], |r| {
            Ok(ObservationProvenance {
                record_id: r.get(0)?,
                run_id: r.get(1)?,
                row: r.get::<_, i64>(2)? as usize,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())
}

fn single_evidence(db: &Connection, runs: &[String]) -> Result<Option<String>> {
    if runs.is_empty() {
        return Ok(None);
    }
    let marks = std::iter::repeat_n("?", runs.len())
        .collect::<Vec<_>>()
        .join(",");
    let mut statement = db
        .prepare(&format!(
            "SELECT DISTINCT evidence_id FROM scans WHERE run_id IN ({marks}) LIMIT 2"
        ))
        .map_err(|e| e.to_string())?;
    let mut scopes = statement
        .query_map(params_from_iter(runs), |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    Ok((scopes.len() == 1).then(|| scopes.remove(0)))
}

fn inventory_entities(db: &Connection, evidence: &str, pid: &str) -> Result<Vec<i64>> {
    let mut statement = db
        .prepare(
            "SELECT DISTINCT e.entity_id FROM observations o
        JOIN observation_entities e ON e.observation_id=o.id
        WHERE o.evidence_id=?1 AND o.pid=?2 AND o.process_role='inventory'",
        )
        .map_err(|e| e.to_string())?;
    statement
        .query_map(params![evidence, pid], |r| r.get(0))
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())
}

fn append_representatives(
    sql: &mut String,
    values: &mut Vec<SqlValue>,
    runs: &[String],
    alias: &str,
) {
    if runs.iter().collect::<HashSet<_>>().len() < 2 {
        return;
    }
    let marks = std::iter::repeat_n("?", runs.len())
        .collect::<Vec<_>>()
        .join(",");
    sql.push_str(&format!(
        " AND {alias}.id IN (SELECT MIN(id) FROM run_observations
        WHERE run_id IN ({marks}) GROUP BY observation_id)"
    ));
    values.extend(runs.iter().cloned().map(SqlValue::Text));
}

fn filter_expression(column: &str) -> Result<String> {
    match column {
        "Domain" => Ok("COALESCE(NULLIF(json_extract(r.fields_json,'$.Domain'),''),browser_domain(json_extract(r.fields_json,'$.URL')))".into()),
        "PID" | "Browser" | "Kind" | "Finding" | "Filename" | "Remote IP" | "Remote port"
        | "Scope" | "Antivirus" | "Evidence status" | "Execution evidence" | "Origin evidence" => Ok(format!("COALESCE(CAST(json_extract(r.fields_json,'$.\"{column}\"') AS TEXT),'')")),
        _ => Err("Unknown filter column".into()),
    }
}
