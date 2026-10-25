// Keeps file navigation and bounded content reads outside rendering.
use super::*;
use volgui::extracted_files::{self, HexPage};

impl Workspace {
    pub(super) fn locate_imhex(&self) {
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::ImHexLocated(extracted_files::imhex()));
        });
    }

    pub(super) fn file_listing_target(&self) -> Option<(PathBuf, RunStatus)> {
        let case = self.case.as_ref()?;
        let run = case
            .document
            .runs
            .iter()
            .find(|run| Some(&run.id) == self.selected_run.as_ref())?;
        let run = self
            .selected
            .as_ref()
            .and_then(|record| {
                extracted_files::completed_dump(case, record, self.file_offset_physical)
            })
            .unwrap_or(run);
        Some((case.run_dir(&run.id), run.status))
    }

    pub(super) fn reset_file_listing(&mut self) {
        self.file_listing_epoch += 1;
        self.file_listing = None;
    }

    pub(super) fn refresh_file_listing(&mut self, cx: &mut Context<Self>) {
        let target = (self.detail == DetailTab::Files)
            .then(|| self.file_listing_target())
            .flatten();
        if target.as_ref() == self.file_listing.as_ref().map(|listing| &listing.target) {
            return;
        }
        self.reset_file_listing();
        if let Some(target) = target {
            let directory = target.0.clone();
            self.file_listing = Some(FileListing {
                target,
                result: None,
            });
            let epoch = self.file_listing_epoch;
            let tx = self.tx.clone();
            thread::spawn(move || {
                let _ = tx.send(Event::FilesListed(
                    epoch,
                    extracted_files::listing(&directory),
                ));
            });
        }
        cx.notify();
    }

    pub(super) fn open_in_imhex(
        &mut self,
        executable: PathBuf,
        file: PathBuf,
        cx: &mut Context<Self>,
    ) {
        let Some(case) = &self.case else { return };
        let directory = case.directory.clone();
        let tx = self.tx.clone();
        self.message = "Preparing file for ImHex...".into();
        thread::spawn(move || {
            let result = extracted_files::open(&executable, &file)
                .map(|()| "Opened in ImHex".into())
                .map_err(|error| format!("Could not open ImHex: {error}"));
            let _ = tx.send(Event::FileActionCompleted(directory, result));
        });
        cx.notify();
    }

    pub(super) fn toggle_hex(&mut self, cx: &mut Context<Self>) {
        self.hex_visible = !self.hex_visible;
        if self.hex_visible {
            self.load_hex(cx);
        } else {
            self.reset_hex();
        }
        cx.notify();
    }

    pub(super) fn reset_hex(&mut self) {
        self.hex_epoch += 1;
        self.hex_view = HexView::Idle;
        self.database_view = None;
        self.database_epoch += 1;
    }

    pub(super) fn set_content_encoding(
        &mut self,
        encoding: volgui::extracted_files::ContentEncoding,
        cx: &mut Context<Self>,
    ) {
        self.content_encoding = encoding;
        if encoding == volgui::extracted_files::ContentEncoding::Sqlite
            && let HexView::Ready { page, .. } = &self.hex_view
        {
            self.load_database(page.path.clone(), None, 0, cx);
        }
        cx.notify();
    }

    pub(super) fn load_database(
        &mut self,
        path: PathBuf,
        table: Option<String>,
        offset: usize,
        cx: &mut Context<Self>,
    ) {
        self.database_view = None;
        self.database_epoch += 1;
        let hex_epoch = self.hex_epoch;
        let epoch = self.database_epoch;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::DatabaseLoaded(
                hex_epoch,
                epoch,
                volgui::file_content::database_page(&path, table.as_deref(), offset),
            ));
        });
        cx.notify();
    }

    pub(super) fn show_file_in_files(
        &mut self,
        id: i64,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(record) = self.row_cache.get(&id).cloned() else {
            return;
        };
        self.remember_location(cx);
        let mut runs = self.group_runs(ArtifactGroup::Files);
        if !runs.contains(&record.run_id) {
            runs.push(record.run_id.clone());
        }
        self.browser_group = ArtifactGroup::Files;
        self.set_scope(runs, ArtifactGroup::Files.label().into(), window, cx);
        self.show_record((*record).clone(), window, cx);
    }

    pub(super) fn load_hex(&mut self, cx: &mut Context<Self>) {
        self.reset_hex();
        let memory = self.case.as_ref().and_then(|case| {
            let record = &self.selected.as_ref()?.record;
            if !matches!(record.text("Kind").as_str(), "Memory URL" | "Memory search") {
                return None;
            }
            let source = case.document.runs.iter().find(|r| {
                r.id == record.text("Source run") && r.plugin == "windows.memmap.Memmap"
            })?;
            let pid = record.fields.get("PID")?.as_u64()?;
            let offset = record.fields.get("Dump offset")?.as_u64()?;
            Some((
                case.run_dir(&source.id).join(format!("pid.{pid}.dmp")),
                offset,
            ))
        });
        if let Some((path, offset)) = memory {
            self.open_hex_file(vec![path.clone()], path, offset, cx);
            return;
        }
        let directory = self.case.as_ref().and_then(|case| {
            let record = self.selected.as_ref()?;
            let run = extracted_files::completed_dump(case, record, self.file_offset_physical)?;
            Some(case.run_dir(&run.id))
        });
        let Some(directory) = directory else {
            cx.notify();
            return;
        };
        self.hex_view = HexView::Loading;
        let epoch = self.hex_epoch;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = (|| {
                let files = extracted_files::list(&directory)?;
                let path = files
                    .first()
                    .ok_or("No cached file contents could be extracted from memory.")?;
                let page = HexPage::read(path, 0)?;
                Ok((files, page))
            })();
            let _ = tx.send(Event::HexLoaded(epoch, result));
        });
        cx.notify();
    }

    pub(super) fn read_hex_page(&mut self, path: PathBuf, offset: u64, cx: &mut Context<Self>) {
        let HexView::Ready { files, .. } = &self.hex_view else {
            return;
        };
        let files = files.clone();
        self.open_hex_file(files, path, offset, cx);
    }

    pub(super) fn open_hex_file(
        &mut self,
        files: Vec<PathBuf>,
        path: PathBuf,
        offset: u64,
        cx: &mut Context<Self>,
    ) {
        self.hex_visible = true;
        self.reset_hex();
        self.hex_view = HexView::Loading;
        let epoch = self.hex_epoch;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = HexPage::read(&path, offset).map(|page| (files, page));
            let _ = tx.send(Event::HexLoaded(epoch, result));
        });
        cx.notify();
    }
}
