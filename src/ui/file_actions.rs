// Keeps file navigation and bounded content reads outside rendering.
use super::*;
use volgui::extracted_files::{self, HexPage};

impl Workspace {
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
