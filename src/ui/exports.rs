// Exports reports, result records, and extracted files.
use super::*;

impl Workspace {
    pub(super) fn export(&mut self, report: bool, window: &mut Window, cx: &mut Context<Self>) {
        let Some(c) = &self.case else {
            return;
        };
        let document = c.document.clone();
        let directory = c.directory.clone();
        let query = self.active_query(cx);
        let tx = self.tx.clone();
        let receiver = cx.prompt_for_new_path(
            &directory,
            Some(if report {
                "case-report.html"
            } else {
                "artifacts.csv"
            }),
        );
        cx.spawn_in(window, async move |_, _| match receiver.await {
            Ok(Ok(Some(path))) => {
                thread::spawn(move || {
                    let result = (|| {
                        let content = if report {
                            document.report(&directory)?
                        } else {
                            ResultStore::at(&directory).export_csv(&query)?
                        };
                        document.export(&directory, &path, content.as_bytes())?;
                        Ok(path)
                    })();
                    let _ = tx.send(Event::Exported(result));
                });
            }
            Ok(Err(e)) => {
                let _ = tx.send(Event::Exported(Err(e.to_string())));
            }
            _ => {}
        })
        .detach();
    }
    pub(super) fn export_file(
        &mut self,
        source: PathBuf,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(case) = &self.case else { return };
        let document = case.document.clone();
        let directory = case.directory.clone();
        let tx = self.tx.clone();
        let receiver =
            cx.prompt_for_new_path(&directory, source.file_name().and_then(|n| n.to_str()));
        cx.spawn_in(window, async move |_, _| match receiver.await {
            Ok(Ok(Some(path))) => {
                thread::spawn(move || {
                    let result = (|| {
                        let mut file = std::fs::File::open(&source).map_err(|e| e.to_string())?;
                        document.export_reader(&directory, &path, &mut file)?;
                        Ok(path)
                    })();
                    let _ = tx.send(Event::Exported(result));
                });
            }
            Ok(Err(error)) => {
                let _ = tx.send(Event::Exported(Err(error.to_string())));
            }
            _ => {}
        })
        .detach();
    }
}
