//! Byte coordinates and bounded reads shared by the virtual hex editor.
use std::{
    io::{Read, Seek, SeekFrom},
    ops::Range,
    path::PathBuf,
    sync::{Arc, Mutex},
};

pub const BYTES_PER_ROW: u64 = 16;
pub const BLOCK_SIZE: u64 = 4096;
pub const DECODE_LIMIT: u64 = 64 * 1024;
pub const ROW_HEIGHT: f64 = 22.;

/// A UTF-8 character occupies its leading byte's cell. Continuation bytes retain
/// their own selectable cells and use a middle dot. Malformed bytes use U+FFFD.
pub fn utf8_cell(offset: u64, total: u64, byte: impl Fn(u64) -> Option<u8>) -> char {
    let Some(current) = byte(offset) else {
        return '·';
    };
    if current.is_ascii() {
        return if current.is_ascii_graphic() || current == b' ' {
            current as char
        } else {
            '.'
        };
    }
    for distance in 0..=3_u64.min(offset) {
        let start = offset - distance;
        let Some(lead) = byte(start) else { continue };
        let length = match lead {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => continue,
        };
        if distance >= length || start.saturating_add(length) > total {
            continue;
        }
        let mut bytes = [0; 4];
        let mut loaded = true;
        for i in 0..length {
            match byte(start + i) {
                Some(b) => bytes[i as usize] = b,
                None => loaded = false,
            }
        }
        if !loaded {
            return '·';
        }
        if let Ok(text) = std::str::from_utf8(&bytes[..length as usize]) {
            let character = text.chars().next().unwrap();
            return if distance != 0 {
                '·'
            } else if character.is_control() {
                '.'
            } else {
                character
            };
        }
    }
    '\u{fffd}'
}

/// Keep the logical scroll position in double precision. Only coordinates relative
/// to the viewport are converted to GPUI's single-precision pixels.
pub struct HexViewport {
    pub top: f64,
    pub height: f64,
    pub rows: u64,
}

impl HexViewport {
    pub fn new(total: u64, offset: u64) -> Self {
        Self {
            top: (offset.min(total.saturating_sub(1)) / BYTES_PER_ROW) as f64 * ROW_HEIGHT,
            height: 0.,
            rows: total.div_ceil(BYTES_PER_ROW),
        }
    }

    pub fn max_top(&self) -> f64 {
        (self.rows as f64 * ROW_HEIGHT - self.height).max(0.)
    }

    pub fn set_top(&mut self, top: f64) {
        self.top = top.clamp(0., self.max_top());
    }

    pub fn visible_rows(&self) -> Range<usize> {
        let first = (self.top / ROW_HEIGHT).floor() as usize;
        let end = ((self.top + self.height) / ROW_HEIGHT).ceil() as usize;
        first..end.min(self.rows as usize)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteSelection {
    pub anchor: u64,
    pub head: u64,
}

impl ByteSelection {
    pub fn new(anchor: u64, head: u64, total: u64) -> Option<Self> {
        let last = total.checked_sub(1)?;
        Some(Self {
            anchor: anchor.min(last),
            head: head.min(last),
        })
    }

    /// Both endpoints include a byte, regardless of the direction of selection.
    pub fn range(self) -> Range<u64> {
        self.anchor.min(self.head)..self.anchor.max(self.head) + 1
    }

    pub fn preview_range(self) -> Range<u64> {
        let range = self.range();
        range.start..range.end.min(range.start.saturating_add(DECODE_LIMIT))
    }
}

/// Lazily opens a verified artifact once. Use only on background workers.
pub struct HexSource {
    path: PathBuf,
    total: u64,
    reader: Mutex<Option<crate::object_store::ArtifactReader>>,
}

impl HexSource {
    pub fn new(path: PathBuf, total: u64) -> Self {
        Self {
            path,
            total,
            reader: Mutex::new(None),
        }
    }

    pub fn read(&self, range: Range<u64>) -> Result<Arc<[u8]>, String> {
        if range.start > range.end
            || range.end > self.total
            || range.end - range.start > DECODE_LIMIT
        {
            return Err("Byte range is outside the dump or exceeds the read limit".into());
        }
        let mut guard = self.reader.lock().map_err(|e| e.to_string())?;
        if guard.is_none() {
            *guard = Some(crate::extracted_files::open_artifact(&self.path)?);
        }
        let reader = guard.as_mut().unwrap();
        reader
            .seek(SeekFrom::Start(range.start))
            .map_err(|e| e.to_string())?;
        let mut bytes = vec![0; (range.end - range.start) as usize];
        reader
            .read_exact(&mut bytes)
            .map_err(|e| format!("Could not read dump bytes: {e}"))?;
        Ok(bytes.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_cells_preserve_byte_coordinates_across_rows_and_blocks() {
        let mut bytes = vec![b' '; 4095];
        bytes.extend_from_slice("é🦀".as_bytes());
        bytes.extend_from_slice(&[0xff, 0xC0, 0xAF, 0xE2]);
        let cell = |i| {
            utf8_cell(i, bytes.len() as u64, |offset| {
                bytes.get(offset as usize).copied()
            })
        };
        assert_eq!(cell(4095), 'é');
        assert_eq!(cell(4096), '·');
        assert_eq!(cell(4097), '🦀');
        for i in 4098..4101 {
            assert_eq!(cell(i), '·');
        }
        for i in 4101..4105 {
            assert_eq!(cell(i), '\u{fffd}');
        }
    }

    #[test]
    fn large_dump_scrolling_includes_the_final_partial_row_and_preserves_small_deltas() {
        let mut viewport = HexViewport::new(1024 * 1024 * 1024 + 7, 0);
        viewport.height = 623.;
        viewport.set_top(f64::MAX);
        assert_eq!(viewport.visible_rows().end, viewport.rows as usize);
        assert!((viewport.rows as f64 * ROW_HEIGHT - viewport.top - viewport.height).abs() < 0.001);
        let top = viewport.top;
        viewport.set_top(top - 3.);
        assert_eq!(top - viewport.top, 3.);
        viewport.set_top(-100.);
        assert_eq!(viewport.visible_rows().start, 0);
    }

    #[test]
    fn selections_include_endpoints_and_clamp_to_file() {
        assert_eq!(ByteSelection::new(19, 14, 20).unwrap().range(), 14..20);
        assert_eq!(ByteSelection::new(14, 19, 20).unwrap().range(), 14..20);
        assert_eq!(ByteSelection::new(90, 90, 20).unwrap().range(), 19..20);
        assert_eq!(ByteSelection::new(0, 0, 0), None);
        assert_eq!(
            ByteSelection::new(u64::MAX, 0, u64::MAX).unwrap().range(),
            0..u64::MAX
        );
    }

    #[test]
    fn source_reads_across_blocks_and_rejects_short_or_unbounded_reads() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let bytes = (0..BLOCK_SIZE + 17).map(|i| i as u8).collect::<Vec<_>>();
        std::fs::write(file.path(), &bytes).unwrap();
        let source = HexSource::new(file.path().into(), bytes.len() as u64);
        assert_eq!(&*source.read(4090..4113).unwrap(), &bytes[4090..4113]);
        assert!(source.read(0..DECODE_LIMIT + 1).is_err());
        assert!(source.read(0..bytes.len() as u64 + 1).is_err());
        std::fs::write(file.path(), &bytes[..8]).unwrap();
        assert!(source.read(0..16).is_err());
    }
}
