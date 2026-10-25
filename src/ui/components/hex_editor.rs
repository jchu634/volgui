//! Virtualized, read-only byte editor. Selection coordinates are shared by both columns.
use super::*;
use gpui_kit::component::scroll::ScrollbarHandle;
use std::{collections::BTreeMap, rc::Rc};
use volgui::hex_editor::{
    BLOCK_SIZE, BYTES_PER_ROW, ByteSelection, DECODE_LIMIT, HexSource, HexViewport, ROW_HEIGHT,
};

const CACHE_BLOCKS: usize = 64;
const MAX_PENDING: usize = 4;
const ADDRESS_WIDTH: f32 = 104.;
const HEX_WIDTH: f32 = 27.;
const UTF8_WIDTH: f32 = 10.;
#[derive(Clone)]
struct HexScroll(Rc<RefCell<HexScrollState>>);

struct HexScrollState {
    viewport: HexViewport,
    bounds: Bounds<Pixels>,
}

impl HexScroll {
    fn scroll_to(&self, row: usize, strategy: ScrollStrategy) {
        let mut state = self.0.borrow_mut();
        let view = &mut state.viewport;
        let top = row as f64 * ROW_HEIGHT;
        let target = match strategy {
            ScrollStrategy::Center => top - (view.height - ROW_HEIGHT) / 2.,
            ScrollStrategy::Top => top,
            _ if top < view.top => top,
            _ if top + ROW_HEIGHT > view.top + view.height => top + ROW_HEIGHT - view.height,
            _ => return,
        };
        view.set_top(target);
    }

    fn scale(&self) -> f64 {
        (self.0.borrow().viewport.max_top() / 1_000_000.).max(1.)
    }
}

impl ScrollbarHandle for HexScroll {
    fn viewport_bounds(&self) -> Bounds<Pixels> {
        self.0.borrow().bounds
    }
    fn offset(&self) -> Point<Pixels> {
        point(
            px(0.),
            px((-self.0.borrow().viewport.top / self.scale()) as f32),
        )
    }
    fn set_offset(&self, offset: Point<Pixels>) {
        let top = -f64::from(f32::from(offset.y)) * self.scale();
        self.0.borrow_mut().viewport.set_top(top);
    }
    fn content_size(&self) -> Size<Pixels> {
        let state = self.0.borrow();
        size(
            state.bounds.size.width,
            px((state.viewport.max_top() / self.scale() + state.viewport.height) as f32),
        )
    }
}

pub(in crate::ui) struct SelectionChanged;

pub(in crate::ui) struct SelectionPreview {
    pub range: Range<u64>,
    pub bytes: Option<Result<Arc<[u8]>, String>>,
}

pub(in crate::ui) struct HexEditor {
    source: Arc<HexSource>,
    total: u64,
    scroll: HexScroll,
    horizontal: ScrollHandle,
    focus: FocusHandle,
    blocks: BTreeMap<u64, Result<Arc<[u8]>, String>>,
    pending: HashSet<u64>,
    visible: Range<u64>,
    selection: Option<ByteSelection>,
    preview: Option<SelectionPreview>,
    preview_task: Option<Task<()>>,
    dragging: bool,
    selection_utf8: bool,
    offset: Entity<InputState>,
    offset_error: Option<String>,
}

impl EventEmitter<SelectionChanged> for HexEditor {}

impl HexEditor {
    pub(in crate::ui) fn new(
        path: PathBuf,
        total: u64,
        offset: u64,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let scroll = HexScroll(Rc::new(RefCell::new(HexScrollState {
            viewport: HexViewport::new(total, offset),
            bounds: Bounds::default(),
        })));
        Self {
            source: Arc::new(HexSource::new(path, total)),
            total,
            scroll,
            horizontal: ScrollHandle::new(),
            focus: cx.focus_handle(),
            blocks: BTreeMap::new(),
            pending: HashSet::new(),
            visible: 0..0,
            selection: None,
            preview: None,
            preview_task: None,
            dragging: false,
            selection_utf8: false,
            offset: field(format!("0x{offset:X}"), "Byte offset", window, cx),
            offset_error: None,
        }
    }

    pub(in crate::ui) fn selection(&self) -> Option<&SelectionPreview> {
        self.preview.as_ref()
    }

    fn request_rows(&mut self, rows: Range<usize>, cx: &mut Context<Self>) {
        let start = (rows.start as u64 * BYTES_PER_ROW).saturating_sub(3);
        let end = (rows.end as u64 * BYTES_PER_ROW)
            .saturating_add(3)
            .min(self.total);
        self.visible = start / BLOCK_SIZE..end.div_ceil(BLOCK_SIZE);
        for block in self.visible.clone() {
            if self.pending.len() >= MAX_PENDING {
                break;
            }
            if self.blocks.contains_key(&block) || !self.pending.insert(block) {
                continue;
            }
            let source = self.source.clone();
            let range = block * BLOCK_SIZE..((block + 1) * BLOCK_SIZE).min(self.total);
            let read = cx
                .background_executor()
                .spawn(async move { source.read(range) });
            cx.spawn(async move |this, cx| {
                let bytes = read.await;
                let _ = this.update(cx, |this, cx| {
                    this.pending.remove(&block);
                    // Rapid scrolling can leave reads behind the viewport. Do not cache them.
                    if this.visible.contains(&block) {
                        while this.blocks.len() >= CACHE_BLOCKS {
                            let victim = this
                                .blocks
                                .keys()
                                .copied()
                                .find(|key| !this.visible.contains(key));
                            let Some(victim) = victim else { break };
                            this.blocks.remove(&victim);
                        }
                        this.blocks.insert(block, bytes);
                    }
                    cx.notify();
                });
            })
            .detach();
        }
    }

    fn select(&mut self, head: u64, extend: bool, cx: &mut Context<Self>) {
        let anchor = self.selection.filter(|_| extend).map_or(head, |s| s.anchor);
        let selection = ByteSelection::new(anchor, head, self.total);
        if self.selection == selection {
            return;
        }
        self.selection = selection;
        self.preview_task = None;
        self.preview = selection.map(|s| SelectionPreview {
            range: s.range(),
            bytes: None,
        });
        cx.emit(SelectionChanged);
        cx.notify();
        let Some(selection) = selection else { return };
        let source = self.source.clone();
        self.preview_task = Some(cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(60))
                .await;
            let bytes = cx
                .background_executor()
                .spawn(async move { source.read(selection.preview_range()) })
                .await;
            let _ = this.update(cx, |this, cx| {
                if this.selection == Some(selection) {
                    this.preview = Some(SelectionPreview {
                        range: selection.range(),
                        bytes: Some(bytes),
                    });
                    cx.emit(SelectionChanged);
                    cx.notify();
                }
            });
        }));
    }

    fn jump(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.offset.read(cx).value();
        let text = text.trim();
        let offset = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => text.parse::<u64>(),
        };
        match offset {
            Ok(offset) if offset < self.total => {
                self.offset_error = None;
                self.select(offset, false, cx);
                self.scroll
                    .scroll_to((offset / BYTES_PER_ROW) as usize, ScrollStrategy::Center);
                self.focus.focus(window, cx);
            }
            _ => {
                self.offset_error =
                    Some("Enter an offset within the dump, in decimal or 0x hexadecimal.".into())
            }
        }
        cx.notify();
    }

    fn key_down(&mut self, event: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        if self.total == 0 || !self.focus.is_focused(window) {
            return;
        }
        let key = event.keystroke.key.as_str();
        let modifiers = event.keystroke.modifiers;
        if modifiers.secondary() && key == "a" {
            self.select(0, false, cx);
            self.select(self.total - 1, true, cx);
        } else if modifiers.secondary() && key == "c" {
            if let Some(SelectionPreview {
                bytes: Some(Ok(bytes)),
                ..
            }) = &self.preview
            {
                let text = if self.selection_utf8 {
                    String::from_utf8_lossy(bytes).into_owned()
                } else {
                    bytes
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                cx.write_to_clipboard(ClipboardItem::new_string(text));
            }
        } else {
            let head = self.selection.map_or(0, |s| s.head);
            let page = (self.scroll.0.borrow().viewport.height / ROW_HEIGHT) as u64;
            let next = match key {
                "left" => head.saturating_sub(1),
                "right" => head.saturating_add(1),
                "up" => head.saturating_sub(BYTES_PER_ROW),
                "down" => head.saturating_add(BYTES_PER_ROW),
                "pageup" => head.saturating_sub(page.max(1) * BYTES_PER_ROW),
                "pagedown" => head.saturating_add(page.max(1) * BYTES_PER_ROW),
                "home" if modifiers.secondary() => 0,
                "end" if modifiers.secondary() => self.total - 1,
                "home" => head / BYTES_PER_ROW * BYTES_PER_ROW,
                "end" => head / BYTES_PER_ROW * BYTES_PER_ROW + BYTES_PER_ROW - 1,
                "escape" => {
                    self.selection = None;
                    self.preview = None;
                    self.preview_task = None;
                    cx.emit(SelectionChanged);
                    cx.notify();
                    cx.stop_propagation();
                    return;
                }
                _ => return,
            }
            .min(self.total - 1);
            self.select(next, modifiers.shift, cx);
            self.scroll
                .scroll_to((next / BYTES_PER_ROW) as usize, ScrollStrategy::Nearest);
        }
        cx.stop_propagation();
    }

    fn byte(&self, offset: u64) -> Option<u8> {
        self.blocks
            .get(&(offset / BLOCK_SIZE))
            .and_then(|r| r.as_ref().ok())
            .and_then(|bytes| bytes.get((offset % BLOCK_SIZE) as usize))
            .copied()
    }

    fn byte_cell(&self, offset: u64, utf8: bool, cx: &mut Context<Self>) -> AnyElement {
        let byte = self.byte(offset);
        let selected = self.selection.is_some_and(|s| s.range().contains(&offset));
        let text = match (byte, utf8) {
            (Some(_), true) => {
                volgui::hex_editor::utf8_cell(offset, self.total, |offset| self.byte(offset))
                    .to_string()
            }
            (Some(b), false) => format!("{b:02X}"),
            (None, true) => "·".into(),
            (None, false) => "··".into(),
        };
        div()
            .id((if utf8 { "hex-utf8" } else { "hex-byte" }, offset as usize))
            .w(px(if utf8 { UTF8_WIDTH } else { HEX_WIDTH }))
            .h(px(ROW_HEIGHT as f32))
            .flex_shrink_0()
            .flex()
            .items_center()
            .justify_center()
            .cursor_text()
            .when(byte == Some(0), |s| {
                s.text_color(cx.theme().muted_foreground)
            })
            .when(selected, |s| {
                s.bg(cx.theme().primary)
                    .text_color(cx.theme().primary_foreground)
            })
            .child(text)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                    this.focus.focus(window, cx);
                    this.dragging = true;
                    this.selection_utf8 = utf8;
                    this.select(offset, event.modifiers.shift, cx);
                    cx.stop_propagation();
                }),
            )
            .on_mouse_move(cx.listener(move |this, event: &MouseMoveEvent, _, cx| {
                if this.dragging && event.dragging() {
                    this.select(offset, true, cx);
                }
            }))
            .into_any_element()
    }

    fn row(&self, row: usize, cx: &mut Context<Self>) -> AnyElement {
        let start = row as u64 * BYTES_PER_ROW;
        let count = (self.total - start).min(BYTES_PER_ROW);
        let mut hex = div().flex().w(px(HEX_WIDTH * 16.)).flex_shrink_0();
        let mut utf8 = div()
            .flex()
            .pl_2()
            .border_l_1()
            .border_color(cx.theme().border);
        for column in 0..count {
            hex = hex.child(self.byte_cell(start + column, false, cx));
            utf8 = utf8.child(self.byte_cell(start + column, true, cx));
        }
        div()
            .h(px(ROW_HEIGHT as f32))
            .flex()
            .items_center()
            .child(
                div()
                    .w(px(ADDRESS_WIDTH))
                    .flex_shrink_0()
                    .pl_3()
                    .text_color(cx.theme().muted_foreground)
                    .id(("hex-address", row))
                    .tooltip(move |window, cx| {
                        Tooltip::new(format!("Dump offset 0x{start:X}")).build(window, cx)
                    })
                    .child(format!("{:010X}", start & 0xFF_FFFF_FFFF)),
            )
            .child(hex)
            .child(utf8)
            .into_any_element()
    }
}

impl Render for HexEditor {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let mut header = div()
            .flex()
            .h(px(28.))
            .items_center()
            .flex_shrink_0()
            .bg(cx.theme().secondary)
            .text_color(cx.theme().muted_foreground)
            .border_b_1()
            .border_color(cx.theme().border)
            .child(
                div()
                    .w(px(ADDRESS_WIDTH))
                    .flex_shrink_0()
                    .pl_3()
                    .child("Address"),
            );
        for column in 0..16 {
            header = header.child(
                div()
                    .w(px(HEX_WIDTH))
                    .flex_shrink_0()
                    .text_center()
                    .child(format!("+{column:X}")),
            );
        }
        header = header.child(
            div()
                .pl_2()
                .border_l_1()
                .border_color(cx.theme().border)
                .child("UTF-8"),
        );
        let entity = cx.entity().clone();
        let list = canvas(
            move |bounds, window, cx| {
                entity.update(cx, |this, cx| {
                    let (range, top) = {
                        let mut state = this.scroll.0.borrow_mut();
                        state.bounds = bounds;
                        state.viewport.height = f64::from(f32::from(bounds.size.height));
                        let top = state.viewport.top;
                        state.viewport.set_top(top);
                        (state.viewport.visible_rows(), state.viewport.top)
                    };
                    this.request_rows(range.clone(), cx);
                    window.with_content_mask(Some(ContentMask { bounds }), |window| {
                        range
                            .map(|row| {
                                let mut item = this.row(row, cx);
                                item.layout_as_root(
                                    size(
                                        AvailableSpace::Definite(bounds.size.width),
                                        AvailableSpace::Definite(px(ROW_HEIGHT as f32)),
                                    ),
                                    window,
                                    cx,
                                );
                                item.prepaint_at(
                                    bounds.origin
                                        + point(px(0.), px((row as f64 * ROW_HEIGHT - top) as f32)),
                                    window,
                                    cx,
                                );
                                item
                            })
                            .collect::<Vec<_>>()
                    })
                })
            },
            |bounds, mut items, window, cx| {
                window.with_content_mask(Some(ContentMask { bounds }), |window| {
                    for item in &mut items {
                        item.paint(window, cx);
                    }
                })
            },
        )
        .size_full();
        let scroll = self.scroll.clone();
        let status = self.selection.map_or_else(
            || format!("{} bytes · Read-only", self.total),
            |s| {
                let r = s.range();
                format!(
                    "0x{:X}..0x{:X} · {} bytes selected{}",
                    r.start,
                    r.end,
                    r.end - r.start,
                    if r.end - r.start > DECODE_LIMIT {
                        " · Decode/copy limited to first 64 KiB"
                    } else {
                        ""
                    }
                )
            },
        );
        let error = self.blocks.values().find_map(|r| r.as_ref().err()).cloned();
        div()
            .id("hex-editor")
            .size_full()
            .min_w_0()
            .min_h_0()
            .flex()
            .flex_col()
            .track_focus(&self.focus)
            .on_key_down(cx.listener(Self::key_down))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _, _, _| this.dragging = false),
            )
            .on_mouse_up_out(
                MouseButton::Left,
                cx.listener(|this, _, _, _| this.dragging = false),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_3()
                    .py_1()
                    .flex_shrink_0()
                    .child(
                        Input::new(&self.offset)
                            .id("hex-editor-offset")
                            .aria_label("Go to byte offset")
                            .small()
                            .w(px(150.)),
                    )
                    .child(
                        Button::new("hex-editor-go")
                            .xsmall()
                            .ghost()
                            .label("Go to offset")
                            .on_click(cx.listener(|this, _, window, cx| this.jump(window, cx))),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child("Drag or Shift-click to select"),
                    ),
            )
            .when_some(self.offset_error.clone().or(error), |view, error| {
                view.child(
                    div()
                        .px_3()
                        .text_xs()
                        .text_color(cx.theme().danger)
                        .child(error)
                        .child(
                            Button::new("hex-editor-retry")
                                .xsmall()
                                .ghost()
                                .label("Retry")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.blocks.retain(|_, result| result.is_ok());
                                    this.offset_error = None;
                                    cx.notify();
                                })),
                        ),
                )
            })
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .child(
                        div()
                            .id("hex-editor-horizontal")
                            .size_full()
                            .overflow_x_scroll()
                            .track_scroll(&self.horizontal)
                            .child(
                                div()
                                    .h_full()
                                    .w_full()
                                    .min_w(px(720.))
                                    .flex()
                                    .flex_col()
                                    .font_family("Consolas")
                                    .text_size(px(12.))
                                    .child(header)
                                    .when(self.total == 0, |s| {
                                        s.child(div().p_3().child("This dump is empty."))
                                    })
                                    .child(
                                        div()
                                            .id("hex-editor-viewport")
                                            .flex_1()
                                            .min_h_0()
                                            .overflow_hidden()
                                            .on_scroll_wheel(cx.listener(
                                                |this, event: &ScrollWheelEvent, _, cx| {
                                                    let delta = event
                                                        .delta
                                                        .pixel_delta(px(ROW_HEIGHT as f32));
                                                    if delta.y != px(0.) && !event.modifiers.shift {
                                                        let mut state = this.scroll.0.borrow_mut();
                                                        let top = state.viewport.top
                                                            - f64::from(f32::from(delta.y));
                                                        state.viewport.set_top(top);
                                                        cx.notify();
                                                        cx.stop_propagation();
                                                    }
                                                },
                                            ))
                                            .child(list),
                                    ),
                            ),
                    )
                    .child(Scrollbar::vertical(&scroll).mode(ScrollbarMode::Always))
                    .child(Scrollbar::horizontal(&self.horizontal).mode(ScrollbarMode::Always)),
            )
            .child(
                div()
                    .flex_shrink_0()
                    .px_3()
                    .py_1()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child(status),
            )
    }
}
