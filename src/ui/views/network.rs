use super::*;
use volgui::network::{Endpoint, Entry, Filter, Overview, Selection, common_service, service};

const ENTRIES_PER_PAGE: usize = 40;
const PORTS_PER_PEER: usize = 12;
const NETWORK_NODE_HEIGHT: f32 = 76.;
const NETWORK_ROW_HEIGHT: f32 = 34.;
const NETWORK_PEER_GAP: f32 = 32.;

fn network_ip_menu_item(label: String, selected: bool, first: bool, last: bool) -> PopupMenuItem {
    PopupMenuItem::element(move |_, cx| {
        let mut background = *cx.theme().tokens.accent;
        background.l *= 0.75;
        div()
            .w_full()
            .when(first, |row| row.pt_1())
            .when(last, |row| row.pb_1())
            .child(
                div()
                    .mx_neg_2()
                    .px_2()
                    .min_h(px(26.))
                    .flex()
                    .items_center()
                    .rounded(cx.theme().radius.min(px(8.)))
                    .when(selected, |row| row.bg(background))
                    .child(label.clone()),
            )
    })
}

#[derive(Default)]
pub(in crate::ui) struct NetworkViewCache {
    overview: Option<(Filter, Overview)>,
    sidebar: Option<(Filter, Option<Selection>, Vec<usize>)>,
}

impl Workspace {
    fn network_filter_menu(&self, protocol: bool, cx: &mut Context<Self>) -> impl IntoElement {
        let values = if protocol {
            self.network.protocols.clone()
        } else {
            self.network.states.clone()
        };
        let selected = if protocol {
            &self.network_protocol
        } else {
            &self.network_state
        };
        let weak = cx.entity().downgrade();
        app_button(if protocol {
            "network-protocol"
        } else {
            "network-state"
        })
        .small()
        .dropdown_caret(true)
        .label(selected.clone().unwrap_or_else(|| {
            if protocol {
                "All protocols".into()
            } else {
                "All states".into()
            }
        }))
        .dropdown_menu(move |mut menu, _, _| {
            let weak_all = weak.clone();
            menu = menu.item(PopupMenuItem::new("All").on_click(move |_, _, cx| {
                let _ = weak_all.update(cx, |this, cx| {
                    if protocol {
                        this.network_protocol = None;
                    } else {
                        this.network_state = None;
                    }
                    this.network_scroll.set_offset(Point::default());
                    this.network_sidebar_page = 0;
                    cx.notify();
                });
            }));
            for value in &values {
                let value = value.clone();
                let weak = weak.clone();
                menu = menu.item(PopupMenuItem::new(value.clone()).on_click(move |_, _, cx| {
                    let _ = weak.update(cx, |this, cx| {
                        if protocol {
                            this.network_protocol = Some(value.clone());
                        } else {
                            this.network_state = Some(value.clone());
                        }
                        this.network_scroll.set_offset(Point::default());
                        this.network_sidebar_page = 0;
                        cx.notify();
                    });
                }));
            }
            menu
        })
    }

    fn select_network_endpoint(&mut self, endpoint: Selection, cx: &mut Context<Self>) {
        self.network_endpoint = Some(endpoint);
        self.network_sidebar_page = 0;
        self.network_sidebar_scroll.set_offset(Point::default());
        self.content_sidebar_visible = true;
        cx.notify();
    }

    fn network_port(&self, endpoint: Endpoint, id: usize, cx: &mut Context<Self>) -> AnyElement {
        let selected =
            self.network_endpoint.as_ref() == Some(&Selection::Endpoint(endpoint.clone()));
        app_button(("network-port", id))
            .xsmall()
            .w_full()
            .selected(selected)
            .label(
                endpoint
                    .port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "?".into()),
            )
            .tooltip(format!(
                "{} · {} · inspect every matching entry",
                endpoint.label(),
                service(endpoint.port)
            ))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.select_network_endpoint(Selection::Endpoint(endpoint.clone()), cx)
            }))
            .into_any_element()
    }

    fn network_node(
        &self,
        address: String,
        label: &'static str,
        id: usize,
        can_switch: bool,
        partial: bool,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let selected = self
            .network_endpoint
            .as_ref()
            .is_some_and(|e| e == &Selection::Address(address.clone()));
        let inspect = address.clone();
        let focus = address.clone();
        div()
            .id(("network-node", id))
            .cursor_pointer()
            .on_click(cx.listener(move |this, _, _, cx| {
                this.select_network_endpoint(Selection::Address(inspect.clone()), cx);
            }))
            .flex()
            .flex_col()
            .items_start()
            .gap_1()
            .p_3()
            .w(px(180.))
            .h(px(NETWORK_NODE_HEIGHT))
            .rounded_lg()
            .border_1()
            .border_color(if selected {
                cx.theme().primary
            } else {
                cx.theme().border
            })
            .bg(if partial {
                partial_matches::background()
            } else {
                cx.theme().background
            })
            .when(partial, |node| {
                node.text_color(partial_matches::foreground())
                    .aria_label("Contains partial matches")
            })
            .shadow_sm()
            .child(
                div()
                    .flex()
                    .w_full()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(
                        div()
                            .text_xs()
                            .text_color(if partial {
                                partial_matches::foreground()
                            } else {
                                cx.theme().muted_foreground
                            })
                            .child(if partial {
                                "Contains partial matches"
                            } else {
                                label
                            }),
                    )
                    .when(can_switch, |row| {
                        row.child(
                            app_button(("network-focus", id))
                                .xsmall()
                                .label("Switch IP")
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    cx.stop_propagation();
                                    this.network_all_sources = false;
                                    this.network_focus = Some(focus.clone());
                                    this.network_scroll.set_offset(Point::default());
                                    cx.notify();
                                })),
                        )
                    }),
            )
            .child(div().child(address))
            .into_any_element()
    }

    fn network_filter(&self, cx: &App) -> Filter {
        Filter {
            include_partial: self.settings.show_partial_matches,
            focus: self.network_focus.clone(),
            text: self.query.read(cx).value().to_ascii_lowercase(),
            protocol: self.network_protocol.clone(),
            state: self.network_state.clone(),
            hide_system: self.network_hide_system,
            hide_noise: self.network_hide_noise,
            interesting_only: self.network_interesting,
            all_sources: self.network_all_sources,
        }
    }

    pub(in crate::ui) fn render_network(&self, cx: &mut Context<Self>) -> AnyElement {
        let filter = self.network_filter(cx);
        let mut cache = self.network_cache.borrow_mut();
        if cache
            .overview
            .as_ref()
            .is_none_or(|(key, _)| key != &filter)
        {
            cache.overview = Some((filter.clone(), self.network.overview(&filter)));
        }
        let overview = &cache
            .overview
            .as_ref()
            .expect("network overview initialized")
            .1;
        let focus = overview.focus.clone();
        let addresses: Vec<_> = overview.addresses.iter().cloned().collect();
        let all_sources = self.network_all_sources;
        let selected_ip = focus.clone();
        let weak = cx.entity().downgrade();
        let picker_width = if !all_sources && focus.as_ref().is_some_and(|ip| ip.contains(':')) {
            390.
        } else {
            190.
        };
        let filters = div()
            .flex()
            .flex_wrap()
            .flex_1()
            .min_w_0()
            .items_center()
            .gap_2()
            .child(self.network_filter_menu(true, cx))
            .child(self.network_filter_menu(false, cx))
            .child(
                Checkbox::new("network-hide-system")
                    .label("Hide common system processes")
                    .checked(self.network_hide_system)
                    .on_change(cx.listener(|this, checked, _, cx| {
                        this.network_hide_system = *checked;
                        this.network_sidebar_page = 0;
                        this.network_scroll.set_offset(Point::default());
                        cx.notify();
                    })),
            )
            .child(
                Checkbox::new("network-hide-noise")
                    .label("Hide local / empty endpoints")
                    .checked(self.network_hide_noise)
                    .on_change(cx.listener(|this, checked, _, cx| {
                        this.network_hide_noise = *checked;
                        this.network_sidebar_page = 0;
                        this.network_scroll.set_offset(Point::default());
                        cx.notify();
                    })),
            );
        let mut navigation = div()
            .flex()
            .items_center()
            .gap_2()
            .min_w_0()
            .flex_shrink_0();
        for (id, label, table) in [
            ("network-graph-view", "Graph", false),
            ("network-table-view", "Table", true),
        ] {
            navigation = navigation.child(
                app_button(id)
                    .small()
                    .label(label)
                    .selected(self.network_table_view == table)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.network_table_view = table;
                        cx.notify();
                    })),
            );
        }
        if !self.network_table_view {
            let previous = volgui::network::adjacent_address(&addresses, focus.as_deref(), false);
            let next = volgui::network::adjacent_address(&addresses, focus.as_deref(), true);
            navigation = navigation.child(
                app_button("network-focus-picker")
                    .small()
                    .dropdown_caret(true)
                    .w(px(picker_width))
                    .flex_shrink_0()
                    .label(if all_sources {
                        "All source IPs".into()
                    } else {
                        focus.unwrap_or_else(|| "Choose IP".into())
                    })
                    .dropdown_menu(move |mut menu, _, _| {
                        menu = menu
                            .min_w(px(picker_width))
                            .scrollable(true)
                            .max_h(px(320.));
                        let weak_all = weak.clone();
                        menu = menu
                            .item(
                                network_ip_menu_item(
                                    "All source IPs".into(),
                                    all_sources,
                                    true,
                                    addresses.is_empty(),
                                )
                                .on_click(move |_, _, cx| {
                                    let _ = weak_all.update(cx, |this, cx| {
                                        this.network_all_sources = true;
                                        this.network_scroll.set_offset(Point::default());
                                        cx.notify();
                                    });
                                }),
                            )
                            .separator();
                        for (index, ip) in addresses.iter().enumerate() {
                            let ip = ip.clone();
                            let weak = weak.clone();
                            let selected = !all_sources && selected_ip.as_ref() == Some(&ip);
                            let item = network_ip_menu_item(
                                ip.clone(),
                                selected,
                                false,
                                index + 1 == addresses.len(),
                            );
                            menu = menu.item(item.on_click(move |_, _, cx| {
                                let _ = weak.update(cx, |this, cx| {
                                    this.network_focus = Some(ip.clone());
                                    this.network_all_sources = false;
                                    this.network_scroll.set_offset(Point::default());
                                    cx.notify();
                                });
                            }));
                        }
                        menu
                    }),
            );
            for (id, label, target) in [
                ("network-prev-ip", "Previous IP", previous),
                ("network-next-ip", "Next IP", next),
            ] {
                navigation = navigation.child(
                    app_button(id)
                        .small()
                        .label(label)
                        .disabled(all_sources || target.is_none())
                        .on_click(cx.listener(move |this, _, _, cx| {
                            if let Some(ip) = &target {
                                this.network_focus = Some(ip.clone());
                                this.network_all_sources = false;
                                this.network_scroll.set_offset(Point::default());
                                cx.notify();
                            }
                        })),
                );
            }
        }
        let recovering = self.case.as_ref().and_then(|case| {
            case.document.runs.iter().rev().find(|run| {
                Some(&run.evidence_id) == self.selected_evidence.as_ref()
                    && run.plugin == volgui::analysis::NETWORK
                    && matches!(run.status, RunStatus::Queued | RunStatus::Running)
            })
        });
        let mut root = div()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .min_w_0()
            .overflow_hidden()
            .child(self.render_results_toolbar(cx))
            .child(
                div()
                    .flex()
                    .items_start()
                    .justify_between()
                    .gap_2()
                    .px_3()
                    .py_1()
                    .flex_shrink_0()
                    .child(filters)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                Checkbox::new("network-interesting")
                                    .label("Interesting traffic")
                                    .checked(self.network_interesting)
                                    .on_change(cx.listener(|this, _, window, cx| {
                                        this.toggle_interesting_network(window, cx)
                                    })),
                            )
                            .child(
                                app_button("network-investigate")
                                    .small()
                                    .label("Analyze network")
                                    .flex_shrink_0()
                                    .disabled(
                                        self.evidence().is_none()
                                            || self.installation.is_none()
                                            || self.is_working(),
                                    )
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.confirm_repeat_analysis(
                                            volgui::analysis::NETWORK,
                                            Self::analyze_network,
                                            window,
                                            cx,
                                        )
                                    })),
                            ),
                    ),
            )
            .child(
                div()
                    .id("network-navigation")
                    .w_full()
                    .min_w_0()
                    .flex_shrink_0()
                    .overflow_x_scroll()
                    .track_scroll(&self.scroll_state.area(
                        scroll_state::ScrollArea::NetworkNavigation(self.selected_evidence.clone()),
                    ))
                    .px_3()
                    .py_1()
                    .child(navigation),
            );
        if let Some(run) = recovering {
            root = root.child(div().px_3().py_1().text_xs().child(format!("Network evidence recovery {}. Configuration and command findings will appear here when it finishes.", run.status.label().to_lowercase())));
        }
        let mut body = div()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .min_w_0()
            .overflow_hidden()
            .child(div().px_3().py_1().text_xs().flex_shrink_0().child(format!(
                "{} IPs · {} of {} entries · {} peers · {} unplotted",
                overview.addresses.len(),
                overview.matching,
                self.network.entries.len(),
                overview.peers.len(),
                self.network.unplotted
            )));
        if self.network_loading {
            body = body.child(
                div()
                    .p_4()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("Loading network entries..."),
            );
        } else if self.network.entries.is_empty() {
            body = body.child(
                div()
                    .p_4()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(self.results_empty_message(cx)),
            );
        } else if self.network_table_view {
            self.sync_network_table(overview.indices.clone(), cx);
            self.restore_table_scroll(
                scroll_state::ResultTableKind::Network,
                &self.network_table,
                cx,
            );
            body = body.child(
                div()
                    .id("network-table")
                    .aria_label("Network connection table")
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .overflow_hidden()
                    .p_2()
                    .child(
                        DataTable::new(&self.network_table)
                            .small()
                            .header_row_height(px(32.)),
                    ),
            );
        } else if overview.matching == 0 {
            body = body.child(div().p_4().text_sm().text_color(cx.theme().muted_foreground).child("No network entries match these filters. Clear the search or turn off filters to see more entries."));
        } else {
            body = body.child(self.render_network_canvas(overview, cx));
        }
        drop(cache);
        let content = if self.content_sidebar_visible {
            h_resizable("network-endpoint-split")
                .child(
                    resizable_panel()
                        .size_range(px(280.)..Pixels::MAX)
                        .child(body),
                )
                .child(
                    resizable_panel()
                        .size(px(365.))
                        .size_range(px(280.)..px(800.))
                        .flex_none()
                        .fixed()
                        .child(self.render_network_sidebar(cx)),
                )
                .into_any_element()
        } else {
            body.into_any_element()
        };
        root.child(
            div()
                .flex_1()
                .min_h_0()
                .min_w_0()
                .overflow_hidden()
                .child(content),
        )
        .into_any_element()
    }

    fn render_network_canvas(&self, overview: &Overview, cx: &mut Context<Self>) -> AnyElement {
        // Lay out every peer, but instantiate controls only around the visible viewport.
        let top = -f32::from(self.network_scroll.offset().y);
        let viewport_height = f32::from(self.network_scroll.bounds().size.height).max(600.);
        let visible = (top - 200.)..(top + viewport_height + 200.);
        let mut layout = Vec::new();
        let mut spans = std::collections::BTreeMap::<String, (f32, f32)>::new();
        let mut y = 20.;
        for (key, links) in &overview.peers {
            let rows = if key.0.is_none() {
                overview
                    .references
                    .get(&key.1)
                    .map_or(1, |ports| ports.len())
            } else {
                links.len()
            };
            let height = (rows.clamp(1, PORTS_PER_PEER) as f32 * NETWORK_ROW_HEIGHT)
                .max(NETWORK_NODE_HEIGHT)
                + NETWORK_PEER_GAP;
            if let Some(source) = &key.0 {
                spans
                    .entry(source.clone())
                    .and_modify(|span| span.1 = y + height)
                    .or_insert((y, y + height));
            }
            layout.push((key, links, y, height));
            y += height;
        }
        let height = (y + 30.).max(340.);
        let hubs: std::collections::BTreeMap<_, _> = spans
            .iter()
            .map(|(source, (start, end))| {
                let inset = (NETWORK_NODE_HEIGHT + NETWORK_PEER_GAP) / 2.;
                (source, (top + 140.).clamp(start + inset, end - inset))
            })
            .collect();
        let color = cx.theme().muted_foreground;
        let accent = cx.theme().primary;
        let mut nodes = div().relative().w(px(800.)).h(px(height));
        let mut lines = Vec::new();
        let mut peer_lines = Vec::new();
        for (peer_index, ((source, ip), links, y, block_height)) in layout.iter().enumerate() {
            if y + block_height < visible.start || *y > visible.end {
                continue;
            }
            let center = y + block_height / 2.;
            nodes = nodes.child(
                div()
                    .absolute()
                    .left(px(605.))
                    .top(px(center - NETWORK_NODE_HEIGHT / 2.))
                    .child(self.network_node(
                        ip.clone(),
                        if source.is_some() {
                            "Peer IP"
                        } else {
                            "Text reference"
                        },
                        peer_index,
                        true,
                        overview.partial_addresses.contains(ip),
                        cx,
                    )),
            );
            let mut port_id = peer_index * PORTS_PER_PEER * 3;
            if source.is_none()
                && let Some(ports) = overview.references.get(ip)
            {
                let count = ports.len().min(PORTS_PER_PEER);
                for (i, port) in ports.iter().take(PORTS_PER_PEER).enumerate() {
                    let row_y = center + (i as f32 - (count as f32 - 1.) / 2.) * NETWORK_ROW_HEIGHT;
                    let endpoint = Endpoint {
                        address: ip.clone(),
                        port: *port,
                    };
                    let selected = self.network_endpoint.as_ref()
                        == Some(&Selection::Endpoint(endpoint.clone()));
                    peer_lines.push((row_y, center, selected));
                    nodes = nodes.child(
                        div()
                            .absolute()
                            .left(px(513.))
                            .top(px(row_y - 10.))
                            .w(px(65.))
                            .child(self.network_port(endpoint, port_id, cx)),
                    );
                    port_id += 1;
                }
            }
            for (i, (local, remote, protocol)) in links.iter().take(PORTS_PER_PEER).enumerate() {
                let count = links.len().min(PORTS_PER_PEER);
                let row_y = center + (i as f32 - (count as f32 - 1.) / 2.) * NETWORK_ROW_HEIGHT;
                let highlighted = self.network_endpoint.as_ref().is_some_and(|selected| {
                    selected == &Selection::Endpoint(local.clone())
                        || selected == &Selection::Endpoint(remote.clone())
                });
                if let Some(source) = source {
                    lines.push((hubs[source], row_y, highlighted));
                }
                peer_lines.push((row_y, center, highlighted));
                nodes = nodes
                    .child(
                        div()
                            .absolute()
                            .left(px(215.))
                            .top(px(row_y - 10.))
                            .w(px(65.))
                            .child(self.network_port(local.clone(), port_id, cx)),
                    )
                    .child(
                        div()
                            .absolute()
                            .left(px(513.))
                            .top(px(row_y - 10.))
                            .w(px(65.))
                            .child(self.network_port(remote.clone(), port_id + 1, cx)),
                    )
                    .child(
                        div()
                            .absolute()
                            .left(px(365.))
                            .top(px(row_y - 17.))
                            .text_xs()
                            .text_color(color)
                            .child(protocol.clone()),
                    );
                port_id += 2;
            }
            if links.len() > PORTS_PER_PEER {
                nodes = nodes.child(
                    div()
                        .absolute()
                        .left(px(220.))
                        .top(px(y + block_height - 20.))
                        .text_xs()
                        .child(format!(
                            "{} more port pairs. Click the peer IP for all entries.",
                            links.len() - PORTS_PER_PEER
                        )),
                );
            }
        }
        let paths = canvas(
            move |bounds, _, _| bounds,
            move |bounds, _, window, _| {
                for (hub_y, row_y, selected) in &lines {
                    let p = |x, y| bounds.origin + point(px(x), px(y));
                    let mut path = PathBuilder::stroke(px(if *selected { 2. } else { 1. }));
                    path.move_to(p(195., *hub_y));
                    path.curve_to(p(214., *row_y), p(204., *hub_y));
                    path.move_to(p(280., *row_y));
                    path.line_to(p(513., *row_y));
                    if let Ok(path) = path.build() {
                        window.paint_path(
                            path,
                            if *selected {
                                accent
                            } else {
                                color.opacity(0.5)
                            },
                        );
                    }
                }
                for (row_y, center, selected) in &peer_lines {
                    let p = |x, y| bounds.origin + point(px(x), px(y));
                    let mut path = PathBuilder::stroke(px(if *selected { 2. } else { 1. }));
                    path.move_to(p(578., *row_y));
                    path.curve_to(p(605., *center), p(590., *row_y));
                    if let Ok(path) = path.build() {
                        window.paint_path(
                            path,
                            if *selected {
                                accent
                            } else {
                                color.opacity(0.5)
                            },
                        );
                    }
                }
            },
        )
        .absolute()
        .size_full();
        let mut graph = div()
            .relative()
            .w(px(800.))
            .h(px(height))
            .child(paths)
            .child(nodes);
        for (i, (source, (start, end))) in spans.iter().enumerate() {
            if *end < visible.start || *start > visible.end {
                continue;
            }
            graph = graph.child(
                div()
                    .absolute()
                    .left(px(15.))
                    .top(px(hubs[source] - NETWORK_NODE_HEIGHT / 2.))
                    .child(self.network_node(
                        source.clone(),
                        if self.network_all_sources {
                            "Source IP"
                        } else {
                            "Focus IP"
                        },
                        usize::MAX - i,
                        spans.len() > 1,
                        overview.partial_addresses.contains(source),
                        cx,
                    )),
            );
        }
        div()
            .relative()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .overflow_hidden()
            .child(
                div()
                    .id("network-graph-scroll")
                    .aria_label("Network connection canvas")
                    .size_full()
                    .overflow_scroll()
                    .track_scroll(&self.network_scroll)
                    .on_scroll_wheel(cx.listener(|_, _, _, cx| cx.notify()))
                    .child(graph),
            )
            .child(Scrollbar::vertical(&self.network_scroll).mode(ScrollbarMode::Always))
            .child(Scrollbar::horizontal(&self.network_scroll).mode(ScrollbarMode::Always))
            .into_any_element()
    }

    fn render_network_sidebar(&self, cx: &mut Context<Self>) -> AnyElement {
        let endpoint = self.network_endpoint.as_ref();
        let filter = self.network_filter(cx);
        let mut cache = self.network_cache.borrow_mut();
        if cache
            .sidebar
            .as_ref()
            .is_none_or(|(key, selection, _)| key != &filter || selection.as_ref() != endpoint)
        {
            let indices = cache
                .overview
                .as_ref()
                .map(|(_, overview)| overview.indices.as_ref().clone())
                .unwrap_or_default();
            let indices = indices
                .into_iter()
                .filter(|i| endpoint.is_none_or(|s| s.matches(&self.network.entries[*i])))
                .collect();
            cache.sidebar = Some((filter, endpoint.cloned(), indices));
        }
        let entries = &cache
            .sidebar
            .as_ref()
            .expect("network sidebar initialized")
            .2;
        let page = self
            .network_sidebar_page
            .min(entries.len().saturating_sub(1) / ENTRIES_PER_PAGE);
        let mut sidebar = div()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .min_w_0()
            .overflow_hidden()
            .border_l_1()
            .border_color(cx.theme().border)
            .child(
                div()
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .flex()
                            .w_full()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .child(
                                div().text_sm().font_weight(FontWeight::SEMIBOLD).child(
                                    endpoint
                                        .map(Selection::label)
                                        .unwrap_or_else(|| "Network evidence".into()),
                                ),
                            )
                            .child(
                                app_button("network-all-entries")
                                    .xsmall()
                                    .label("Show all entries")
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.network_endpoint = None;
                                        this.network_sidebar_page = 0;
                                        cx.notify();
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .text_xs()
                            .child(format!("{} matching entries", entries.len())),
                    ),
            );
        let mut cards = div()
            .id("network-endpoint-entries")
            .flex_1()
            .min_h_0()
            .min_w_0()
            .w_full()
            .overflow_y_scroll()
            .track_scroll(&self.network_sidebar_scroll)
            .p_2()
            .flex()
            .flex_col()
            .gap_2();
        for entry in entries
            .iter()
            .skip(page * ENTRIES_PER_PAGE)
            .take(ENTRIES_PER_PAGE)
        {
            cards = cards.child(self.render_network_entry(&self.network.entries[*entry], cx));
        }
        if entries.is_empty() {
            cards = cards.child("No entries match this endpoint.");
        }
        sidebar = sidebar.child(cards).child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .p_2()
                .child(
                    app_button("network-entry-prev")
                        .xsmall()
                        .label("Previous")
                        .disabled(page == 0)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.network_sidebar_page = this.network_sidebar_page.saturating_sub(1);
                            this.network_sidebar_scroll.set_offset(Point::default());
                            cx.notify();
                        })),
                )
                .child(div().text_xs().child(format!(
                    "{} / {}",
                    page + 1,
                    entries.len().div_ceil(ENTRIES_PER_PAGE).max(1)
                )))
                .child(
                    app_button("network-entry-next")
                        .xsmall()
                        .label("Next")
                        .disabled((page + 1) * ENTRIES_PER_PAGE >= entries.len())
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.network_sidebar_page += 1;
                            this.network_sidebar_scroll.set_offset(Point::default());
                            cx.notify();
                        })),
                ),
        );
        sidebar.into_any_element()
    }

    fn render_network_entry(&self, entry: &Entry, cx: &mut Context<Self>) -> AnyElement {
        let id = entry.source.id;
        let source = entry.source.clone();
        let pid = entry.pid.clone();
        let mut card = div()
            .id(key("network-entry", &id.to_string()))
            .when(entry.source.record.is_partial_match(), |card| {
                card.bg(partial_matches::background())
                    .text_color(partial_matches::foreground())
                    .child("Partial match")
            })
            .min_w_0()
            .w_full()
            .overflow_hidden()
            .flex_shrink_0()
            .p_3()
            .rounded_lg()
            .border_1()
            .border_color(if self.selected.as_ref().is_some_and(|r| r.id == id) {
                cx.theme().primary
            } else {
                cx.theme().border
            })
            .flex()
            .flex_col()
            .gap_1()
            .text_xs();
        let known = |value: &str| {
            !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "" | "unknown"
                    | "not recovered"
                    | "n/a"
                    | "none"
                    | "null"
                    | "-"
                    | "unreadable"
                    | "not available"
            )
        };
        let endpoints = [&entry.local, &entry.remote]
            .into_iter()
            .flatten()
            .map(|endpoint| match common_service(endpoint.port) {
                Some(service) => format!("{} ({service})", endpoint.label()),
                None => endpoint.label(),
            })
            .collect::<Vec<_>>();
        let header = if known(&entry.protocol) {
            format!("Protocol: {}", entry.protocol)
        } else {
            endpoints.join(" \u{2194} ")
        };
        card = card.child(
            div()
                .flex()
                .w_full()
                .items_center()
                .justify_between()
                .gap_2()
                .child(div().flex_1().min_w_0().child(header))
                .child(
                    app_button(key("network-inspect", &id.to_string()))
                        .xsmall()
                        .label("Inspect record")
                        .on_click(cx.listener(move |this, _, window, cx| {
                            cx.stop_propagation();
                            this.detail = DetailTab::Overview;
                            this.show_record((*source).clone(), window, cx);
                        })),
                ),
        );
        for (label, value) in [
            ("Created", entry.created.as_str()),
            ("State", entry.state.as_str()),
        ] {
            if known(value) {
                card = card.child(div().child(format!("{label}: {value}")));
            }
        }
        if known(&entry.protocol) && !endpoints.is_empty() {
            card = card.child(div().child(endpoints.join(" ↔ ")));
        }
        if entry.finding {
            let finding = entry.source.record.text("Finding");
            if known(&finding) {
                card = card.child(div().text_color(cx.theme().primary).child(finding));
            }
            for field in ["Share", "Username", "Password", "Source type"] {
                let text = entry.source.record.text(field);
                if known(&text) {
                    card = card.child(div().child(format!("{field}: {text}")));
                }
            }
        }
        let mut actions = div().flex().flex_wrap().min_w_0().items_center().gap_2();

        if known(&pid) {
            actions = actions.child(
                app_button(key("network-process", &id.to_string()))
                    .xsmall()
                    .label(if known(&entry.owner) {
                        format!("{} (PID {})", entry.owner, pid)
                    } else {
                        format!("PID {}", pid)
                    })
                    .tooltip("Go to process view")
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.stop_propagation();
                        this.open_process(pid.clone(), cx);
                    })),
            );
        }
        card.child(actions)
            .on_click(cx.listener(move |this, _, _, cx| {
                this.detail = DetailTab::Overview;
                this.load_record(id, cx);
            }))
            .into_any_element()
    }
}
