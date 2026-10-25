use super::*;
use volgui::network::{Endpoint, Entry, Filter, Overview, Selection, service};

const PEERS_PER_PAGE: usize = 6;
const ENTRIES_PER_PAGE: usize = 40;
const PORTS_PER_PEER: usize = 12;

#[derive(Default)]
pub(in crate::ui) struct NetworkViewCache {
    overview: Option<(Filter, Overview)>,
    sidebar: Option<(Option<Selection>, Vec<usize>)>,
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
        Button::new(if protocol {
            "network-protocol"
        } else {
            "network-state"
        })
        .small()
        .ghost()
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
                    this.network_page = 0;
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
                        this.network_page = 0;
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
        Button::new(("network-port", id))
            .xsmall()
            .ghost()
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
            .rounded_lg()
            .border_1()
            .border_color(if selected {
                cx.theme().primary
            } else {
                cx.theme().border
            })
            .bg(cx.theme().background)
            .shadow_sm()
            .child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child(label),
            )
            .child(div().child(address))
            .child(
                Button::new(("network-focus", id))
                    .xsmall()
                    .ghost()
                    .label("Switch IP")
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.stop_propagation();
                        this.network_focus = Some(focus.clone());
                        this.network_page = 0;
                        cx.notify();
                    })),
            )
            .into_any_element()
    }

    pub(in crate::ui) fn render_network(&self, cx: &mut Context<Self>) -> AnyElement {
        let mut root = div()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .min_w_0()
            .overflow_hidden()
            .child(self.render_results_toolbar(cx));
        let focus = self.network_focus.clone();
        let weak = cx.entity().downgrade();
        let addresses: Vec<_> = self.network.addresses.keys().cloned().collect();
        let current = focus
            .as_ref()
            .and_then(|s| addresses.iter().position(|ip| ip == s))
            .unwrap_or(0);
        let mut controls = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_2()
            .px_3()
            .py_2()
            .child(self.network_filter_menu(true, cx))
            .child(self.network_filter_menu(false, cx))
            .child(
                Button::new("network-focus-picker")
                    .small()
                    .ghost()
                    .dropdown_caret(true)
                    .label(focus.clone().unwrap_or_else(|| "Choose IP".into()))
                    .dropdown_menu(move |mut menu, _, _| {
                        // Focus is also reachable for every node by the previous/next IP controls.
                        for ip in addresses.iter().skip(current.saturating_sub(30)).take(61) {
                            let ip = ip.clone();
                            let weak = weak.clone();
                            menu = menu.item(PopupMenuItem::new(ip.clone()).on_click(
                                move |_, _, cx| {
                                    let _ = weak.update(cx, |this, cx| {
                                        this.network_focus = Some(ip.clone());
                                        this.network_page = 0;
                                        cx.notify();
                                    });
                                },
                            ));
                        }
                        menu
                    }),
            );
        for (id, label, forward) in [
            ("network-prev-ip", "Previous IP", false),
            ("network-next-ip", "Next IP", true),
        ] {
            controls = controls.child(
                Button::new(id)
                    .xsmall()
                    .ghost()
                    .label(label)
                    .disabled(self.network.addresses.is_empty())
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let ips: Vec<_> = this.network.addresses.keys().cloned().collect();
                        let at = this
                            .network_focus
                            .as_ref()
                            .and_then(|ip| ips.iter().position(|v| v == ip))
                            .unwrap_or(0);
                        let next = if forward {
                            (at + 1) % ips.len()
                        } else {
                            (at + ips.len() - 1) % ips.len()
                        };
                        this.network_focus = ips.get(next).cloned();
                        this.network_page = 0;
                        cx.notify();
                    })),
            );
        }
        controls = controls.child(
            Button::new("network-investigate")
                .small()
                .label("Analyze network")
                .disabled(
                    self.evidence().is_none() || self.installation.is_none() || self.is_working(),
                )
                .on_click(cx.listener(|this, _, window, cx| this.analyze_network(window, cx))),
        );
        root = root.child(controls);

        let filter = Filter {
            focus: focus.clone(),
            text: self.query.read(cx).value().to_ascii_lowercase(),
            protocol: self.network_protocol.clone(),
            state: self.network_state.clone(),
        };
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
        let peers = &overview.peers;
        let references = &overview.references;
        let visible_entries = overview.matching;
        let page = self
            .network_page
            .min(peers.len().saturating_sub(1) / PEERS_PER_PAGE);
        let mut graph = div().relative().w(px(800.)).min_h(px(340.));
        let page_peers: Vec<_> = peers
            .iter()
            .skip(page * PEERS_PER_PAGE)
            .take(PEERS_PER_PAGE)
            .collect();
        let heights: Vec<_> = page_peers
            .iter()
            .map(|(_, links)| (links.len().clamp(1, PORTS_PER_PEER) as f32 * 34. + 48.).max(120.))
            .collect();
        let height = heights.iter().sum::<f32>().max(340.) + 30.;
        let hub_y = 140.;
        graph = graph.h(px(height));
        let color = cx.theme().muted_foreground;
        let accent = cx.theme().primary;
        let mut lines = Vec::new();
        let mut y = 20.;
        let mut port_id = 0;
        for (peer_index, ((ip, links), block_height)) in page_peers.iter().zip(heights).enumerate()
        {
            let center = y + block_height / 2.;
            graph = graph.child(div().absolute().left(px(605.)).top(px(center - 50.)).child(
                self.network_node(
                    (*ip).clone(),
                    if links.is_empty() {
                        "Text reference"
                    } else {
                        "Peer IP"
                    },
                    peer_index,
                    cx,
                ),
            ));
            if let Some(ports) = references.get(*ip) {
                let mut buttons = div()
                    .absolute()
                    .left(px(605.))
                    .top(px(center + 50.))
                    .flex()
                    .gap_1();
                for port in ports.iter().take(PORTS_PER_PEER) {
                    buttons = buttons.child(self.network_port(
                        Endpoint {
                            address: (*ip).clone(),
                            port: *port,
                        },
                        port_id,
                        cx,
                    ));
                    port_id += 1;
                }
                graph = graph.child(buttons);
            }
            for (i, (local, remote, protocol)) in links.iter().take(PORTS_PER_PEER).enumerate() {
                let row_y = y + 24. + i as f32 * 34.;
                let highlighted = self.network_endpoint.as_ref().is_some_and(|selected| {
                    selected == &Selection::Endpoint(local.clone())
                        || selected == &Selection::Endpoint(remote.clone())
                });
                lines.push((row_y, center, highlighted));
                graph = graph
                    .child(
                        div()
                            .absolute()
                            .left(px(215.))
                            .top(px(row_y - 12.))
                            .w(px(65.))
                            .child(self.network_port(local.clone(), port_id, cx)),
                    )
                    .child(
                        div()
                            .absolute()
                            .left(px(513.))
                            .top(px(row_y - 12.))
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
                            .child(if protocol.is_empty() {
                                "Text reference".into()
                            } else {
                                protocol.clone()
                            }),
                    );
                port_id += 2;
            }
            if links.len() > PORTS_PER_PEER {
                graph = graph.child(
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
            y += block_height;
        }
        let paths = canvas(
            move |bounds, _, _| bounds,
            move |bounds, _, window, _| {
                for (row_y, center, selected) in &lines {
                    let p = |x, y| bounds.origin + point(px(x), px(y));
                    let mut path = PathBuilder::stroke(px(if *selected { 2. } else { 1. }));
                    path.move_to(p(195., hub_y));
                    path.curve_to(p(214., *row_y), p(204., hub_y));
                    path.move_to(p(278., *row_y));
                    path.line_to(p(510., *row_y));
                    path.move_to(p(575., *row_y));
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
        // Paint links first; controls remain clickable above the canvas.
        graph = div()
            .relative()
            .w(px(800.))
            .h(px(height))
            .child(paths)
            .child(graph);
        if let Some(ip) = &focus {
            graph = graph.child(
                div()
                    .absolute()
                    .left(px(15.))
                    .top(px(hub_y - 50.))
                    .child(self.network_node(ip.clone(), "Focus IP", usize::MAX, cx)),
            );
        }
        let mut body = div()
            .flex()
            .flex_col()
            .size_full()
            .min_h_0()
            .min_w_0()
            .overflow_hidden()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_3()
                    .py_1()
                    .text_xs()
                    .text_color(color)
                    .child(format!(
                        "{} IPs · {visible_entries} matching entries · {} peers · {} unplotted",
                        self.network.addresses.len(),
                        peers.len(),
                        self.network.unplotted
                    ))
                    .child(
                        Button::new("network-prev-page")
                            .xsmall()
                            .ghost()
                            .label("Previous peers")
                            .disabled(page == 0)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.network_page = this.network_page.saturating_sub(1);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("network-next-page")
                            .xsmall()
                            .ghost()
                            .label("Next peers")
                            .disabled((page + 1) * PEERS_PER_PAGE >= peers.len())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.network_page += 1;
                                cx.notify();
                            })),
                    ),
            );
        body = if self.network_loading {
            body.child(div().p_4().child("Loading network graph..."))
        } else if self.network.addresses.is_empty() {
            body.child(div().p_4().child("No IP endpoints recovered. Run Analyze network, select socket analyses, or clear the search. Other records remain available in the endpoint sidebar."))
        } else {
            body.child(
                div()
                    .id("network-graph-scroll")
                    .aria_label("Network IP graph")
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .w_full()
                    .overflow_scroll()
                    .track_scroll(&self.network_scroll)
                    .child(graph),
            )
        };
        drop(cache);
        root = if self.content_sidebar_visible {
            root.child(
                div()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .w_full()
                    .overflow_hidden()
                    .child(
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
                            ),
                    ),
            )
        } else {
            root.child(
                div()
                    .flex_1()
                    .min_h_0()
                    .min_w_0()
                    .overflow_hidden()
                    .child(body),
            )
        };
        root.into_any_element()
    }

    fn render_network_sidebar(&self, cx: &mut Context<Self>) -> AnyElement {
        let endpoint = self.network_endpoint.as_ref();
        let mut cache = self.network_cache.borrow_mut();
        if cache
            .sidebar
            .as_ref()
            .is_none_or(|(key, _)| key.as_ref() != endpoint)
        {
            cache.sidebar = Some((endpoint.cloned(), self.network.selected_indices(endpoint)));
        }
        let entries = &cache
            .sidebar
            .as_ref()
            .expect("network sidebar initialized")
            .1;
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
                        div().text_sm().font_weight(FontWeight::SEMIBOLD).child(
                            endpoint
                                .map(Selection::label)
                                .unwrap_or_else(|| "Network evidence".into()),
                        ),
                    )
                    .child(
                        div()
                            .text_xs()
                            .child(format!("{} matching entries", entries.len())),
                    )
                    .child(
                        Button::new("network-all-entries")
                            .xsmall()
                            .ghost()
                            .label("Show all entries")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.network_endpoint = None;
                                this.network_sidebar_page = 0;
                                cx.notify();
                            })),
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
                    Button::new("network-entry-prev")
                        .xsmall()
                        .ghost()
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
                    Button::new("network-entry-next")
                        .xsmall()
                        .ghost()
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
        for (label, value) in [
            ("Created", entry.created.as_str()),
            ("Protocol", entry.protocol.as_str()),
            ("State", entry.state.as_str()),
        ] {
            if known(value) {
                card = card.child(div().child(format!("{label}: {value}")));
            }
        }
        let endpoints = [&entry.local, &entry.remote]
            .into_iter()
            .flatten()
            .map(Endpoint::label)
            .collect::<Vec<_>>();
        if !endpoints.is_empty() {
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
        let mut actions = div().flex().items_center().gap_2().child(
            Button::new(key("network-inspect", &id.to_string()))
                .xsmall()
                .ghost()
                .label("Inspect record")
                .on_click(cx.listener(move |this, _, window, cx| {
                    cx.stop_propagation();
                    this.detail = DetailTab::Overview;
                    this.show_record((*source).clone(), window, cx);
                })),
        );
        if known(&pid) {
            actions = actions.child(
                Button::new(key("network-process", &id.to_string()))
                    .xsmall()
                    .ghost()
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
