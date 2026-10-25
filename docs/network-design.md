# Network investigation

## Caller workflow

Choose Network investigation and correlation in New analysis, or Analyze network in Network. The draft queues available socket, process, command history and handle inventories before the native parser. The native job waits for preceding engine work, correlates their saved records and stores ordinary immutable finding records and hashed output through the existing case lifecycle.

`Graph::load(store, query, epoch, token)` builds IP and endpoint membership off the UI thread. `Selection::Address(ip)` includes either side at every port; `Selection::Endpoint(endpoint)` requires address and port together on the same side, including an unknown port. The UI opens original records with `load_record` or `show_record` and resolves process links through the existing PID ambiguity checks.

## Storage and rendering

SQLite remains authoritative. `ResultStore::network_ids` returns every run/row occurrence in the selected scope. It bypasses the general browser's representative deduplication. The graph uses raw records so conflicting entity enrichment cannot invent a socket owner or overwrite an endpoint.

The graph shows one focus IP and up to six peer IPs per page, with twelve port pairs per peer. Overflow is explicit. The sidebar pages through all occurrences, forty at a time. Graph search, protocol and state filters do not change sidebar membership. Text-only references have separate nodes without invented links to the focus host. Explicit drive-command credentials and previously saved configuration candidates sort before other endpoint records. Bottom details retain bookmarks, raw JSON and run diagnostics. Source bytes opens the acquisition at the saved match offset, with context offset retained separately. Back retains the endpoint, filters, pages and graph scroll position.

The first alternative was a persisted, versioned endpoint projection with SQL indexes. That supports larger cases with less memory, but adds migrations and synchronization for a derived view. The second was standalone indexed analysis bundles, which duplicated case ownership. This implementation uses an in-memory projection built from SQLite occurrences. It accepts memory proportional to the scoped network records while bounding rendered nodes and sidebar cards. Search text and sidebar priority are prepared during background loading. Overview and sidebar membership are cached until their inputs change, so scrolling does not rescan and sort the scope. No second persistent data store is introduced.

## Evidence rules

Sockets and recovered command text remain distinct. The parser reads completed source runs preceding its queued job and records the exact source run, row and field, plus parser version and evidence fingerprint. It supports cancellation and reports a 20,000-finding limit and unavailable inventories. It extracts credentials only from explicit net use commands, excludes password prompts and scopes credentials to the specific command and share. It does not inspect unrelated username/password text or resolve share hostnames without separate evidence.

Network preprocessing does not open the acquisition to scan bytes. Global string search and Process Memory are separate tools for explicitly requested memory recovery. Parser version network-v2-records replaces the earlier whole-acquisition network string scan. Old immutable findings remain in the case with their original network-v1 provenance, including any previous Meterpreter configuration candidates and source offsets. Those historic findings do not cause a new memory scan.

## Verification

`tests/network.rs` covers exact endpoint pairing, IPv6 scopes, wildcard addresses, zero and missing ports, repeated observations across runs, stale workers, persistence, chooser prerequisites, queue barriers, quoted credentials, prompt markers, chained-command credential scoping, and source provenance. Regressions verify that network-shaped strings in raw acquisition bytes produce no findings and unrelated credentials in collected records are ignored, while credentials in an explicit network drive command retain their source run and row.

`examples/validate_network.rs` runs the same chooser queue and record correlation on a capture and exports network.csv into a new case. The acquisition and any existing case stay unchanged.
