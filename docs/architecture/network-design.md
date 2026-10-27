# Network investigation

Network investigation queues available socket, process, command and handle inventories before a native parser. Findings use the normal case queue, result store, bookmarks and exports. See [analysis details](../analysis-details.md#network) for supported formats and limits.

## Projection and rendering

`ResultStore::network_ids` preserves every run/row occurrence. A background worker builds an in-memory projection from raw records, preventing entity enrichment from inventing owners or endpoints. This avoids a second persistent store at the cost of memory proportional to scoped records.

Graph, table and sidebar share search, protocol, state and noise filters. The graph shows one focus IP or all source IPs on a continuous virtualized canvas. Each peer displays up to twelve port pairs; the sidebar exposes all occurrences in forty-record pages. The table virtualizes rows and sorts PID/port columns numerically. Graph focus does not restrict the table.

Address selection matches either socket side. Endpoint selection requires address and port on the same side. Text-only references remain separate from observed edges. Back restores selection, filters, paging and scroll position. Source bytes uses the recorded acquisition offset; process-attribution findings use their pinned dump.

## Evidence and filters

The parser consumes preceding completed runs from the same evidence and retains source run, row, field and parser version. Credentials come only from explicit network-drive commands and remain scoped to their command/share. Hostnames are not resolved without evidence. Recovered configurations and command references do not prove execution or communication.

Noise filters cover loopback, wildcard endpoints, port zero and missing remote endpoints. Unknown owners or ports alone are not noise. Analysis findings bypass noise heuristics. System classification uses process basenames and makes no safety claim.

Interesting Traffic includes recovered findings, SMB and common remote administration endpoints. Other filters still apply. It queues missing native recovery, reuses active jobs and retries interrupted or older parsers. Completed jobs refresh evidence-wide views. Historical download configuration rows remain available with original provenance.

## Validation

Network tests cover endpoint pairing, IPv6, missing ports/owners, repeated occurrences, source boundaries, queue barriers, cancellation, persistence and credential scoping. UI checks cover numeric sorting, endpoint paging, source bytes, bounded IP navigation, scrolling and Back restoration. Use the network validation command in [Validation](../validation.md).
