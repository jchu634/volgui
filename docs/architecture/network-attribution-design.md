# Network process attribution

The caller queues Network investigation as before. Supported Windows engines also receive a separate `volgui.network.ProcessAttribution` job. The chooser exposes Network process attribution independently, with an optional `--pid PID`. Browser recovery and Process Memory retain their existing interpretation and memory-region scope.

## Grounding and design comparison

The original Network parser scans acquisition bytes and selected engine inventories. Its output has no process mapping. Process Memory already recovered the dxdiag endpoint, but it scans only private writable VADs and produces text candidates. Browser's memory collector and Process Memory both validate Memmap dumps through `analysis/process_memory.rs`. Native jobs are queue barriers, and deferred jobs expand into prerequisites while preserving their original report identity.

Two whole designs were considered. Reverse-mapping acquisition offsets would be efficient for known hits, but requires native knowledge of ELF and other capture layers that VolGUI currently delegates to its engine. It would also miss strings or configurations visible only after virtual page reconstruction. Scanning mapped process dumps reuses existing full/user dumps, reads virtual sequences across fragmented physical pages, and can discover endpoints absent from acquisition-level findings. This implementation chooses mapped dumps and keeps capture-layer translation in the engine.

The architect skill's referenced `how` and `arena` skills are not installed. The source flow was traced locally, and a separate design runner compared the two approaches. No human checkpoint was requested.

## Interface sketch and ownership

```rust
// analysis/network_attribution.rs owns selection, provenance and interpretation.
pub fn recovery_runs(directory, document, evidence, engine, arguments, cancel)
    -> Result<Vec<Run>, String>;
pub fn analyze(directory, document, run, cancel, progress)
    -> Result<(Table, String), String>;

// process_memory.rs owns validated user mappings and bounded reads.
fn scan_windows(reader, ranges, cancel, max_bytes, visit)
    -> Result<(u64, bool), String>;

// network/memory.rs owns the existing legacy payload format.
fn meterpreter_config(bytes, endpoint_offset, uri)
    -> Option<serde_json::Value>;
```

A selected PID uses pinned unfiltered process/command inventories directly. Broad discovery first runs or reuses an exact VAD regex request for ASCII/UTF-16 TCP and supported program markers, plus stock Beacon TLV headers under the supported XOR keys. Only discovered PIDs present in PsList are collected. This avoids dumping every process merely to find a small number of configuration candidates. The engine can miss unreadable processes or objects absent from PsList; this limitation is retained in the report. Engines without VAD regex discovery can still use an explicit PID.

Deferred preparation pins exact inventory, discovery, Memmap and VadInfo IDs. Complete compatible full/user dumps are reused, including Browser and Process Memory collections. Failed inputs cannot silently become successful empty results. Retries preserve user options but resolve their inputs again. Network's automatic attribution reuse compares source identity fingerprints as well as parser version, so later process collections invalidate prior coverage.

The parser intersects validated user mappings with readable VADs. Private, image and read-only regions are eligible; guard/no-access regions are excluded. Discontiguous virtual ranges are never joined. Windows retain up to 4 KiB before the core and 8 KiB after it. Command extraction walks back at most 2 KiB from its marker and retains at most 4 KiB of text bytes. The nonoverlapping core and per-process identities suppress repeated observations. UTF-16's shifted BE endpoint interpretation is retained as alternate coordinates rather than an extra artifact.

Findings retain PID, process creation context, command line, virtual and dump coordinates, VAD bounds/protection/mapped file, source identities and evidence fingerprint. Validated configurations additionally retain UUIDs, session data and a hash of their complete reconstructed bytes. Process bytes establish presence in an address space, not successful communication, exclusive ownership or execution. They remain separate observations from acquisition configurations and sockets.

The process limit is 256, the finding limit 20,000, the per-process read limit 1 GiB and the total read limit 4 GiB. Limits, cancellation and unavailable ranges are explicit. Selecting a process-memory finding's Source bytes opens its pinned dump, never the acquisition at a virtual offset.

## Validation and profiling

Unit and integration checks cover image/read-only memory, configurations crossing scan windows and physical-page boundaries, missing virtual ranges, IPv6, encoding ambiguity, cancellation, read limits, compatible dump reuse and exact source identity. Real-capture verification uses `examples/reparse_attribution.rs` without writing the source case. The dxdiag capture produces five endpoint locations and four configurations that pass complete virtual-memory validation.

`examples/profile_native_jobs.rs` profiles native parsing, the production result writer, object-store capture and SQLite import separately. It reads the source case, writes only temporary benchmark cases, compares imported rows and retains output hashes for baseline/treatment comparisons. Measurements and resulting optimisations are documented in `analysis-performance.md`.

## Additional program parsing

`network/commands.rs` owns explicit tool syntax, separate from payload configuration validators. It handles Ncat/netcat connect targets with scoped options, socat TCP/EXEC operands, PowerShell/.NET TcpClient constructors, literal Python socket targets and Bash TCP redirections. These are command references, not validated malware configurations. Listener mode, unresolved variables and unsupported syntax do not produce guessed remote targets. Command spans in memory retain their start coordinate and length; the address is explicitly labelled as the start of the command text.

`network/beacon.rs` validates stock Cobalt Strike Beacon HTTP(S) TLV settings. It supports unencoded bytes and default XOR keys `0x2e` and `0x69`, bounded typed fields, a zero terminator with padding, valid protocol/port/sleep/jitter settings, a DER RSA public-key structure and domain/URI pairs. It retains hashes of both the encoded and decoded logical setting spans. The validator does not infer Beacon version or surrounding slot size. Unknown keys, remapped fields, DNS/SMB/TCP Beacon transports, Sliver and Havoc remain unsupported. Tests use synthetic, non-executable format fixtures; no additional real malware-family capture was provided.

Acquisition scanning and process scanning call the same Beacon validator. Acquisition findings remain unattributed; process findings retain their mapped-source evidence. Configured hostnames appear as hostname references and are never resolved to invented IP addresses.

Format and syntax references consulted:

- [Fox-IT's original Beacon parser and format definitions](https://github.com/fox-it/dissect.cobaltstrike/blob/main/dissect/cobaltstrike/beacon.py).
- [Ncat usage](https://nmap.org/ncat/guide/ncat-usage.html) and [execution options](https://nmap.org/book/ncat-man.html).
- [Upstream socat manual](https://www.dest-unreach.org/socat/doc/socat.html), also distributed as the [socat manual page](https://man7.org/linux/man-pages/man1/socat.1.html).
- [Python socket documentation](https://docs.python.org/3/library/socket.html).
- [Microsoft TcpClient constructors](https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient.-ctor).
- [GNU Bash redirections](https://www.gnu.org/s/bash/manual/html_node/Redirections.html).
