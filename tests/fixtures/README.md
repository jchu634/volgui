# Test fixtures

`defender-entry.bin` contains synthetic encrypted Defender Entries metadata for one file resource and the invented threat `Trojan:Win32/SyntheticTest`. It includes a resource ID, file size and independently encrypted sections with CRC-32 checksums. It contains no executable content. Tests exercise metadata recovery and storage.
