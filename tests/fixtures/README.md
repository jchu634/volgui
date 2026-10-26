`defender-entry.bin` is synthetic encrypted Microsoft Defender Entries metadata.
It contains one file resource, `C:\Users\Alice\Downloads\payload.exe`, the
invented threat `Trojan:Win32/SyntheticTest`, a resource ID and a file size field.
It contains no executable content. The independently encrypted sections include
CRC-32 checksums. Tests use it to exercise the complete recovery and storage flow.
