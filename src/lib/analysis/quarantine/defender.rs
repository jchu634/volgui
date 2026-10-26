//! Defender Entries metadata. Payload ResourceData files are never decrypted.
//! Format: https://www.fox-it.com/be-en/reverse-reveal-recover-windows-defender-quarantine-forensics/
use crate::volatility::Record;
use serde_json::json;

const KEY: [u8; 256] = [
    0x1e, 0x87, 0x78, 0x1b, 0x8d, 0xba, 0xa8, 0x44, 0xce, 0x69, 0x70, 0x2c, 0x0c, 0x78, 0xb7, 0x86,
    0xa3, 0xf6, 0x23, 0xb7, 0x38, 0xf5, 0xed, 0xf9, 0xaf, 0x83, 0x53, 0x0f, 0xb3, 0xfc, 0x54, 0xfa,
    0xa2, 0x1e, 0xb9, 0xcf, 0x13, 0x31, 0xfd, 0x0f, 0x0d, 0xa9, 0x54, 0xf6, 0x87, 0xcb, 0x9e, 0x18,
    0x27, 0x96, 0x97, 0x90, 0x0e, 0x53, 0xfb, 0x31, 0x7c, 0x9c, 0xbc, 0xe4, 0x8e, 0x23, 0xd0, 0x53,
    0x71, 0xec, 0xc1, 0x59, 0x51, 0xb8, 0xf3, 0x64, 0x9d, 0x7c, 0xa3, 0x3e, 0xd6, 0x8d, 0xc9, 0x04,
    0x7e, 0x82, 0xc9, 0xba, 0xad, 0x97, 0x99, 0xd0, 0xd4, 0x58, 0xcb, 0x84, 0x7c, 0xa9, 0xff, 0xbe,
    0x3c, 0x8a, 0x77, 0x52, 0x33, 0x55, 0x7d, 0xde, 0x13, 0xa8, 0xb1, 0x40, 0x87, 0xcc, 0x1b, 0xc8,
    0xf1, 0x0f, 0x6e, 0xcd, 0xd0, 0x83, 0xa9, 0x59, 0xcf, 0xf8, 0x4a, 0x9d, 0x1d, 0x50, 0x75, 0x5e,
    0x3e, 0x19, 0x18, 0x18, 0xaf, 0x23, 0xe2, 0x29, 0x35, 0x58, 0x76, 0x6d, 0x2c, 0x07, 0xe2, 0x57,
    0x12, 0xb2, 0xca, 0x0b, 0x53, 0x5e, 0xd8, 0xf6, 0xc5, 0x6c, 0xe7, 0x3d, 0x24, 0xbd, 0xd0, 0x29,
    0x17, 0x71, 0x86, 0x1a, 0x54, 0xb4, 0xc2, 0x85, 0xa9, 0xa3, 0xdb, 0x7a, 0xca, 0x6d, 0x22, 0x4a,
    0xea, 0xcd, 0x62, 0x1d, 0xb9, 0xf2, 0xa2, 0x2e, 0xd1, 0xe9, 0xe1, 0x1d, 0x75, 0xbe, 0xd7, 0xdc,
    0x0e, 0xcb, 0x0a, 0x8e, 0x68, 0xa2, 0xff, 0x12, 0x63, 0x40, 0x8d, 0xc8, 0x08, 0xdf, 0xfd, 0x16,
    0x4b, 0x11, 0x67, 0x74, 0xcd, 0x0b, 0x9b, 0x8d, 0x05, 0x41, 0x1e, 0xd6, 0x26, 0x2e, 0x42, 0x9b,
    0xa4, 0x95, 0x67, 0x6b, 0x83, 0x98, 0xdb, 0x2f, 0x35, 0xd3, 0xc1, 0xb9, 0xce, 0xd5, 0x26, 0x36,
    0xf2, 0x76, 0x5e, 0x1a, 0x95, 0xcb, 0x7c, 0xa4, 0xc3, 0xdd, 0xab, 0xdd, 0xbf, 0xf3, 0x82, 0x53,
];
pub(super) const MAX_BYTES: usize = 8 * 1024 * 1024;

fn crypt(bytes: &[u8]) -> Vec<u8> {
    let mut state: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + usize::from(state[i]) + usize::from(KEY[i])) & 255;
        state.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    bytes
        .iter()
        .map(|byte| {
            i = (i + 1) & 255;
            j = (j + usize::from(state[i])) & 255;
            state.swap(i, j);
            byte ^ state[(usize::from(state[i]) + usize::from(state[j])) & 255]
        })
        .collect()
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    bytes
        .get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| "Truncated Defender metadata".into())
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, String> {
    bytes
        .get(offset..offset + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| "Truncated Defender metadata".into())
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}
fn timestamp(value: u64) -> String {
    let Some(ticks) = value.checked_sub(116_444_736_000_000_000) else {
        return String::new();
    };
    chrono::DateTime::from_timestamp(
        (ticks / 10_000_000) as i64,
        ((ticks % 10_000_000) * 100) as u32,
    )
    .map(|t| t.to_rfc3339())
    .unwrap_or_default()
}
fn utf16(bytes: &[u8]) -> Result<String, String> {
    if !bytes.len().is_multiple_of(2) {
        return Err("Invalid Defender UTF-16 field".into());
    }
    let units = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .take_while(|v| *v != 0)
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|_| "Invalid Defender UTF-16 field".into())
}

pub(super) fn parse(bytes: &[u8]) -> Result<Vec<Record>, String> {
    if bytes.len() < 60 || bytes.len() > MAX_BYTES {
        return Err("Invalid Defender metadata size".into());
    }
    let header = crypt(&bytes[..60]);
    if header[..4] != [0xdb, 0xe8, 0xc5, 0x01] || header[56..] != [0xdb, 0xe8, 0xc5, 0x02] {
        return Err("Unsupported Defender metadata header".into());
    }
    let size1 = u32_at(&header, 40)? as usize;
    let size2 = u32_at(&header, 44)? as usize;
    if size1 < 53
        || size2 < 8
        || size1 > MAX_BYTES
        || size2 > MAX_BYTES
        || 60 + size1 + size2 > bytes.len()
    {
        return Err("Incomplete Defender metadata sections".into());
    }
    let meta = crypt(&bytes[60..60 + size1]);
    let resources = crypt(&bytes[60 + size1..60 + size1 + size2]);
    if crc32(&meta) != u32_at(&header, 48)? || crc32(&resources) != u32_at(&header, 52)? {
        return Err("Defender metadata checksum mismatch; cached bytes may be incomplete".into());
    }
    if u32_at(&meta, 48)? != 1 {
        return Err("Unsupported Defender metadata version".into());
    }
    let name_bytes = &meta[52..];
    let end = name_bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or("Unterminated Defender threat name")?;
    let threat =
        std::str::from_utf8(&name_bytes[..end]).map_err(|_| "Invalid Defender threat name")?;
    if threat.is_empty() {
        return Err("Missing Defender threat name".into());
    }
    let count = u32_at(&resources, 0)? as usize;
    if count == 0 || count > 1024 || 4 + count * 4 > resources.len() {
        return Err("Invalid Defender resource count".into());
    }
    let mut offsets = Vec::with_capacity(count);
    for index in 0..count {
        let offset = u32_at(&resources, 4 + index * 4)? as usize;
        if offset < 4 + count * 4 || offset >= resources.len() || offsets.contains(&offset) {
            return Err("Invalid Defender resource offset".into());
        }
        offsets.push(offset);
    }
    offsets.sort_unstable();
    let mut rows = Vec::new();
    for (index, start) in offsets.iter().copied().enumerate() {
        let limit = offsets.get(index + 1).copied().unwrap_or(resources.len());
        let bytes = &resources[start..limit];
        let end = bytes
            .chunks_exact(2)
            .position(|b| b == [0, 0])
            .map(|i| i * 2)
            .ok_or("Unterminated Defender detection path")?;
        let mut path = utf16(&bytes[..end])?;
        let fields = bytes
            .get(end + 2..end + 4)
            .ok_or("Truncated Defender field count")?;
        let count = u16::from_le_bytes([fields[0], fields[1]]) as usize;
        if count > 1024 {
            return Err("Invalid Defender field count".into());
        }
        let kind_start = end + 4;
        let kind_end = bytes
            .get(kind_start..)
            .and_then(|b| b.iter().position(|v| *v == 0))
            .map(|i| kind_start + i)
            .ok_or("Unterminated Defender detection type")?;
        let kind = std::str::from_utf8(&bytes[kind_start..kind_end])
            .map_err(|_| "Invalid Defender detection type")?;
        let mut row = super::super::record(
            json!({"Threat":threat,"Quarantined at":timestamp(u64_at(&meta, 32)?),
            "Threat ID":u64_at(&meta, 40)?,"Detection type":kind,
            "Quarantine ID":meta[..16].iter().map(|b| format!("{b:02X}")).collect::<String>()}),
        );
        let mut position = start + kind_end + 1;
        for _ in 0..count {
            position = (position + 3) & !3;
            if position + 4 > limit {
                return Err("Truncated Defender resource field".into());
            }
            let field = &resources[position..limit];
            let size = u16::from_le_bytes([field[0], field[1]]) as usize;
            let identifier = u16::from_le_bytes([field[2], field[3]]) & 0xfff;
            let data = field
                .get(4..4 + size)
                .ok_or("Truncated Defender resource value")?;
            match identifier {
                2 => {
                    row.fields.insert(
                        "Resource ID".into(),
                        data.iter()
                            .map(|b| format!("{b:02X}"))
                            .collect::<String>()
                            .into(),
                    );
                }
                12 => path = utf16(data)?,
                15..=17 => {
                    row.fields.insert(
                        match identifier {
                            15 => "File created",
                            16 => "File accessed",
                            _ => "File modified",
                        }
                        .into(),
                        timestamp(u64_at(data, 0)?).into(),
                    );
                }
                18 => {
                    row.fields
                        .insert("File size".into(), u64_at(data, 0)?.into());
                }
                _ => {}
            }
            position += 4 + size;
        }
        if kind == "file" && !path.is_empty() {
            row.fields.insert("Original path".into(), path.into());
            rows.push(row);
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut meta = vec![0; 52];
        meta[32..40].copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
        meta[40..48].copy_from_slice(&2147519003u64.to_le_bytes());
        meta[48..52].copy_from_slice(&1u32.to_le_bytes());
        meta.extend_from_slice(b"Trojan:Win32/Test\0");
        let mut resources = vec![2, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0];
        for path in [r"C:\Users\Alice\Downloads\bad.exe", r"C:\Temp\second.exe"] {
            if resources.len() > 12 {
                let offset = resources.len() as u32;
                resources[8..12].copy_from_slice(&offset.to_le_bytes());
            }
            resources.extend(path.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
            resources.extend_from_slice(&[0, 0]);
            resources.extend_from_slice(b"file\0");
        }
        let mut header = vec![0; 60];
        header[..4].copy_from_slice(&[0xdb, 0xe8, 0xc5, 0x01]);
        header[56..].copy_from_slice(&[0xdb, 0xe8, 0xc5, 0x02]);
        header[40..44].copy_from_slice(&(meta.len() as u32).to_le_bytes());
        header[44..48].copy_from_slice(&(resources.len() as u32).to_le_bytes());
        header[48..52].copy_from_slice(&crc32(&meta).to_le_bytes());
        header[52..56].copy_from_slice(&crc32(&resources).to_le_bytes());
        [crypt(&header), crypt(&meta), crypt(&resources)].concat()
    }
    #[test]
    fn reads_multiple_resources_and_rejects_partial_or_corrupt_cache_bytes() {
        // Defender stores the running CRC before the usual final inversion.
        assert_eq!(crc32(b"123456789"), 0x340bc6d9);
        let bytes = fixture();
        let rows = parse(&bytes).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].text("Threat"), "Trojan:Win32/Test");
        assert_eq!(rows[1].text("Original path"), r"C:\Temp\second.exe");
        for end in 0..bytes.len() {
            assert!(parse(&bytes[..end]).is_err());
        }
        let mut corrupt = bytes;
        *corrupt.last_mut().unwrap() ^= 0xff;
        assert!(parse(&corrupt).unwrap_err().contains("checksum"));
    }
    #[test]
    fn malformed_lengths_and_offsets_do_not_panic() {
        for seed in 0..=255u8 {
            let _ = parse(&vec![seed; 512]);
        }
        let bytes = fixture();
        let mut header = crypt(&bytes[..60]);
        header[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&[crypt(&header), bytes[60..].to_vec()].concat()).is_err());
    }
}
