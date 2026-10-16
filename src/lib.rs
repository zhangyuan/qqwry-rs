use encoding_rs::GBK;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

/// Reads a little-endian u32, or `None` if it would read past the buffer.
fn read_u32(buf: &[u8], pos: usize) -> Option<u32> {
    let bytes = buf.get(pos..pos + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads a little-endian u24, or `None` if it would read past the buffer.
fn read_u24(buf: &[u8], pos: usize) -> Option<u32> {
    let bytes = buf.get(pos..pos + 3)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]))
}

/// Reads a NUL-terminated GBK string, or `None` if it is unterminated or past
/// the end of the buffer.
fn read_string(buf: &[u8], pos: usize) -> Option<(String, usize)> {
    let rest = buf.get(pos..)?;
    let end = rest.iter().position(|&byte| byte == 0)? + pos;
    let (decoded, _, _) = GBK.decode(&buf[pos..end]);
    Some((decoded.into_owned(), end + 1))
}

fn malformed(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

#[derive(Debug)]
pub enum LookupError {
    ParseIp(std::net::AddrParseError),
    NotFound,
    Malformed,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LookupError::ParseIp(e) => write!(f, "IP解析错误: {}", e),
            LookupError::NotFound => write!(f, "未找到"),
            LookupError::Malformed => write!(f, "数据库格式错误"),
        }
    }
}

impl std::error::Error for LookupError {}

impl From<std::net::AddrParseError> for LookupError {
    fn from(e: std::net::AddrParseError) -> Self {
        LookupError::ParseIp(e)
    }
}

pub struct Qqwry {
    data: Vec<u8>,
    index_start: usize,
    index_end: usize,
}

impl Qqwry {
    /// Opens and lightly validates a qqwry database.
    ///
    /// The data is validated lazily while looking up: a corrupt or truncated
    /// file yields [`LookupError::Malformed`] rather than panicking.
    pub fn new(dat_path: impl AsRef<Path>) -> std::io::Result<Self> {
        Self::from_bytes(fs::read(dat_path)?)
    }

    /// Builds a database from an in-memory `qqwry.dat` image.
    ///
    /// Useful when the database is embedded in the binary or already held in
    /// memory; [`Qqwry::new`] is a thin wrapper around it.
    pub fn from_bytes(data: impl Into<Vec<u8>>) -> std::io::Result<Self> {
        let data = data.into();

        let index_start =
            read_u32(&data, 0).ok_or_else(|| malformed("qqwry: truncated header"))? as usize;
        let index_end =
            read_u32(&data, 4).ok_or_else(|| malformed("qqwry: truncated header"))? as usize;

        if index_start > index_end || index_end > data.len() {
            return Err(malformed("qqwry: index range is out of bounds"));
        }

        Ok(Qqwry {
            data,
            index_start,
            index_end,
        })
    }

    fn read_region(&self, offset: usize) -> Result<(String, usize), LookupError> {
        let buf = &self.data;
        let flag = *buf.get(offset).ok_or(LookupError::Malformed)?;

        if flag == 0 {
            return Ok((String::new(), offset + 1));
        }

        if flag == 0x01 || flag == 0x02 {
            let area_offset = read_u24(buf, offset + 1).ok_or(LookupError::Malformed)? as usize;
            if area_offset == 0 {
                Ok((String::new(), offset + 4))
            } else {
                read_string(buf, area_offset).ok_or(LookupError::Malformed)
            }
        } else {
            read_string(buf, offset).ok_or(LookupError::Malformed)
        }
    }

    /// Finds the record whose range contains `ip`.
    ///
    /// The index is sorted by start address, so we binary-search for the last
    /// entry whose start is `<= ip` and then check its end address. This only
    /// touches the index during the search (one random read at the end),
    /// instead of reading every probed record.
    fn search_ip(&self, ip: u32) -> Result<Option<usize>, LookupError> {
        let buf = &self.data;
        let count = (self.index_end - self.index_start) / 7 + 1;

        let mut left = 0usize;
        let mut right = count;
        while left < right {
            let mid = left + (right - left) / 2;
            let offset = self.index_start + mid * 7;
            let start_ip = read_u32(buf, offset).ok_or(LookupError::Malformed)?;

            if start_ip <= ip {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        if left == 0 {
            return Ok(None);
        }

        let offset = self.index_start + (left - 1) * 7;
        let record_offset = read_u24(buf, offset + 4).ok_or(LookupError::Malformed)? as usize;
        if record_offset == 0 {
            return Ok(None);
        }

        let end_ip = read_u32(buf, record_offset).ok_or(LookupError::Malformed)?;
        if ip <= end_ip {
            Ok(Some(record_offset))
        } else {
            Ok(None)
        }
    }

    fn read_location(&self, offset: usize) -> Result<(String, String), LookupError> {
        let buf = &self.data;
        let pos = offset + 4;
        let flag = *buf.get(pos).ok_or(LookupError::Malformed)?;

        let (location, isp) = if flag == 0x01 {
            let country_offset = read_u24(buf, pos + 1).ok_or(LookupError::Malformed)? as usize;
            let flag2 = *buf.get(country_offset).ok_or(LookupError::Malformed)?;

            if flag2 == 0x02 {
                let country_offset2 =
                    read_u24(buf, country_offset + 1).ok_or(LookupError::Malformed)? as usize;
                let (country, _) =
                    read_string(buf, country_offset2).ok_or(LookupError::Malformed)?;
                let (area, _) = self.read_region(country_offset + 4)?;
                (country, area)
            } else {
                let (country, next) =
                    read_string(buf, country_offset).ok_or(LookupError::Malformed)?;
                let (area, _) = self.read_region(next)?;
                (country, area)
            }
        } else if flag == 0x02 {
            let country_offset = read_u24(buf, pos + 1).ok_or(LookupError::Malformed)? as usize;
            let (country, _) = read_string(buf, country_offset).ok_or(LookupError::Malformed)?;
            let (area, _) = self.read_region(pos + 4)?;
            (country, area)
        } else {
            let (country, next) = read_string(buf, pos).ok_or(LookupError::Malformed)?;
            let (area, _) = self.read_region(next)?;
            (country, area)
        };

        Ok((location, isp))
    }

    /// Looks up a textual IPv4 address, e.g. `"8.8.8.8"`.
    pub fn lookup(&self, ip: &str) -> Result<(String, String), LookupError> {
        self.lookup_ip(ip.parse()?)
    }

    /// Looks up an [`Ipv4Addr`] without re-parsing a string.
    pub fn lookup_ip(&self, ip: Ipv4Addr) -> Result<(String, String), LookupError> {
        let ip = u32::from_be_bytes(ip.octets());

        match self.search_ip(ip)? {
            Some(record_offset) => self.read_location(record_offset),
            None => Err(LookupError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u32_reader_rejects_short_input() {
        assert_eq!(read_u32(&[1, 2, 3], 0), None);
        assert_eq!(read_u32(&[1, 2, 3, 4], 0), Some(0x0403_0201));
    }

    #[test]
    fn u24_reader_rejects_short_input() {
        assert_eq!(read_u24(&[1, 2], 0), None);
        assert_eq!(read_u24(&[1, 2, 3], 0), Some(0x03_0201));
    }

    #[test]
    fn string_reader_stops_at_nul() {
        assert_eq!(read_string(b"ab\0c", 0), Some(("ab".to_string(), 3)));
    }

    #[test]
    fn string_reader_rejects_unterminated_input() {
        assert_eq!(read_string(b"abc", 0), None);
    }

    #[test]
    fn open_rejects_truncated_header() {
        let path = std::env::temp_dir().join("qqwry-truncated-header.dat");
        fs::write(&path, [0u8; 4]).expect("write temp file");
        assert!(Qqwry::new(&path).is_err());
    }

    #[test]
    fn open_rejects_index_range_beyond_file() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&9_999_999u32.to_le_bytes());
        let path = std::env::temp_dir().join("qqwry-bad-index.dat");
        fs::write(&path, &bytes).expect("write temp file");
        assert!(Qqwry::new(&path).is_err());
    }

    /// A record offset pointing past the end of the file must be reported,
    /// not read out of bounds.
    #[test]
    fn lookup_reports_malformed_for_out_of_bounds_record() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&8u32.to_le_bytes()); // index_start
        bytes.extend_from_slice(&15u32.to_le_bytes()); // index_end
        bytes.extend_from_slice(&0x0101_0101u32.to_le_bytes()); // start ip: 1.1.1.1
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // record offset past EOF

        let path = std::env::temp_dir().join("qqwry-bad-record.dat");
        fs::write(&path, &bytes).expect("write temp file");

        let qqwry = Qqwry::new(&path).expect("open database");
        assert!(matches!(
            qqwry.lookup("1.1.1.1"),
            Err(LookupError::Malformed)
        ));
    }

    /// An address outside every indexed range is `NotFound`, not an error.
    #[test]
    fn lookup_reports_not_found_outside_every_range() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&8u32.to_le_bytes()); // index_start
        bytes.extend_from_slice(&8u32.to_le_bytes()); // index_end: a single entry
        bytes.extend_from_slice(&0x0101_0101u32.to_le_bytes()); // start ip: 1.1.1.1
        bytes.extend_from_slice(&15u32.to_le_bytes()[..3]); // record offset
        bytes.extend_from_slice(&0x0101_0101u32.to_le_bytes()); // end ip: 1.1.1.1

        let path = std::env::temp_dir().join("qqwry-single-range.dat");
        fs::write(&path, &bytes).expect("write temp file");

        let qqwry = Qqwry::new(&path).expect("open database");
        assert!(matches!(
            qqwry.lookup("2.2.2.2"),
            Err(LookupError::NotFound)
        ));
    }

    #[test]
    fn from_bytes_rejects_truncated_header() {
        assert!(Qqwry::from_bytes(vec![0u8; 4]).is_err());
    }

    #[test]
    fn from_bytes_rejects_reversed_index_range() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.extend_from_slice(&8u32.to_le_bytes());
        assert!(Qqwry::from_bytes(bytes).is_err());
    }

    /// Wraps raw bytes in a `Qqwry` so the location readers can be exercised
    /// without laying out a whole index.
    fn probe(data: Vec<u8>) -> Qqwry {
        Qqwry {
            data,
            index_start: 0,
            index_end: 0,
        }
    }

    /// Assembles a minimal, well-formed database from `(start, end, location,
    /// isp)` ranges. Strings are ASCII, so the GBK decoding is a no-op.
    fn build_database<S: AsRef<str>>(ranges: &[(u32, u32, S, S)]) -> Vec<u8> {
        let mut data = vec![0u8; 8]; // header, filled in below
        let mut record_offsets = Vec::with_capacity(ranges.len());

        for (_, end, location, isp) in ranges {
            record_offsets.push(data.len() as u32);
            data.extend_from_slice(&end.to_le_bytes());
            data.extend_from_slice(location.as_ref().as_bytes());
            data.push(0);
            data.extend_from_slice(isp.as_ref().as_bytes());
            data.push(0);
        }

        let index_start = data.len() as u32;
        for ((start, ..), offset) in ranges.iter().zip(&record_offsets) {
            data.extend_from_slice(&start.to_le_bytes());
            data.extend_from_slice(&offset.to_le_bytes()[..3]);
        }
        let index_end = data.len() as u32 - 7;

        data[0..4].copy_from_slice(&index_start.to_le_bytes());
        data[4..8].copy_from_slice(&index_end.to_le_bytes());
        data
    }

    #[test]
    fn region_reads_plain_redirected_and_empty_values() {
        let qqwry = probe(b"Telecom\0".to_vec());
        assert_eq!(qqwry.read_region(0).unwrap(), ("Telecom".to_string(), 8));

        let mut data = vec![0x01, 4, 0, 0];
        data.extend_from_slice(b"Telecom\0");
        let qqwry = probe(data);
        assert_eq!(qqwry.read_region(0).unwrap(), ("Telecom".to_string(), 12));

        // A redirect to offset 0 means "no area".
        let qqwry = probe(vec![0x02, 0, 0, 0]);
        assert_eq!(qqwry.read_region(0).unwrap(), (String::new(), 4));

        // A NUL flag is an empty string.
        let qqwry = probe(vec![0x00]);
        assert_eq!(qqwry.read_region(0).unwrap(), (String::new(), 1));
    }

    #[test]
    fn location_plain_mode_reads_country_then_area() {
        let mut data = vec![0u8; 4]; // end ip (unused here)
        data.extend_from_slice(b"China\0Telecom\0");
        let qqwry = probe(data);
        assert_eq!(
            qqwry.read_location(0).unwrap(),
            ("China".to_string(), "Telecom".to_string())
        );
    }

    #[test]
    fn location_mode_two_reads_redirected_country_and_inline_area() {
        let mut data = vec![0u8; 4]; // end ip
        data.push(0x02);
        data.extend_from_slice(&[0, 0, 0]); // country pointer, patched below
        data.extend_from_slice(b"Telecom\0"); // area follows the pointer inline

        let country_offset = data.len() as u32;
        data.extend_from_slice(b"China\0");
        data[5..8].copy_from_slice(&country_offset.to_le_bytes()[..3]);

        let qqwry = probe(data);
        assert_eq!(
            qqwry.read_location(0).unwrap(),
            ("China".to_string(), "Telecom".to_string())
        );
    }

    #[test]
    fn location_mode_one_with_plain_country_reads_area_after_country() {
        let mut data = vec![0u8; 4]; // end ip
        data.push(0x01);
        data.extend_from_slice(&8u32.to_le_bytes()[..3]); // country pointer
        data.extend_from_slice(b"China\0Telecom\0");

        let qqwry = probe(data);
        assert_eq!(
            qqwry.read_location(0).unwrap(),
            ("China".to_string(), "Telecom".to_string())
        );
    }

    #[test]
    fn location_mode_one_follows_a_second_redirect_for_country() {
        let mut data = vec![0u8; 4]; // end ip
        data.push(0x01);
        data.extend_from_slice(&8u32.to_le_bytes()[..3]); // country block at 8
        data.push(0x02); // country block: redirect again
        data.extend_from_slice(&[0, 0, 0]); // country pointer, patched below
        data.extend_from_slice(b"Telecom\0"); // area at 12

        let country_offset = data.len() as u32;
        data.extend_from_slice(b"China\0");
        data[9..12].copy_from_slice(&country_offset.to_le_bytes()[..3]);

        let qqwry = probe(data);
        assert_eq!(
            qqwry.read_location(0).unwrap(),
            ("China".to_string(), "Telecom".to_string())
        );
    }

    #[test]
    fn location_reports_malformed_on_truncated_data() {
        let qqwry = probe(vec![0, 0, 0, 0]); // mode byte is missing
        assert!(matches!(
            qqwry.read_location(0),
            Err(LookupError::Malformed)
        ));

        let qqwry = probe(vec![0, 0, 0, 0, 0x01, 0xFF, 0xFF]); // pointer past EOF
        assert!(matches!(
            qqwry.read_location(0),
            Err(LookupError::Malformed)
        ));
    }

    #[test]
    fn lookup_finds_ranges_and_boundaries() {
        let db = build_database(&[
            (0x0101_0101, 0x0101_01FF, "China", "Telecom"),
            (0x0202_0202, 0x0202_0202, "USA", "Google"),
        ]);
        let qqwry = Qqwry::from_bytes(db).expect("open database");

        let china = ("China".to_string(), "Telecom".to_string());
        assert_eq!(qqwry.lookup("1.1.1.1").unwrap(), china);
        assert_eq!(qqwry.lookup("1.1.1.128").unwrap(), china);
        assert_eq!(qqwry.lookup("1.1.1.255").unwrap(), china);

        let usa = ("USA".to_string(), "Google".to_string());
        assert_eq!(qqwry.lookup_ip("2.2.2.2".parse().unwrap()).unwrap(), usa);

        for ip in ["0.0.0.1", "1.1.2.0", "3.3.3.3", "255.255.255.255"] {
            assert!(
                matches!(qqwry.lookup(ip), Err(LookupError::NotFound)),
                "{ip} should not be found"
            );
        }
    }

    #[test]
    fn lookup_rejects_invalid_ip_literals() {
        let db = build_database(&[(0x0101_0101, 0x0101_01FF, "China", "Telecom")]);
        let qqwry = Qqwry::from_bytes(db).expect("open database");

        for ip in ["999.1.1.1", "not-an-ip", "::1"] {
            assert!(
                matches!(qqwry.lookup(ip), Err(LookupError::ParseIp(_))),
                "{ip} should be a parse error"
            );
        }
    }

    #[test]
    fn binary_search_handles_many_ranges() {
        let ranges: Vec<(u32, u32, String, String)> = (0..1000u32)
            .map(|i| {
                let start = 0x0A00_0000 + i * 256;
                (start, start + 255, format!("loc{i}"), format!("isp{i}"))
            })
            .collect();
        let db = build_database(&ranges);
        let qqwry = Qqwry::from_bytes(db).expect("open database");

        for (i, (start, end, location, isp)) in ranges.iter().enumerate() {
            for address in [*start, *start + 1, *end] {
                let got = qqwry.lookup_ip(address.into()).unwrap();
                assert_eq!(got, (location.clone(), isp.clone()), "range {i}");
            }
        }

        // One past the last range is not covered.
        let after_last = ranges.last().unwrap().1 + 1;
        assert!(matches!(
            qqwry.lookup_ip(after_last.into()),
            Err(LookupError::NotFound)
        ));
    }
}
