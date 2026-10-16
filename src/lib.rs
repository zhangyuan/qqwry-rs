//! A reader for the 纯真 (qqwry) IPv4 database format.
//!
//! # File layout
//!
//! * An 8-byte header: two little-endian `u32`s holding the offset of the
//!   first and the last index entry.
//! * The records, from offset 8 up to the index.
//! * The index, one 7-byte entry per range: a 4-byte start address followed
//!   by a 3-byte offset to the corresponding record.
//!
//! # Records
//!
//! A record is a 4-byte end address followed by two GBK, NUL-terminated
//! values — the country/location and then the area/ISP. Either value is a
//! plain string or a redirect:
//!
//! * `0x01`: the value is at the 3-byte little-endian offset that follows.
//! * `0x02`: like `0x01`, but the rest of the record (the area) continues
//!   right after the pointer.
//! * any other byte: the value is a plain NUL-terminated string, and a NUL
//!   byte on its own means an empty value.
//!
//! Since a redirected country also moves the area, a lookup resolves the
//! country first and then follows it to the area.

use encoding_rs::GBK;
use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

/// Each index entry is a 4-byte start address plus a 3-byte record offset.
const INDEX_ENTRY_LEN: usize = 7;
/// An IPv4 address is four bytes, little-endian in this format.
const IPV4_LEN: usize = 4;
/// Redirects carry a 3-byte little-endian offset.
const POINTER_LEN: usize = 3;
/// A redirect is a mode byte plus its pointer.
const REDIRECT_LEN: usize = 1 + POINTER_LEN;
/// Mode byte: the value lives at the following 3-byte offset.
const REDIRECT_MODE_1: u8 = 0x01;
/// Mode byte: like mode 1, but the record continues after the pointer.
const REDIRECT_MODE_2: u8 = 0x02;

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

/// Reads a NUL-terminated GBK string, returning it and the offset just past
/// the terminator. `None` if it is unterminated or past the end of the buffer.
fn read_string(buf: &[u8], pos: usize) -> Option<(String, usize)> {
    let rest = buf.get(pos..)?;
    let end = rest.iter().position(|&byte| byte == 0)? + pos;
    let (decoded, _, _) = GBK.decode(&buf[pos..end]);
    Some((decoded.into_owned(), end + 1))
}

/// Like [`read_string`] but reports the end offset as [`Error::Malformed`].
fn read_text(buf: &[u8], pos: usize) -> Result<String, Error> {
    read_string(buf, pos)
        .map(|(text, _)| text)
        .ok_or(Error::Malformed)
}

/// Errors from opening or querying a [`Qqwry`] database.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The database file could not be read.
    Io(std::io::Error),
    /// The database is truncated or otherwise malformed.
    Malformed,
    /// The address is not a valid IPv4 address.
    ParseIp(std::net::AddrParseError),
    /// The database does not cover the address.
    NotFound,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(error) => write!(f, "cannot read database: {error}"),
            Error::Malformed => f.write_str("malformed qqwry database"),
            Error::ParseIp(error) => write!(f, "invalid IPv4 address: {error}"),
            Error::NotFound => f.write_str("address not found in database"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(error) => Some(error),
            Error::ParseIp(error) => Some(error),
            Error::Malformed | Error::NotFound => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(error: std::net::AddrParseError) -> Self {
        Error::ParseIp(error)
    }
}

/// The values a database maps an address to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    /// Country, province and city, e.g. `"中国–江苏–南京"`.
    pub location: String,
    /// Area or ISP, e.g. `"电信"`.
    pub isp: String,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, {}", self.location, self.isp)
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
    /// file yields [`Error::Malformed`] rather than panicking.
    pub fn new(dat_path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::from_bytes(fs::read(dat_path)?)
    }

    /// Builds a database from an in-memory `qqwry.dat` image.
    ///
    /// Useful when the database is embedded in the binary or already held in
    /// memory; [`Qqwry::new`] is a thin wrapper around it.
    pub fn from_bytes(data: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let data = data.into();

        let index_start = read_u32(&data, 0).ok_or(Error::Malformed)? as usize;
        // The second header field is the offset of the *last* index entry, so
        // a whole entry has to fit after it.
        let index_end = read_u32(&data, 4).ok_or(Error::Malformed)? as usize;
        let index_fits = index_end
            .checked_add(INDEX_ENTRY_LEN)
            .is_some_and(|end| end <= data.len());
        if index_start > index_end || !index_fits {
            return Err(Error::Malformed);
        }

        Ok(Qqwry {
            data,
            index_start,
            index_end,
        })
    }

    /// Reads the area/ISP that follows a record's country field.
    fn read_area(&self, offset: usize) -> Result<String, Error> {
        let buf = &self.data;
        let mode = *buf.get(offset).ok_or(Error::Malformed)?;

        if mode == REDIRECT_MODE_1 || mode == REDIRECT_MODE_2 {
            let area_offset = read_u24(buf, offset + 1).ok_or(Error::Malformed)? as usize;
            if area_offset == 0 {
                // A zero pointer means there is no area.
                Ok(String::new())
            } else {
                read_text(buf, area_offset)
            }
        } else {
            // A plain string, or empty when the first byte is NUL.
            read_text(buf, offset)
        }
    }

    /// Finds the record whose range contains `ip`.
    ///
    /// The index is sorted by start address, so we binary-search for the last
    /// entry whose start is `<= ip` and then check its end address. This only
    /// touches the index during the search (one random read at the end),
    /// instead of reading every probed record.
    fn search_ip(&self, ip: u32) -> Result<Option<usize>, Error> {
        let buf = &self.data;
        let count = (self.index_end - self.index_start) / INDEX_ENTRY_LEN + 1;

        let mut left = 0usize;
        let mut right = count;
        while left < right {
            let mid = left + (right - left) / 2;
            let start =
                read_u32(buf, self.index_start + mid * INDEX_ENTRY_LEN).ok_or(Error::Malformed)?;

            if start <= ip {
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        let Some(index) = left.checked_sub(1) else {
            return Ok(None);
        };

        let entry = self.index_start + index * INDEX_ENTRY_LEN;
        let record = read_u24(buf, entry + IPV4_LEN).ok_or(Error::Malformed)? as usize;
        if record == 0 {
            return Ok(None);
        }

        // The index is ordered by start address, but only the record itself
        // knows where its range ends.
        let end = read_u32(buf, record).ok_or(Error::Malformed)?;
        if ip <= end {
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    /// Reads the country and area of the record at `offset`.
    fn read_location(&self, offset: usize) -> Result<Location, Error> {
        let buf = &self.data;
        let pos = offset + IPV4_LEN; // the region begins after the end address
        let mode = *buf.get(pos).ok_or(Error::Malformed)?;

        let (location, isp) = match mode {
            REDIRECT_MODE_1 => {
                let country_offset = read_u24(buf, pos + 1).ok_or(Error::Malformed)? as usize;
                let country_mode = *buf.get(country_offset).ok_or(Error::Malformed)?;

                if country_mode == REDIRECT_MODE_2 {
                    // The country is redirected a second time, and the area
                    // follows the second pointer.
                    let country_offset2 =
                        read_u24(buf, country_offset + 1).ok_or(Error::Malformed)? as usize;
                    let country = read_text(buf, country_offset2)?;
                    (country, self.read_area(country_offset + REDIRECT_LEN)?)
                } else {
                    let (country, next) =
                        read_string(buf, country_offset).ok_or(Error::Malformed)?;
                    (country, self.read_area(next)?)
                }
            }
            REDIRECT_MODE_2 => {
                let country_offset = read_u24(buf, pos + 1).ok_or(Error::Malformed)? as usize;
                let country = read_text(buf, country_offset)?;
                (country, self.read_area(pos + REDIRECT_LEN)?)
            }
            _ => {
                let (country, next) = read_string(buf, pos).ok_or(Error::Malformed)?;
                (country, self.read_area(next)?)
            }
        };

        Ok(Location { location, isp })
    }

    /// Looks up a textual IPv4 address such as `"8.8.8.8"`.
    pub fn lookup(&self, ip: &str) -> Result<Location, Error> {
        self.lookup_ip(ip.parse()?)
    }

    /// Looks up an [`Ipv4Addr`] without parsing a string first.
    pub fn lookup_ip(&self, ip: Ipv4Addr) -> Result<Location, Error> {
        let ip = u32::from_be_bytes(ip.octets());

        match self.search_ip(ip)? {
            Some(record) => self.read_location(record),
            None => Err(Error::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(location: &str, isp: &str) -> Location {
        Location {
            location: location.to_string(),
            isp: isp.to_string(),
        }
    }

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
    fn location_displays_as_comma_separated_values() {
        assert_eq!(location("China", "Telecom").to_string(), "China, Telecom");
    }

    #[test]
    fn open_rejects_truncated_header() {
        let path = std::env::temp_dir().join("qqwry-truncated-header.dat");
        fs::write(&path, [0u8; 4]).expect("write temp file");
        assert!(matches!(Qqwry::new(&path), Err(Error::Malformed)));
    }

    #[test]
    fn open_rejects_index_range_beyond_file() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&9_999_999u32.to_le_bytes());
        assert!(matches!(Qqwry::from_bytes(bytes), Err(Error::Malformed)));
    }

    #[test]
    fn from_bytes_rejects_truncated_header() {
        assert!(matches!(
            Qqwry::from_bytes(vec![0u8; 4]),
            Err(Error::Malformed)
        ));
    }

    #[test]
    fn from_bytes_rejects_reversed_index_range() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.extend_from_slice(&8u32.to_le_bytes());
        assert!(matches!(Qqwry::from_bytes(bytes), Err(Error::Malformed)));
    }

    /// A record offset pointing past the end of the file must be reported,
    /// not read out of bounds.
    #[test]
    fn lookup_reports_malformed_for_out_of_bounds_record() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&8u32.to_le_bytes()); // index_start
        bytes.extend_from_slice(&8u32.to_le_bytes()); // index_end: a single entry
        bytes.extend_from_slice(&0x0101_0101u32.to_le_bytes()); // start ip: 1.1.1.1
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // record offset past EOF

        let qqwry = Qqwry::from_bytes(bytes).expect("open database");
        assert!(matches!(qqwry.lookup("1.1.1.1"), Err(Error::Malformed)));
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

        let qqwry = Qqwry::from_bytes(bytes).expect("open database");
        assert!(matches!(qqwry.lookup("2.2.2.2"), Err(Error::NotFound)));
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
        let index_end = data.len() as u32 - INDEX_ENTRY_LEN as u32;

        data[0..4].copy_from_slice(&index_start.to_le_bytes());
        data[4..8].copy_from_slice(&index_end.to_le_bytes());
        data
    }

    #[test]
    fn area_reads_plain_redirected_and_empty_values() {
        let qqwry = probe(b"Telecom\0".to_vec());
        assert_eq!(qqwry.read_area(0).unwrap(), "Telecom");

        let mut data = vec![REDIRECT_MODE_1, 4, 0, 0];
        data.extend_from_slice(b"Telecom\0");
        let qqwry = probe(data);
        assert_eq!(qqwry.read_area(0).unwrap(), "Telecom");

        // A redirect to offset 0 means "no area".
        let qqwry = probe(vec![REDIRECT_MODE_2, 0, 0, 0]);
        assert_eq!(qqwry.read_area(0).unwrap(), "");

        // A NUL mode byte is an empty string.
        let qqwry = probe(vec![0x00]);
        assert_eq!(qqwry.read_area(0).unwrap(), "");
    }

    #[test]
    fn location_plain_mode_reads_country_then_area() {
        let mut data = vec![0u8; IPV4_LEN]; // end ip (unused here)
        data.extend_from_slice(b"China\0Telecom\0");
        let qqwry = probe(data);
        assert_eq!(
            qqwry.read_location(0).unwrap(),
            location("China", "Telecom")
        );
    }

    #[test]
    fn location_mode_two_reads_redirected_country_and_inline_area() {
        let mut data = vec![0u8; IPV4_LEN]; // end ip
        data.push(REDIRECT_MODE_2);
        data.extend_from_slice(&[0, 0, 0]); // country pointer, patched below
        data.extend_from_slice(b"Telecom\0"); // area follows the pointer inline

        let country_offset = data.len() as u32;
        data.extend_from_slice(b"China\0");
        data[5..8].copy_from_slice(&country_offset.to_le_bytes()[..3]);

        let qqwry = probe(data);
        assert_eq!(
            qqwry.read_location(0).unwrap(),
            location("China", "Telecom")
        );
    }

    #[test]
    fn location_mode_one_with_plain_country_reads_area_after_country() {
        let mut data = vec![0u8; IPV4_LEN]; // end ip
        data.push(REDIRECT_MODE_1);
        data.extend_from_slice(&8u32.to_le_bytes()[..POINTER_LEN]); // country pointer
        data.extend_from_slice(b"China\0Telecom\0");

        let qqwry = probe(data);
        assert_eq!(
            qqwry.read_location(0).unwrap(),
            location("China", "Telecom")
        );
    }

    #[test]
    fn location_mode_one_follows_a_second_redirect_for_country() {
        let mut data = vec![0u8; IPV4_LEN]; // end ip
        data.push(REDIRECT_MODE_1);
        data.extend_from_slice(&8u32.to_le_bytes()[..POINTER_LEN]); // country block at 8
        data.push(REDIRECT_MODE_2); // country block: redirect again
        data.extend_from_slice(&[0, 0, 0]); // country pointer, patched below
        data.extend_from_slice(b"Telecom\0"); // area at 12

        let country_offset = data.len() as u32;
        data.extend_from_slice(b"China\0");
        data[9..12].copy_from_slice(&country_offset.to_le_bytes()[..3]);

        let qqwry = probe(data);
        assert_eq!(
            qqwry.read_location(0).unwrap(),
            location("China", "Telecom")
        );
    }

    #[test]
    fn location_reports_malformed_on_truncated_data() {
        let qqwry = probe(vec![0, 0, 0, 0]); // mode byte is missing
        assert!(matches!(qqwry.read_location(0), Err(Error::Malformed)));

        let qqwry = probe(vec![0, 0, 0, 0, REDIRECT_MODE_1, 0xFF, 0xFF]); // pointer past EOF
        assert!(matches!(qqwry.read_location(0), Err(Error::Malformed)));
    }

    #[test]
    fn lookup_finds_ranges_and_boundaries() {
        let db = build_database(&[
            (0x0101_0101, 0x0101_01FF, "China", "Telecom"),
            (0x0202_0202, 0x0202_0202, "USA", "Google"),
        ]);
        let qqwry = Qqwry::from_bytes(db).expect("open database");

        let china = location("China", "Telecom");
        assert_eq!(qqwry.lookup("1.1.1.1").unwrap(), china);
        assert_eq!(qqwry.lookup("1.1.1.128").unwrap(), china);
        assert_eq!(qqwry.lookup("1.1.1.255").unwrap(), china);

        let usa = location("USA", "Google");
        assert_eq!(qqwry.lookup_ip("2.2.2.2".parse().unwrap()).unwrap(), usa);

        for ip in ["0.0.0.1", "1.1.2.0", "3.3.3.3", "255.255.255.255"] {
            assert!(
                matches!(qqwry.lookup(ip), Err(Error::NotFound)),
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
                matches!(qqwry.lookup(ip), Err(Error::ParseIp(_))),
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
                assert_eq!(got.location, *location, "range {i}");
                assert_eq!(got.isp, *isp, "range {i}");
            }
        }

        // One past the last range is not covered.
        let after_last = ranges.last().unwrap().1 + 1;
        assert!(matches!(
            qqwry.lookup_ip(after_last.into()),
            Err(Error::NotFound)
        ));
    }
}
