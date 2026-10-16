use encoding_rs::GBK;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

fn ip_to_u32(ip: &str) -> Result<u32, std::net::AddrParseError> {
    let addr: Ipv4Addr = ip.parse()?;
    Ok(u32::from_be_bytes(addr.octets()))
}

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
        let data = fs::read(dat_path)?;

        let index_start = read_u32(&data, 0)
            .ok_or_else(|| malformed("qqwry: truncated header"))? as usize;
        let index_end = read_u32(&data, 4)
            .ok_or_else(|| malformed("qqwry: truncated header"))? as usize;

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

    fn search_ip(&self, ip: u32) -> Result<Option<usize>, LookupError> {
        let buf = &self.data;
        let mut left = 0usize;
        let mut right = (self.index_end - self.index_start) / 7;

        while left <= right {
            let mid = (left + right) / 2;
            let offset = self.index_start + mid * 7;
            let start_ip = read_u32(buf, offset).ok_or(LookupError::Malformed)?;
            let record_offset = read_u24(buf, offset + 4).ok_or(LookupError::Malformed)? as usize;
            let end_ip = read_u32(buf, record_offset).ok_or(LookupError::Malformed)?;

            if ip < start_ip {
                if mid == 0 {
                    break;
                }
                right = mid - 1;
            } else if ip > end_ip {
                left = mid + 1;
            } else {
                return Ok(Some(record_offset));
            }
        }

        Ok(None)
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

    pub fn lookup(&self, ip: &str) -> Result<(String, String), LookupError> {
        let ip_u32 = ip_to_u32(ip)?;

        match self.search_ip(ip_u32)? {
            Some(record_offset) if record_offset > 0 => self.read_location(record_offset),
            _ => Err(LookupError::NotFound),
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
}
