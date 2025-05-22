use encoding_rs::GBK;
use std::fs;
use std::net::Ipv4Addr;

fn ip_to_u32(ip: &str) -> Result<u32, std::net::AddrParseError> {
    let addr: Ipv4Addr = ip.parse()?;
    Ok(u32::from_be_bytes(addr.octets()))
}

fn read_u32(buf: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
}

fn read_u24(buf: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], 0])
}

fn read_string(buf: &[u8], pos: usize) -> (String, usize) {
    read_str_gbk(buf, pos)
}

fn read_str_gbk(buf: &[u8], pos: usize) -> (String, usize) {
    let mut end = pos;
    while buf[end] != 0 {
        end += 1;
    }
    let (cow, _, _) = GBK.decode(&buf[pos..end]);
    (cow.into_owned(), end + 1)
}

#[derive(Debug)]
pub enum LookupError {
    ParseIp(std::net::AddrParseError),
    NotFound,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LookupError::ParseIp(e) => write!(f, "IP解析错误: {}", e),
            LookupError::NotFound => write!(f, "未找到"),
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
    pub fn new(dat_path: &str) -> std::io::Result<Self> {
        let data = fs::read(dat_path)?;
        let index_start = read_u32(&data, 0) as usize;
        let index_end = read_u32(&data, 4) as usize;
        Ok(Qqwry {
            data,
            index_start,
            index_end,
        })
    }

    fn read_region(&self, offset: usize) -> (String, usize) {
        let buf = &self.data;
        if buf[offset] == 0 {
            return ("".to_string(), offset + 1);
        }
        let flag = buf[offset];
        if flag == 0x01 || flag == 0x02 {
            let area_offset = read_u24(buf, offset + 1) as usize;
            if area_offset == 0 {
                ("".to_string(), offset + 4)
            } else {
                read_string(buf, area_offset)
            }
        } else {
            read_string(buf, offset)
        }
    }

    fn search_ip(&self, ip: u32) -> usize {
        let index_start = self.index_start;
        let index_end = self.index_end;
        let buf = &self.data;
        let mut left = 0;
        let mut right = (index_end - index_start) / 7;
        while left <= right {
            let mid = (left + right) / 2;
            let offset = index_start + mid * 7;
            let start_ip = read_u32(buf, offset);
            let record_offset = read_u24(buf, offset + 4) as usize;
            let end_ip = read_u32(buf, record_offset);
            if ip < start_ip {
                if mid == 0 {
                    break;
                }
                right = mid - 1;
            } else if ip > end_ip {
                left = mid + 1;
            } else {
                return record_offset;
            }
        }
        0
    }

    fn read_location(&self, offset: usize) -> (String, String) {
        let buf = &self.data;
        let pos = offset + 4;
        let flag = buf[pos];
        let (location, isp);
        if flag == 0x01 {
            let country_offset = read_u24(buf, pos + 1) as usize;
            let flag2 = buf[country_offset];
            if flag2 == 0x02 {
                let country_offset2 = read_u24(buf, country_offset + 1) as usize;
                let (c, _) = read_string(buf, country_offset2);
                location = c;
                let (a, _) = self.read_region(country_offset + 4);
                isp = a;
            } else {
                let (c, next) = read_string(buf, country_offset);
                location = c;
                let (a, _) = self.read_region(next);
                isp = a;
            }
        } else if flag == 0x02 {
            let country_offset = read_u24(buf, pos + 1) as usize;
            let (c, _) = read_string(buf, country_offset);
            location = c;
            let (a, _) = self.read_region(pos + 4);
            isp = a;
        } else {
            let (c, next) = read_string(buf, pos);
            location = c;
            let (a, _) = self.read_region(next);
            isp = a;
        }
        (location, isp)
    }

    pub fn lookup(&self, ip: &str) -> Result<(String, String), LookupError> {
        let ip_u32 = ip_to_u32(ip)?;
        let record_offset = self.search_ip(ip_u32);
        if record_offset > 0 {
            Ok(self.read_location(record_offset))
        } else {
            Err(LookupError::NotFound)
        }
    }
}
