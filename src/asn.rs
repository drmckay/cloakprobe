use crate::config::AppConfig;
use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

#[derive(Debug, Clone)]
pub struct AsnInfo {
    pub asn: u32,
    pub as_name: String,
    pub prefix: String,
    pub rir: String,
    pub country: Option<String>,
    pub org_name: Option<String>,
}

pub trait AsnDatabase: Send + Sync {
    fn lookup(&self, ip: IpAddr) -> Option<AsnInfo>;
}

/// On-disk ASN DB format (little endian):
///
/// Header (20 bytes):
/// - magic: 4 bytes = b"ASND"
/// - version: u32 = 1 (old format) or 2 (with AS names)
/// - v4_count: u32
/// - v6_count: u32
/// - reserved: u32 = 0
///
/// Version 2 (variable size):
/// IPv4 entries:
/// - start:   u32  (range_start, inclusive)
/// - end:     u32  (range_end, inclusive)
/// - asn:     u32
/// - country: [u8; 2] (ISO country code uppercased, or 0,0)
/// - as_name_len: u8 (length of AS name string, max 255)
/// - as_name: [u8; as_name_len] (UTF-8 AS name/description)
///
/// IPv6 entries follow similar pattern
///
/// The DB is built from the ip2asn-combined.tsv dataset using the asn_builder binary.
///
/// RIPE DB v2 format with string interning:
/// - org_names: Vec<String> - unique organization names
/// - asn_to_org: HashMap<u32, u16> - ASN -> index into org_names
struct RipeOrgDb {
    org_names: Vec<String>,
    asn_to_org: HashMap<u32, u16>,
}

impl RipeOrgDb {
    fn lookup(&self, asn: u32) -> Option<&str> {
        self.asn_to_org
            .get(&asn)
            .and_then(|&idx| self.org_names.get(idx as usize))
            .map(|s| s.as_str())
    }
}

pub struct FileAsnDb {
    v4: Vec<V4Entry>,
    v6: Vec<V6Entry>,
    ripe_db: Option<RipeOrgDb>,
}

#[derive(Clone, Debug)]
struct V4Entry {
    start: u32,
    end: u32,
    asn: u32,
    country: [u8; 2],
    as_name: String,
}

#[derive(Clone, Debug)]
struct V6Entry {
    start: u128,
    end: u128,
    asn: u32,
    country: [u8; 2],
    as_name: String,
}

pub fn load_asn_db(cfg: &AppConfig) -> Result<FileAsnDb, String> {
    // Load ASN database
    let asn_data = fs::read(&cfg.asn_db_path).map_err(|e| {
        format!(
            "Failed to read ASN database from {}: {}",
            cfg.asn_db_path, e
        )
    })?;

    let mut db = FileAsnDb::from_bytes(&asn_data)?;

    // Load RIPE organization database if available
    if let Some(ref ripe_db_path) = cfg.ripe_db_path {
        if Path::new(ripe_db_path).exists() {
            tracing::info!("Loading RIPE org database from: {}", ripe_db_path);
            let ripe_data = fs::read(ripe_db_path).map_err(|e| {
                format!("Failed to read RIPE database from {}: {}", ripe_db_path, e)
            })?;

            match load_ripe_db(&ripe_data) {
                Ok(ripe_db) => {
                    tracing::info!(
                        "RIPE org database loaded: {} orgs, {} ASN mappings",
                        ripe_db.org_names.len(),
                        ripe_db.asn_to_org.len()
                    );
                    db.ripe_db = Some(ripe_db);
                }
                Err(e) => {
                    tracing::warn!("Failed to load RIPE database: {}", e);
                }
            }
        } else {
            tracing::warn!("RIPE org database file not found: {}", ripe_db_path);
        }
    }

    Ok(db)
}

fn load_ripe_db(data: &[u8]) -> Result<RipeOrgDb, String> {
    if data.len() < 16 {
        return Err("RIPE DB: file too small".into());
    }

    let magic = &data[0..4];
    if magic != b"RIPE" {
        return Err("RIPE DB: invalid magic".into());
    }

    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());

    match version {
        1 => load_ripe_db_v1(data),
        2 => load_ripe_db_v2(data),
        _ => Err(format!("RIPE DB: unsupported version {}", version)),
    }
}

/// Load legacy v1 format (for backwards compatibility)
fn load_ripe_db_v1(data: &[u8]) -> Result<RipeOrgDb, String> {
    let count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let mut offset = 12;

    let mut org_names = Vec::new();
    let mut asn_to_org = HashMap::new();
    let mut org_name_to_idx: HashMap<String, u16> = HashMap::new();

    for _ in 0..count {
        if offset + 4 > data.len() {
            return Err("RIPE DB v1: file truncated".into());
        }
        let asn = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // Read org_name
        if offset >= data.len() {
            return Err("RIPE DB v1: file truncated".into());
        }
        let org_name_len = data[offset] as usize;
        offset += 1;
        let org_name = if org_name_len > 0 {
            if offset + org_name_len > data.len() {
                return Err("RIPE DB v1: file truncated".into());
            }
            Some(String::from_utf8_lossy(&data[offset..offset + org_name_len]).to_string())
        } else {
            None
        };
        offset += org_name_len;

        // Skip org_id
        if offset >= data.len() {
            return Err("RIPE DB v1: file truncated".into());
        }
        let org_id_len = data[offset] as usize;
        offset += 1 + org_id_len;

        // Skip description (u16 length)
        if offset + 2 > data.len() {
            return Err("RIPE DB v1: file truncated".into());
        }
        let desc_len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2 + desc_len;

        // Skip country
        if offset >= data.len() {
            return Err("RIPE DB v1: file truncated".into());
        }
        let country_len = data[offset] as usize;
        offset += 1 + country_len;

        // Skip address lines
        if offset >= data.len() {
            return Err("RIPE DB v1: file truncated".into());
        }
        let addr_count = data[offset] as usize;
        offset += 1;
        for _ in 0..addr_count {
            if offset >= data.len() {
                return Err("RIPE DB v1: file truncated".into());
            }
            let addr_len = data[offset] as usize;
            offset += 1 + addr_len;
        }

        // Add to our interned structure
        if let Some(name) = org_name {
            let idx = if let Some(&existing_idx) = org_name_to_idx.get(&name) {
                existing_idx
            } else {
                let new_idx = org_names.len() as u16;
                org_names.push(name.clone());
                org_name_to_idx.insert(name, new_idx);
                new_idx
            };
            asn_to_org.insert(asn, idx);
        }
    }

    Ok(RipeOrgDb {
        org_names,
        asn_to_org,
    })
}

/// Load v2 format with string interning
fn load_ripe_db_v2(data: &[u8]) -> Result<RipeOrgDb, String> {
    if data.len() < 16 {
        return Err("RIPE DB v2: file too small".into());
    }

    let org_count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let asn_count = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

    let mut offset = 16;

    // Read org names
    let mut org_names = Vec::with_capacity(org_count);
    for _ in 0..org_count {
        if offset + 2 > data.len() {
            return Err("RIPE DB v2: file truncated reading org name length".into());
        }
        let len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;

        if offset + len > data.len() {
            return Err("RIPE DB v2: file truncated reading org name".into());
        }
        let name = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
        offset += len;
        org_names.push(name);
    }

    // Read ASN mappings
    let mut asn_to_org = HashMap::with_capacity(asn_count);
    for _ in 0..asn_count {
        if offset + 6 > data.len() {
            return Err("RIPE DB v2: file truncated reading ASN mapping".into());
        }
        let asn = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let idx = u16::from_le_bytes(data[offset + 4..offset + 6].try_into().unwrap());
        offset += 6;
        asn_to_org.insert(asn, idx);
    }

    Ok(RipeOrgDb {
        org_names,
        asn_to_org,
    })
}

impl FileAsnDb {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 20 {
            return Err("ASN DB: file too small".into());
        }

        if &data[0..4] != b"ASND" {
            return Err("ASN DB: invalid magic".into());
        }

        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != 1 && version != 2 {
            return Err(format!("ASN DB: unsupported version {version}"));
        }

        let has_as_name = version >= 2;

        let v4_count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let v6_count = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        // reserved = data[16..20]

        let mut offset = 20;

        let mut v4 = Vec::with_capacity(v4_count);
        for _ in 0..v4_count {
            if offset + 14 > data.len() {
                return Err("ASN DB: file truncated".into());
            }

            let start = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            let end = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
            let asn = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());
            let country = [data[offset + 12], data[offset + 13]];
            offset += 14;

            let as_name = if has_as_name {
                if offset >= data.len() {
                    return Err("ASN DB: file truncated".into());
                }
                let name_len = data[offset] as usize;
                offset += 1;
                if offset + name_len > data.len() {
                    return Err("ASN DB: file truncated".into());
                }
                let name_bytes = &data[offset..offset + name_len];
                offset += name_len;
                String::from_utf8_lossy(name_bytes).to_string()
            } else {
                format!("AS{}", asn)
            };

            v4.push(V4Entry {
                start,
                end,
                asn,
                country,
                as_name,
            });
        }

        let mut v6 = Vec::with_capacity(v6_count);
        for _ in 0..v6_count {
            if offset + 38 > data.len() {
                return Err("ASN DB: file truncated".into());
            }

            let start_hi = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            let start_lo = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());
            let end_hi = u64::from_le_bytes(data[offset + 16..offset + 24].try_into().unwrap());
            let end_lo = u64::from_le_bytes(data[offset + 24..offset + 32].try_into().unwrap());
            let asn = u32::from_le_bytes(data[offset + 32..offset + 36].try_into().unwrap());
            let country = [data[offset + 36], data[offset + 37]];
            offset += 38;

            let as_name = if has_as_name {
                if offset >= data.len() {
                    return Err("ASN DB: file truncated".into());
                }
                let name_len = data[offset] as usize;
                offset += 1;
                if offset + name_len > data.len() {
                    return Err("ASN DB: file truncated".into());
                }
                let name_bytes = &data[offset..offset + name_len];
                offset += name_len;
                String::from_utf8_lossy(name_bytes).to_string()
            } else {
                format!("AS{}", asn)
            };

            let start = ((start_hi as u128) << 64) | (start_lo as u128);
            let end = ((end_hi as u128) << 64) | (end_lo as u128);

            v6.push(V6Entry {
                start,
                end,
                asn,
                country,
                as_name,
            });
        }

        tracing::debug!(
            "Loaded {} IPv4 entries and {} IPv6 entries",
            v4.len(),
            v6.len()
        );

        Ok(Self {
            v4,
            v6,
            ripe_db: None,
        })
    }

    fn lookup_v4(&self, ip: Ipv4Addr) -> Option<AsnInfo> {
        let ip_num = ipv4_to_u32(ip);
        if self.v4.is_empty() {
            tracing::warn!("ASN database has no IPv4 entries");
            return None;
        }

        let mut lo = 0usize;
        let mut hi = self.v4.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let entry = &self.v4[mid];
            if ip_num < entry.start {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }

        if lo == 0 {
            return None;
        }
        let idx = lo - 1;
        let entry = &self.v4[idx];
        if ip_num <= entry.end && entry.asn != 0 {
            Some(self.asn_info_from_entry(
                entry.asn,
                &entry.as_name,
                entry.country,
                entry.start,
                entry.end,
                true,
            ))
        } else {
            None
        }
    }

    fn lookup_v6(&self, ip: Ipv6Addr) -> Option<AsnInfo> {
        let ip_num = ipv6_to_u128(ip);
        if self.v6.is_empty() {
            tracing::warn!("ASN database has no IPv6 entries");
            return None;
        }

        let mut lo = 0usize;
        let mut hi = self.v6.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let entry = &self.v6[mid];
            if ip_num < entry.start {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }

        if lo == 0 {
            return None;
        }
        let idx = lo - 1;
        let entry = &self.v6[idx];
        if ip_num <= entry.end && entry.asn != 0 {
            Some(self.asn_info_from_entry_v6(
                entry.asn,
                &entry.as_name,
                entry.country,
                entry.start,
                entry.end,
            ))
        } else {
            None
        }
    }

    fn asn_info_from_entry(
        &self,
        asn: u32,
        as_name: &str,
        country: [u8; 2],
        start: u32,
        end: u32,
        _is_v4: bool,
    ) -> AsnInfo {
        let prefix = format!(
            "{}/{}",
            u32_to_ipv4(start),
            prefix_len_from_range_v4(start, end)
        );

        let org_name = self
            .ripe_db
            .as_ref()
            .and_then(|db| db.lookup(asn))
            .map(|s| s.to_string());

        AsnInfo {
            asn,
            as_name: as_name.to_string(),
            prefix,
            rir: "ip2asn".into(),
            country: country_opt(country),
            org_name,
        }
    }

    fn asn_info_from_entry_v6(
        &self,
        asn: u32,
        as_name: &str,
        country: [u8; 2],
        start: u128,
        end: u128,
    ) -> AsnInfo {
        let prefix = format!(
            "{}/{}",
            u128_to_ipv6(start),
            prefix_len_from_range_v6(start, end)
        );

        let org_name = self
            .ripe_db
            .as_ref()
            .and_then(|db| db.lookup(asn))
            .map(|s| s.to_string());

        AsnInfo {
            asn,
            as_name: as_name.to_string(),
            prefix,
            rir: "ip2asn".into(),
            country: country_opt(country),
            org_name,
        }
    }
}

impl AsnDatabase for FileAsnDb {
    fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        match ip {
            IpAddr::V4(v4) => self.lookup_v4(v4),
            IpAddr::V6(v6) => self.lookup_v6(v6),
        }
    }
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    let o = ip.octets();
    ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
}

fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    let o = ip.octets();
    u128::from_be_bytes(o)
}

fn country_opt(country: [u8; 2]) -> Option<String> {
    if country[0] == 0 && country[1] == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(&country).to_string())
    }
}

fn u32_to_ipv4(v: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        ((v >> 24) & 0xff) as u8,
        ((v >> 16) & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
        (v & 0xff) as u8,
    )
}

fn u128_to_ipv6(v: u128) -> Ipv6Addr {
    let bytes = v.to_be_bytes();
    Ipv6Addr::from(bytes)
}

fn prefix_len_from_range_v4(start: u32, end: u32) -> u8 {
    let range = end.saturating_sub(start) + 1;
    let bits = 32u32.saturating_sub(range.leading_zeros());
    32u8.saturating_sub(bits as u8)
}

fn prefix_len_from_range_v6(start: u128, end: u128) -> u8 {
    let range = end.saturating_sub(start) + 1;
    let bits = 128u32.saturating_sub(range.leading_zeros());
    128u8.saturating_sub(bits as u8)
}
