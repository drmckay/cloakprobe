use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{Read, Write},
};

/// Parses ASN number from string like "AS12345"
fn parse_asn_number(s: &str) -> Option<u32> {
    s.strip_prefix("AS").and_then(|num| num.parse::<u32>().ok())
}

/// Parse ripe.db.organisation file to get org_id -> org_name mapping
fn parse_organisations(content: &str) -> HashMap<String, String> {
    let mut org_map: HashMap<String, String> = HashMap::new();
    let mut current_org_id: Option<String> = None;
    let mut current_org_name: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
            continue;
        }

        if line.starts_with("organisation:") {
            // Save previous entry
            if let (Some(org_id), Some(org_name)) = (current_org_id.take(), current_org_name.take())
            {
                org_map.insert(org_id, org_name);
            }

            // Parse new org_id
            current_org_id = Some(
                line.strip_prefix("organisation:")
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            );
            current_org_name = None;
        } else if current_org_id.is_some() && line.starts_with("org-name:") {
            current_org_name = Some(
                line.strip_prefix("org-name:")
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            );
        }
    }

    // Save last entry
    if let (Some(org_id), Some(org_name)) = (current_org_id, current_org_name) {
        org_map.insert(org_id, org_name);
    }

    org_map
}

/// ASN info from aut-num file
struct AutNumInfo {
    org_id: Option<String>,
    as_name: Option<String>,
}

/// Parse ripe.db.aut-num file to get ASN -> (org_id, as_name) mapping
fn parse_aut_num(content: &str) -> HashMap<u32, AutNumInfo> {
    let mut asn_map: HashMap<u32, AutNumInfo> = HashMap::new();
    let mut current_asn: Option<u32> = None;
    let mut current_org_id: Option<String> = None;
    let mut current_as_name: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
            continue;
        }

        if line.starts_with("aut-num:") {
            // Save previous entry
            if let Some(asn) = current_asn.take() {
                asn_map.insert(
                    asn,
                    AutNumInfo {
                        org_id: current_org_id.take(),
                        as_name: current_as_name.take(),
                    },
                );
            }

            // Parse new ASN
            let asn_str = line.strip_prefix("aut-num:").unwrap_or("").trim();
            current_asn = parse_asn_number(asn_str);
            current_org_id = None;
            current_as_name = None;
        } else if current_asn.is_some() {
            if line.starts_with("org:") {
                current_org_id = Some(line.strip_prefix("org:").unwrap_or("").trim().to_string());
            } else if line.starts_with("as-name:") {
                current_as_name =
                    Some(line.strip_prefix("as-name:").unwrap_or("").trim().to_string());
            }
        }
    }

    // Save last entry
    if let Some(asn) = current_asn {
        asn_map.insert(
            asn,
            AutNumInfo {
                org_id: current_org_id,
                as_name: current_as_name,
            },
        );
    }

    asn_map
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "Usage: {} <ripe.db.aut-num.txt> <ripe.db.organisation.txt> <output.bin>",
            args[0]
        );
        eprintln!();
        eprintln!("Download RIPE database dumps:");
        eprintln!("  curl -O ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.aut-num.gz");
        eprintln!("  curl -O ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.organisation.gz");
        eprintln!("  gunzip ripe.db.aut-num.gz ripe.db.organisation.gz");
        std::process::exit(1);
    }

    let autnum_file = &args[1];
    let org_file = &args[2];
    let output = &args[3];

    // Read organisation file
    eprintln!("[*] Reading organisation file: {}", org_file);
    let mut file = File::open(org_file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let org_content = String::from_utf8_lossy(&bytes);

    let org_map = parse_organisations(&org_content);
    eprintln!("[*] Parsed {} organisation entries", org_map.len());

    // Read aut-num file
    eprintln!("[*] Reading aut-num file: {}", autnum_file);
    let mut file = File::open(autnum_file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let autnum_content = String::from_utf8_lossy(&bytes);

    let asn_info_map = parse_aut_num(&autnum_content);
    eprintln!("[*] Parsed {} ASN entries", asn_info_map.len());

    // Build ASN -> org_name mapping with string interning
    // Step 1: Collect unique org_names and build index
    let mut org_name_to_idx: HashMap<String, u16> = HashMap::new();
    let mut org_names: Vec<String> = Vec::new();

    // Step 2: Build ASN -> org_name_idx mapping
    let mut asn_to_idx: Vec<(u32, u16)> = Vec::new();

    let mut from_org_count = 0u32;
    let mut from_asname_count = 0u32;

    for (asn, info) in &asn_info_map {
        // Try to get org_name from organisation file via org_id
        // If not available, fall back to as-name
        let org_name = if let Some(ref org_id) = info.org_id {
            if let Some(name) = org_map.get(org_id) {
                from_org_count += 1;
                Some(name.clone())
            } else {
                // org_id exists but not found in organisation file, use as-name
                info.as_name.clone().inspect(|_| {
                    from_asname_count += 1;
                })
            }
        } else {
            // No org_id, use as-name as fallback
            info.as_name.clone().inspect(|_| {
                from_asname_count += 1;
            })
        };

        if let Some(name) = org_name {
            let idx = if let Some(&existing_idx) = org_name_to_idx.get(&name) {
                existing_idx
            } else {
                let new_idx = org_names.len() as u16;
                org_names.push(name.clone());
                org_name_to_idx.insert(name, new_idx);
                new_idx
            };
            asn_to_idx.push((*asn, idx));
        }
    }

    // Sort by ASN for binary search
    asn_to_idx.sort_by_key(|(asn, _)| *asn);

    eprintln!(
        "[*] Built mapping: {} ASNs -> {} unique org names",
        asn_to_idx.len(),
        org_names.len()
    );
    eprintln!(
        "[*] Sources: {} from organisation file, {} from as-name fallback",
        from_org_count, from_asname_count
    );

    // Write binary format v2:
    // Header (16 bytes):
    //   - magic: 4 bytes = b"RIPE"
    //   - version: u32 = 2
    //   - org_count: u32 (number of unique org names)
    //   - asn_count: u32 (number of ASN mappings)
    // Org names section:
    //   - For each org: len:u16, name:utf8
    // ASN mappings section:
    //   - For each mapping: asn:u32, org_idx:u16 (sorted by ASN)

    let mut out = Vec::new();

    // Header
    out.extend_from_slice(b"RIPE");
    out.extend_from_slice(&2u32.to_le_bytes()); // version 2
    out.extend_from_slice(&(org_names.len() as u32).to_le_bytes());
    out.extend_from_slice(&(asn_to_idx.len() as u32).to_le_bytes());

    // Org names
    for name in &org_names {
        let bytes = name.as_bytes();
        let len = bytes.len().min(65535) as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&bytes[..len as usize]);
    }

    // ASN mappings
    for (asn, idx) in &asn_to_idx {
        out.extend_from_slice(&asn.to_le_bytes());
        out.extend_from_slice(&idx.to_le_bytes());
    }

    let mut out_file = File::create(output)?;
    out_file.write_all(&out)?;

    eprintln!("[*] Written {} bytes to {} (v2 format)", out.len(), output);
    eprintln!("[*] Done.");

    Ok(())
}
