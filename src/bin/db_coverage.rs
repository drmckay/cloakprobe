//! Database coverage analyzer - compares ASNs in asn_db.bin vs orgs_db.bin

use std::collections::HashSet;
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <asn_db.bin> [orgs_db.bin]", args[0]);
        eprintln!();
        eprintln!("Analyzes coverage between ASN database and organization database.");
        std::process::exit(1);
    }

    let asn_db_path = &args[1];
    let org_db_path = args.get(2).map(|s| s.as_str());

    // Load ASN database and extract unique ASNs
    println!("Loading ASN database: {}", asn_db_path);
    let asn_data = fs::read(asn_db_path)?;
    let asn_set = extract_asns_from_asn_db(&asn_data)?;
    println!("  Unique ASNs in ip2asn: {}", asn_set.len());

    // Load org database if provided
    if let Some(org_path) = org_db_path {
        println!("\nLoading organization database: {}", org_path);
        let org_data = fs::read(org_path)?;
        let org_asn_set = extract_asns_from_org_db(&org_data)?;
        println!("  Unique ASNs in orgs_db: {}", org_asn_set.len());

        // Calculate coverage
        let covered: HashSet<_> = asn_set.intersection(&org_asn_set).collect();
        let missing: HashSet<_> = asn_set.difference(&org_asn_set).collect();
        let extra: HashSet<_> = org_asn_set.difference(&asn_set).collect();

        let coverage_pct = (covered.len() as f64 / asn_set.len() as f64) * 100.0;

        println!("\n=== Coverage Analysis ===");
        println!(
            "ASNs in ip2asn with org data:    {} ({:.2}%)",
            covered.len(),
            coverage_pct
        );
        println!("ASNs in ip2asn without org data: {}", missing.len());
        println!(
            "ASNs in orgs_db not in ip2asn:   {} (may be unannounced)",
            extra.len()
        );

        // Show some sample missing ASNs
        if !missing.is_empty() {
            println!("\nSample ASNs without org data (first 20):");
            let mut sample: Vec<_> = missing.iter().copied().collect();
            sample.sort();
            for asn in sample.iter().take(20) {
                println!("  AS{}", asn);
            }
        }

        // Show some sample extra ASNs
        if !extra.is_empty() {
            println!("\nSample ASNs in orgs_db but not in ip2asn (first 10):");
            let mut sample: Vec<_> = extra.iter().copied().collect();
            sample.sort();
            for asn in sample.iter().take(10) {
                println!("  AS{}", asn);
            }
        }
    }

    Ok(())
}

fn extract_asns_from_asn_db(data: &[u8]) -> Result<HashSet<u32>, String> {
    if data.len() < 20 {
        return Err("ASN DB too small".into());
    }

    let magic = &data[0..4];
    if magic != b"ASND" {
        return Err(format!("Invalid ASN DB magic: {:?}", magic));
    }

    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let v4_count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let v6_count = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

    println!(
        "  Version: {}, IPv4 entries: {}, IPv6 entries: {}",
        version, v4_count, v6_count
    );

    let mut asns = HashSet::new();
    let mut offset = 20;

    // Parse IPv4 entries
    for _ in 0..v4_count {
        if offset + 14 > data.len() {
            break;
        }
        // start(4) + end(4) + asn(4) + country(2) = 14 bytes minimum
        let asn = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());
        asns.insert(asn);

        // Skip variable length AS name
        if version >= 2 && offset + 14 < data.len() {
            let name_len = data[offset + 14] as usize;
            offset += 15 + name_len;
        } else {
            offset += 14;
        }
    }

    // Parse IPv6 entries
    for _ in 0..v6_count {
        if offset + 38 > data.len() {
            break;
        }
        // start(16) + end(16) + asn(4) + country(2) = 38 bytes minimum
        let asn = u32::from_le_bytes(data[offset + 32..offset + 36].try_into().unwrap());
        asns.insert(asn);

        // Skip variable length AS name
        if version >= 2 && offset + 38 < data.len() {
            let name_len = data[offset + 38] as usize;
            offset += 39 + name_len;
        } else {
            offset += 38;
        }
    }

    Ok(asns)
}

fn extract_asns_from_org_db(data: &[u8]) -> Result<HashSet<u32>, String> {
    if data.len() < 16 {
        return Err("Org DB too small".into());
    }

    let magic = &data[0..4];

    match magic {
        b"ORGS" => extract_asns_from_orgs_v1(data),
        b"RIPE" => extract_asns_from_ripe_legacy(data),
        _ => Err(format!("Unknown org DB magic: {:?}", magic)),
    }
}

fn extract_asns_from_orgs_v1(data: &[u8]) -> Result<HashSet<u32>, String> {
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let org_count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let asn_count = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

    println!(
        "  Format: ORGS v{}, {} orgs, {} ASN mappings",
        version, org_count, asn_count
    );

    // Skip org entries to get to ASN mappings
    let mut offset = 16;
    for _ in 0..org_count {
        // 7 strings, each: len(u16) + utf8
        for _ in 0..7 {
            if offset + 2 > data.len() {
                return Err("Truncated org entry".into());
            }
            let len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2 + len;
        }
    }

    // Read ASN mappings
    let mut asns = HashSet::new();
    for _ in 0..asn_count {
        if offset + 6 > data.len() {
            break;
        }
        let asn = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        asns.insert(asn);
        offset += 6; // asn(4) + org_idx(2)
    }

    Ok(asns)
}

fn extract_asns_from_ripe_legacy(data: &[u8]) -> Result<HashSet<u32>, String> {
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let org_count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let asn_count = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

    println!(
        "  Format: RIPE v{}, {} orgs, {} ASN mappings",
        version, org_count, asn_count
    );

    // For legacy format, just count the ASN mappings
    // This is a rough estimate since the format is different
    let mut asns = HashSet::new();

    // Skip to ASN section (rough estimate)
    let mut offset = 16;

    // Skip org entries
    for _ in 0..org_count {
        if offset + 2 > data.len() {
            break;
        }
        let len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2 + len;
    }

    // Read ASN mappings
    for _ in 0..asn_count {
        if offset + 6 > data.len() {
            break;
        }
        let asn = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        asns.insert(asn);
        offset += 6;
    }

    Ok(asns)
}
