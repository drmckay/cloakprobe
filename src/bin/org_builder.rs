use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

/// Expected input CSV (no headers), comma-separated, 8 fields:
/// asn,org_id,org_name,country,rir,org_type,abuse_contact,last_updated
/// Empty fields are allowed (treated as None).
/// Supports RFC 4180 CSV format with quoted fields containing commas.
///
/// Optional --fallback <ip2asn.tsv> to fill in missing ASNs with ip2asn data:
/// ip2asn TSV format: start_ip, end_ip, asn, country, as_name
///
/// Output format (binary):
/// magic "ORGS"
/// version u32 = 1
/// org_count u32
/// asn_count u32
/// org entries (org_count):
///   7 strings (org_id, org_name, country, rir, org_type, abuse_contact, last_updated), each len:u16 + utf8 bytes (len=0 => None)
/// asn mappings (asn_count):
///   asn:u32, org_idx:u16 (sorted by ASN)
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Parse arguments: <orgs.csv> <output.bin> [--fallback <ip2asn.tsv>]
    let mut csv_path: Option<String> = None;
    let mut output_path: Option<String> = None;
    let mut fallback_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--fallback" {
            if i + 1 < args.len() {
                fallback_path = Some(args[i + 1].clone());
                i += 2;
            } else {
                eprintln!("Error: --fallback requires a path argument");
                std::process::exit(1);
            }
        } else if csv_path.is_none() {
            csv_path = Some(args[i].clone());
            i += 1;
        } else if output_path.is_none() {
            output_path = Some(args[i].clone());
            i += 1;
        } else {
            eprintln!("Error: unexpected argument '{}'", args[i]);
            std::process::exit(1);
        }
    }

    if csv_path.is_none() || output_path.is_none() {
        eprintln!(
            "Usage: {} <orgs.csv> <output.bin> [--fallback <ip2asn.tsv>]",
            args[0]
        );
        eprintln!();
        eprintln!("Input CSV columns (no header):");
        eprintln!("asn,org_id,org_name,country,rir,org_type,abuse_contact,last_updated");
        eprintln!();
        eprintln!("Optional --fallback: ip2asn TSV file to fill missing ASNs with country/AS name");
        eprintln!("  Format: start_ip, end_ip, asn, country, as_name (tab-separated)");
        eprintln!();
        eprintln!("Example:");
        eprintln!(
            "  {} orgs.csv orgs_db.bin --fallback ip2asn-combined.tsv",
            args[0]
        );
        std::process::exit(1);
    }

    run_with_args(
        &csv_path.unwrap(),
        &output_path.unwrap(),
        fallback_path.as_deref(),
    )
}

/// Parse a CSV line handling quoted fields (RFC 4180)
/// - Fields may be enclosed in double quotes
/// - Quotes inside quoted fields are escaped by doubling ("")
/// - Commas inside quoted fields are preserved
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current_field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if !in_quotes => {
                // Start of quoted field
                in_quotes = true;
            }
            '"' if in_quotes => {
                // Check for escaped quote (doubled quotes)
                if chars.peek() == Some(&'"') {
                    chars.next(); // consume the second quote
                    current_field.push('"');
                } else {
                    // End of quoted field
                    in_quotes = false;
                }
            }
            ',' if !in_quotes => {
                // Field separator
                fields.push(current_field.trim().to_string());
                current_field = String::new();
            }
            _ => {
                current_field.push(c);
            }
        }
    }

    // Don't forget the last field
    fields.push(current_field.trim().to_string());

    fields
}

#[derive(Debug, Clone)]
struct OrgRecord {
    org_id: Option<String>,
    org_name: Option<String>,
    country: Option<String>,
    rir: Option<String>,
    org_type: Option<String>,
    abuse_contact: Option<String>,
    last_updated: Option<String>,
}

#[allow(clippy::type_complexity)]
type OrgKey = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn run_with_args(
    input: &str,
    output: &str,
    fallback_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(input)?;
    let reader = BufReader::new(file);

    let mut orgs: Vec<OrgRecord> = Vec::new();
    let mut org_key_to_idx: HashMap<OrgKey, u16> = HashMap::new();
    let mut asn_to_org: Vec<(u32, u16)> = Vec::new();
    let mut known_asns: HashSet<u32> = HashSet::new();

    for (lineno, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        // Use proper CSV parsing for quoted fields
        let parts = parse_csv_line(&line);
        if parts.len() != 8 {
            eprintln!(
                "[WARN] Line {}: expected 8 columns, got {} -> {}",
                lineno + 1,
                parts.len(),
                line
            );
            continue;
        }

        let asn: u32 = match parts[0].parse() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("[WARN] Line {}: invalid ASN '{}'", lineno + 1, parts[0]);
                continue;
            }
        };

        let to_opt = |s: &String| {
            if s.is_empty() {
                None
            } else {
                Some(s.clone())
            }
        };

        let record = OrgRecord {
            org_id: to_opt(&parts[1]),
            org_name: to_opt(&parts[2]),
            country: to_opt(&parts[3]),
            rir: to_opt(&parts[4]),
            org_type: to_opt(&parts[5]),
            abuse_contact: to_opt(&parts[6]),
            last_updated: to_opt(&parts[7]),
        };

        let key = (
            record.org_id.clone(),
            record.org_name.clone(),
            record.country.clone(),
            record.rir.clone(),
        );

        let idx = if let Some(&idx) = org_key_to_idx.get(&key) {
            idx
        } else {
            let new_idx = orgs.len() as u16;
            orgs.push(record);
            org_key_to_idx.insert(key, new_idx);
            new_idx
        };

        asn_to_org.push((asn, idx));
        known_asns.insert(asn);
    }

    eprintln!(
        "[*] Parsed {} orgs, {} ASN mappings from RIR data",
        orgs.len(),
        asn_to_org.len()
    );

    // Process fallback ip2asn data if provided
    if let Some(fallback) = fallback_path {
        let fallback_count = process_ip2asn_fallback(
            fallback,
            &known_asns,
            &mut orgs,
            &mut org_key_to_idx,
            &mut asn_to_org,
        )?;
        eprintln!(
            "[*] Added {} fallback entries from ip2asn (total ASNs: {})",
            fallback_count,
            asn_to_org.len()
        );
    }

    // Sort ASN mappings by ASN
    asn_to_org.sort_by_key(|(asn, _)| *asn);

    // Build output
    let mut out = Vec::new();
    out.extend_from_slice(b"ORGS");
    out.extend_from_slice(&1u32.to_le_bytes()); // version
    out.extend_from_slice(&(orgs.len() as u32).to_le_bytes());
    out.extend_from_slice(&(asn_to_org.len() as u32).to_le_bytes());

    let write_str = |out: &mut Vec<u8>, val: &Option<String>| {
        if let Some(s) = val {
            let bytes = s.as_bytes();
            let len = bytes.len().min(65535) as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&bytes[..len as usize]);
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
    };

    for org in &orgs {
        write_str(&mut out, &org.org_id);
        write_str(&mut out, &org.org_name);
        write_str(&mut out, &org.country);
        write_str(&mut out, &org.rir);
        write_str(&mut out, &org.org_type);
        write_str(&mut out, &org.abuse_contact);
        write_str(&mut out, &org.last_updated);
    }

    for (asn, idx) in &asn_to_org {
        out.extend_from_slice(&asn.to_le_bytes());
        out.extend_from_slice(&idx.to_le_bytes());
    }

    let mut f = File::create(output)?;
    f.write_all(&out)?;

    eprintln!("[*] Written {} bytes to {} (ORGS v1)", out.len(), output);

    Ok(())
}

/// Parse ip2asn TSV and add entries for ASNs not already in RIR data
/// ip2asn format: start_ip \t end_ip \t asn \t country \t as_name
fn process_ip2asn_fallback(
    path: &str,
    known_asns: &HashSet<u32>,
    orgs: &mut Vec<OrgRecord>,
    org_key_to_idx: &mut HashMap<OrgKey, u16>,
    asn_to_org: &mut Vec<(u32, u16)>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut fallback_asns: HashMap<u32, (String, String)> = HashMap::new(); // asn -> (country, as_name)

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 5 {
            continue;
        }

        // Parse ASN
        let asn: u32 = match parts[2].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Skip if already in RIR data
        if known_asns.contains(&asn) {
            continue;
        }

        // Skip reserved ASN 0
        if asn == 0 {
            continue;
        }

        let country = parts[3].to_string();
        let as_name = parts[4].to_string();

        // Only add if we haven't seen this ASN yet (ip2asn may have multiple ranges per ASN)
        fallback_asns.entry(asn).or_insert((country, as_name));
    }

    let mut count = 0;
    for (asn, (country, as_name)) in fallback_asns {
        // Create fallback org record
        let record = OrgRecord {
            org_id: None,
            org_name: if as_name.is_empty() || as_name == "Not routed" {
                None
            } else {
                Some(as_name)
            },
            country: if country.is_empty() || country == "None" {
                None
            } else {
                Some(country.clone())
            },
            rir: Some("ip2asn".to_string()), // Mark as fallback source
            org_type: Some("fallback".to_string()),
            abuse_contact: None,
            last_updated: None,
        };

        let key = (
            record.org_id.clone(),
            record.org_name.clone(),
            record.country.clone(),
            record.rir.clone(),
        );

        let idx = if let Some(&idx) = org_key_to_idx.get(&key) {
            idx
        } else {
            let new_idx = orgs.len() as u16;
            orgs.push(record);
            org_key_to_idx.insert(key, new_idx);
            new_idx
        };

        asn_to_org.push((asn, idx));
        count += 1;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_parse_csv_simple() {
        let line = "15169,GOGL-ARIN,Google LLC,US,ARIN,hosting,abuse@google.com,2024-12-09";
        let parts = parse_csv_line(line);
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[0], "15169");
        assert_eq!(parts[1], "GOGL-ARIN");
        assert_eq!(parts[2], "Google LLC");
        assert_eq!(parts[3], "US");
        assert_eq!(parts[4], "ARIN");
    }

    #[test]
    fn test_parse_csv_quoted_with_comma() {
        let line = r#"12345,ORG-TEST,"Company, Inc.",US,ARIN,isp,abuse@example.com,2024-12-09"#;
        let parts = parse_csv_line(line);
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[0], "12345");
        assert_eq!(parts[1], "ORG-TEST");
        assert_eq!(parts[2], "Company, Inc.");
        assert_eq!(parts[3], "US");
        assert_eq!(parts[4], "ARIN");
    }

    #[test]
    fn test_parse_csv_quoted_with_escaped_quotes() {
        let line = r#"67890,ORG-QUOTE,"He said ""Hello""",GB,RIPE,isp,,2024-12-09"#;
        let parts = parse_csv_line(line);
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[0], "67890");
        assert_eq!(parts[2], r#"He said "Hello""#);
        assert_eq!(parts[3], "GB");
    }

    #[test]
    fn test_parse_csv_empty_fields() {
        let line = "12345,,,,ARIN,,,2024-12-09";
        let parts = parse_csv_line(line);
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[0], "12345");
        assert_eq!(parts[1], "");
        assert_eq!(parts[2], "");
        assert_eq!(parts[4], "ARIN");
        assert_eq!(parts[7], "2024-12-09");
    }

    #[test]
    fn test_parse_csv_multiple_commas_in_quoted() {
        let line = r#"99999,ORG-X,"One, Two, Three, Inc.",CA,APNIC,hosting,,2024-01-01"#;
        let parts = parse_csv_line(line);
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[2], "One, Two, Three, Inc.");
    }

    #[test]
    fn builds_orgs_db_from_csv() {
        let dir = tempdir().unwrap();
        let csv_path = dir.path().join("orgs.csv");
        let out_path = dir.path().join("orgs_db.bin");

        let csv = "\
15169,GOGL-ARIN,Google LLC,US,ARIN,hosting,abuse@google.com,2024-12-09
13335,CLDR-ARIN,Cloudflare,US,ARIN,cdn,abuse@cloudflare.com,2024-12-09
";
        std::fs::write(&csv_path, csv).unwrap();

        run_with_args(csv_path.to_str().unwrap(), out_path.to_str().unwrap(), None).unwrap();

        let data = std::fs::read(&out_path).unwrap();
        assert_eq!(&data[0..4], b"ORGS");
    }

    #[test]
    fn builds_orgs_db_with_quoted_fields() {
        let dir = tempdir().unwrap();
        let csv_path = dir.path().join("orgs_quoted.csv");
        let out_path = dir.path().join("orgs_db.bin");

        let csv = r#"15169,GOGL-ARIN,Google LLC,US,ARIN,hosting,abuse@google.com,2024-12-09
12345,ORG-TEST,"Company, Inc.",US,ARIN,isp,abuse@test.com,2024-12-09
67890,ORG-QUOTE,"He said ""Hi""",GB,RIPE,,,2024-12-09
"#;
        std::fs::write(&csv_path, csv).unwrap();

        run_with_args(csv_path.to_str().unwrap(), out_path.to_str().unwrap(), None).unwrap();

        let data = std::fs::read(&out_path).unwrap();
        assert_eq!(&data[0..4], b"ORGS");

        // Verify the file has the expected structure
        let org_count = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let asn_count = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_eq!(org_count, 3);
        assert_eq!(asn_count, 3);
    }

    #[test]
    fn builds_orgs_db_with_fallback() {
        let dir = tempdir().unwrap();
        let csv_path = dir.path().join("orgs.csv");
        let ip2asn_path = dir.path().join("ip2asn.tsv");
        let out_path = dir.path().join("orgs_db.bin");

        // RIR data - only has AS15169
        let csv = "15169,GOGL-ARIN,Google LLC,US,ARIN,hosting,abuse@google.com,2024-12-09\n";
        std::fs::write(&csv_path, csv).unwrap();

        // ip2asn data - has AS15169 (should be skipped) and AS13335 (should be added)
        let ip2asn = "\
1.0.0.0\t1.0.0.255\t15169\tUS\tGOOGLE
1.1.1.0\t1.1.1.255\t13335\tUS\tCLOUDFLARE
";
        std::fs::write(&ip2asn_path, ip2asn).unwrap();

        run_with_args(
            csv_path.to_str().unwrap(),
            out_path.to_str().unwrap(),
            Some(ip2asn_path.to_str().unwrap()),
        )
        .unwrap();

        let data = std::fs::read(&out_path).unwrap();
        assert_eq!(&data[0..4], b"ORGS");

        // Should have 2 org records and 2 ASN mappings
        let org_count = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let asn_count = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_eq!(asn_count, 2); // AS15169 from RIR + AS13335 from fallback
        assert!(org_count >= 2); // At least 2 orgs
    }
}
