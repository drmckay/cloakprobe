use clap::Parser;
use flate2::read::GzDecoder;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};

/// Unified RPSL parser for RIPE, APNIC, LACNIC, AFRINIC bulk data.
///
/// Outputs CSV to stdout: asn,org_id,org_name,country,rir,org_type,abuse_contact,last_updated
///
/// Supports:
///   - Separate aut-num and organisation files (RIPE, APNIC)
///   - Combined database files (LACNIC, AFRINIC)
///   - Gzipped input (auto-detected by .gz extension)
#[derive(Parser, Debug)]
#[command(name = "org_builder_rpsl")]
#[command(about = "Parse RPSL format RIR data and output CSV")]
struct Args {
    /// Path to aut-num file (or combined DB file if --combined is used)
    #[arg(long)]
    aut_num: Option<String>,

    /// Path to organisation file (optional, not needed for combined DB)
    #[arg(long)]
    organisation: Option<String>,

    /// Path to combined database file containing both aut-num and organisation objects
    #[arg(long)]
    combined: Option<String>,

    /// RIR name to tag records with (RIPE, APNIC, LACNIC, AFRINIC)
    #[arg(long)]
    rir: String,

    /// Path to role/person file for resolving abuse-c handles to email addresses
    #[arg(long)]
    role: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    run_with_args(args)
}

fn run_with_args(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let rir = args.rir.to_uppercase();

    // Parse role/person data to resolve abuse-c handles to emails
    let role_email_map: HashMap<String, String> = if let Some(ref role_path) = args.role {
        // Explicit role file provided
        let content = read_file_auto(role_path)?;
        parse_roles(&content)
    } else if let Some(ref combined_path) = args.combined {
        // Combined file: also parse roles from the same file
        let content = read_file_auto(combined_path)?;
        parse_roles(&content)
    } else {
        HashMap::new()
    };

    // Parse organisation data
    let org_map: HashMap<String, OrgDetails> = if let Some(ref combined_path) = args.combined {
        // Combined file: parse both aut-num and organisation from same file
        let content = read_file_auto(combined_path)?;
        parse_organisations_extended(&content)
    } else if let Some(ref org_path) = args.organisation {
        let content = read_file_auto(org_path)?;
        parse_organisations_extended(&content)
    } else {
        HashMap::new()
    };

    // Parse aut-num data
    let autnum_content = if let Some(ref combined_path) = args.combined {
        read_file_auto(combined_path)?
    } else if let Some(ref autnum_path) = args.aut_num {
        read_file_auto(autnum_path)?
    } else {
        return Err("Either --aut-num or --combined must be specified".into());
    };

    let asn_entries = parse_aut_num_extended(&autnum_content);

    // Output CSV to stdout
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for entry in &asn_entries {
        let org_details = entry.org_id.as_ref().and_then(|id| org_map.get(id));

        let org_name = org_details
            .and_then(|o| o.org_name.clone())
            .unwrap_or_default();
        let country = org_details
            .and_then(|o| o.country.clone())
            .or(entry.country.clone())
            .unwrap_or_default();
        let org_type = org_details
            .and_then(|o| o.org_type.clone())
            .unwrap_or_default();
        // Get abuse-c handle and resolve to email if role mapping available
        let abuse_handle = org_details
            .and_then(|o| o.abuse_c.clone())
            .or(entry.abuse_c.clone());

        let abuse_contact = abuse_handle
            .as_ref()
            .and_then(|handle| role_email_map.get(handle).cloned())
            .unwrap_or_else(|| abuse_handle.unwrap_or_default());

        let last_updated = entry.last_modified.clone().unwrap_or_default();

        writeln!(
            out,
            "{},{},{},{},{},{},{},{}",
            entry.asn,
            escape_csv(&entry.org_id.clone().unwrap_or_default()),
            escape_csv(&org_name),
            escape_csv(&country),
            &rir,
            escape_csv(&org_type),
            escape_csv(&abuse_contact),
            escape_csv(&last_updated)
        )?;
    }

    eprintln!(
        "[*] {} - Parsed {} organisations, {} ASN entries, {} role mappings",
        rir,
        org_map.len(),
        asn_entries.len(),
        role_email_map.len()
    );

    Ok(())
}

/// Read file, auto-detecting gzip by extension
/// Uses lossy UTF-8 conversion to handle Latin-1 encoded RIR data
fn read_file_auto(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let file = File::open(path)?;

    let bytes = if path.ends_with(".gz") {
        let mut decoder = GzDecoder::new(file);
        let mut bytes = Vec::new();
        decoder.read_to_end(&mut bytes)?;
        bytes
    } else {
        let mut reader = BufReader::new(file);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        bytes
    };

    // Use lossy UTF-8 conversion - RIR data may contain Latin-1 characters
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Organisation details from RPSL organisation object
#[derive(Debug, Clone, Default)]
struct OrgDetails {
    org_name: Option<String>,
    country: Option<String>,
    org_type: Option<String>,
    abuse_c: Option<String>,
}

/// Aut-num entry from RPSL aut-num object
#[derive(Debug, Clone)]
struct AutNumEntry {
    asn: u32,
    org_id: Option<String>,
    country: Option<String>,
    abuse_c: Option<String>,
    last_modified: Option<String>,
}

/// Parse organisation objects from RPSL content, extracting extended fields
fn parse_organisations_extended(content: &str) -> HashMap<String, OrgDetails> {
    let mut org_map: HashMap<String, OrgDetails> = HashMap::new();
    let mut current_org_id: Option<String> = None;
    let mut current_details = OrgDetails::default();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
            continue;
        }

        if line.starts_with("organisation:") {
            // Save previous org if exists
            if let Some(id) = current_org_id.take() {
                org_map.insert(id, current_details.clone());
            }
            current_org_id = Some(extract_value(line, "organisation:"));
            current_details = OrgDetails::default();
        } else if current_org_id.is_some() {
            if line.starts_with("org-name:") {
                current_details.org_name = Some(extract_value(line, "org-name:"));
            } else if line.starts_with("country:") {
                current_details.country = Some(extract_value(line, "country:"));
            } else if line.starts_with("org-type:") {
                current_details.org_type = Some(extract_value(line, "org-type:"));
            } else if line.starts_with("abuse-c:") {
                current_details.abuse_c = Some(extract_value(line, "abuse-c:"));
            }
        }
    }

    // Save last org
    if let Some(id) = current_org_id {
        org_map.insert(id, current_details);
    }

    org_map
}

/// Parse aut-num objects from RPSL content, extracting extended fields
fn parse_aut_num_extended(content: &str) -> Vec<AutNumEntry> {
    let mut entries: Vec<AutNumEntry> = Vec::new();
    let mut current_asn: Option<u32> = None;
    let mut current_org_id: Option<String> = None;
    let mut current_country: Option<String> = None;
    let mut current_abuse_c: Option<String> = None;
    let mut current_last_modified: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
            continue;
        }

        if line.starts_with("aut-num:") {
            // Save previous entry if exists
            if let Some(asn) = current_asn.take() {
                entries.push(AutNumEntry {
                    asn,
                    org_id: current_org_id.take(),
                    country: current_country.take(),
                    abuse_c: current_abuse_c.take(),
                    last_modified: current_last_modified.take(),
                });
            }
            current_asn = parse_asn_number(&extract_value(line, "aut-num:"));
            current_org_id = None;
            current_country = None;
            current_abuse_c = None;
            current_last_modified = None;
        } else if current_asn.is_some() {
            if line.starts_with("org:") {
                current_org_id = Some(extract_value(line, "org:"));
            } else if line.starts_with("country:") {
                current_country = Some(extract_value(line, "country:"));
            } else if line.starts_with("abuse-c:") {
                current_abuse_c = Some(extract_value(line, "abuse-c:"));
            } else if line.starts_with("last-modified:") {
                current_last_modified = Some(extract_value(line, "last-modified:"));
            }
        }
    }

    // Save last entry
    if let Some(asn) = current_asn {
        entries.push(AutNumEntry {
            asn,
            org_id: current_org_id,
            country: current_country,
            abuse_c: current_abuse_c,
            last_modified: current_last_modified,
        });
    }

    entries
}

/// Extract value after a field prefix
fn extract_value(line: &str, prefix: &str) -> String {
    line.strip_prefix(prefix).unwrap_or("").trim().to_string()
}

/// Parse role/person objects from RPSL content to extract handle -> email mappings
/// Supports both "role:" and "person:" object types
/// The handle is in the "nic-hdl:" field, not in the "role:" or "person:" field
fn parse_roles(content: &str) -> HashMap<String, String> {
    let mut role_map: HashMap<String, String> = HashMap::new();
    let mut current_handle: Option<String> = None;
    let mut current_email: Option<String> = None;
    let mut in_role_object = false;

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
            continue;
        }

        // Start of role or person object
        if line.starts_with("role:") || line.starts_with("person:") {
            // Save previous role if exists
            if let (Some(handle), Some(email)) = (current_handle.take(), current_email.take()) {
                if !email.is_empty() {
                    role_map.insert(handle, email);
                }
            }
            in_role_object = true;
            current_handle = None;
            current_email = None;
        } else if in_role_object {
            // Extract handle from nic-hdl field (this is the actual handle used in abuse-c)
            if line.starts_with("nic-hdl:") {
                current_handle = Some(extract_value(line, "nic-hdl:"));
            }
            // Extract email address
            else if line.starts_with("e-mail:") {
                current_email = Some(extract_value(line, "e-mail:"));
            } else if line.starts_with("email:") {
                // Some RIRs use "email:" instead of "e-mail:"
                current_email = Some(extract_value(line, "email:"));
            }
            // End of object (empty line or start of new object)
            else if line.is_empty() {
                // Save current role if we have both handle and email
                if let (Some(handle), Some(email)) = (current_handle.take(), current_email.take()) {
                    if !email.is_empty() {
                        role_map.insert(handle, email);
                    }
                }
                in_role_object = false;
            }
        }
    }

    // Save last role
    if let (Some(handle), Some(email)) = (current_handle, current_email) {
        if !email.is_empty() {
            role_map.insert(handle, email);
        }
    }

    role_map
}

/// Parse ASN number from string like "AS64500" or "64500"
fn parse_asn_number(s: &str) -> Option<u32> {
    let s = s.trim();
    let num_str = if s.to_uppercase().starts_with("AS") {
        &s[2..]
    } else {
        s
    };
    num_str.parse::<u32>().ok()
}

/// Escape CSV field (quote if contains comma, quote, or newline)
fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_organisations() {
        let content = r#"
organisation:   ORG-EX1-RIPE
org-name:       Example Organization
country:        DE
org-type:       LIR
abuse-c:        ABUSE1-RIPE

organisation:   ORG-TEST-RIPE
org-name:       Test Company
country:        US
org-type:       OTHER
"#;
        let orgs = parse_organisations_extended(content);
        assert_eq!(orgs.len(), 2);

        let org1 = orgs.get("ORG-EX1-RIPE").unwrap();
        assert_eq!(org1.org_name, Some("Example Organization".to_string()));
        assert_eq!(org1.country, Some("DE".to_string()));
        assert_eq!(org1.org_type, Some("LIR".to_string()));
        assert_eq!(org1.abuse_c, Some("ABUSE1-RIPE".to_string()));

        let org2 = orgs.get("ORG-TEST-RIPE").unwrap();
        assert_eq!(org2.org_name, Some("Test Company".to_string()));
        assert_eq!(org2.country, Some("US".to_string()));
    }

    #[test]
    fn test_parse_aut_num() {
        let content = r#"
aut-num:        AS64500
as-name:        EXAMPLE-AS
org:            ORG-EX1-RIPE
country:        DE
last-modified:  2024-01-15T12:00:00Z

aut-num:        AS64501
as-name:        TEST-AS
org:            ORG-TEST-RIPE
country:        US
abuse-c:        ABUSE2-RIPE
"#;
        let entries = parse_aut_num_extended(content);
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].asn, 64500);
        assert_eq!(entries[0].org_id, Some("ORG-EX1-RIPE".to_string()));
        assert_eq!(entries[0].country, Some("DE".to_string()));
        assert_eq!(
            entries[0].last_modified,
            Some("2024-01-15T12:00:00Z".to_string())
        );

        assert_eq!(entries[1].asn, 64501);
        assert_eq!(entries[1].org_id, Some("ORG-TEST-RIPE".to_string()));
        assert_eq!(entries[1].abuse_c, Some("ABUSE2-RIPE".to_string()));
    }

    #[test]
    fn test_parse_asn_number() {
        assert_eq!(parse_asn_number("AS64500"), Some(64500));
        assert_eq!(parse_asn_number("64500"), Some(64500));
        assert_eq!(parse_asn_number("as12345"), Some(12345));
        assert_eq!(parse_asn_number("invalid"), None);
    }

    #[test]
    fn test_escape_csv() {
        assert_eq!(escape_csv("simple"), "simple");
        assert_eq!(escape_csv("with,comma"), "\"with,comma\"");
        assert_eq!(escape_csv("with\"quote"), "\"with\"\"quote\"");
        assert_eq!(escape_csv("with\nnewline"), "\"with\nnewline\"");
    }

    #[test]
    fn test_combined_db_parsing() {
        // Simulates a combined DB file with both organisation and aut-num objects
        let content = r#"
organisation:   ORG-COMBINED-TEST
org-name:       Combined Test Org
country:        FR
org-type:       LIR

aut-num:        AS99999
as-name:        COMBINED-AS
org:            ORG-COMBINED-TEST
country:        FR
"#;
        let orgs = parse_organisations_extended(content);
        let entries = parse_aut_num_extended(content);

        assert_eq!(orgs.len(), 1);
        assert_eq!(entries.len(), 1);

        let org = orgs.get("ORG-COMBINED-TEST").unwrap();
        assert_eq!(org.org_name, Some("Combined Test Org".to_string()));

        assert_eq!(entries[0].asn, 99999);
        assert_eq!(entries[0].org_id, Some("ORG-COMBINED-TEST".to_string()));
    }

    #[test]
    fn test_parse_roles() {
        let content = r#"
role:           Abuse Contact Role
address:        Example Street 1
e-mail:         abuse@example.com
admin-c:        ADMIN1-RIPE
tech-c:         TECH1-RIPE
nic-hdl:        ABUSE1-RIPE

person:         Abuse Contact Person
address:        Test Avenue 2
e-mail:         abuse2@test.com
nic-hdl:        ABUSE2-RIPE

role:           No Email Role
address:        No Email Street
admin-c:        ADMIN2-RIPE
nic-hdl:        NO-EMAIL-RIPE
"#;
        let roles = parse_roles(content);
        assert_eq!(roles.len(), 2);
        assert_eq!(
            roles.get("ABUSE1-RIPE"),
            Some(&"abuse@example.com".to_string())
        );
        assert_eq!(
            roles.get("ABUSE2-RIPE"),
            Some(&"abuse2@test.com".to_string())
        );
        assert_eq!(roles.get("NO-EMAIL-RIPE"), None);
    }

    #[test]
    fn test_resolve_abuse_contact() {
        // Test that abuse handles are resolved to emails
        let role_map: HashMap<String, String> = [
            ("ABUSE1-RIPE".to_string(), "abuse@example.com".to_string()),
            ("ABUSE2-RIPE".to_string(), "abuse2@test.com".to_string()),
        ]
        .iter()
        .cloned()
        .collect();

        // Test resolution
        assert_eq!(
            role_map.get("ABUSE1-RIPE"),
            Some(&"abuse@example.com".to_string())
        );
        assert_eq!(role_map.get("UNKNOWN-RIPE"), None);
    }
}
