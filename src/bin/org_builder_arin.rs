use clap::Parser;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Write};

/// ARIN XML bulk data parser.
///
/// Outputs CSV to stdout: asn,org_id,org_name,country,rir,org_type,abuse_contact,last_updated
///
/// ARIN provides bulk data in XML format (requires registration):
///   - asns.xml: ASN allocations
///   - orgs.xml: Organization details
///   - pocs.xml: Point of contact (for abuse contacts)
///
/// Download from: https://www.arin.net/resources/registry/whois/bulk/
#[derive(Parser, Debug)]
#[command(name = "org_builder_arin")]
#[command(about = "Parse ARIN XML bulk data and output CSV")]
struct Args {
    /// Path to ARIN asns.xml file
    #[arg(long)]
    asns: String,

    /// Path to ARIN orgs.xml file
    #[arg(long)]
    orgs: String,

    /// Path to ARIN pocs.xml file (optional, for abuse contacts)
    #[arg(long)]
    pocs: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    run_with_args(args)
}

fn run_with_args(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    // Parse organizations first
    let org_map = parse_orgs_xml(&args.orgs)?;
    eprintln!("[*] ARIN - Parsed {} organizations", org_map.len());

    // Parse POCs if provided (for abuse contacts)
    let poc_map = if let Some(ref pocs_path) = args.pocs {
        let map = parse_pocs_xml(pocs_path)?;
        eprintln!("[*] ARIN - Parsed {} POCs", map.len());
        map
    } else {
        HashMap::new()
    };

    // Parse ASNs and output CSV
    let asn_entries = parse_asns_xml(&args.asns)?;
    eprintln!("[*] ARIN - Parsed {} ASN entries", asn_entries.len());

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for entry in &asn_entries {
        let org_details = entry.org_handle.as_ref().and_then(|h| org_map.get(h));

        let org_name = org_details.and_then(|o| o.name.clone()).unwrap_or_default();
        let country = org_details
            .and_then(|o| o.country.clone())
            .unwrap_or_default();
        let org_type = org_details
            .and_then(|o| o.org_type.clone())
            .unwrap_or_default();

        // Try to get abuse contact from POC if available
        let abuse_contact = org_details
            .and_then(|o| o.poc_handles.iter().find_map(|h| poc_map.get(h)))
            .and_then(|poc| poc.email.clone())
            .unwrap_or_default();

        let last_updated = entry.update_date.clone().unwrap_or_default();

        writeln!(
            out,
            "{},{},{},{},ARIN,{},{},{}",
            entry.start_asn,
            escape_csv(&entry.org_handle.clone().unwrap_or_default()),
            escape_csv(&org_name),
            escape_csv(&country),
            escape_csv(&org_type),
            escape_csv(&abuse_contact),
            escape_csv(&last_updated)
        )?;
    }

    Ok(())
}

/// ASN entry from ARIN asns.xml
#[derive(Debug, Clone, Default)]
struct AsnEntry {
    start_asn: u32,
    end_asn: u32,
    org_handle: Option<String>,
    update_date: Option<String>,
}

/// Organization entry from ARIN orgs.xml
#[derive(Debug, Clone, Default)]
struct OrgEntry {
    handle: String,
    name: Option<String>,
    country: Option<String>,
    org_type: Option<String>,
    poc_handles: Vec<String>,
}

/// POC entry from ARIN pocs.xml
#[derive(Debug, Clone, Default)]
struct PocEntry {
    handle: String,
    email: Option<String>,
    poc_type: Option<String>,
}

/// Parse ARIN asns.xml file
fn parse_asns_xml(path: &str) -> Result<Vec<AsnEntry>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut xml_reader = Reader::from_reader(reader);
    xml_reader.config_mut().trim_text(true);

    let mut entries: Vec<AsnEntry> = Vec::new();
    let mut current_entry: Option<AsnEntry> = None;
    let mut current_element = String::new();
    let mut buf = Vec::new();

    loop {
        match xml_reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                current_element = name.clone();

                if name == "asn" {
                    current_entry = Some(AsnEntry::default());
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "asn" {
                    if let Some(entry) = current_entry.take() {
                        if entry.start_asn > 0 {
                            entries.push(entry);
                        }
                    }
                }
                current_element.clear();
            }
            Ok(Event::Text(e)) => {
                if let Some(ref mut entry) = current_entry {
                    let text = e.unescape()?.to_string();
                    match current_element.as_str() {
                        "startAsNumber" => {
                            entry.start_asn = text.parse().unwrap_or(0);
                        }
                        "endAsNumber" => {
                            entry.end_asn = text.parse().unwrap_or(0);
                        }
                        "orgHandle" => {
                            entry.org_handle = Some(text);
                        }
                        "updateDate" => {
                            entry.update_date = Some(text);
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e).into()),
            _ => {}
        }
        buf.clear();
    }

    Ok(entries)
}

/// Parse ARIN orgs.xml file
fn parse_orgs_xml(path: &str) -> Result<HashMap<String, OrgEntry>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut xml_reader = Reader::from_reader(reader);
    xml_reader.config_mut().trim_text(true);

    let mut orgs: HashMap<String, OrgEntry> = HashMap::new();
    let mut current_entry: Option<OrgEntry> = None;
    let mut current_element = String::new();
    let mut in_iso3166_1 = false;
    let mut buf = Vec::new();

    loop {
        match xml_reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                current_element = name.clone();

                if name == "org" {
                    current_entry = Some(OrgEntry::default());
                } else if name == "iso3166-1" {
                    in_iso3166_1 = true;
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "org" {
                    if let Some(entry) = current_entry.take() {
                        if !entry.handle.is_empty() {
                            orgs.insert(entry.handle.clone(), entry);
                        }
                    }
                } else if name == "iso3166-1" {
                    in_iso3166_1 = false;
                }
                current_element.clear();
            }
            Ok(Event::Text(e)) => {
                if let Some(ref mut entry) = current_entry {
                    let text = e.unescape()?.to_string();
                    match current_element.as_str() {
                        "handle" => {
                            entry.handle = text;
                        }
                        "name" => {
                            entry.name = Some(text);
                        }
                        "code2" if in_iso3166_1 => {
                            entry.country = Some(text);
                        }
                        "orgTypeId" => {
                            entry.org_type = Some(text);
                        }
                        "pocHandle" => {
                            entry.poc_handles.push(text);
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e).into()),
            _ => {}
        }
        buf.clear();
    }

    Ok(orgs)
}

/// Parse ARIN pocs.xml file (Point of Contact)
fn parse_pocs_xml(path: &str) -> Result<HashMap<String, PocEntry>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut xml_reader = Reader::from_reader(reader);
    xml_reader.config_mut().trim_text(true);

    let mut pocs: HashMap<String, PocEntry> = HashMap::new();
    let mut current_entry: Option<PocEntry> = None;
    let mut current_element = String::new();
    let mut buf = Vec::new();

    loop {
        match xml_reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                current_element = name.clone();

                if name == "poc" {
                    current_entry = Some(PocEntry::default());
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "poc" {
                    if let Some(entry) = current_entry.take() {
                        // Only keep abuse contacts
                        if entry.poc_type.as_deref() == Some("AB") && !entry.handle.is_empty() {
                            pocs.insert(entry.handle.clone(), entry);
                        }
                    }
                }
                current_element.clear();
            }
            Ok(Event::Text(e)) => {
                if let Some(ref mut entry) = current_entry {
                    let text = e.unescape()?.to_string();
                    match current_element.as_str() {
                        "handle" => {
                            entry.handle = text;
                        }
                        "email" => {
                            entry.email = Some(text);
                        }
                        "contactType" => {
                            entry.poc_type = Some(text);
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e).into()),
            _ => {}
        }
        buf.clear();
    }

    Ok(pocs)
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
    use tempfile::tempdir;

    #[test]
    fn test_parse_asns_xml() {
        let dir = tempdir().unwrap();
        let asns_path = dir.path().join("asns.xml");

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<asns>
  <asn>
    <startAsNumber>15169</startAsNumber>
    <endAsNumber>15169</endAsNumber>
    <orgHandle>GOGL</orgHandle>
    <updateDate>2024-01-15</updateDate>
  </asn>
  <asn>
    <startAsNumber>13335</startAsNumber>
    <endAsNumber>13335</endAsNumber>
    <orgHandle>CLOUD14</orgHandle>
    <updateDate>2024-02-20</updateDate>
  </asn>
</asns>"#;

        std::fs::write(&asns_path, xml).unwrap();
        let entries = parse_asns_xml(asns_path.to_str().unwrap()).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].start_asn, 15169);
        assert_eq!(entries[0].org_handle, Some("GOGL".to_string()));
        assert_eq!(entries[1].start_asn, 13335);
        assert_eq!(entries[1].org_handle, Some("CLOUD14".to_string()));
    }

    #[test]
    fn test_parse_orgs_xml() {
        let dir = tempdir().unwrap();
        let orgs_path = dir.path().join("orgs.xml");

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<orgs>
  <org>
    <handle>GOGL</handle>
    <name>Google LLC</name>
    <iso3166-1>
      <code2>US</code2>
      <code3>USA</code3>
    </iso3166-1>
    <orgTypeId>HOSTING</orgTypeId>
    <pocHandle>ABUSE-GOGL</pocHandle>
  </org>
</orgs>"#;

        std::fs::write(&orgs_path, xml).unwrap();
        let orgs = parse_orgs_xml(orgs_path.to_str().unwrap()).unwrap();

        assert_eq!(orgs.len(), 1);
        let org = orgs.get("GOGL").unwrap();
        assert_eq!(org.name, Some("Google LLC".to_string()));
        assert_eq!(org.country, Some("US".to_string()));
        assert_eq!(org.org_type, Some("HOSTING".to_string()));
        assert!(org.poc_handles.contains(&"ABUSE-GOGL".to_string()));
    }

    #[test]
    fn test_parse_pocs_xml() {
        let dir = tempdir().unwrap();
        let pocs_path = dir.path().join("pocs.xml");

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<pocs>
  <poc>
    <handle>ABUSE-GOGL</handle>
    <contactType>AB</contactType>
    <email>network-abuse@google.com</email>
  </poc>
  <poc>
    <handle>TECH-GOGL</handle>
    <contactType>TE</contactType>
    <email>noc@google.com</email>
  </poc>
</pocs>"#;

        std::fs::write(&pocs_path, xml).unwrap();
        let pocs = parse_pocs_xml(pocs_path.to_str().unwrap()).unwrap();

        // Only abuse contacts (AB type) should be included
        assert_eq!(pocs.len(), 1);
        let poc = pocs.get("ABUSE-GOGL").unwrap();
        assert_eq!(poc.email, Some("network-abuse@google.com".to_string()));
    }

    #[test]
    fn test_escape_csv() {
        assert_eq!(escape_csv("simple"), "simple");
        assert_eq!(escape_csv("with,comma"), "\"with,comma\"");
        assert_eq!(escape_csv("Google LLC"), "Google LLC");
    }

    #[test]
    fn test_full_arin_pipeline() {
        let dir = tempdir().unwrap();

        let asns_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<asns>
  <asn>
    <startAsNumber>15169</startAsNumber>
    <endAsNumber>15169</endAsNumber>
    <orgHandle>GOGL</orgHandle>
    <updateDate>2024-01-15</updateDate>
  </asn>
</asns>"#;

        let orgs_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<orgs>
  <org>
    <handle>GOGL</handle>
    <name>Google LLC</name>
    <iso3166-1>
      <code2>US</code2>
    </iso3166-1>
    <orgTypeId>HOSTING</orgTypeId>
    <pocHandle>ABUSE-GOGL</pocHandle>
  </org>
</orgs>"#;

        let pocs_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<pocs>
  <poc>
    <handle>ABUSE-GOGL</handle>
    <contactType>AB</contactType>
    <email>abuse@google.com</email>
  </poc>
</pocs>"#;

        let asns_path = dir.path().join("asns.xml");
        let orgs_path = dir.path().join("orgs.xml");
        let pocs_path = dir.path().join("pocs.xml");

        std::fs::write(&asns_path, asns_xml).unwrap();
        std::fs::write(&orgs_path, orgs_xml).unwrap();
        std::fs::write(&pocs_path, pocs_xml).unwrap();

        // Parse all files
        let asn_entries = parse_asns_xml(asns_path.to_str().unwrap()).unwrap();
        let org_map = parse_orgs_xml(orgs_path.to_str().unwrap()).unwrap();
        let poc_map = parse_pocs_xml(pocs_path.to_str().unwrap()).unwrap();

        assert_eq!(asn_entries.len(), 1);
        assert_eq!(org_map.len(), 1);
        assert_eq!(poc_map.len(), 1);

        // Verify data linkage
        let entry = &asn_entries[0];
        let org = org_map.get(entry.org_handle.as_ref().unwrap()).unwrap();
        let poc = poc_map.get(&org.poc_handles[0]).unwrap();

        assert_eq!(entry.start_asn, 15169);
        assert_eq!(org.name, Some("Google LLC".to_string()));
        assert_eq!(poc.email, Some("abuse@google.com".to_string()));
    }
}
