use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
};

fn ipv4_to_u32(ip: std::net::Ipv4Addr) -> u32 {
    let o = ip.octets();
    ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
}

fn ipv6_to_u128(ip: std::net::Ipv6Addr) -> u128 {
    let o = ip.octets();
    u128::from_be_bytes(o)
}

#[derive(Debug)]
struct V4Entry {
    start: u32,
    end: u32,
    asn: u32,
    country: [u8; 2],
    as_name: String,
}

#[derive(Debug)]
struct V6Entry {
    start: u128,
    end: u128,
    asn: u32,
    country: [u8; 2],
    as_name: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "Usage: {} <ip2asn-combined.tsv> <output-asn_db.bin>",
            args[0]
        );
        std::process::exit(1);
    }

    let input = &args[1];
    let output = &args[2];

    let f = File::open(input)?;
    let reader = BufReader::new(f);

    let mut v4 = Vec::<V4Entry>::new();
    let mut v6 = Vec::<V6Entry>::new();

    for line_res in reader.lines() {
        let line = line_res?;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        // Format: range_start range_end AS_number country_code AS_description
        let mut parts = line.splitn(5, char::is_whitespace);
        let start_str = match parts.next() {
            Some(s) => s.trim(),
            None => continue,
        };
        let end_str = match parts.next() {
            Some(s) => s.trim(),
            None => continue,
        };
        let asn_str = match parts.next() {
            Some(s) => s.trim(),
            None => continue,
        };
        let country_str = match parts.next() {
            Some(s) => s.trim(),
            None => "",
        };
        let as_description = match parts.next() {
            Some(s) => s.trim(),
            None => "",
        };

        let asn: u32 = asn_str.parse().unwrap_or(0);
        let mut country = [0u8; 2];
        let cs = country_str.as_bytes();
        if cs.len() >= 2 {
            country[0] = cs[0].to_ascii_uppercase();
            country[1] = cs[1].to_ascii_uppercase();
        }

        let as_name = if as_description.is_empty() {
            format!("AS{}", asn)
        } else {
            as_description.to_string()
        };

        let start_ip: IpAddr = match start_str.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let end_ip: IpAddr = match end_str.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        match (start_ip, end_ip) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                v4.push(V4Entry {
                    start: ipv4_to_u32(s),
                    end: ipv4_to_u32(e),
                    asn,
                    country,
                    as_name: as_name.clone(),
                });
            }
            (IpAddr::V6(s), IpAddr::V6(e)) => {
                v6.push(V6Entry {
                    start: ipv6_to_u128(s),
                    end: ipv6_to_u128(e),
                    asn,
                    country,
                    as_name: as_name.clone(),
                });
            }
            _ => {
                continue;
            }
        }
    }

    // sort both lists by start
    v4.sort_by_key(|e| e.start);
    v6.sort_by_key(|e| e.start);

    let v4_count = v4.len() as u32;
    let v6_count = v6.len() as u32;

    let mut out = Vec::<u8>::new();

    // Header - version 2 format (with AS names, no RIPE data)
    out.extend_from_slice(b"ASND");
    out.extend_from_slice(&2u32.to_le_bytes()); // version
    out.extend_from_slice(&v4_count.to_le_bytes());
    out.extend_from_slice(&v6_count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved

    // v4 entries
    for e in &v4 {
        out.extend_from_slice(&e.start.to_le_bytes());
        out.extend_from_slice(&e.end.to_le_bytes());
        out.extend_from_slice(&e.asn.to_le_bytes());
        out.extend_from_slice(&e.country);
        let name_bytes = e.as_name.as_bytes();
        let len = name_bytes.len().min(255);
        if name_bytes.len() > 255 {
            eprintln!(
                "Warning: AS name too long for AS{}: {}...",
                e.asn,
                &e.as_name[..50]
            );
        }
        out.push(len as u8);
        out.extend_from_slice(&name_bytes[..len]);
    }

    // v6 entries
    for e in &v6 {
        let sh = (e.start >> 64) as u64;
        let sl = e.start as u64;
        let eh = (e.end >> 64) as u64;
        let el = e.end as u64;

        out.extend_from_slice(&sh.to_le_bytes());
        out.extend_from_slice(&sl.to_le_bytes());
        out.extend_from_slice(&eh.to_le_bytes());
        out.extend_from_slice(&el.to_le_bytes());
        out.extend_from_slice(&e.asn.to_le_bytes());
        out.extend_from_slice(&e.country);
        let name_bytes = e.as_name.as_bytes();
        let len = name_bytes.len().min(255);
        if name_bytes.len() > 255 {
            eprintln!(
                "Warning: AS name too long for AS{}: {}...",
                e.asn,
                &e.as_name[..50]
            );
        }
        out.push(len as u8);
        out.extend_from_slice(&name_bytes[..len]);
    }

    std::fs::write(output, &out)?;

    eprintln!(
        "Written ASN DB v2: {} ({} bytes, v4: {}, v6: {})",
        output,
        out.len(),
        v4_count,
        v6_count
    );

    Ok(())
}
