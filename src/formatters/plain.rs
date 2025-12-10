use std::fmt::Write;

/// Helper functions for building plain text responses.
/// These can be used by handlers to format plain text output more easily.
pub mod text_builder {
    use super::*;

    /// Writes IP information to the output buffer.
    pub fn write_ip_info(out: &mut String, ip: &str, ip_version: u8) {
        writeln!(out, "IP: {} (IPv{})", ip, ip_version).ok();
    }

    /// Writes ASN information to the output buffer.
    pub fn write_asn_info(
        out: &mut String,
        asn: u32,
        as_name: &str,
        prefix: &str,
        rir: &str,
        country: Option<&str>,
    ) {
        let country_str = country.unwrap_or("-");
        writeln!(
            out,
            "ASN: AS{} {} ({}, {}, {})",
            asn, as_name, prefix, rir, country_str
        )
        .ok();
    }

    /// Writes organization information to the output buffer.
    pub fn write_org_info(
        out: &mut String,
        org_name: Option<&str>,
        org_id: Option<&str>,
        org_type: Option<&str>,
        abuse_contact: Option<&str>,
        last_updated: Option<&str>,
    ) {
        if let Some(name) = org_name {
            writeln!(out, "Org: {}", name).ok();
        }
        if let Some(id) = org_id {
            writeln!(out, "Org-ID: {}", id).ok();
        }
        if let Some(org_type) = org_type {
            writeln!(out, "Org-Type: {}", org_type).ok();
        }
        if let Some(abuse) = abuse_contact {
            writeln!(out, "Abuse: {}", abuse).ok();
        }
        if let Some(updated) = last_updated {
            writeln!(out, "Org-Updated: {}", updated).ok();
        }
    }

    /// Writes TLS connection information to the output buffer.
    pub fn write_tls_info(
        out: &mut String,
        tls_version: Option<&str>,
        http_protocol: Option<&str>,
    ) {
        if let Some(tls) = tls_version {
            let proto = http_protocol.unwrap_or("-");
            writeln!(out, "TLS: {} over {}", tls, proto).ok();
        }
    }

    /// Writes server response time to the output buffer.
    pub fn write_response_time(out: &mut String, response_time_ms: f64) {
        writeln!(out, "\nResponse-Time: {:.2} ms", response_time_ms).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_ip_info() {
        let mut out = String::new();
        text_builder::write_ip_info(&mut out, "8.8.8.8", 4);
        assert!(out.contains("IP: 8.8.8.8 (IPv4)"));
    }

    #[test]
    fn test_write_asn_info() {
        let mut out = String::new();
        text_builder::write_asn_info(
            &mut out,
            15169,
            "Google LLC",
            "8.8.8.0/24",
            "ARIN",
            Some("US"),
        );
        assert!(out.contains("ASN: AS15169"));
        assert!(out.contains("Google LLC"));
    }

    #[test]
    fn test_write_org_info() {
        let mut out = String::new();
        text_builder::write_org_info(
            &mut out,
            Some("Google LLC"),
            Some("GOGL"),
            Some("Content"),
            Some("abuse@google.com"),
            None,
        );
        assert!(out.contains("Org: Google LLC"));
        assert!(out.contains("Org-ID: GOGL"));
        assert!(out.contains("Abuse: abuse@google.com"));
    }

    #[test]
    fn test_write_tls_info() {
        let mut out = String::new();
        text_builder::write_tls_info(&mut out, Some("TLSv1.3"), Some("HTTP/2"));
        assert!(out.contains("TLS: TLSv1.3 over HTTP/2"));
    }

    #[test]
    fn test_write_response_time() {
        let mut out = String::new();
        text_builder::write_response_time(&mut out, 0.42);
        assert!(out.contains("Response-Time: 0.42 ms"));
    }
}
