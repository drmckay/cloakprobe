use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone)]
pub struct IpDetails {
    pub primary: String,
    pub hex: String,
    pub expanded: String,
    pub binary: String,
    pub numeric: String,
    pub ip_type: String,
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
        || (octets[0] == 192 && octets[1] == 168)
}

fn is_link_local_v4(ip: &Ipv4Addr) -> bool {
    ip.octets()[0] == 169 && ip.octets()[1] == 254
}

fn is_multicast_v4(ip: &Ipv4Addr) -> bool {
    (224..=239).contains(&ip.octets()[0])
}

fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

fn is_multicast_v6(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xff00 == 0xff00
}

/// Compute IP details (representation, type)
pub fn get_ip_details(ip: &IpAddr) -> IpDetails {
    match ip {
        IpAddr::V4(ipv4) => {
            let ip_type = if ipv4.is_loopback() {
                "Loopback"
            } else if is_private_v4(ipv4) {
                "Private"
            } else if is_link_local_v4(ipv4) {
                "Link-local"
            } else if is_multicast_v4(ipv4) {
                "Multicast"
            } else {
                "Public"
            };

            let octets = ipv4.octets();
            let hex = format!(
                "0x{:02X}{:02X}{:02X}{:02X}",
                octets[0], octets[1], octets[2], octets[3]
            );
            let binary = format!(
                "{:08b}.{:08b}.{:08b}.{:08b}",
                octets[0], octets[1], octets[2], octets[3]
            );
            let numeric = u32::from_be_bytes(octets).to_string();

            IpDetails {
                primary: ipv4.to_string(),
                hex,
                expanded: ipv4.to_string(),
                binary,
                numeric,
                ip_type: ip_type.to_string(),
            }
        }
        IpAddr::V6(ipv6) => {
            let ip_type = if ipv6.is_loopback() {
                "Loopback"
            } else if ipv6.is_unspecified() {
                "Unspecified"
            } else if is_link_local_v6(ipv6) {
                "Link-local"
            } else if is_multicast_v6(ipv6) {
                "Multicast"
            } else {
                "Global"
            };

            let segments = ipv6.segments();
            let expanded = format!(
                "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7]
            );
            let binary = format!(
                "{:016b}:{:016b}:{:016b}:{:016b}:{:016b}:{:016b}:{:016b}:{:016b}",
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7]
            );

            IpDetails {
                primary: ipv6.to_string(),
                hex: format!("{:032x}", u128::from_be_bytes(ipv6.octets())),
                expanded,
                binary,
                numeric: u128::from(*ipv6).to_string(),
                ip_type: ip_type.to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_get_ip_details_ipv4_public() {
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.primary, "8.8.8.8");
        assert_eq!(details.ip_type, "Public");
    }

    #[test]
    fn test_get_ip_details_ipv4_private() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.primary, "192.168.1.1");
        assert_eq!(details.ip_type, "Private");
    }

    #[test]
    fn test_get_ip_details_ipv4_loopback() {
        let ip = IpAddr::from_str("127.0.0.1").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.primary, "127.0.0.1");
        assert_eq!(details.ip_type, "Loopback");
    }

    #[test]
    fn test_get_ip_details_ipv4_link_local() {
        let ip = IpAddr::from_str("169.254.1.1").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.ip_type, "Link-local");
    }

    #[test]
    fn test_get_ip_details_ipv4_multicast() {
        let ip = IpAddr::from_str("224.0.0.1").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.ip_type, "Multicast");
    }

    #[test]
    fn test_get_ip_details_ipv6_global() {
        let ip = IpAddr::from_str("2001:4860:4860::8888").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.ip_type, "Global");
    }

    #[test]
    fn test_get_ip_details_ipv6_loopback() {
        let ip = IpAddr::from_str("::1").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.ip_type, "Loopback");
    }

    #[test]
    fn test_get_ip_details_ipv6_link_local() {
        let ip = IpAddr::from_str("fe80::1").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.ip_type, "Link-local");
    }

    #[test]
    fn test_get_ip_details_ipv6_multicast() {
        let ip = IpAddr::from_str("ff02::1").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.ip_type, "Multicast");
    }

    #[test]
    fn test_get_ip_details_ipv4_hex_format() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.hex, "0xC0A80101");
    }

    #[test]
    fn test_get_ip_details_ipv4_binary_format() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.binary, "11000000.10101000.00000001.00000001");
    }

    #[test]
    fn test_get_ip_details_ipv4_numeric() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let details = get_ip_details(&ip);
        assert_eq!(details.numeric, "3232235777");
    }
}
