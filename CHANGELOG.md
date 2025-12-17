# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- AS name (`as-name`) field extracted from RIR data for more accurate AS naming
  - RPSL parser now extracts `as-name` field from aut-num objects
  - Org DB v2 format stores `as_name` per organization record
  - AS name from RIR data takes precedence over ip2asn (fixes truncated names like `ASN-VODAFONE-` → `ASN-VODAFONE-HU`)

### Changed
- Comprehensive handler tests for all endpoint handlers
  - Health handler tests (1 test)
  - Info handler tests (4 tests: basic, ASN data, nginx mode, invalid IP)
  - Plain handler tests (5 tests: basic, ASN data, nginx mode, invalid IP, client hints)
  - HTML handler tests (4 tests: basic, ASN data, nginx mode, missing IP)
  - Privacy handler tests (1 test)
  - Total: 15 new handler tests, bringing total test count to 70

### Changed
- Org DB format upgraded to v2 (adds `as_name` field, backward compatible reader for v1)
- CSV format for org builders now includes 9 fields: `asn,as_name,org_id,org_name,country,rir,org_type,abuse_contact,last_updated`

### Fixed
- Fixed quick-xml 0.38 API compatibility (GeneralRef events for XML entity handling)
- Fixed truncated AS names from iptoasn.com (e.g., AS21334 now shows `ASN-VODAFONE-HU` instead of `ASN-VODAFONE-`)

### Previously Added
- IP Address Details card UI improvements
  - IPv4 hexadecimal format changed from dotted notation (`C0.A8.01.01`) to 0x prefix format (`0xC0A80101`) without dots
  - Removed redundant `/24 Subnet` and `Subnet Size` rows from IPv4 details
  - Removed redundant `/64 Network` and `Network Size` rows from IPv6 details
- Codebase refactoring for improved maintainability and performance
  - **Modular handler structure**: Split `handlers/mod.rs` into separate handler modules
    - `handlers/info.rs` - JSON API handler
    - `handlers/html.rs` - HTML UI handler
    - `handlers/plain.rs` - Plain text handler
    - `handlers/privacy.rs` - Privacy policy handler
    - `handlers/health.rs` - Health check handler
    - `handlers/mod.rs` - Module exports and `AppState` definition
  - Extracted Cloudflare header processing to dedicated `headers/cloudflare.rs` module
  - Moved utility functions to focused modules (`utils/sanitize.rs`, `utils/dnt.rs`, `utils/ip.rs`)
  - Cached Tera template engine in `AppState` to avoid re-initialization on each request
  - Optimized sanitization functions to accept `Option<&str>` and reduce string cloning
  - Improved code organization: connection, nginx, client, and cloudflare header extraction now in separate modules
  - **Formatter helpers now actively used**: HTML, JSON, and plain text handlers now use formatter helper functions
    - Reduced code duplication: ~400 lines of repetitive context building code replaced with reusable helpers
    - Header item building logic extracted to `formatters/html.rs` (geo location, network, connection, security, proxy items)
    - Plain text output now uses `formatters/plain.rs` helpers for consistent formatting
  - **String cloning optimization**: Reduced unnecessary cloning by using references (`&str`) instead of owned strings
    - Cloudflare header extraction now uses references (`geo_ref`, `network_ref`, etc.) instead of cloning values
    - Reduced memory allocations and improved performance, especially for high-traffic scenarios
  - **Template context building optimization**: Pre-sized context HashMap and batch operations using formatter helpers
    - Context building now uses helper functions that batch insertions efficiently
    - Reduced HashMap reallocations during context construction

## [0.1.3] - 2025-01-10

### Added
- Server response time displayed in Server Information card
  - Shows processing time in milliseconds (e.g., `0.42 ms`)
  - Available in HTML UI, JSON API (`server.response_time_ms`), and plain text output
- HTTP cache prevention headers on all dynamic endpoints
  - `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`
  - `Pragma: no-cache` and `Expires: 0` for HTTP/1.0 compatibility
  - Applied to HTML, JSON, and plain text responses
- Client-side authoritative NS lookup for ISP hint detection
  - Queries NS records for reverse DNS zone via Cloudflare DoH
  - Extracts ISP/provider domain from nameserver hostnames (e.g., `ns1.telekom.hu` → `telekom.hu`)
  - Runs in parallel with PTR lookup for faster results
  - Displayed below reverse DNS result as "Authoritative NS (ISP Hint)"
- Multi-RIR organization database integration with Rust parsers
  - `org_builder_rpsl`: Unified RPSL parser for RIPE, APNIC, LACNIC, AFRINIC bulk data
  - `org_builder_arin`: ARIN XML parser for asns.xml, orgs.xml, pocs.xml
  - Support for gzipped input files via `flate2` crate
  - Streaming XML parsing via `quick-xml` for memory efficiency
- Normalized org schema: ASN → org_id, org_name, country, RIR, org_type, abuse_contact, last_updated
- Extended organization info in API/UI: org ID, RIR source, country, org type, abuse contact, last updated
- Updated database update scripts for all 5 RIRs
  - `scripts/download_rir_orgs.sh`: Downloads and parses all RIR bulk data
  - `scripts/update_org_db.sh`: Orchestrates full database rebuild
  - Automatic fallback to delegated stats for RIRs with unavailable bulk data
- Comprehensive integration tests for all 5 RIR parsers (`tests/rir_integration.rs`)
- ip2asn fallback for organization database coverage
  - `org_builder --fallback <ip2asn.tsv>` option adds missing ASNs from ip2asn data
  - Provides country code and AS name for ASNs without RIR organization records
  - Improves coverage from ~94% to ~99.99% of all announced ASNs
  - Fallback entries marked with `rir: "ip2asn"` and `org_type: "fallback"`
- `db_coverage` tool to analyze ASN coverage between asn_db and orgs_db
- Mode-aware connection headers for nginx deployment
  - Nginx mode uses `X-TLS-Version`, `X-TLS-Cipher`, `X-HTTP-Protocol` headers
  - Cloudflare mode uses `X-CF-TLS-Version`, `X-CF-TLS-Cipher`, `X-CF-HTTP-Protocol` headers
  - Nginx configurations in documentation updated with connection header proxy settings
- Extended nginx header support
  - `X-Request-ID`: Unique request identifier (nginx `$request_id`)
  - `X-Remote-Port`: Client source port (nginx `$remote_port`)
  - `X-Connection-ID`: Connection serial number (nginx `$connection`)
  - Displayed in Connection Details card when in nginx mode
- Optional GeoIP support for nginx mode
  - `X-GeoIP-Country`, `X-GeoIP-City`, `X-GeoIP-Region`, `X-GeoIP-Latitude/Longitude`, `X-GeoIP-Postal-Code`, `X-GeoIP-Org`
  - Requires nginx GeoIP module (`ngx_http_geoip_module` or `ngx_http_geoip2_module`)
  - Displayed in dedicated "Geo Location (GeoIP)" card when data is available
  - Documentation includes GeoIP setup guide for nginx
- JSON API includes new `nginx` object with geo and proxy headers when in nginx mode
- `ConnectionInfo` now includes `tls_cipher`, `request_id`, `remote_port`, `connection_id` fields
- Abuse contact handle resolution to email addresses
  - `org_builder_rpsl` now parses role/person objects to resolve abuse-c handles (e.g., "RFOR-RIPE") to actual email addresses
  - `--role` CLI argument accepts role/person file path for handle resolution
  - Combined database files (AFRINIC, LACNIC) automatically parse roles from the same file
  - `download_rir_orgs.sh` downloads role files for RIPE and APNIC
  - Abuse contact field now displays email addresses instead of RIR-specific handles

### Changed
- Network Information card simplified
  - RIR field now displays Org RIR value (removed duplicate "Org RIR" row)
  - Removed "Org Country" field (duplicated "Country Code")
  - Plain text output also updated to remove duplicate fields
- Cloudflare Headers card is now hidden in nginx mode (only shown when `mode = "cloudflare"`)
- Proxy Headers shown in a separate card when in nginx mode
- CF-Ray and Datacenter fields hidden in Connection Details card when not in cloudflare mode
  - IP Address Details card now shows version-appropriate information:
  - IPv4: Dotted Decimal, Hexadecimal (0x format), Binary Format, Numeric (u32), Address Type
  - IPv6: Standard Notation, Full Expanded, Binary Format, Address Type
  - IPv6: Standard Notation, Full Expanded, Binary, /64 Network, Network Size
  - Removed redundant/meaningless fields (decimal format for IPv6 was showing hex)
- Renamed `ripe_db_path` config option to `org_db_path` (backward compatible via alias)
- Environment variable `CLOAKPROBE_RIPE_DB_PATH` renamed to `CLOAKPROBE_ORG_DB_PATH` (legacy supported)

### Fixed
- CSV parser now properly handles RFC 4180 quoted fields (org names with commas like `"Company, Inc."`)
- RPSL parser handles Latin-1 encoded characters in RIR data via lossy UTF-8 conversion

### Removed
- `org_builder_ripe.rs` (replaced by unified `org_builder_rpsl.rs`)
- `scripts/build-release.sh` (releases now handled by GitHub Actions)
- `scripts/update_ripe_db.sh` (replaced by multi-RIR `update_org_db.sh`)

## [0.1.2] - 2025-12-09

### Added
- TOML configuration file support (`cloakprobe.toml`)
  - Structured configuration with `[server]`, `[privacy]`, and `[database]` sections
  - Config file search order: CLI arg > `./cloakprobe.toml` > `/etc/cloakprobe/cloakprobe.toml`
  - Environment variables can override config file values
- Proxy mode configuration: `cloudflare` (CF-Connecting-IP) or `nginx` (X-Real-IP, X-Forwarded-For)
- Command line options: `-c/--config`, `-h/--help`, `-v/--version`
- Example configuration file (`cloakprobe.example.toml`) with full documentation
- Configurable bind address and port via config file
- Comprehensive nginx deployment documentation (`docs/nginx-deployment.md`)
  - Cloudflare-proxied setup with IP restrictions
  - Direct nginx setup (no Cloudflare)
  - IPv6-only instance for dual-stack network detection
  - Security hardening (header spoofing prevention)
  - Cloudflare IP auto-update script
  - Systemd multi-instance service template
- Favicon with spy figure and magnifying glass logo (SVG, inline data URI)
- DNT (Do Not Track) header display in Client Information (HTML, JSON, plain text)
- Comprehensive privacy/security headers support:
  - Privacy: Sec-GPC (Global Privacy Control), Save-Data, Upgrade-Insecure-Requests
  - Request context: Referer, Origin
  - Sec-Fetch headers: Site, Mode, Dest, User
  - Extended Client Hints: Sec-CH-UA-Mobile, Sec-CH-UA-Full-Version-List, Device-Memory, Viewport-Width, Downlink, RTT, ECT
- Client Information card now organized into subsections: Privacy, Client Hints, Sec-Fetch

### Changed
- Configuration now uses TOML file instead of scattered environment variables
- Renamed JSON API endpoint from `/api/v1/info` to `/api/v1/json`
- Renamed CF-IPCountry to Country in Cloudflare Geo Location card for cleaner UI
- Removed duplicate Country field (from X-CF-Country header) - now only CF-IPCountry value is shown as "Country"
- Simplified CloudflareGeoHeaders JSON structure (removed cf_ipcountry field, kept only country)

### Fixed
- Mobile responsive: Long IPv6 addresses and hostnames no longer overflow the container

## [0.1.1] - 2025-12-05

### Added
- Client-side reverse DNS lookup using Cloudflare DNS over HTTPS (DoH)
- Content Security Policy updated to allow Cloudflare DoH API connections
- Tera template engine integration for cleaner HTML generation
- Cloudflare Worker headers support (X-CF-Country, X-CF-City, X-CF-Region, X-CF-ASN, X-CF-Trust-Score, etc.)
- TLS Cipher display in Connection Details card
- HTML sanitization for all Cloudflare header values to prevent XSS attacks
- Cloudflare Headers card with organized sections (Geo Location, Network, Connection, Security, Proxy Headers)
- Privacy Policy page (`/privacy`) - GDPR and CCPA compliant
- Automatic database path detection - searches `data/` directory if environment variables are not set
- All header values now consistently use `<code>` tags for better readability

### Changed
- Connection Details card now prioritizes CF worker header values (X-CF-HTTP-Protocol, X-CF-TLS-Version) when available
- HTML generation moved from inline format! macro to separate template files for better maintainability
- All Cloudflare header values are sanitized before HTML rendering
- Database paths are now automatically detected if not specified via environment variables
- All header values consistently displayed with `<code>` tags for uniform styling

### Removed
- CF-IPCity and City display from HTML UI
- Removed ripe_ip_builder (unused)

## [0.1.0] - 2025-12-03

### Added
- Initial release
- HTML UI with detailed IP information
- JSON and plain text API endpoints
- IPv4 and IPv6 support
- ASN database lookup using ip2asn data
- Cloudflare header parsing (CF-Connecting-IP, CF-Visitor, CF-Ray, etc.)
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Country code display
- Network information display (ASN, AS name, prefix, RIR)
- IP address details (decimal, hex, binary formats)
- Connection details (TLS version, HTTP protocol)
- Client information (User-Agent, Accept headers)
- Graceful shutdown support
- Configurable port via environment variable
- Privacy modes (strict, balanced)

[Unreleased]: https://github.com/drmckay/cloakprobe/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/drmckay/cloakprobe/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/drmckay/cloakprobe/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/drmckay/cloakprobe/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/drmckay/cloakprobe/releases/tag/v0.1.0

