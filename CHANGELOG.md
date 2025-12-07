# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Favicon with spy figure and magnifying glass logo (SVG, inline data URI)
- DNT (Do Not Track) header display in Client Information (HTML, JSON, plain text)
- Comprehensive privacy/security headers support:
  - Privacy: Sec-GPC (Global Privacy Control), Save-Data, Upgrade-Insecure-Requests
  - Request context: Referer, Origin
  - Sec-Fetch headers: Site, Mode, Dest, User
  - Extended Client Hints: Sec-CH-UA-Mobile, Sec-CH-UA-Full-Version-List, Device-Memory, Viewport-Width, Downlink, RTT, ECT
- Client Information card now organized into subsections: Privacy, Client Hints, Sec-Fetch

### Changed
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

[Unreleased]: https://github.com/drmckay/cloakprobe/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/drmckay/cloakprobe/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/drmckay/cloakprobe/releases/tag/v0.1.0

