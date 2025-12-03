# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Copy-to-clipboard button for IP address in HTML UI

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

[Unreleased]: https://github.com/drmckay/cloakprobe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/drmckay/cloakprobe/releases/tag/v0.1.0

