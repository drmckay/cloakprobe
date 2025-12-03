# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible
for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < Latest | :x:                |

## Reporting a Vulnerability

Please report security vulnerabilities privately. **Do not file a public issue.**

### How to Report

Report security vulnerabilities using [GitHub Security Advisories](https://github.com/drmckay/cloakprobe/security/advisories/new)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- We will acknowledge receipt within 48 hours
- We will provide a detailed response within 7 days
- We will keep you informed of the progress

### Disclosure Policy

- We will coordinate disclosure with you
- We will credit you for the discovery (if desired)
- We will publish a security advisory after the fix is released

## Security Best Practices

When using CloakProbe:

- Always run behind a reverse proxy (nginx/Apache)
- Use HTTPS/TLS encryption
- Keep the ASN database updated
- Monitor logs for suspicious activity
- Run with minimal required permissions
- Keep dependencies up to date (`cargo audit`)

## Known Security Considerations

- CloakProbe relies on Cloudflare headers for IP detection
- Ensure Cloudflare is properly configured
- The ASN database is read-only and safe
- No user input is processed without validation

