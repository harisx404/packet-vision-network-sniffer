# Security Policy

## Supported Versions

We actively maintain and provide security updates for the following versions of **PacketVision Network Sniffer**:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability within **PacketVision Network Sniffer**, please send an email directly to **Muhammad Haris** at `itsharis.tech@gmail.com`. All security advisories will be triaged and addressed promptly.

**Do not open a public GitHub issue for security vulnerabilities.**

### Resolution Process
1. Acknowledge receipt of the vulnerability report within 48 hours.
2. Provide an estimated timeline for investigation and resolution.
3. Issue a patch release and publish a security advisory.

---

### Terminal Security Notice
PacketVision Network Sniffer includes built-in payload sanitization to strip ANSI escape sequences and non-printable control bytes (`0x00-0x1F`, `0x7F-0x9F`) from intercepted network traffic, protecting user terminals from arbitrary terminal control code injection attacks.
