# Changelog

All notable changes to **PacketVision Network Sniffer** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-07-22

### Added
- **Producer-Consumer Threading Engine:** Non-blocking multi-threaded architecture separating packet capture from dissection and rendering.
- **Deep Protocol Dissection:** Full L2-L7 protocol parser for Ethernet, IPv4, IPv6, ARP, ICMP, TCP, UDP, and DNS.
- **Terminal UI & Hex Dissection:** Rich-powered terminal display with side-by-side hex and sanitized ASCII payload viewer.
- **Filtering System:** Support for Berkeley Packet Filters (BPF), protocol filtering, CIDR block IP matching, and port filtering.
- **Data Export Engine:** Timestamped export capabilities to JSON, CSV, and Wireshark-compatible PCAP files.
- **Memory Safety & RAM Protection:** Sliding-window FIFO buffer capping memory usage; `store=False` prevents Scapy heap exhaustion.
- **Terminal Injection Protection:** Automated sanitization of raw payload bytes to prevent ANSI control sequence injection.
- **Test Suite:** Automated unit testing suite with 15 passing tests using Scapy mock packets.

---

### Author & Attribution
Developed and maintained by **Muhammad Haris ([@harisx404](https://github.com/harisx404))** — `itsharis.tech@gmail.com`.
