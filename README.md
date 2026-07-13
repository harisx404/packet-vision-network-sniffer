<h1 align="center">Network Packet Sniffer</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB.svg?style=flat&logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/License-MIT-22c55e.svg?style=flat" alt="License MIT">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-6366f1.svg?style=flat" alt="Platform">
  <img src="https://img.shields.io/badge/Internship-CodeAlpha-8b5cf6.svg?style=flat" alt="CodeAlpha">
</p>

<p align="center">
  A command-line network packet sniffer engineered with a Producer-Consumer threading architecture,<br>
  deep protocol dissection, memory safety controls, and a rich terminal interface.
</p>

---

## Overview

This tool captures and analyzes live network traffic directly from raw sockets. It is designed to give users granular, real-time visibility into what is traveling across their network interface — from DNS resolution queries to raw TCP payload bytes — all from a clean, color-coded terminal display.

The architecture deliberately separates the capture pipeline from the presentation layer, which means the UI can never block the sniffer from capturing packets, even under heavy load.

## Features

| Feature | Description |
|---|---|
| **Multithreaded Capture** | Producer thread captures packets; Consumer thread analyzes and renders them independently |
| **Deep Protocol Dissection** | Parses TCP flags, UDP ports, ICMP types, ARP operations, and DNS queries |
| **RAM Protection** | Sliding-window FIFO buffer caps memory usage; `store=False` prevents Scapy heap exhaustion |
| **Terminal Security** | All payload bytes are sanitized to prevent ANSI escape code terminal injection |
| **Flexible Filtering** | BPF expressions, protocol types, CIDR block IP matching, and port filtering |
| **Data Export** | Capture to JSON, CSV, or Wireshark-compatible PCAP |
| **Rich Terminal UI** | Color-coded protocol output, hex/ASCII payload viewer, and session statistics |

## Requirements

- Python 3.9 or higher
- **Administrator or root privileges** (raw socket access)
- **Windows only**: [Npcap](https://npcap.com/) must be installed

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/harisx404/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer

# 2. Install dependencies
pip install -r requirements.txt

# 3. Verify the installation with the demo script
sudo python run_demo.py
```

## Usage

All capture commands require elevated privileges. Use `sudo` on Linux/macOS or run from an **Administrator** terminal on Windows.

### Basic Capture

```bash
# Capture all traffic on the default interface
sudo python main.py

# List all available network interfaces
sudo python main.py --list-interfaces

# Capture exactly 100 packets on a specific interface
sudo python main.py -i eth0 -c 100
```

### Filtering

```bash
# Capture only TCP traffic with verbose flag/sequence details
sudo python main.py -p tcp -v

# Filter by source IP using CIDR notation
sudo python main.py --src-ip 192.168.1.0/24

# Use a raw BPF expression for maximum control
sudo python main.py -f "udp and port 53"
```

### Payload Inspection

```bash
# Display hex/ASCII payload alongside each TCP packet
sudo python main.py -p tcp --payload

# Capture HTTPS traffic and inspect payloads (TLS handshake bytes)
sudo python main.py -p tcp --port 443 --payload
```

### Exporting Data

```bash
# Auto-generate a timestamped JSON export
sudo python main.py -c 50 -o capture.json

# Export to CSV for spreadsheet analysis
sudo python main.py -c 50 -o capture.csv --format csv

# Save a Wireshark-compatible PCAP file
sudo python main.py --save-pcap traffic.pcap
```

## 📸 Screenshots

### Live Packet Inspection & Payload Analysis
*Monitoring TCP traffic with real-time ANSI-sanitized payload extraction.*

![Live Capture 1](docs/screenshots/SS1.png)

![Live Capture 2](docs/screenshots/SS2.png)

![Live Capture 3](docs/screenshots/SS3.png)

![Live Capture 4](docs/screenshots/SS4.png)

### Automated Demo Script
*Programmatic execution showing graceful thread handling and JSON export.*

![Demo Script 1](docs/screenshots/demo_script-1.png)

![Demo Script 2](docs/screenshots/demo_script-2.png)

## Project Structure

```
CodeAlpha_NetworkSniffer/
├── main.py                  # CLI entry point and argument parser
├── run_demo.py              # Standalone demo and smoke-test script
├── requirements.txt         # Python dependencies
├── setup.py                 # Package configuration
├── src/
│   ├── sniffer.py           # Core engine: thread management and lifecycle
│   ├── analyzer.py          # L3/L4 packet dissection logic
│   ├── filters.py           # BPF generation and Python-level filtering
│   ├── display.py           # Rich-powered terminal UI
│   ├── logger.py            # JSON, CSV, PCAP export with memory capping
│   ├── config.py            # Dataclass config, constants, and color maps
│   └── utils.py             # Shared helpers: formatting, validation, sanitization
├── docs/
│   └── architecture.md      # Deep-dive engineering and security documentation
└── tests/
    ├── conftest.py           # Shared pytest fixtures (mock packets)
    ├── test_analyzer.py      # Protocol dissection unit tests
    ├── test_filters.py       # BPF and CIDR filtering unit tests
    └── test_utils.py         # Utility function unit tests
```

## Running Tests

The test suite uses `pytest` with mock Scapy packets — no live network interface is needed.

```bash
python -m pytest tests/ -v
```

## Architecture

For a detailed breakdown of the threading model, memory safety design, security controls, and performance considerations, see the [Architecture Guide](docs/architecture.md).

## Contributing

Contributions and issue reports are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

*Developed for the CodeAlpha Cybersecurity Internship — focused on performance, memory safety, and terminal security.*
