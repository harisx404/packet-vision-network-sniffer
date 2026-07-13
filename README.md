<h1 align="center">
  🛡️ CodeAlpha Network Sniffer
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License MIT">
  <img src="https://img.shields.io/badge/Internship-CodeAlpha-blueviolet.svg" alt="CodeAlpha">
</p>

<p align="center">
  <b>A professional, multithreaded network packet sniffer built for the CodeAlpha Cybersecurity Internship.</b>
</p>

---

## 📌 Overview

This project is a high-performance, command-line network packet sniffer written entirely in Python. Unlike basic sniffers, this tool is engineered with a **Producer-Consumer threading architecture**, ensuring zero dropped packets even during high-traffic bursts. It extracts and analyzes L3/L4 protocols (TCP, UDP, ICMP, DNS) directly from raw bytes, featuring advanced security measures like **Memory Buffer Capping** and **ANSI Payload Sanitization**.

## ✨ Features

- **Multithreaded Architecture**: Uses `queue.Queue` to separate blocking packet capture (Producer) from the Rich-based UI rendering pipeline (Consumer).
- **RAM Protection**: Scapy's default in-memory storage is disabled. A custom Sliding Window FIFO queue prevents `MemoryError` and RAM exhaustion during infinite captures.
- **Terminal Security**: Network payloads are aggressively sanitized to prevent malicious ANSI escape code (`\x1b`) terminal injection attacks.
- **Deep Dissection**: Automatically parses TCP flags, UDP ports, ICMP codes, ARP operations, and DNS queries.
- **Beautiful UI**: Uses the `rich` library to render a clean, color-coded, and highly readable console interface.
- **Export Capabilities**: Export your captures to JSON, CSV, or Wireshark-compatible PCAP files.
- **Advanced Filtering**: Support for raw BPF filters, protocol types, CIDR block IP matching, and port filtering.

---

## 🚀 Installation

This tool utilizes raw network sockets. **Administrative/Root privileges are required.**

```bash
# 1. Clone the repository
git clone https://github.com/harisx404/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer

# 2. Install dependencies
pip install -r requirements.txt

# 3. Test the setup using the demo script
sudo python run_demo.py
```

## 💻 Usage

Start the sniffer by running `main.py` with `sudo` (Linux/macOS) or from an Administrator Command Prompt (Windows).

### Basic Commands
```bash
# Capture unlimited traffic on the default interface
sudo python main.py

# List all available network interfaces
sudo python main.py --list-interfaces

# Capture exactly 100 packets on eth0
sudo python main.py -i eth0 -c 100
```

### Advanced Filtering
```bash
# Capture only HTTP traffic (port 80) and show verbose details
sudo python main.py -p tcp --port 80 -v

# Show side-by-side Hex and ASCII payloads
sudo python main.py --payload

# Use a raw BPF filter
sudo python main.py -f "udp and port 53"
```

### Exporting Data
```bash
# Save to a JSON file
sudo python main.py -c 50 -o capture.json

# Export to a Wireshark PCAP file
sudo python main.py --save-pcap traffic.pcap
```

---

## 📸 Screenshots

*(To be added: Run the tool, take screenshots of the beautiful terminal UI and payload inspection, place them in `docs/screenshots/`, and link them here.)*

---

## 📂 Architecture

- **`sniffer.py`**: The orchestration engine managing the Producer and Consumer daemon threads.
- **`logger.py`**: Handles strict memory-capped FIFO buffering and serialization to JSON/CSV/PCAP.
- **`filters.py`**: Combines native Scapy BPF generation with custom Python-level CIDR evaluations.
- **`analyzer.py`**: Deep-packet inspection logic and protocol categorization.
- **`display.py`**: ANSI-sanitized, rich-powered UI rendering.

## 🤝 Contributing

Contributions are welcome! Please read the [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
*Engineered for the CodeAlpha Internship Program. Developed with a focus on performance, memory safety, and terminal security.*
