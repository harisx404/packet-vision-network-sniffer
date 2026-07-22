# Contributing

Thank you for your interest in contributing to **PacketVision Network Sniffer**. This document outlines the development guidelines, architectural constraints, and the pull request process.

## Getting Started

1. Fork the repository and clone it locally.
2. Ensure you are running Python 3.9 or higher.
3. Install all dependencies: `pip install -r requirements.txt`
4. Run the test suite to confirm your environment is healthy:
   ```bash
   python -m pytest tests/ -v
   ```

## Development Workflow

1. Create a dedicated branch for your work:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Make your changes and write or update tests where applicable.
3. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add IPv6 packet dissection
   fix: handle malformed ICMP checksum
   docs: update architecture guide
   refactor: simplify BPF string builder
   ```
4. Push your branch and open a Pull Request against `main`.

## Architectural Constraints

This project enforces strict rules to maintain performance and security. Pull requests that violate these will not be merged.

### Threading Rules

- **Never block the capture thread.** The `_packet_handler` Scapy callback must remain near-zero latency. No file I/O, `time.sleep()`, or heavy computation is allowed inside it.
- All analysis and display work happens exclusively in the Consumer thread (`_process_queue`).

### Memory Safety Rules

- **Do not set `store=True`** in Scapy's `sniff()` call. This causes unlimited heap growth and will crash the application.
- The `PacketLogger._raw_packets` list must remain bounded by `Config.max_memory_packets` via the FIFO pop-before-append pattern in `logger.py`.

### Security Rules

- **Do not print raw bytes to the terminal.** All payload data must pass through `utils.format_payload()`, which sanitizes ANSI escape codes, before being rendered.
- Any new display path that renders packet content must enforce the same byte-range check (`32 <= byte <= 126`).

## Code Style

- Type annotations are required on every function signature.
- Google-style docstrings are required on every public class and method.
- Lines should not exceed 100 characters.
- No inline comments that simply restate what the code already says (e.g., `# returns the value`).

## Reporting Issues

Please open a GitHub Issue and include:
- Your OS and Python version
- The exact command you ran
- The full traceback or error output
