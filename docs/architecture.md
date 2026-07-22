# Architecture & Engineering Guide

> This document is the technical reference for **PacketVision Network Sniffer**. It covers
> the concurrency model, memory safety design, security controls, and testing strategy.
> Intended for project maintainers, contributors, and technical reviewers.

---

## 1. System Architecture

The tool is built on a modular Producer-Consumer architecture that completely isolates the packet capture pipeline from UI rendering and data logging. This ensures the capture rate is never throttled by slow rendering or disk I/O.

### Data Flow

```
[ Network Interface ]
        │  (raw bytes via libpcap / Npcap)
        ▼
[ Producer Thread — Scapy sniff() ]
        │  queue.put_nowait()  →  drops silently on queue.Full
        ▼
[ queue.Queue  (maxsize=1000) ]
        │  queue.get(timeout=0.5)
        ▼
[ Consumer Thread — _process_queue() ]
        ├── PacketFilter   →  BPF + Python-level CIDR / port checks
        ├── PacketAnalyzer →  L3/L4 dissection, flag extraction, DNS parsing
        ├── DisplayManager →  Rich UI rendering (color-coded, sanitized)
        └── PacketLogger   →  Memory-capped JSON / CSV / PCAP export
```

### Thread Lifecycle

| Thread | Type | Role |
|---|---|---|
| `CaptureThread` | daemon | Runs Scapy `sniff()` indefinitely; terminates when `_stop_event` is set |
| `ProcessThread` | daemon | Drains the queue; exits when `_running` is `False` and queue is empty |
| Main thread | regular | Blocks on `time.sleep(0.1)` loop; catches `KeyboardInterrupt` and calls `stop()` |

---

## 2. Module Breakdown

### `sniffer.py` — Orchestration Engine

The central coordinator. Instantiates all sub-components and manages the two daemon threads.

Key design decisions:
- **`put_nowait()` over `put()`**: The Scapy callback must never block. If the queue is full (Consumer is lagging), the packet is silently dropped to protect the capture rate and memory.
- **`stop_filter` lambda**: Scapy's `stop_filter` parameter is polled on each captured packet. When `_stop_event` is set, Scapy's internal loop exits cleanly without requiring `os.kill()` or thread interruption.
- **`join(timeout=3)`**: Both threads are given 3 seconds to finish draining before the main thread proceeds to export and summary rendering.

### `analyzer.py` — Protocol Dissection Engine

Converts raw Scapy `Packet` objects into clean Python dictionaries.

Dissection hierarchy:
1. **Ethernet (L2)**: Extracts source and destination MAC addresses.
2. **IP / IPv6 (L3)**: Extracts source/destination IPs, TTL, and protocol number.
3. **TCP / UDP / ICMP / ARP (L4)**: Extracts ports, flags, sequence numbers, ICMP type/code, and ARP operation.
4. **Application layer**: Identifies DNS queries/responses (Port 53) and common services via `COMMON_PORTS` lookup.

Timestamp extraction reads `packet.time` (the kernel-assigned epoch timestamp from libpcap), falling back to `time.time()` if the attribute is missing.

### `filters.py` — Layered Filtering Engine

Applies two layers of filtering:

1. **BPF (kernel level)**: A BPF string is constructed from the user's protocol/IP/port flags and passed directly to Scapy. The kernel discards non-matching packets before they reach Python, significantly reducing CPU load on busy networks.
2. **Python level**: For cases BPF cannot handle (e.g., CIDR block matching, application-level protocol detection), `should_capture()` performs a secondary evaluation in the Consumer thread.

CIDR matching uses Python's `ipaddress.ip_network()` to correctly evaluate whether a packet IP falls within a given subnet (e.g., `192.168.1.0/24`).

### `display.py` — Terminal UI

Built entirely on the [Rich](https://github.com/Textualize/rich) library. Key rendering choices:

- **`Console(highlight=False)`**: Disables Rich's auto-highlighting, which prevents it from accidentally re-coloring IP addresses and other captured data in unintended ways.
- **Packet lines**: Rendered as `rich.text.Text` objects with per-segment styles rather than markup strings, avoiding markup injection from packet content.
- **Payload panel**: Wrapped in a `Panel` with a dim magenta border, clearly separating raw hex/ASCII data from the packet summary line.
- **Stats table**: Uses `box.SIMPLE` with fixed-width columns to guarantee alignment is stable regardless of terminal width.

### `logger.py` — Memory-Safe Data Export

**FIFO Memory Cap (Critical Path)**:

```python
if len(self._raw_packets) >= self.config.max_memory_packets:
    self._raw_packets.pop(0)   # evict oldest before appending new
self._raw_packets.append(raw_packet)
```

The check uses `>=` and pops *before* appending. This guarantees the list length never exceeds `max_memory_packets` at any point, even transiently. The default limit is 50,000 packets.

**JSON Serialization**: Custom `_json_serializer` handles `bytes` objects (converts to hex string) and falls back to `str()` for any unknown Scapy field types, preventing `TypeError` crashes during export.

### `utils.py` — Shared Utilities

`format_payload(payload, max_size)` is the primary security boundary for terminal output:

```python
for b in chunk:
    if 32 <= b <= 126:   # printable ASCII range only
        ascii_part += chr(b)
    else:
        ascii_part += "."
```

Any byte outside the standard printable range — including `\x1b` (ANSI escape), `\x07` (bell), and null bytes — is replaced with a neutral `.` character. This prevents a malicious host from embedding terminal control sequences inside packet payloads to manipulate the operator's screen.

---

## 3. Performance Considerations

### High-Traffic Environments

On a busy interface (e.g., a university switch span port), packet rate can exceed 10,000 pps. The queue acts as a bounded buffer absorbing burst traffic. If the Consumer thread cannot keep up, `queue.Full` is raised and caught silently in `_packet_handler`. The application remains stable at the cost of dropping excess packets.

### CPU Load

String formatting in `analyzer.py` is the primary CPU cost per packet. The analyzer returns a plain `dict`, leaving all formatting work to `display.py`. This means the `--quiet` mode (`-q`) is significantly faster, as the Consumer skips all Rich rendering and only runs the analyzer and logger.

---

## 4. Security Controls

### Privilege Check

On startup, the application checks for root/admin privileges using `ctypes.windll.shell32.IsUserAnAdmin()` (Windows) or `os.geteuid() == 0` (POSIX). A failed check triggers `sys.exit(1)` immediately, before any network socket is opened.

### Terminal Injection Prevention

**Threat**: A malicious server sends a response payload containing `\x1b[2J` (clear screen) or `\x1b[31m` (change text color). If printed directly, this can be used to hide captured output or mislead the operator.

**Mitigation**: `utils.format_payload()` enforces a strict byte allowlist, rendering the attack inert. The hex column is also safe — it outputs hex digits only (e.g., `1b`), which carry no special meaning to a terminal emulator.

---

## 5. Testing

Tests are located in `tests/` and use `pytest` with mock Scapy packet fixtures defined in `conftest.py`. No live network interface is required to run the test suite.

```bash
python -m pytest tests/ -v
```

| Test File | Coverage Area |
|---|---|
| `test_analyzer.py` | TCP/UDP/ICMP/DNS dissection correctness |
| `test_filters.py` | Protocol, IP, CIDR, and port filter logic |
| `test_utils.py` | Byte formatting, MAC formatting, IP validation |

---

## 6. Dependencies

| Library | Version | Purpose |
|---|---|---|
| `scapy` | ≥ 2.5.0 | Packet capture and protocol dissection |
| `rich` | ≥ 13.0.0 | Terminal UI rendering |
| `colorama` | ≥ 0.4.6 | Windows ANSI escape code support |
| `pytest` | ≥ 7.0.0 | Test framework |
| `pytest-mock` | ≥ 3.0.0 | Mock fixtures for unit tests |