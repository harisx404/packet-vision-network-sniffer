# Architectural Documentation & Engineering Guide
**Network Packet Sniffer**

This document serves as the technical wiki for understanding the underlying mechanics of the Network Packet Sniffer. It is intended for project maintainers, recruiters reviewing technical depth, and open-source contributors.

---

## 1. High-Level System Architecture

The tool is built on a highly modular architecture that completely isolates packet capture from presentation and logging.

### Data Flow Diagram
```text
[Network Interface] 
       ↓ (Raw Bytes)
[Scapy Sniff Loop (Producer Thread)] 
       ↓ (Thread-Safe put_nowait)
[queue.Queue Buffer]
       ↓ (Blocking get)
[Processing Loop (Consumer Thread - _process_queue)]
       ├→ [PacketFilter] (BPF & CIDR IP Matching)
       ├→ [PacketAnalyzer] (Layer Dissection & Flag Extraction)
       ├→ [DisplayManager] (ANSI-Sanitized Rich UI Rendering)
       └→ [PacketLogger] (Memory Capped JSON/PCAP Export)
```

## 2. Core Module Details

### A. Packet Capture Layer (`sniffer.py`)
- **Concurrency Model**: Uses a dedicated daemon thread for Scapy's blocking `sniff()` call (Producer), and a separate processing thread (Consumer).
- **Decoupling**: Strictly separates capture from processing using `queue.Queue(maxsize=1000)` to prevent the UI rendering pipeline from slowing down the capture rate. If the queue is full due to UI lag, packets are dropped immediately to protect memory.
- **Memory Safety (Logger)**: The `PacketLogger` implements a FIFO "Sliding Window" for raw packet storage. When the internal `_raw_packets` list exceeds `max_memory_packets` (default 50,000), older packets are popped to prevent `MemoryError` during infinite captures.

### B. Filtering Engine (`filters.py`)
- **Layered Filtering**: Supports filtering at the `IP`, `TCP`, `UDP`, and `ICMP` levels.
- **BPF Compliance**: Fully integrates Berkeley Packet Filter (BPF) syntax for high-performance packet selection.
- **CIDR Validation**: Uses Python's `ipaddress` module to safely validate and match IP addresses against CIDR ranges.

### C. Analysis Engine (`analyzer.py`)
- **L3/L4 Dissection**: Automatically handles the hierarchical structure of Scapy packets (IP -> TCP/UDP).
- **Transport Protocol Detection**:
    - Extracts TCP Flags (SYN, ACK, FIN, RST, PSH, URG).
    - Detects UDP fragmented packets.
    - Identifies DNS queries/responses (Port 53).
    - Extracts HTTP/S headers.
- **Payload Sanitization (Critical)**:
    - The `format_payload` function strips all ANSI escape codes (`\x1b`, `\033`) from raw packet data.
    - **Reason**: Prevents malicious payloads from executing escape sequences in the terminal (e.g., clearing the screen or changing text colors to hide data).

### D. Display Engine (`display.py`)
- **UI Framework**: Built entirely on `rich` for modern terminal UI features.
- **Live Dashboard**: A "Producer/Consumer" UI loop that updates the dashboard only when new data is available in the queue, preventing CPU spinlock.
- **Data Tables**: Uses `rich.table` for displaying packet lists, with syntax highlighting based on protocol type.
- **Progress Indicators**: Real-time spinners and progress bars for capture duration and data transfer.

## 3. Performance & Scalability Considerations

### A. Handling High Traffic Environments
- **Scenario**: A busy university network or ISP connection.
- **Mitigation**:
    1.  **Queue Overflow**: The `put_nowait()` method will raise a `queue.Full` exception if the buffer is full. The `_packet_handler` thread catches this and silently drops the packet, prioritizing system stability over completeness.
    2.  **CPU Load**: Heavy string formatting in `analyzer.py` can be costly.
    3.  **Solution**: The `PacketAnalyzer` returns a structured dictionary. The `DisplayManager` is optimized to only update specific cells in the `Table` widget rather than redrawing the entire screen.

### B. Memory Management
- **Stateless Capture**: The `sniff()` function is configured with `store=False` to prevent Scapy from building a linked list of all packets in RAM.
- **Buffer Control**: The consumer loop strictly enforces buffer limits, ensuring the application can run indefinitely on a standard laptop without memory leaks.

## 4. Security Architecture

### A. Privilege Escalation Prevention
- **Root Detection**: The application uses `os.geteuid()` (Linux/macOS) and `ctypes` (Windows) to detect root/admin privileges. It crashes immediately with a clean exit if not root, preventing the application from entering a "failed" state where it might display partial data.

### B. Terminal Injection Prevention
- **The Threat**: A malicious actor could send a packet containing `\x1b[2J\x1b[3J` (Clear Screen) or `\x1b[31m` (Red Text).
- **The Fix**: The `PacketAnalyzer.format_payload` method explicitly replaces all non-printable ASCII characters (including `\x1b` and `\033` sequences) with a neutral `.` character.

## 5. Testing Strategy

### A. Unit Testing (pytest)
- **Isolate Layer Behavior**: Tests for `PacketAnalyzer` verify that TCP flags are correctly extracted from mock packet objects without needing a live network interface.
- **Filter Validation**: Uses `ipaddress` logic to verify CIDR masking.

### B. Integration Testing
- **File I/O**: Ensures JSON and CSV exports do not corrupt data and can serialize complex network objects.

## 6. Environment & Dependencies

### A. OS Compatibility
- **Linux/macOS**: Full support via Scapy's raw sockets.
- **Windows**: Requires Npcap to be installed manually.

### B. Python Environment
- **Version**: Python 3.9+
- **Libraries**:
    - `scapy`: Packet manipulation.
    - `rich`: Terminal rendering.
    - `colorama`: Windows ANSI support.