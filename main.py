"""
main.py
=======
Command-line entry point for the Network Packet Sniffer.
Provides a comprehensive CLI interface for configuring and starting packet captures.
"""

import argparse
import sys
import os

from src.config import Config, TOOL_INFO
from src.sniffer import PacketSniffer
from src.utils import get_available_interfaces

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    # Python version check
    if sys.version_info < (3, 9):
        print("Error: Python 3.9 or higher is required.")
        sys.exit(1)

    epilog_examples = """
Examples:
  sudo python main.py                                  # Capture all traffic on default interface
  sudo python main.py -i eth0 -c 100                   # Capture 100 packets on eth0
  sudo python main.py -p tcp --port 80 -v              # Verbose HTTP traffic
  sudo python main.py -p dns -o dns.json               # Save DNS traffic to JSON
  sudo python main.py -f "udp and port 53"             # Raw BPF filter
  sudo python main.py --list-interfaces                # Show available interfaces
  sudo python main.py -i eth0 -c 200 --save-pcap capture.pcap
  sudo python main.py -p tcp --port 443 --payload      # Show HTTPS payloads
"""

    parser = argparse.ArgumentParser(
        prog="packet-sniffer",
        description=f"{TOOL_INFO['name']} — {TOOL_INFO['description']}",
        epilog=epilog_examples,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Capture Options
    cap_group = parser.add_argument_group("Capture Options")
    cap_group.add_argument("-i", "--interface", help="Network interface to capture on (default: auto-detect)")
    cap_group.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture, 0=unlimited (default: 0)")
    cap_group.add_argument("-t", "--timeout", type=float, default=0.0, help="Stop capture after N seconds, 0=no limit (default: 0)")

    # Filter Options
    filter_group = parser.add_argument_group("Filter Options")
    filter_group.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp", "arp", "dns", "http", "https", "ssh", "ftp", "smtp"], 
                              help="Protocol filter")
    filter_group.add_argument("--src-ip", help="Filter by source IP address (supports CIDR: 192.168.1.0/24)")
    filter_group.add_argument("--dst-ip", help="Filter by destination IP address")
    filter_group.add_argument("--port", type=int, help="Filter by port number (matches src OR dst)")
    filter_group.add_argument("-f", "--filter", help="Raw BPF filter expression (overrides protocol/ip/port filters)")

    # Output Options
    out_group = parser.add_argument_group("Output Options")
    out_group.add_argument("-o", "--output", help="Save capture to file (auto-names if no path given)")
    out_group.add_argument("--format", choices=["json", "csv"], default="json", help="Output format: json or csv (default: json)")
    out_group.add_argument("--save-pcap", help="Save raw capture as PCAP file (Wireshark compatible)")
    out_group.add_argument("--log", action="store_true", help="Enable file logging to logs/capture.log")

    # Display Options
    disp_group = parser.add_argument_group("Display Options")
    disp_group.add_argument("-v", "--verbose", action="store_true", help="Show detailed packet information")
    disp_group.add_argument("--payload", action="store_true", help="Show packet payload (hex + ASCII)")
    disp_group.add_argument("-q", "--quiet", action="store_true", help="Suppress packet output (capture silently)")

    # Info Commands
    info_group = parser.add_argument_group("Info Commands")
    info_group.add_argument("--list-interfaces", action="store_true", help="List available network interfaces and exit")
    info_group.add_argument("--version", action="store_true", help="Show version and exit")

    args = parser.parse_args()

    # Handle Info Commands
    if args.version:
        print(f"{TOOL_INFO['name']} v{TOOL_INFO['version']} by {TOOL_INFO['author']}")
        sys.exit(0)

    if args.list_interfaces:
        sniffer = PacketSniffer(Config())
        sniffer.list_interfaces()
        sys.exit(0)

    # Build Config
    config = Config(
        interface=args.interface or "",
        packet_count=args.count,
        timeout=args.timeout,
        filter_protocol=args.protocol or "",
        filter_src_ip=args.src_ip or "",
        filter_dst_ip=args.dst_ip or "",
        filter_port=args.port or 0,
        bpf_filter=args.filter or "",
        verbose=args.verbose,
        show_payload=args.payload,
        quiet=args.quiet,
        output_file=args.output or "",
        output_format=args.format,
        save_pcap=args.save_pcap or "",
        log_to_file=args.log,
    )

    # Start sniffer
    sniffer = PacketSniffer(config)
    sniffer.start()

if __name__ == "__main__":
    main()
