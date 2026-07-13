"""
config.py
=========
Configuration module for the Network Packet Sniffer.
Defines all constants, default settings, and color mappings.
"""

from dataclasses import dataclass, field

@dataclass
class Config:
    """Dataclass holding all configuration settings for the packet sniffer."""
    # Capture settings
    interface: str = ""           # Empty = auto-detect default interface
    packet_count: int = 0         # 0 = unlimited
    timeout: float = 0.0          # 0.0 = no timeout
    
    # Filters
    filter_protocol: str = ""     # tcp | udp | icmp | arp | dns | http
    filter_src_ip: str = ""
    filter_dst_ip: str = ""
    filter_port: int = 0          # 0 = no port filter
    bpf_filter: str = ""          # Raw BPF expression, overrides others
    
    # Output
    verbose: bool = False
    show_payload: bool = False
    show_raw: bool = False
    quiet: bool = False
    output_file: str = ""
    output_format: str = "json"   # json | csv
    save_pcap: str = ""
    log_to_file: bool = False
    log_file: str = "logs/capture.log"
    max_payload_size: int = 64    # bytes to display from payload
    max_memory_packets: int = 50000 # to prevent RAM exhaustion

PROTOCOL_COLORS = {
    "TCP":   "green",
    "UDP":   "blue",
    "ICMP":  "yellow",
    "DNS":   "magenta",
    "HTTP":  "cyan",
    "HTTPS": "bright_cyan",
    "ARP":   "bright_yellow",
    "SSH":   "bright_green",
    "FTP":   "bright_blue",
    "SMTP":  "bright_magenta",
    "OTHER": "white",
}

COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
    80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS-NS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    587: "SMTP-TLS", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 5601: "Kibana", 9200: "Elasticsearch"
}

TOOL_INFO = {
    "name": "Network Packet Sniffer",
    "version": "1.0.0",
    "author": "Haris",
    "github": "harisx404",
    "repo": "CodeAlpha_NetworkSniffer",
    "description": "Professional network traffic analysis tool",
    "internship": "CodeAlpha Cybersecurity Internship",
}

BANNER = """
 ╔══════════════════════════════════════════════════════════╗
 ║        NETWORK PACKET SNIFFER  v1.0.0                   ║
 ║        Professional Network Traffic Analyzer            ║
 ║        github.com/harisx404/CodeAlpha_NetworkSniffer    ║
 ╚══════════════════════════════════════════════════════════╝
"""
