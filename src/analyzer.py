"""
analyzer.py
===========
Packet analysis module for dissecting packets into structured data.
"""

import time
from typing import Optional, Any, Tuple, Dict, List

from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
try:
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    HTTP = HTTPRequest = HTTPResponse = None

from src.config import COMMON_PORTS, PROTOCOL_COLORS
from src.utils import format_payload, get_service_name, format_mac, timestamp_now, format_bytes

class PacketAnalyzer:
    """Core intelligence layer that extracts structured data from scapy packets."""

    def __init__(self):
        self._packet_count = 0
        self._protocol_stats: Dict[str, int] = {}
        self._bytes_captured = 0
        self._start_time: float = time.time()

    def analyze(self, packet: Packet) -> Dict[str, Any]:
        """Main method to analyze a packet and return a structured dictionary."""
        try:
            self._packet_count += 1
            
            # Base structures
            time_only, full_time = self._get_timestamp(packet)
            src_mac, dst_mac = self._analyze_ethernet(packet)
            
            # Get IP Layer info
            ip_info = self._analyze_ip_layer(packet)
            
            # Transport / Application specifics
            protocol = "OTHER"
            protocol_detail = ""
            transport_info = {}
            app_info = {}
            
            if packet.haslayer(TCP):
                protocol = "TCP"
                transport_info = self._analyze_tcp(packet)
            elif packet.haslayer(UDP):
                protocol = "UDP"
                transport_info = self._analyze_udp(packet)
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                transport_info = self._analyze_icmp(packet)
            elif packet.haslayer(ARP):
                protocol = "ARP"
                transport_info = self._analyze_arp(packet)
                
            # Check for DNS
            if packet.haslayer(DNS):
                protocol_detail = "DNS"
                app_info.update(self._analyze_dns(packet))
                
            # If protocol detail is empty, use port detection
            if not protocol_detail and (protocol in ["TCP", "UDP"]):
                sport = transport_info.get("src_port")
                dport = transport_info.get("dst_port")
                protocol_detail = self._detect_protocol_detail(protocol, sport, dport, packet)
            
            if not protocol_detail:
                protocol_detail = protocol
                
            # Get Payload
            payload_bytes, payload_preview = self._extract_payload(packet)
            
            # Update stats
            size = ip_info.get("size", len(packet))
            self._update_stats(protocol_detail, size)
            
            result = {
                "number": self._packet_count,
                "timestamp": time_only,
                "timestamp_full": full_time,
                "protocol": protocol,
                "protocol_detail": protocol_detail,
                "src_ip": ip_info.get("src_ip", "N/A"),
                "dst_ip": ip_info.get("dst_ip", "N/A"),
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_port": transport_info.get("src_port"),
                "dst_port": transport_info.get("dst_port"),
                "size": size,
                "ttl": ip_info.get("ttl"),
                "protocol_num": ip_info.get("protocol_num"),
                "flags": transport_info.get("flags", ""),
                "seq": transport_info.get("seq"),
                "ack": transport_info.get("ack"),
                "window": transport_info.get("window"),
                "icmp_type": transport_info.get("icmp_type"),
                "icmp_code": transport_info.get("icmp_code"),
                "icmp_type_name": transport_info.get("icmp_type_name", ""),
                "arp_op": transport_info.get("arp_op", ""),
                "arp_src_ip": transport_info.get("arp_src_ip", ""),
                "arp_dst_ip": transport_info.get("arp_dst_ip", ""),
                "dns_queries": app_info.get("dns_queries", []),
                "dns_answers": app_info.get("dns_answers", []),
                "dns_is_response": app_info.get("dns_is_response", False),
                "payload": payload_bytes,
                "payload_preview": payload_preview,
                "payload_size": len(payload_bytes) if payload_bytes else 0,
                "summary": "",
                "layer_info": {}
            }
            
            result["summary"] = self._build_summary(result)
            return result
        except Exception:
            # Fallback dict that won't crash the UI
            return {
                "number": self._packet_count,
                "timestamp": self._get_timestamp(packet)[0] if packet else "00:00:00",
                "timestamp_full": self._get_timestamp(packet)[1] if packet else "1970-01-01 00:00:00",
                "protocol": "ERROR",
                "protocol_detail": "ERROR",
                "src_ip": "N/A", "dst_ip": "N/A",
                "src_mac": "00:00:00:00:00:00", "dst_mac": "00:00:00:00:00:00",
                "src_port": None, "dst_port": None,
                "size": 0, "ttl": None, "protocol_num": None, "flags": "",
                "seq": None, "ack": None, "window": None,
                "icmp_type": None, "icmp_code": None, "icmp_type_name": "",
                "arp_op": "", "arp_src_ip": "", "arp_dst_ip": "",
                "dns_queries": [], "dns_answers": [], "dns_is_response": False,
                "payload": b"", "payload_preview": "", "payload_size": 0,
                "summary": "Malformed packet error", "layer_info": {}
            }

    def _get_timestamp(self, packet: Packet) -> Tuple[str, str]:
        """Get formatted timestamp from packet."""
        try:
            pt = float(packet.time) if packet and hasattr(packet, 'time') else time.time()
            dt = datetime.fromtimestamp(pt)
            return dt.strftime("%H:%M:%S.%f"), dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "00:00:00.000000", "1970-01-01 00:00:00"

    def _analyze_ethernet(self, packet: Packet) -> Tuple[str, str]:
        """Extract MAC addresses from Ethernet layer."""
        try:
            if packet.haslayer(Ether):
                eth = packet[Ether]
                return format_mac(eth.src), format_mac(eth.dst)
            return "00:00:00:00:00:00", "00:00:00:00:00:00"
        except Exception:
            return "00:00:00:00:00:00", "00:00:00:00:00:00"

    def _analyze_ip_layer(self, packet: Packet) -> Dict[str, Any]:
        """Extract IP or IPv6 layer info."""
        try:
            if packet.haslayer(IP):
                ip = packet[IP]
                return {
                    "src_ip": ip.src, "dst_ip": ip.dst,
                    "ttl": ip.ttl, "protocol_num": ip.proto,
                    "size": len(ip)
                }
            elif packet.haslayer(IPv6):
                ip = packet[IPv6]
                return {
                    "src_ip": ip.src, "dst_ip": ip.dst,
                    "ttl": ip.hlim, "protocol_num": ip.nh,
                    "size": len(ip)
                }
            return {}
        except Exception:
            return {}

    def _analyze_tcp(self, packet: Packet) -> Dict[str, Any]:
        """Extract TCP layer information including flag decoding."""
        try:
            tcp = packet[TCP]
            flags = int(tcp.flags)
            flag_str = ""
            
            # Map bits: SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04, PSH=0x08, URG=0x20
            f_list = []
            if flags & 0x01: f_list.append("FIN")
            if flags & 0x02: f_list.append("SYN")
            if flags & 0x04: f_list.append("RST")
            if flags & 0x08: f_list.append("PSH")
            if flags & 0x10: f_list.append("ACK")
            if flags & 0x20: f_list.append("URG")
            
            flag_str = "-".join(f_list) if f_list else str(flags)
            
            return {
                "src_port": tcp.sport, "dst_port": tcp.dport,
                "flags": flag_str, "seq": tcp.seq, "ack": tcp.ack, "window": tcp.window
            }
        except Exception:
            return {}

    def _analyze_udp(self, packet: Packet) -> Dict[str, Any]:
        """Extract UDP layer info."""
        try:
            udp = packet[UDP]
            return {"src_port": udp.sport, "dst_port": udp.dport}
        except Exception:
            return {}

    def _analyze_icmp(self, packet: Packet) -> Dict[str, Any]:
        """Extract ICMP type and code."""
        try:
            icmp = packet[ICMP]
            types = {
                0: "Echo Reply", 3: "Dest Unreachable", 4: "Source Quench",
                5: "Redirect", 8: "Echo Request", 11: "Time Exceeded",
                12: "Parameter Problem", 13: "Timestamp Request", 14: "Timestamp Reply"
            }
            return {
                "icmp_type": icmp.type, "icmp_code": icmp.code,
                "icmp_type_name": types.get(icmp.type, f"Type {icmp.type}")
            }
        except Exception:
            return {}

    def _analyze_arp(self, packet: Packet) -> Dict[str, Any]:
        """Extract ARP ops and IPs."""
        try:
            arp = packet[ARP]
            op_name = "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op)
            return {
                "arp_op": op_name, "arp_src_ip": arp.psrc, "arp_dst_ip": arp.pdst
            }
        except Exception:
            return {}

    def _analyze_dns(self, packet: Packet) -> Dict[str, Any]:
        """Extract DNS queries and answers."""
        try:
            dns = packet[DNS]
            queries = []
            answers = []
            
            if dns.qdcount > 0 and dns.qd:
                for i in range(dns.qdcount):
                    try:
                        qname = dns.qd[i].qname.decode("utf-8", errors="ignore").rstrip('.')
                        if qname: queries.append(qname)
                    except Exception: pass
            
            if dns.ancount > 0 and dns.an:
                for i in range(dns.ancount):
                    try:
                        rdata = dns.an[i].rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode("utf-8", errors="ignore")
                        answers.append(str(rdata))
                    except Exception: pass

            return {
                "dns_queries": queries,
                "dns_answers": answers,
                "dns_is_response": bool(dns.qr)
            }
        except Exception:
            return {}

    def _detect_protocol_detail(self, transport_proto: str, src_port: Optional[int], dst_port: Optional[int], packet: Packet) -> str:
        """Detect higher-level protocol from port numbers."""
        try:
            ports = [p for p in (src_port, dst_port) if p is not None]
            if not ports:
                return transport_proto
                
            for port in ports:
                if port in COMMON_PORTS:
                    return COMMON_PORTS[port].upper()
            return transport_proto
        except Exception:
            return transport_proto

    def _extract_payload(self, packet: Packet) -> Tuple[bytes, str]:
        """Extract and format raw packet payload."""
        try:
            # Check for Raw layer or use bytes casting fallback
            from scapy.packet import Raw
            if packet.haslayer(Raw):
                payload_bytes = bytes(packet[Raw].load)
            else:
                # If no raw layer, payload is essentially empty for our display purposes
                payload_bytes = b""
                
            preview = format_payload(payload_bytes)
            return payload_bytes, preview
        except Exception:
            return b"", ""

    def _build_summary(self, info: Dict[str, Any]) -> str:
        """Build a human-readable one-line summary."""
        try:
            proto = info.get("protocol", "")
            
            if proto == "ARP":
                op = info.get("arp_op")
                if op == "request":
                    return f"Who has {info.get('arp_dst_ip')}? Tell {info.get('arp_src_ip')}"
                elif op == "reply":
                    return f"{info.get('arp_src_ip')} is at {info.get('src_mac')}"
                return "ARP packet"
                
            elif proto == "ICMP":
                return f"{info.get('src_ip')} → {info.get('dst_ip')}  {info.get('icmp_type_name')}"
                
            elif proto in ("TCP", "UDP"):
                sport = info.get("src_port", "")
                dport = info.get("dst_port", "")
                detail = info.get("protocol_detail", proto)
                size = info.get("size", 0)
                
                base = f"{info.get('src_ip')}:{sport} → {info.get('dst_ip')}:{dport}  [{detail}]  {size} bytes"
                
                if proto == "TCP" and info.get("flags"):
                    base += f"  [{info.get('flags')}]"
                    
                if detail == "DNS":
                    queries = info.get("dns_queries", [])
                    if queries:
                        base += f"  query: {queries[0]}"
                        
                return base
                
            return f"{info.get('src_ip')} → {info.get('dst_ip')} [{proto}] {info.get('size')} bytes"
        except Exception:
            return "Summary unavailable"

    def _update_stats(self, protocol: str, size: int) -> None:
        """Update traffic statistics."""
        try:
            self._bytes_captured += size
            self._protocol_stats[protocol] = self._protocol_stats.get(protocol, 0) + 1
        except Exception:
            pass

    def get_stats(self) -> Dict[str, Any]:
        """Return current statistics."""
        return {
            "total_packets": self._packet_count,
            "total_bytes": self._bytes_captured,
            "bytes_formatted": format_bytes(self._bytes_captured),
            "protocol_distribution": dict(self._protocol_stats),
            "duration_seconds": time.time() - self._start_time,
        }

    def reset(self) -> None:
        """Reset all packet counters and statistics."""
        self._packet_count = 0
        self._protocol_stats = {}
        self._bytes_captured = 0
        self._start_time = time.time()
