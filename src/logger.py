"""
logger.py
=========
File logging and data export functionality (JSON, CSV, PCAP).
"""

import json
import csv
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from scapy.all import wrpcap

from src.config import Config, TOOL_INFO
from src.utils import generate_filename, format_bytes

class PacketLogger:
    """Handles logging captures to a file and exporting to JSON, CSV, PCAP."""

    def __init__(self, config: Config):
        self.config = config
        self._packets: List[Dict[str, Any]] = []
        self._raw_packets: list = []     # Raw scapy Packet objects
        self._file_logger: Optional[logging.Logger] = None
        
        # Create directories if missing
        Path("logs").mkdir(exist_ok=True)
        Path("captures").mkdir(exist_ok=True)
        
        if config.log_to_file:
            self._setup_file_logger()

    def _setup_file_logger(self) -> None:
        """Set up Python logging to write to config.log_file."""
        try:
            self._file_logger = logging.getLogger("packet_sniffer")
            level = logging.DEBUG if self.config.verbose else logging.INFO
            self._file_logger.setLevel(level)
            
            # Avoid duplicate handlers if instantiated multiple times
            if not self._file_logger.handlers:
                handler = logging.FileHandler(self.config.log_file, encoding='utf-8')
                formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
                handler.setFormatter(formatter)
                self._file_logger.addHandler(handler)
        except Exception as e:
            print(f"[ERROR] Failed to set up file logger: {e}")

    def log_packet(self, packet_info: Dict[str, Any], raw_packet=None) -> None:
        """Store packet for export and write to log file if enabled."""
        try:
            self._packets.append(packet_info)
            if raw_packet is not None:
                # CRITICAL RAM PROTECTION
                if len(self._raw_packets) >= self.config.max_memory_packets:
                    self._raw_packets.pop(0)  # Remove oldest packet (FIFO method)
                self._raw_packets.append(raw_packet)
            
            if self._file_logger:
                num = packet_info.get("number", 0)
                proto = packet_info.get("protocol", "")
                src = f"{packet_info.get('src_ip')}:{packet_info.get('src_port')}" if packet_info.get("src_port") else packet_info.get('src_ip')
                dst = f"{packet_info.get('dst_ip')}:{packet_info.get('dst_port')}" if packet_info.get("dst_port") else packet_info.get('dst_ip')
                detail = packet_info.get("protocol_detail", proto)
                size = packet_info.get("size", 0)
                
                msg = f"#{num} {proto} {src} → {dst} [{detail}] {size}B"
                self._file_logger.info(msg)
        except Exception:
            pass

    def save_to_json(self, filepath: str = "") -> str:
        """Export captured packets to a JSON file."""
        if not filepath:
            filepath = os.path.join("captures", generate_filename("json"))
            
        def _json_serializer(obj):
            if isinstance(obj, bytes):
                return obj.hex()
            # IMPORTANT SERIALIZATION FIX: Fallback for unknown objects to prevent crashes
            return str(obj)

        data = {
            "metadata": {
                "tool": TOOL_INFO["name"],
                "version": TOOL_INFO["version"],
                "author": f"{TOOL_INFO['author']} | {TOOL_INFO['github']}",
                "github": f"https://github.com/{TOOL_INFO['github']}/{TOOL_INFO['repo']}",
                "internship": TOOL_INFO["internship"],
                "capture_start": datetime.now().isoformat(),
                "total_packets": len(self._packets),
                "interface": self.config.interface or "auto",
                "filters_applied": {
                    "protocol": self.config.filter_protocol,
                    "src_ip": self.config.filter_src_ip,
                    "dst_ip": self.config.filter_dst_ip,
                    "port": self.config.filter_port,
                    "bpf": self.config.bpf_filter
                }
            },
            "packets": self._packets
        }
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, default=_json_serializer, indent=2)
            return filepath
        except Exception as e:
            print(f"[ERROR] Failed to save JSON file: {e}")
            return ""

    def save_to_csv(self, filepath: str = "") -> str:
        """Export captured packets to a CSV file."""
        if not filepath:
            filepath = os.path.join("captures", generate_filename("csv"))
            
        columns = [
            "number", "timestamp", "protocol", "protocol_detail", "src_ip", "src_port", 
            "dst_ip", "dst_port", "size", "ttl", "flags", "seq", "ack", "window", 
            "dns_queries", "summary"
        ]
        
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
                writer.writeheader()
                
                for pkt in self._packets:
                    row = {col: pkt.get(col, "") for col in columns}
                    
                    # Convert lists to strings
                    for col in ["dns_queries"]:
                        if isinstance(row[col], list):
                            row[col] = "; ".join(row[col])
                            
                    writer.writerow(row)
            return filepath
        except Exception as e:
            print(f"[ERROR] Failed to save CSV file: {e}")
            return ""

    def save_to_pcap(self, filepath: str = "") -> str:
        """Save raw packets to a PCAP file using scapy."""
        if not filepath:
            filepath = os.path.join("captures", generate_filename("pcap"))
            
        if not self._raw_packets:
            print("[WARN] No raw packets to save.")
            return ""
            
        try:
            wrpcap(filepath, self._raw_packets)
            return filepath
        except Exception as e:
            print(f"[ERROR] Failed to save PCAP file: {e}")
            return ""

    def get_packet_count(self) -> int:
        """Return the number of captured packets."""
        return len(self._packets)

    def get_summary(self) -> Dict[str, Any]:
        """Return a basic summary of the capture session."""
        return {
            "total_packets": len(self._packets),
            "has_raw_packets": len(self._raw_packets) > 0,
            "can_export_pcap": len(self._raw_packets) > 0,
        }

    def clear(self) -> None:
        """Clear the packet buffers."""
        self._packets.clear()
        self._raw_packets.clear()

    def close(self) -> None:
        """Close log handlers and release resources."""
        try:
            if self._file_logger:
                for handler in self._file_logger.handlers[:]:
                    handler.close()
                    self._file_logger.removeHandler(handler)
        except Exception:
            pass
