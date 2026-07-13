"""
utils.py
========
Utility functions for formatting, validation, and system checks.
"""

import os
import sys
import socket
import time
import ctypes
import re
from datetime import datetime
from typing import Optional

from scapy.all import get_if_list, conf
from src.config import COMMON_PORTS

def get_available_interfaces() -> list[str]:
    """Get a list of available network interfaces."""
    try:
        interfaces = get_if_list()
        return sorted(interfaces) if interfaces else ["eth0"]
    except Exception:
        return ["eth0"]

def get_default_interface() -> str:
    """Get the default network interface."""
    try:
        iface = conf.iface
        if iface:
            return str(iface)
        interfaces = get_available_interfaces()
        return interfaces[0] if interfaces else ""
    except Exception:
        interfaces = get_available_interfaces()
        return interfaces[0] if interfaces else ""

def format_mac(mac: Optional[str]) -> str:
    """Format a MAC address to uppercase XX:XX:XX:XX:XX:XX format."""
    try:
        if not mac:
            return "00:00:00:00:00:00"
        return mac.upper()
    except Exception:
        return "00:00:00:00:00:00"

def format_bytes(size: int) -> str:
    """Convert integer bytes to a human-readable string."""
    try:
        if size is None or size < 0:
            return "0 B"
        if size < 1024:
            return f"{size} B"
        if size < 1024 ** 2:
            return f"{size / 1024:.1f} KB"
        if size < 1024 ** 3:
            return f"{size / 1024 ** 2:.1f} MB"
        return f"{size / 1024 ** 3:.1f} GB"
    except Exception:
        return "0 B"

def format_duration(seconds: float) -> str:
    """Convert seconds to HH:MM:SS format."""
    try:
        if seconds is None or seconds < 0:
            return "00:00:00"
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"
    except Exception:
        return "00:00:00"

def get_service_name(port: Optional[int], protocol: str = "tcp") -> str:
    """Look up the service name for a given port."""
    try:
        if port is None:
            return "Unknown"
        if port in COMMON_PORTS:
            return COMMON_PORTS[port]
        return socket.getservbyport(port, protocol)
    except Exception:
        return "Unknown"

def validate_ip(ip: str) -> bool:
    """Validate an IPv4 address."""
    try:
        if not ip:
            return False
        socket.inet_aton(ip)
        # Handle cases where inet_aton accepts short strings (e.g., '1')
        return ip.count('.') == 3
    except Exception:
        return False

def validate_ipv6(ip: str) -> bool:
    """Validate an IPv6 address."""
    try:
        if not ip:
            return False
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except Exception:
        return False

def validate_interface(interface: str) -> bool:
    """Check if an interface is valid/available."""
    try:
        if not interface:
            return False
        return interface in get_available_interfaces()
    except Exception:
        return False

def timestamp_now() -> str:
    """Return the current datetime as a formatted string."""
    try:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    except Exception:
        return "1970-01-01 00:00:00.000000"

def format_payload(payload: bytes, max_size: int = 64) -> str:
    """Format raw bytes for hex/ASCII side-by-side display."""
    try:
        if not payload:
            return ""
        
        # Truncate payload
        truncated = len(payload) > max_size
        payload = payload[:max_size]
        
        # Sanitize ANSI escape codes
        # Replace \x1b (27) or \x07 (bell) or other weird controls except standard ones if needed,
        # but the prompt specifically says replace \x1b and \033 with neutral markers.
        # Actually, replacing it in the ASCII interpretation is enough because hex is just hex.
        # Let's ensure the bytes don't get printed raw anyway.
        
        lines = []
        for i in range(0, len(payload), 16):
            chunk = payload[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            
            # Pad hex part to align columns
            hex_part = hex_part.ljust(47)
            
            ascii_part = ""
            for b in chunk:
                # 32-126 are standard printable ASCII. 
                # Anything else is replaced by '.'
                if 32 <= b <= 126:
                    ascii_part += chr(b)
                else:
                    ascii_part += "."
            
            lines.append(f"{i:04x}  {hex_part}  |{ascii_part}|")
            
        result = "\n".join(lines)
        if truncated:
            result += "\n[truncated]"
        return result
    except Exception:
        return ""

def is_root() -> bool:
    """Check if the script is running with administrative privileges."""
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def generate_filename(extension: str, prefix: str = "capture") -> str:
    """Generate a timestamped filename."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        extension = extension.lstrip(".")
        return f"{prefix}_{timestamp}.{extension}"
    except Exception:
        return f"{prefix}_error.{extension.lstrip('.')}"
