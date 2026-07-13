"""
display.py
==========
Rich-powered terminal user interface for displaying network traffic.
"""

import sys
from datetime import datetime
from typing import Dict, Any, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.rule import Rule
from rich.columns import Columns

from src.config import PROTOCOL_COLORS, TOOL_INFO, BANNER
from src.utils import format_bytes, format_duration

class DisplayManager:
    """Handles all terminal output formatting using the Rich library."""

    def __init__(self, verbose: bool = False, show_payload: bool = False, quiet: bool = False):
        self.console = Console()
        self.verbose = verbose
        self.show_payload = show_payload
        self.quiet = quiet
        self._packet_line_count = 0

    def print_banner(self) -> None:
        """Print the application ASCII banner."""
        if self.quiet:
            return
        try:
            panel = Panel(
                Text(BANNER, justify="center", style="bold white"),
                border_style="bright_cyan",
                box=box.DOUBLE
            )
            self.console.print(panel)
            self.console.print()
        except Exception:
            pass

    def print_config(self, config: Any) -> None:
        """Print the active capture configuration."""
        if self.quiet:
            return
        try:
            iface_str = config.interface if config.interface else "auto-detect"
            count_str = f"{config.packet_count} packets" if config.packet_count > 0 else "unlimited"
            timeout_str = f"{config.timeout} seconds" if config.timeout > 0 else "none"
            filters = []
            if config.filter_protocol: filters.append(f"Protocol: {config.filter_protocol}")
            if config.filter_src_ip: filters.append(f"Src IP: {config.filter_src_ip}")
            if config.filter_dst_ip: filters.append(f"Dst IP: {config.filter_dst_ip}")
            if config.filter_port: filters.append(f"Port: {config.filter_port}")
            if config.bpf_filter: filters.append(f"BPF: {config.bpf_filter}")
            
            filter_str = ", ".join(filters) if filters else "None"
            
            content = f"[bright_cyan][+][/bright_cyan] Interface  : {iface_str}\n"
            content += f"[bright_cyan][+][/bright_cyan] Filters    : {filter_str}\n"
            content += f"[bright_cyan][+][/bright_cyan] Limit      : {count_str}\n"
            content += f"[bright_cyan][+][/bright_cyan] Timeout    : {timeout_str}\n"
            if config.output_file:
                content += f"[bright_cyan][+][/bright_cyan] Output     : {config.output_file} ({config.output_format.upper()})\n"
            content += f"[bright_cyan][+][/bright_cyan] Started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            panel = Panel(
                content,
                title="Capture Configuration",
                title_align="left",
                border_style="cyan",
                box=box.ROUNDED
            )
            self.console.print(panel)
            self.console.print()
        except Exception:
            pass

    def print_packet(self, info: Dict[str, Any]) -> None:
        """Print a single packet line."""
        try:
            num = info.get("number", 0)
            time_str = info.get("timestamp", "")
            proto = info.get("protocol", "OTHER")
            proto_color = PROTOCOL_COLORS.get(proto, "white")
            
            detail = info.get("protocol_detail", proto)
            detail_color = PROTOCOL_COLORS.get(detail, proto_color)
            
            src_ip = info.get("src_ip", "")
            dst_ip = info.get("dst_ip", "")
            size = info.get("size", 0)
            
            text = Text()
            text.append(f"[#{num:06d}] ", style="dim")
            text.append(f"[{time_str}] ", style="dim white")
            text.append(f"[{proto}] ", style=f"bold {proto_color}")
            
            if proto == "ARP":
                summary = info.get("summary", "")
                text.append(summary, style="white")
            else:
                sport = info.get("src_port")
                dport = info.get("dst_port")
                
                src_str = f"{src_ip}:{sport}" if sport else src_ip
                dst_str = f"{dst_ip}:{dport}" if dport else dst_ip
                
                text.append(f"{src_str:<21} ", style="bright_white")
                text.append("→  ", style="white")
                text.append(f"{dst_str:<21} ", style="bright_white")
                text.append(f"[{detail}] ", style=f"bold {detail_color}")
                
                if proto == "ICMP":
                    text.append(info.get("icmp_type_name", ""), style="yellow")
                    text.append("  ")
                
                text.append(f"{size} bytes", style="dim")
                
            self.console.print(text)
            
            if self.verbose:
                extra = []
                if info.get("ttl"): extra.append(f"TTL: {info.get('ttl')}")
                if info.get("flags"): extra.append(f"Flags: [{info.get('flags')}]")
                if info.get("seq"): extra.append(f"Seq: {info.get('seq')}")
                if info.get("ack"): extra.append(f"Ack: {info.get('ack')}")
                if info.get("window"): extra.append(f"Win: {info.get('window')}")
                if extra:
                    self.console.print("   └─ " + "  ".join(extra), style="dim cyan")
                    
            if self.show_payload and info.get("payload_preview"):
                self.console.print("   └─ Payload:", style="dim magenta")
                self.console.print(info.get("payload_preview"), style="dim white")
                self.console.print()
                
        except Exception:
            pass

    def print_stats(self, stats: Dict[str, Any]) -> None:
        """Print protocol statistics table."""
        try:
            total = stats.get("total_packets", 0)
            if total == 0:
                self.console.print("\n[yellow]No packets captured.[/yellow]")
                return
                
            dist = stats.get("protocol_distribution", {})
            
            table = Table(title="Protocol Distribution", box=box.SIMPLE, show_edge=False)
            table.add_column("Protocol", style="cyan")
            table.add_column("Count", justify="right", style="magenta")
            table.add_column("Percent", justify="right", style="green")
            table.add_column("Graph", style="blue")
            
            sorted_dist = sorted(dist.items(), key=lambda x: x[1], reverse=True)
            
            for proto, count in sorted_dist:
                pct = (count / total) * 100
                bar_len = int(pct / 5)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                color = PROTOCOL_COLORS.get(proto, "white")
                table.add_row(
                    f"[{color}]{proto}[/{color}]",
                    str(count),
                    f"{pct:.1f}%",
                    bar
                )
                
            self.console.print(table)
        except Exception:
            pass

    def print_error(self, message: str) -> None:
        """Print an error message to stderr."""
        try:
            self.console.print(f"[bold red][ERROR][/bold red] {message}", stderr=True)
        except Exception:
            pass

    def print_warning(self, message: str) -> None:
        """Print a warning message."""
        try:
            if not self.quiet:
                self.console.print(f"[bold yellow][WARN][/bold yellow]  {message}")
        except Exception:
            pass

    def print_info(self, message: str) -> None:
        """Print an info message."""
        try:
            if not self.quiet:
                self.console.print(f"[bold cyan][*][/bold cyan]    {message}")
        except Exception:
            pass

    def print_success(self, message: str) -> None:
        """Print a success message."""
        try:
            if not self.quiet:
                self.console.print(f"[bold green][✓][/bold green]    {message}")
        except Exception:
            pass

    def print_separator(self) -> None:
        """Print a horizontal rule."""
        try:
            if not self.quiet:
                self.console.print(Rule(style="cyan"))
        except Exception:
            pass

    def print_capture_complete(self, stats: Dict[str, Any], output_file: str = "", duration: float = 0) -> None:
        """Print the final capture summary."""
        try:
            dur_str = format_duration(duration)
            content = f"Total Packets : {stats.get('total_packets', 0):<15} Duration : {dur_str}\n"
            content += f"Total Data    : {stats.get('bytes_formatted', '0 B'):<15}"
            if output_file:
                content += f" Saved to : {output_file}"
                
            panel = Panel(
                content,
                title="CAPTURE COMPLETE",
                border_style="green",
                box=box.DOUBLE
            )
            self.console.print()
            self.console.print(panel)
            self.console.print()
            self.print_stats(stats)
        except Exception:
            pass

    def print_packet_detail(self, info: Dict[str, Any]) -> None:
        """Print full packet details for verbose mode (if needed)."""
        if not self.verbose:
            return
        # A simple dump for verbose mode if specifically requested in isolation
        try:
            content = ""
            for k, v in info.items():
                if k not in ["payload", "layer_info", "payload_preview"]:
                    content += f"[cyan]{k}:[/cyan] {v}\n"
            self.console.print(Panel(content, title=f"Packet #{info.get('number')} Details"))
        except Exception:
            pass

    def print_interfaces(self, interfaces: List[str], default: str = "") -> None:
        """Print list of available network interfaces."""
        try:
            table = Table(title="Available Network Interfaces", box=box.ROUNDED)
            table.add_column("Interface Name", style="cyan")
            table.add_column("Status", style="green")
            
            for iface in interfaces:
                status = "[bold green]Default[/bold green]" if iface == default else ""
                table.add_row(iface, status)
                
            self.console.print(table)
        except Exception:
            pass

    def print_permission_warning(self) -> None:
        """Print warning about missing root privileges."""
        try:
            content = "This tool uses raw sockets which require administrative/root privileges.\n"
            content += "If you encounter errors or missing packets, run the tool with sudo:\n"
            content += "[bold white]sudo python main.py[/bold white]"
            panel = Panel(content, title="Permission Warning", border_style="yellow")
            self.console.print(panel)
        except Exception:
            pass
