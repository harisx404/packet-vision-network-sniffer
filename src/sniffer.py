"""
sniffer.py
==========
Core sniffer engine coordinating packet capture, filtering, analysis, and display.
"""

import threading
import time
import sys
import os
import queue
from typing import Optional

from scapy.all import sniff

from src.config import Config
from src.analyzer import PacketAnalyzer
from src.display import DisplayManager
from src.filters import PacketFilter
from src.logger import PacketLogger
from src.utils import get_default_interface, validate_interface, is_root, format_duration

class PacketSniffer:
    """Core orchestration engine for network packet capture and processing."""

    def __init__(self, config: Config):
        self.config = config
        self.analyzer = PacketAnalyzer()
        self.display = DisplayManager(
            verbose=config.verbose,
            show_payload=config.show_payload,
            quiet=config.quiet
        )
        self.filter_engine = PacketFilter(config)
        self.logger = PacketLogger(config)
        
        self._running = False
        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._processing_thread: Optional[threading.Thread] = None
        self._packet_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._start_time: float = 0.0
        self._packet_count = 0

    def start(self) -> None:
        """Start the capture and processing threads."""
        self.display.print_banner()
        
        if not self.check_root():
            self.display.print_error("Raw network capture requires administrative/root privileges. Please run with sudo.")
            sys.exit(1)
            
        if not self.config.interface:
            self.config.interface = get_default_interface()
            
        if not validate_interface(self.config.interface):
            self.display.print_error(f"Invalid or unavailable interface: {self.config.interface}")
            return
            
        self.display.print_config(self.config)
        self.display.print_separator()
        
        self._start_time = time.time()
        self._running = True
        
        # Start Producer
        self._capture_thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="CaptureThread"
        )
        self._capture_thread.start()
        
        # Start Consumer
        self._processing_thread = threading.Thread(
            target=self._process_queue, daemon=True, name="ProcessThread"
        )
        self._processing_thread.start()
        
        try:
            while self._running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.display.print_info("Stopping capture... (Ctrl+C detected)")
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully stop the sniffer."""
        if not self._running:
            return
            
        self._stop_event.set()
        self._running = False
        
        # Wait for threads to finish
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=3)
        if self._processing_thread and self._processing_thread.is_alive():
            self._processing_thread.join(timeout=3)
            
        self.display.print_separator()
        duration = time.time() - self._start_time
        
        # Handle file exports
        output_file = ""
        if self.config.output_file or self.config.output_format:
            if self.config.output_format.lower() == "csv":
                output_file = self.logger.save_to_csv(self.config.output_file)
            else:
                output_file = self.logger.save_to_json(self.config.output_file)
            if output_file:
                self.display.print_success(f"Saved capture to {output_file}")
                
        if self.config.save_pcap:
            pcap_file = self.logger.save_to_pcap(self.config.save_pcap)
            if pcap_file:
                self.display.print_success(f"Saved PCAP to {pcap_file}")
                
        self.logger.close()
        self.display.print_capture_complete(self.analyzer.get_stats(), output_file, duration)

    def _capture_loop(self) -> None:
        """Producer thread: continuously sniffs packets."""
        sniff_kwargs = {
            "iface": self.config.interface,
            "prn": self._packet_handler,
            "store": False,          # Crucial: Don't store packets in memory inside scapy
            "stop_filter": lambda p: self._stop_event.is_set(),
        }
        
        bpf = self.filter_engine.get_bpf_filter()
        if bpf:
            sniff_kwargs["filter"] = bpf
            
        try:
            sniff(**sniff_kwargs)
        except PermissionError:
            self.display.print_error("Root/admin privileges required. Run with sudo.")
        except OSError as e:
            self.display.print_error(f"Interface error: {e}")
        except Exception as e:
            self.display.print_error(f"Capture error: {e}")
        finally:
            self._running = False

    def _packet_handler(self, packet) -> None:
        """Scapy callback: simply puts the packet into the processing queue."""
        try:
            self._packet_queue.put_nowait(packet)
        except queue.Full:
            # If the processing thread is too slow, silently drop to protect memory
            pass

    def _process_queue(self) -> None:
        """Consumer thread: processes packets from the queue."""
        while self._running or not self._packet_queue.empty():
            try:
                packet = self._packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue
                
            try:
                # Python-level filtering
                if not self.filter_engine.should_capture(packet):
                    continue
                    
                packet_info = self.analyzer.analyze(packet)
                
                if not self.config.quiet:
                    self.display.print_packet(packet_info)
                    
                self.logger.log_packet(packet_info, raw_packet=packet)
                
                self._packet_count += 1
                
                if self.config.packet_count > 0 and self._packet_count >= self.config.packet_count:
                    self._stop_event.set()
                    self._running = False
            except Exception:
                pass # Never crash on a single bad packet
            finally:
                self._packet_queue.task_done()

    def list_interfaces(self) -> None:
        """Get available interfaces and display them."""
        from src.utils import get_available_interfaces
        interfaces = get_available_interfaces()
        default = get_default_interface()
        self.display.print_interfaces(interfaces, default)

    @staticmethod
    def check_root() -> bool:
        """Check if running as root."""
        return is_root()
