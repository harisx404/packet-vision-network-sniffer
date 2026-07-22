"""
run_demo.py
===========
Standalone demonstration script for the Network Packet Sniffer.

Executes a short, automated capture to verify the core pipeline is functional.
This script does not require interactive input and exits automatically after
the packet limit is reached. Useful for smoke-testing after installation.

Usage:
    # Linux / macOS
    sudo python run_demo.py

    # Windows (from an Administrator terminal)
    python run_demo.py
"""

import sys
import time

from src.config import Config, TOOL_INFO
from src.sniffer import PacketSniffer


def run_demo() -> None:
    """Execute a short automated capture to validate the sniffer pipeline."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        
    print(f"\n  {TOOL_INFO['name']} — Demo Mode")
    print("  Capturing 20 packets and exporting to JSON.\n")
    print("  Press Ctrl+C at any time to stop.\n")
    print("  " + "=" * 50)

    config = Config(
        packet_count=20,
        timeout=30.0,
        output_format="json",
        output_file="demo_capture.json",
        verbose=True,
    )

    sniffer = PacketSniffer(config)

    try:
        sniffer.start()

        # Block until the daemon threads finish
        while sniffer._running:
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n  [!] Demo interrupted by user.")
        sniffer.stop()
        sys.exit(0)


if __name__ == "__main__":
    run_demo()
