# Contributing to CodeAlpha Network Sniffer

First off, thank you for considering contributing to this project! 

## 1. Where do I go from here?
If you've noticed a bug or have a feature request, please open an issue on GitHub. If you'd like to submit code, please open a Pull Request (PR).

## 2. Setting up your environment
1. Fork the repo and clone it locally.
2. Ensure you are using Python 3.9 or higher.
3. Install dependencies: `pip install -r requirements.txt`.

## 3. Architecture Rules (Strict)
This project adheres to specific architectural guidelines to maintain performance and security. If your PR violates these, it will be rejected:
- **No Blocking the Sniffer**: Never place `time.sleep()`, file I/O operations, or heavy computations inside the `_packet_handler` scapy callback. All heavy processing must occur in the Consumer thread.
- **Memory Safety**: Do not enable `store=True` in Scapy. Memory buffers must use strict FIFO capping.
- **Terminal Injection**: Do not print raw payload bytes to the screen. All byte representations must pass through the ANSI sanitizer in `utils.py`.

## 4. Submitting a Pull Request
1. Create a new branch: `git checkout -b feature-name`
2. Commit your changes: `git commit -m "feat: added new protocol dissection"` (Use Conventional Commits).
3. Ensure all tests pass: `python -m pytest tests/`
4. Push to the branch and open a PR.
