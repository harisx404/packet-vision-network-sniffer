from setuptools import setup, find_packages

setup(
    name="CodeAlpha_NetworkSniffer",
    version="1.0.0",
    description="A network packet sniffer built for CodeAlpha",
    author="Haris",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "rich>=13.0.0",
        "colorama>=0.4.6"
    ],
    entry_points={
        "console_scripts": [
            "packet-sniffer=main:main"
        ]
    },
    python_requires=">=3.9",
)
