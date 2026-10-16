
# 🐻‍❄️ WhiteBear Security Suite

**A Python-based network auditing and learning project.**

WhiteBear Security Suite is an educational tool for checking TCP ports on authorized private networks and generating text reports.

## Features

- TCP port scanning
- Common service-name identification
- Private IPv4 network validation
- Concurrent port checks
- Automatic text report generation
- Simple command-line interface

## Requirements

- Python 3.10 or newer recommended
- Linux, Termux/Kali NetHunter, or another Python-compatible environment
- Permission to test the target network

No third-party Python packages are currently required.

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/WhiteBear-Suite.git
cd WhiteBear-Suite
```

## Usage

Run the scanner:

```bash
python3 scanner.py
```

Enter your authorized private IPv4 subnet when prompted, for example:

`192.168.1.0/24`

Choose either the common-port list or ports 1–1024.

Reports are saved in the `reports/` directory.

## Limitations

- Scans TCP ports only.
- Service names are inferred from port numbers.
- Does not confirm exact software versions.
- Firewalls and network isolation may affect results.

## Responsible Use

Only scan networks and devices you own or have explicit permission to test.

## Author

**4rjun_0xV01d_f4t3**

Project: WhiteBear Security Suite
