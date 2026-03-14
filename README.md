# OSINT Recon Agent

A passive reconnaissance tool built in Python that gathers open-source intelligence on target domains. Designed for authorized security assessments and PJPT/PNPT exam preparation.

## Features

- **DNS Enumeration** — Queries A, MX, NS, and TXT records to map out a target's DNS infrastructure
- **WHOIS Lookup** — Retrieves registrant details, name servers, contact emails, and organizational info
- **Shodan Integration** — Pulls open ports, running services, and banners without active scanning (coming soon)
- **Certificate Transparency** — Queries crt.sh for issued certificates, subdomains, and cert metadata (coming soon)

## Installation

```bash
git clone https://github.com/grantabe/osint-recon-agent.git
cd osint-recon-agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root for API keys:

```
SHODAN_API_KEY=your_key_here
```

This file is excluded from version control via `.gitignore`.

## Usage

```bash
python3 main.py <target-domain>
```

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Always obtain proper written authorization before performing reconnaissance on any target. Unauthorized use against systems you do not own or have permission to test is illegal.