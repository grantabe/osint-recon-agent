# OSINT Recon Agent

An AI-powered passive reconnaissance tool that autonomously gathers open-source intelligence on target domains. Built with Python and the Anthropic API, the agent executes recon tools and analyzes the results, and produces a prioritized security report.

## How It Works

The tool uses Claude's tool-use API to orchestrate four recon modules. Given a target domain, the AI agent processes the results, and generates a structured report highlighting security findings ranked by severity.

```
User provides domain
        ↓
   AI Agent runs
   these tools 
        ↓
  ┌─────┼─────┬──────────┐
  ↓     ↓     ↓          ↓
 DNS  WHOIS  Shodan   crt.sh
  ↓     ↓     ↓          ↓
  └─────┼─────┴──────────┘
        ↓
  Agent analyzes results
        ↓
  Generates prioritized
  security report (HTML/MD)
```

## Features

- **DNS Enumeration** — Queries A, MX, NS, and TXT records to map DNS infrastructure, mail servers, and SPF/DKIM configurations
- **WHOIS Lookup** — Retrieves registrant details, registrar, name servers, contact emails, and organizational info
- **Shodan Integration** — Resolves domain to IPs and pulls open ports, services, TLS/SSL cipher details, certificate expiration, WAF detection, and known vulnerabilities: This is all without active scanning
- **Certificate Transparency** — Queries crt.sh for issued certificates, discovering subdomains and tracking certificate issuers and expiration dates
- **AI-Powered Analysis** — Claude analyzes all gathered data and produces a structured report with findings prioritized by severity and actionable remediation steps
- **Structured Reports** — Generates output in HTML and Markdown formats

## Installation

```bash
git clone https://github.com/grantabe/osint-recon-agent.git
cd osint-recon-agent
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\Activate.ps1     # Windows PowerShell
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root:

```
SHODAN_API_KEY=your_shodan_key
ANTHROPIC_API_KEY=your_anthropic_key
```

- **Shodan API key**: Free tier available at [shodan.io](https://shodan.io)
- **Anthropic API key**: Available at [console.anthropic.com](https://console.anthropic.com)

## Usage

```bash
python3 main.py <target-domain>
```

Example:

```bash
python3 main.py example.com
```

## Sample Report Output

The agent produces reports that include:

- Executive summary of the target's infrastructure
- DNS infrastructure mapping
- Registrant and organizational details
- Open ports and services with TLS/SSL analysis
- Certificate transparency findings and subdomain discovery
- Security findings prioritized by severity (Critical / High / Medium / Low)
- Actionable remediation recommendations

## Tech Stack

- **Python 3**
- **Anthropic API** — Claude tool-use for autonomous agent orchestration
- **dnspython** — DNS record enumeration
- **python-whois** — WHOIS lookups
- **Shodan API** — Passive host intelligence
- **Requests** — crt.sh certificate transparency queries
- **python-dotenv** — Environment variable management

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Always obtain proper written authorization before performing reconnaissance on any target. Unauthorized use against systems you do not own or have permission to test is illegal.