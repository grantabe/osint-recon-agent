tools =[
    {
        "name": "dns_lookup",
        "description": "Queries DNS records for a target domain. Returns A records (IP addresses), MX records (mail servers), NS records (name servers), and TXT records (SPF, domain verification, and other metadata).",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The target domain name, e.g. google.com"
                }
            },
            "required": ["domain"]
        }
            },
    {
        "name": "whois_lookup",
        "description": "Performs a WHOIS lookup on a target domain. Returns registrant details including registrar, name servers, contact emails, organization name, physical address, and country.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The target domain name, e.g. google.com"
                }
            },
            "required": ["domain"]
        }
            },
    {
        "name": "shodan_ip_recon",
        "description": "Resolves a domain to its IP addresses and queries Shodan for each IP. Returns open ports, transport protocols, SSL/TLS cipher details, certificate expiration dates, known vulnerabilities, ASN, ISP, organization, hostnames, and OS detection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The target domain name, e.g. google.com"
                }
            },
            "required": ["domain"]
        }
            },
    {
        "name": "certificate_enum",
        "description": "Queries certificate transparency logs via crt.sh for a target domain. Returns issued certificates including subject names, issuer, expiration dates, and subdomains found in certificate name values.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The target domain name, e.g. google.com"
                }
            },
            "required": ["domain"]
        }
            }

]