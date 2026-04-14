import requests
import dns.resolver as resolver, whois
import dotenv, os, argparse, re, time
from shodan import Shodan, APIError
import json
from datetime import datetime
from anthropic import Anthropic
from tools import tools
import markdown as md_lib
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich.panel import Panel

console = Console()

DOMAIN_RE = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')


'''
Shodan API → open ports and services
python-whois → registrant/owner info
dnspython → DNS records (A, MX, NS, TXT, subdomains)
crt.sh API → certificate transparency logs
'''

#Initializing Environment Variables
dotenv.load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY")


def dns_lookup(domain):

    ip_list =[]
    mx_list =[]
    ns_list =[]
    txt_list =[]

    record_enumeration = {
        "a_records":ip_list,
        "mx_records":mx_list,
        "ns_records":ns_list,
        "txt_records":txt_list
    }

#Returns A Records
    try:
        ip_address = resolver.resolve(domain, rdtype='A')
        for ip in ip_address:
            ip_list.append(str(ip))

    except (resolver.NXDOMAIN, resolver.NoNameservers, resolver.NoAnswer, resolver.Timeout) as e:
        if not ip_list:
            ip_list.append("No A Records found.")
        print(e)

#Returns MX Records
    try:
        mx_server = resolver.resolve(domain, rdtype='MX')
        for mx in mx_server:
            mx_list.append(str(mx))
   
    except (resolver.NXDOMAIN, resolver.NoNameservers, resolver.NoAnswer, resolver.Timeout) as e:
        if not mx_list:
            mx_list.append("No MX Records found.")
        print(e)

#Returns NS Records
    try:
        ns_servers = resolver.resolve(domain, rdtype='NS')
        for ns in ns_servers:
            ns_list.append(str(ns))
   
    except (resolver.NXDOMAIN, resolver.NoNameservers, resolver.NoAnswer, resolver.Timeout) as e:
        if not ns_list:
            ns_list.append("No NS Records found.")
        print(e)

#Returns TXT Records
    try:
        txt_records = resolver.resolve(domain, rdtype='TXT')
        for txt in txt_records:
            txt_list.append(str(txt))

    except Exception as e:
        if not txt_list:
            txt_list.append("No TXT Records found.")
        print(e)
    return json.dumps(record_enumeration)


#Searches for registrant/owner info
def whois_lookup(domain):
    try:

        results = whois.whois(domain)
        registrar = results.get('registrar')
        name_servers = results.get('name_servers')
        emails = results.get('emails')
        name = results.get('name')
        org = results.get('org')
        address = results.get('address')
        country = results.get('country')

        data = {

            "registrar": registrar,
            "name_servers": name_servers,
            "emails": emails,
            "name": name,
            "org": org,
            "address": address,
            "country": country
        }
        for key in data:
            if data[key] == None:
                data[key] = "No data found."

        return json.dumps(data)
    
    except (TimeoutError, ConnectionError, whois.parser.WhoisDomainNotFoundError) as e:
        print(e)
        return json.dumps({"error": "WHOIS lookup failed: " + str(e)})



def shodan_ip_recon(domain):
    
    api = Shodan(SHODAN_API_KEY)
    ip_list = []
    data = []

#Pulls DNS A records
    try:
        ip_address = resolver.resolve(domain, rdtype='A')
        for ip in ip_address:
            ip_list.append(str(ip))
    except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.NoNameservers, resolver.Timeout) as e:
        print(e)
    
    if not ip_list:
        return json.dumps({"error": "No A records found for domain"})

#Makes the Shodan API calls to enumerate the host

    for i, ip in enumerate(ip_list):
        if i > 0:
            time.sleep(1)
        try:
            host = api.host(ip)
            host_list = []

            for entry in host['data']:
                port = entry.get('port', 'N/A')
                transport = entry.get('transport', 'N/A')
                cipher = entry.get('ssl', {}).get('cipher', 'N/A')
                expire_date = entry.get('ssl', {}).get('cert', {}).get('expires', 'N/A')
                vulns =  entry.get('opts', {}).get('vulns', 'N/A')
            
                host_info = {
                    'port': port,
                    'transport': transport,
                    'cipher': cipher,
                    'cert_expires': expire_date,
                    'vulns': vulns
                }
                host_list.append(host_info)
                
            asn = host.get('asn')
            org = host.get('org')
            isp = host.get('isp')
            hostnames = host.get('hostnames', 'N/A')
            os = host.get('os', 'N/A')

            info = {
                'ip_address': ip,
                'asn': asn,
                'org': org,
                'isp': isp,
                'hostnames': hostnames,
                'os': os,
                'services': host_list
            }
            data.append(info)
        except APIError as e:
            print(f"Error for {ip}:{e}")
    return json.dumps(data)


#Pull certificate enumeration
def certificate_enum(domain):
    url = f'https://crt.sh/?q={domain}&output=json'
    cert_list = []
    
    try:
        time.sleep(0.5)
        response = requests.get(url, timeout=15)
        data = json.loads(response.text)
        for object in data:
            name_value = object['name_value']
            issuer_name  = object['issuer_name']
            common_name = object['common_name']
            expir_date_obj = datetime.strptime(object['not_after'], '%Y-%m-%dT%H:%M:%S')
            previous_year = datetime.now().year - 1
            if expir_date_obj.year >= previous_year:
                expir_date = object['not_after']
            else:
                continue

            cert = {
                'name_value': name_value,
                'issuer_name': issuer_name,
                'common_name': common_name,
                'expir_date': expir_date
            }
            cert_list.append(cert)
        return json.dumps(cert_list)


    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        print(f"Connection Error: {e}")
        return json.dumps({"error": str(e)})




tool_functions = {
    "dns_lookup": dns_lookup,
    "whois_lookup": whois_lookup,
    "shodan_ip_recon": shodan_ip_recon,
    "certificate_enum": certificate_enum
}


def call_client(domain):
   

    client = Anthropic(api_key=CLAUDE_API_KEY)

    response = client.messages.create(
        max_tokens=1024,
        system="You are an expert OSINT reconnaissance analyst. Given a target domain, your job is to gather as much intelligence as possible using your available tools. Run each tool against the target domain, analyze the results, and produce a structured recon report. The report should include: DNS infrastructure, registrant/owner information, open ports and services, SSL/TLS details, and any discovered subdomains. Highlight any security findings such as expiring certificates, weak ciphers, known vulnerabilities, or exposed services. Prioritize findings by severity.",
        tools=tools,
        messages=[ 
            {
            "role":"user",
            "content": f"Perform a full recon scan on {domain}"
            },
        ],
        model="claude-opus-4-6"
    )

    tools_results = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Initializing recon tools...", total=None)
        for data in response.content:
            if data.type == "tool_use":
                progress.update(task, description=f"Running [bold]{data.name}[/bold]...")
                result = tool_functions[data.name](data.input['domain'])
                tools_results.append({
                    "type": "tool_result",
                    "tool_use_id": data.id,
                    "content": result
                })
        progress.update(task, description="[green]Tools complete. Generating report...[/green]")

    follow_up = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=4096,
        system="You are an expert OSINT reconnaissance analyst. Given a target domain, your job is to gather as much intelligence as possible using your available tools. Run each tool against the target domain, analyze the results, and produce a structured recon report. The report should include: DNS infrastructure, registrant/owner information, open ports and services, SSL/TLS details, and any discovered subdomains. Highlight any security findings such as expiring certificates, weak ciphers, known vulnerabilities, or exposed services. Prioritize findings by severity.",
        tools=tools,
        messages=[
            {
                "role":"user",
                "content": f"Perform a full recon scan on {domain}"
            },
            {
                "role":"assistant",
                "content": response.content
            },
            {
                "role":"user",
                "content": tools_results
            }
        ]
    )

    return "\n".join(block.text for block in follow_up.content if hasattr(block, "text"))



def save_report(domain, content, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    header = f"# OSINT Report: {domain}\n_Generated: {datetime.now().isoformat()}_\n\n"
    full_content = header + content

    md_path = os.path.join(output_dir, f"{domain}_{timestamp}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(full_content)

    html_body = md_lib.markdown(full_content, extensions=["fenced_code", "tables"])
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Report: {domain}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 900px; margin: 40px auto; padding: 0 24px; color: #1a1a1a; line-height: 1.6; }}
        h1 {{ color: #1a3a5c; border-bottom: 2px solid #1a3a5c; padding-bottom: 8px; }}
        h2 {{ color: #2c5f8a; margin-top: 2em; }}
        h3 {{ color: #3a7ab5; }}
        code {{ background: #f0f4f8; padding: 2px 6px; border-radius: 4px; font-size: 0.88em; }}
        pre {{ background: #f0f4f8; padding: 16px; border-radius: 6px; overflow-x: auto; }}
        pre code {{ background: none; padding: 0; }}
        table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
        th, td {{ border: 1px solid #d0d7de; padding: 8px 12px; text-align: left; }}
        th {{ background: #f0f4f8; font-weight: 600; }}
        em {{ color: #555; }}
        strong {{ color: #111; }}
    </style>
</head>
<body>
{html_body}
</body>
</html>"""

    html_path = os.path.join(output_dir, f"{domain}_{timestamp}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    return md_path, html_path


def parse_args():
    parser = argparse.ArgumentParser(description="OSINT Reconnaissance Agent")
    parser.add_argument("-d", "--domain", metavar="DOMAIN", help="Target domain")
    parser.add_argument("--no-save", action="store_true", help="Print report only, don't save to file")
    parser.add_argument("-o", "--output", default="reports", metavar="DIR", help="Output directory (default: reports/)")
    return parser.parse_args()


def main():
    args = parse_args()
    domain = args.domain or input("Domain: ").strip()

    if not DOMAIN_RE.match(domain):
        console.print("[red]Invalid domain, try again.[/red]")
        return

    console.rule(f"[bold blue]{domain}[/bold blue]")
    report_text = call_client(domain)
    console.print(Panel(Markdown(report_text), title=f"[bold]OSINT Report: {domain}[/bold]", border_style="blue"))

    if not args.no_save:
        md_path, html_path = save_report(domain, report_text, args.output)
        console.print(f"[green]Report saved → {md_path}[/green]")
        console.print(f"[green]Report saved → {html_path}[/green]")


main()
    