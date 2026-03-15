import requests
import dns.resolver as resolver, whois
import dotenv, os
from shodan import Shodan
import json
from datetime import datetime


'''
git add .
git commit  -m "comment"
git push

Shodan API → open ports and services
python-whois → registrant/owner info
dnspython → DNS records (A, MX, NS, TXT, subdomains)
crt.sh API → certificate transparency logs
'''

#Initializing Environment Variables
dotenv.load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")


def dns_lookup(host):

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
        ip_address = resolver.resolve(host, rdtype='A')
        for ip in ip_address:
            ip_list.append(str(ip))

    except Exception as e:
        if not ip_list:
            ip_list.append("No A Records found.")
        print(e)

#Returns MX Records
    try:
        mx_server = resolver.resolve(host, rdtype='MX')
        for mx in mx_server:
            mx_list.append(str(mx))
   
    except Exception as e:
        if not mx_list:
            mx_list.append("No MX Records found.")
        print(e)

#Returns NS Records
    try:
        ns_servers = resolver.resolve(host, rdtype='NS')
        for ns in ns_servers:
            ns_list.append(str(ns))
   
    except Exception as e:
        if not ns_list:
            ns_list.append("No NS Records found.")
        print(e)

#Returns TXT Records
    try:
        txt_records = resolver.resolve(host, rdtype='TXT')
        for txt in txt_records:
            txt_list.append(str(txt))

    except Exception as e:
        if not txt_list:
            txt_list.append("No TXT Records found.")
        print(e)
    return record_enumeration


#Searches for registrant/owner info
def whois_lookup(host):
    try:

        results = whois.whois(host)
        registrar = results['registrar']
        name_servers = results['name_servers']
        emails = results['emails']
        name = results['name']
        org = results['org']
        address = results['address']
        country = results['country']

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

        return data
    
    except Exception as e:
        print(e)
        print("Failed to fetch info...")



def shodan_ip_recon(domain):
    
    api = Shodan(SHODAN_API_KEY)
    ip_list = []
    data = []

#Pulls DNS A records
    try:
        ip_address = resolver.resolve(domain, rdtype='A')
        for ip in ip_address:
            ip_list.append(str(ip))

    except Exception as e:
        if not ip_list:
            ip_list.append("No A Records found.")
        print(e)

#Makes the Shodan API calls to enumerate the host
    try:
        for ip in ip_list:
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

        print(data)
    except Exception as e:
        print(e)
        print('Failed to fetch info...')


def certificate_enum(host):
    url = f'https://crt.sh/?q={host}&output=json'
    cert_list = []
    
    try:
        response = requests.get(url)
        data = json.loads(response.text)
        for object in data:
            name_value = object['name_value']
            issuer_name  = object['issuer_name']
            common_name = object['common_name']
            expir_date_obj = datetime.strptime(object['not_after'], '%Y-%m-%dT%H:%M:%S')
            previous_year = datetime.now().year - 1
            if expir_date_obj.year >= previous_year:
                expir_date = object['not_after']

            cert = {
                'name_value': name_value,
                'issuer_name': issuer_name,
                'common_name': common_name,
                'expir_date': expir_date
            }
            cert_list.append(cert)
        print(cert_list)


    except:
        print("Connection Error")

certificate_enum('cchs.ccusd.org')

