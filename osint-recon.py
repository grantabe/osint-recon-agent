import requests
import dns.resolver as resolver, whois
import dotenv, os
from shodan import Shodan


'''
git add .
git commit  -m "comment"
git push

Shodan API → open ports and services
python-whois → registrant/owner info
dnspython → DNS records (A, MX, NS, TXT, subdomains)
crt.sh API → certificate transparency logs
'''

#Initializing Variables
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
    info_list = []

    try:
        ip_address = resolver.resolve(domain, rdtype='A')
        for ip in ip_address:
            ip_list.append(str(ip))

    except Exception as e:
        if not ip_list:
            ip_list.append("No A Records found.")
        print(e)

    try:
        for ip in ip_list:
            host = api.host(ip)
            port_list = []
            transport_list = []
            
 
            cipher_list = []
            exipires_list = []

            vulns_list = []

            

            for entry in host['data']:
                port = entry.get('port')
                if port != None:
                    port_list.append(port)
                
                transport = entry.get('transport')
                if transport != None:
                    transport_list.append(transport)

                cipher = entry.get('ssl', {}).get('cipher')
                if cipher !=  None:
                    cipher_list.append(cipher)
                expire_date = entry.get('ssl', {}).get('cert', {}).get('expires')
                if expire_date != None:
                    exipires_list.append(expire_date)

                vulns =  entry.get('opts', {}).get('vulns')
                if vulns != None:
                    vulns_list.append(vulns)
                

            asn = host.get('asn')
            org = host.get('org')
            isp = host.get('isp')
            hostnames = host.get('hostnames')
            os = host.get('os', 'n/a')

            print(ip, port_list, transport_list, asn, org, isp, hostnames, os, exipires_list, cipher_list, vulns_list)
    except Exception as e:
        print(e)


shodan_ip_recon("cchs.ccusd.org")