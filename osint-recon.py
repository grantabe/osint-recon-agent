import requests, dns.resolver as resolver, whois
'''
git add .
git commit  -m "comment"
git push

Shodan API → open ports and services
python-whois → registrant/owner info
dnspython → DNS records (A, MX, NS, TXT, subdomains)
crt.sh API → certificate transparency logs
'''


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

print(whois_lookup("cchs.ccusd.org"))


