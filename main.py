import dns.resolver
import re
import ipaddress
import requests
import sys
import argparse
import os
from tqdm import tqdm

def print_banner():
    banner = """
                        =========================================
                        |                                        |
                        |       CloudSquatting Catc7er           |
                        |       By: Abdullah Al-Sultani          |
                        |       https://github.com/ahussam       |
                        |                                        |
                        =========================================
                                            (`  ).                   _           
                                (     ).              .:(`  )`.       
                    )           _(       '`.          :(   .    )      
                            .=(`(      .   )     .--  `.  (    ) )      
                        ((    (..__.:'-'   .+(   )   ` _`  ) )                 
                    `.     `(       ) )       (   .  )     (   )  ._   
                    )      ` __.:'   )     (   (   ))     `-'.-(`  ) 
                    )  )  ( )       --'       `- __.'         :(      )) 
                    .-'  (_.'          .')                    `(    )  ))
                                    (_  )                     ` __.:'          
                                                            
                    --..,___.--,--'`,---..-.--+--.,,-,,..._.--..-._.-a:f--.

    """
    # Split the banner into lines
    lines = banner.split('\n')

    max_length = max(len(line) for line in lines)
    
    centered_lines = [line.center(max_length) for line in lines]
    
    centered_banner = '\n'.join(centered_lines)
    
    # ANSI escape code for yellow text
    yellow = "\033[93m"
    # ANSI escape code to reset text formatting
    reset = "\033[0m"
    # Print the banner text in yellow
    print(f"{yellow}{centered_banner}{reset}")


def is_valid_domain(domain):
    pattern = r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, domain) is not None

def dns_resolver(domain):
    ips = []
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            ips.append(ipval.to_text())
        return ips
    except dns.resolver.NXDOMAIN:
        print(f'No such domain: {domain}')
    except dns.resolver.Timeout:
        print(f'Query timed out for domain: {domain}')
    except dns.resolver.NoNameservers:
        print(f'No nameservers available for domain: {domain}')
    except Exception as e:
        print(f'An error occurred: {e}')
    return ips

def is_in_subnet(ip, subnet):
    return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet)

def is_cloud_provider(ip):
    try:
        with open("ranges.txt", "r") as f:
            for line in f:
                if line.strip() and is_in_subnet(ip, line.strip()):
                    return True
    except FileNotFoundError:
        print("ranges.txt file not found. Please run the script with 'update' to download the ranges.")
    return False

def download_all_networks():
    download_functions = [
        download_aws_networks,
        download_azure_networks,
        download_gcp_networks,
        download_oci_networks,
        download_yandex_networks,
        download_linode_networks,
        download_cloudflare_networks
    ]

    range_list = []
    for download_function in tqdm(download_functions, desc="Downloading networks"):
        try:
            range_list += download_function()
        except Exception as e:
            print(f"\033[91mError downloading networks from {download_function.__name__}: {e}\033[0m")

    write_ips_to_file(range_list)

def write_ips_to_file(ip_list):
    try:
        with open("ranges.txt", 'w') as file:
            for ip_range in ip_list:
                file.write(ip_range + '\n')
        print(f"Successfully wrote {len(ip_list)} IP addresses to ranges.txt")
    except Exception as e:
        print(f"An error occurred: {e}")

def download_aws_networks():
    network_list = []
    try:
        req_aws = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json")
        aws_networks = req_aws.json().get("prefixes", [])
        for data in aws_networks:
            network_list.append(data.get("ip_prefix"))
    except requests.RequestException as e:
        print(f"Error downloading AWS networks: {e}")
    return network_list

def download_azure_networks():
    network_list = []
    initial_url = 'https://www.microsoft.com/en-us/download/details.aspx?id=56519'
    pattern = r'https://download\.microsoft\.com/download/[0-9A-F]{1}/[0-9A-F]{1}/[0-9A-F]{1}/[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/ServiceTags_Public_\d{8}\.json'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://www.google.com/',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
        'Pragma': 'no-cache'
    }
    try:
        response = requests.get(initial_url, headers=headers)
        if response.status_code == 200:
            match = re.search(pattern, response.text)
            if match:
                matched_url = match.group(0)
                json_response = requests.get(matched_url)
                if json_response.status_code == 200:
                    values = json_response.json().get("values", [])
                    for value in values:
                        for network in value.get("properties", {}).get("addressPrefixes", []):
                            if ":" not in network:
                                network_list.append(network)
                else:
                    print(f"Failed to retrieve JSON data. HTTP Status code: {json_response.status_code}")
            else:
                print("No URL matching the pattern was found.")
        else:
            print(f"Failed to retrieve data from the initial URL. HTTP Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error downloading Azure networks: {e}")
    return network_list

def download_gcp_networks():
    network_list = []
    try:
        json_response = requests.get("https://www.gstatic.com/ipranges/cloud.json")
        values = json_response.json().get("prefixes", [])
        for value in values:
            range = value.get("ipv4Prefix")
            if range:
                network_list.append(range)
    except requests.RequestException as e:
        print(f"Error downloading GCP networks: {e}")
    return network_list

def download_oci_networks():
    network_list = []
    try:
        json_response = requests.get("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json")
        values = json_response.json().get("regions", [])
        for value in values:
            for cidr in value.get("cidrs", []):
                network_list.append(cidr.get("cidr"))
    except requests.RequestException as e:
        print(f"Error downloading OCI networks: {e}")
    return network_list

def download_yandex_networks():
    network_list = []
    try:
        response = requests.get("https://yandex.cloud/en/docs/security/ip-list")
        ipv4_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/[0-9]{1,2}')
        ipv4_addresses = ipv4_pattern.findall(response.text)
        network_list.extend(ipv4_addresses)
    except requests.RequestException as e:
        print(f"Error downloading Yandex networks: {e}")
    return network_list

def download_linode_networks():
    network_list = []
    try:
        response = requests.get("https://geoip.linode.com/")
        ipv4_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/[0-9]{1,2}')
        ipv4_addresses = ipv4_pattern.findall(response.text)
        network_list.extend(ipv4_addresses)
    except requests.RequestException as e:
        print(f"Error downloading Linode networks: {e}")
    return network_list

def download_cloudflare_networks():
    network_list = []
    try:
        response = requests.get("https://www.cloudflare.com/ips-v4")
        ipv4_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/[0-9]{1,2}')
        ipv4_addresses = ipv4_pattern.findall(response.text)
        network_list.extend(ipv4_addresses)
    except requests.RequestException as e:
        print(f"Error downloading Cloudflare networks: {e}")
    return network_list

def is_alive(ip, domain):
    try:
        response = requests.get(f'http://{ip}', headers={'host': domain}, timeout=10)
        return response.status_code == 200
    except requests.RequestException:
        return False

def report_vulnerable_domain(ip, domain):
    red = "\033[91m"
    reset = "\033[0m"
    report = f"{red}{domain} || {ip} is vulnerable!{reset}\n"
    report += "=" * 50 + "\n"
    print(report)

def process_domain(domain):
    if is_valid_domain(domain):
        ips = dns_resolver(domain)
        for ip in ips:
            if is_cloud_provider(ip):
                if not is_alive(ip, domain):
                    report_vulnerable_domain(ip, domain)
                    global vulnerable_targets
                    vulnerable_targets += 1
                else:
                    print(f"{domain} is not vulnerable.")
    else:
        print(f"Invalid domain: {domain}")

def main():
    global vulnerable_targets
    vulnerable_targets = 0
    print_banner()
    parser = argparse.ArgumentParser(description="Process a single domain or a file containing domains.")
    parser.add_argument('input', help="A domain name or a file path containing domain names.")
    args = parser.parse_args()
    target = args.input

    if 'update' in target:
        print("Downloading cloud provider ranges.")
        download_all_networks()
        sys.exit()

    if not os.path.isfile("ranges.txt"):
        print("Downloading cloud provider ranges.")
        download_all_networks()

    print("========================+++ Starting +++==============================")
    if os.path.isfile(target):
        with open(target) as file:
            for line in file:
                process_domain(line.strip())
    else:
        process_domain(target)

    print(f"\n{vulnerable_targets} vulnerable domains were found!")
    print("========================+++   Done   +++==============================")

if __name__ == "__main__":
    main()