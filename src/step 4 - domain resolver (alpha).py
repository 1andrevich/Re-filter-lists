import socket
import geoip2.database
import logging
import concurrent.futures
import threading
import gc
import time  # For introducing delay
import requests  # For making API calls to get ASN details
import ipaddress
from idna import encode as idna_encode
from queue import Queue

# Path to the GeoLite2 ASN database (replace with the path to your downloaded GeoLite2-ASN.mmdb)
GEOIP_DB_PATH = "GeoLite2-ASN.mmdb"

# Initialize the GeoIP2 reader
reader = geoip2.database.Reader(GEOIP_DB_PATH)

# Set up logging
logging.basicConfig(level=logging.DEBUG,  # Set the lowest level to capture all logs
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[
                        logging.FileHandler("general.log", mode='a'),
                        logging.StreamHandler()  # This will print logs to console as well
                    ])

# Additional error logging handler
error_logger = logging.getLogger("error")
error_handler = logging.FileHandler("error.log", mode='a')
error_handler.setLevel(logging.ERROR)
error_logger.addHandler(error_handler)

# Lock for writing to the output file in a thread-safe way
file_write_lock = threading.Lock()

# Queue to hold results for batch writing
results_queue = Queue()

# Trusted ASNs: Companies that operate their own ASNs for core services
TRUSTED_ASNS = {
    15169,  # Google
    32934,  # Facebook (Meta)
    714,  # Apple
    8075,  # Microsoft
    2906,  # Netflix
    20940,  # Akamai
    394161,  # Tesla
    13414,  # Twitter
    19679,  # Dropbox
    14492  # LinkedIn
}

# Hosting ASNs: Cloud hosting and CDN providers
HOSTING_ASNS = {
    13335,  # Cloudflare
    54113,  # Fastly
    16509,  # Amazon Web Services (AWS)
    15169,  # Google Cloud
    8075,  # Microsoft Azure
    14061,  # DigitalOcean
    20473,  # Vultr
    63949,  # Linode
    16276,  # OVH
    20940,  # Akamai
    24940,  # Hetzner
    19994,  # Rackspace
    37963,  # Alibaba Cloud
    35908,  # IBM Cloud
    31898,  # Oracle Cloud
    55293,  # Kinsta
    46606,  # HostGator
    26347,  # DreamHost
    26496,  # GoDaddy
    46606  # Bluehost
}

# Main company domains for Trusted ASNs
COMPANY_DOMAINS = {
    'google.com': [15169],  # Google
    'youtube.com': [15169],  # Google (YouTube)
    'facebook.com': [32934],  # Facebook (Meta)
    'instagram.com': [32934],  # Facebook (Meta)
    'whatsapp.com': [32934],  # Facebook (Meta, WhatsApp)
    'apple.com': [714],  # Apple
    'icloud.com': [714],  # Apple iCloud
    'appleid.apple.com': [714],  # Apple ID
    'microsoft.com': [8075],  # Microsoft
    'windows.com': [8075],  # Microsoft
    'live.com': [8075],  # Microsoft
    'office.com': [8075],  # Microsoft Office
    'onedrive.com': [8075],  # Microsoft OneDrive
    'linkedin.com': [14492],  # LinkedIn (Microsoft)
    'netflix.com': [2906],  # Netflix
    'netflixcdn.net': [2906],  # Netflix CDN
    'akamai.com': [20940],  # Akamai
    'akamaihd.net': [20940],  # Akamai CDN
    'twitter.com': [13414],  # Twitter
    'x.com': [13414],  # Twitter
    'dropbox.com': [19679],  # Dropbox
    'tesla.com': [394161]  # Tesla
}


# Function to resolve a domain with retries and punycode support
def resolve_domain(domain, max_retries=2):
    ip_set = set()
    # Convert to punycode if necessary
    try:
        domain = idna_encode(domain).decode('utf-8')
    except Exception as e:
        error_logger.error(f"Punycode conversion failed for domain {domain}: {e}")
        return []

    for _ in range(max_retries):
        try:
            ip_list = socket.gethostbyname_ex(domain)[2]
            ip_set.update(ip_list)
            logging.info(f"Resolved {domain} to IPs: {ip_list}")
        except socket.gaierror as e:
            error_logger.error(f"Could not resolve domain {domain}: {e}")
    return list(ip_set)


# Function to get all CIDRs for a given ASN using the BGPView API with a fallback mechanism
def get_all_cidrs_for_asn(asn):
    cidrs = get_all_cidrs_from_bgpview(asn)
    if not cidrs:
        cidrs = get_all_cidrs_from_ripe(asn)
    if not cidrs:
        cidrs = get_all_cidrs_from_ipinfo(asn)
    return cidrs


# Function to get all CIDRs for a given ASN using the BGPView API
def get_all_cidrs_from_bgpview(asn):
    try:
        url = f"https://api.bgpview.io/asn/{asn}/prefixes"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            ipv4_prefixes = [prefix['prefix'] for prefix in data['data']['ipv4_prefixes']]
            return ipv4_prefixes
        elif response.status_code == 429:
            error_logger.error(f"Rate limit exceeded, waiting before retrying for ASN {asn}")
            time.sleep(60)
            return get_all_cidrs_for_asn(asn)  # Retry
        elif response.status_code == 403:
            error_logger.error(f"Access forbidden for ASN {asn}, status code 403.")
        else:
            error_logger.error(f"Failed to get CIDRs for ASN {asn} from BGPView, status code: {response.status_code}")
        return []
    except Exception as e:
        error_logger.error(f"Error retrieving CIDRs from BGPView for ASN {asn}: {e}")
        return []


# Function to get all CIDRs for a given ASN using the RIPEstat API
def get_all_cidrs_from_ripe(asn):
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            ipv4_prefixes = [prefix['prefix'] for prefix in data['data']['prefixes'] if ':' not in prefix['prefix']]
            logging.info(f"Retrieved CIDRs for ASN {asn} from RIPEstat: {ipv4_prefixes}")
            return ipv4_prefixes
        else:
            error_logger.error(f"Failed to get CIDRs for ASN {asn} from RIPEstat, status code: {response.status_code}")
            return []
    except Exception as e:
        error_logger.error(f"Error retrieving CIDRs from RIPEstat for ASN {asn}: {e}")
        return []


# Function to get all CIDRs for a given ASN using the IPinfo API
def get_all_cidrs_from_ipinfo(asn):
    try:
        url = f"https://ipinfo.io/{asn}"
        token = os.getenv("IPINFO_TOKEN", "").strip()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            ipv4_prefixes = data.get('prefixes', [])
            logging.info(f"Retrieved CIDRs for ASN {asn} from IPinfo: {ipv4_prefixes}")
            return ipv4_prefixes
        else:
            error_logger.error(f"Failed to get CIDRs for ASN {asn} from IPinfo, status code: {response.status_code}")
            return []
    except Exception as e:
        error_logger.error(f"Error retrieving CIDRs from IPinfo for ASN {asn}: {e}")
        return []


# Function to get CIDR block for an IP address using GeoIP2
def get_cidr_for_ip(ip):
    try:
        response = reader.asn(ip)
        asn = response.autonomous_system_number
        network = response.network
        logging.info(f"IP {ip} mapped to ASN {asn}, CIDR: {network}")
        return asn, str(network)
    except Exception as e:
        error_logger.error(f"Error retrieving CIDR for IP {ip}: {e}")
        return None, None


# Function to check if IP is already covered by an existing CIDR
def is_ip_in_existing_cidr(ip, cidrs):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in cidrs:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError as e:
        error_logger.error(f"Invalid IP or CIDR: {ip} - {cidr}: {e}")
    return False


# Function to summarize IPs into subnets with a max /28 size and write to summarized_ip.lst
def summarize_ips(ips, summarized_filename="summarized_ip.lst"):
    try:
        ips = sorted(ips, key=ipaddress.ip_address)
        networks = ipaddress.collapse_addresses([ipaddress.ip_network(f"{ip}/32") for ip in ips])
        summarized_networks = []
        for network in networks:
            if network.prefixlen < 28:
                for subnet in network.subnets(new_prefix=28):
                    summarized_networks.append(subnet)
            else:
                summarized_networks.append(network)

        # Write summarized networks to the summarized_ip.lst file
        with open(summarized_filename, 'a', encoding='utf-8') as f:
            for network in summarized_networks:
                f.write(f"{network}\n")

        return summarized_networks
    except Exception as e:
        error_logger.error(f"Error summarizing IPs: {e}")
        return []


# Function to get all CIDRs for a domain by resolving its IP addresses and querying GeoLite2
def process_domain(domain, existing_cidrs):
    try:
        cidrs = set()
        ip_addresses = resolve_domain(domain)  # Resolve domain to its IP addresses
        hosting_ips = []
        for ip in ip_addresses:
            asn, cidr = get_cidr_for_ip(ip)  # Get ASN and CIDR for each IP
            if asn in TRUSTED_ASNS and is_trusted_domain(domain, asn):
                # Use CIDR only if the domain is a main or trusted domain
                if not is_ip_in_existing_cidr(ip, existing_cidrs):
                    all_cidrs = get_all_cidrs_for_asn(asn)
                    cidrs.update(all_cidrs)
            elif asn not in TRUSTED_ASNS or not is_trusted_domain(domain, asn):
                # If not a trusted company domain, just add /32 addresses
                cidrs.add(f"{ip}/32")
            elif asn in HOSTING_ASNS:
                hosting_ips.append(ip)

        # If there are close-range hosting IPs, summarize them into /28 max
        if hosting_ips:
            summarized_cidrs = summarize_ips(hosting_ips)
            cidrs.update(str(cidr) for cidr in summarized_cidrs)

        return cidrs
    except Exception as e:
        error_logger.error(f"Error processing domain {domain}: {e}")
        return set()


# Function to read domains from domains.lst file
def read_domains_from_file(file_path="domains.lst"):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f.readlines() if line.strip()]
        logging.info(f"Read {len(domains)} domains from file.")
        return domains
    except FileNotFoundError as e:
        error_logger.error(f"File not found: {file_path}, {e}")
        return []


# Function to write CIDRs in batches to output file in a thread-safe way
def write_cidrs_to_file(filename="ip.lst"):
    while True:
        cidrs = results_queue.get()  # Fetch CIDRs from the queue
        if cidrs is None:  # Sentinel value to stop the thread
            break
        with file_write_lock:
            with open(filename, 'a', encoding='utf-8') as f:
                for cidr in cidrs:
                    f.write(f"{cidr}\n")
            logging.info(f"Written {len(cidrs)} CIDRs to {filename}")
        results_queue.task_done()


# Multithreading to handle large domain lists efficiently
def main():
    # Enable garbage collection
    gc.enable()

    # Read the domains from domains.lst file
    domains = read_domains_from_file("domains.lst")
    if not domains:
        logging.info("No domains to process.")
        return

    existing_cidrs = set()  # Keep track of all CIDRs to exclude matching IPs

    # Start the file writer thread
    writer_thread = threading.Thread(target=write_cidrs_to_file, args=("ip.lst",))
    writer_thread.start()

    # Use ThreadPoolExecutor to use more threads (set to 16 threads for better utilization)
    with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
        future_to_domain = {executor.submit(process_domain, domain, existing_cidrs): domain for domain in domains}

        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                domain_cidrs = future.result()
                if domain_cidrs:
                    existing_cidrs.update(domain_cidrs)  # Add new CIDRs to the existing set
                    logging.info(f"CIDRs found for {domain}: {domain_cidrs}")
                    results_queue.put(list(domain_cidrs))  # Send the results to the writer queue
            except Exception as e:
                error_logger.error(f"Error with domain {domain}: {e}")
            finally:
                # Collect garbage after each domain processing to free memory
                gc.collect()

    # Stop the writer thread by sending a sentinel value
    results_queue.put(None)
    writer_thread.join()


if __name__ == "__main__":
    main()
