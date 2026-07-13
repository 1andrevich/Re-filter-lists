import ipaddress
import logging
import os
import geoip2.database
from pathlib import Path
from colorama import Fore, Style, init
from tqdm import tqdm

# 1. Domains to exclude (exact match, case-insensitive)
# These domains and their subdomains will be removed from domains_all.lst
BYPASS_DOMAINS = {
    "yandex.ru", 
    "yandex.net", 
    "yandex.com", 
    "yandex.by", 
    "yandex.kz", 
    "yandex.uz",
    "ya.ru", 
    "ya.net", 
    "yastatic.net", 
    "yandex.st",
    "yaphishtest.ru",
}

# 2. IP addresses and CIDRs to exclude
BYPASS_IPS = {
    "1.1.1.1/32",
    "1.0.0.1/32",
    "8.8.8.8/32",
    "8.8.4.4/32",
}

# 3. ASNs to exclude (to avoid proxying unblocked hosters/companies)
BYPASS_ASNS = {
    13238,   # Yandex LLC 
    200350,  # Yandex.Cloud
}

# =============================================================================

# Paths (Relative to project root, matching Step 6 logic)
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
GEOIP_DB_PATH = REPO_ROOT / 'sum/GeoLite2-ASN.mmdb'
DOMAINS_FILE = REPO_ROOT / 'sum/output/domains_all.lst'
IP_FILE = REPO_ROOT / 'sum/output/ipsum.lst'

# Author's style logging
def configure_logging():
    init()
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[
            logging.FileHandler(SCRIPT_DIR / 'bypass_filter.log', mode='a', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger()

logger = configure_logging()

def is_subdomain(domain, bypass_set):
    domain = domain.lower()
    if domain in bypass_set:
        return True
    parts = domain.split('.')
    for i in range(len(parts) - 1):
        parent = '.'.join(parts[i+1:])
        if parent in bypass_set:
            return True
    return False

def is_ip_bypassed(ip_str, reader):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        
        # 1. Check direct IP/CIDR bypass
        for b_cidr in BYPASS_IPS:
            if ip_obj in ipaddress.ip_network(b_cidr, strict=False):
                return True, f"IP/CIDR: {b_cidr}"
        
        # 2. Check ASN bypass
        if reader:
            try:
                response = reader.asn(ip_str)
                asn = response.autonomous_system_number
                if asn in BYPASS_ASNS:
                    return True, f"ASN: AS{asn}"
            except Exception:
                pass
                
    except Exception as e:
        logger.debug(f"Skip IP check for {ip_str}: {e}")
    return False, ""

def filter_domains(domains):
    if not BYPASS_DOMAINS:
        return domains, 0
    
    filtered = []
    removed = 0
    for domain in domains:
        if is_subdomain(domain, BYPASS_DOMAINS):
            removed += 1
            logger.info(f"{Fore.YELLOW}Bypassing domain: {domain}{Style.RESET_ALL}")
            continue
        filtered.append(domain)
    return filtered, removed

def filter_ips(ip_entries, reader):
    if not BYPASS_IPS and not BYPASS_ASNS:
        return ip_entries, 0
    
    filtered = []
    removed = 0
    for entry in tqdm(ip_entries, desc="Filtering IPs"):
        # Get base IP from CIDR for ASN check
        ip_str = entry.split('/')[0]
        
        excluded, reason = is_ip_bypassed(ip_str, reader)
        if excluded:
            removed += 1
            logger.info(f"{Fore.YELLOW}Bypassing IP/CIDR {entry} due to {reason}{Style.RESET_ALL}")
            continue
        filtered.append(entry)
    return filtered, removed

def main():
    logger.info(f"{Fore.CYAN}Step 7 - Applying Final Bypass Filters...{Style.RESET_ALL}")
    
    # Initialize GeoIP reader if needed
    reader = None
    if BYPASS_ASNS and GEOIP_DB_PATH.exists():
        try:
            reader = geoip2.database.Reader(str(GEOIP_DB_PATH))
        except Exception as e:
            logger.error(f"{Fore.RED}Failed to initialize GeoIP reader: {e}{Style.RESET_ALL}")

    # Process Domains
    if DOMAINS_FILE.exists():
        with open(DOMAINS_FILE, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        filtered_domains, rem_d = filter_domains(domains)
        
        with open(DOMAINS_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(filtered_domains) + '\n')
        logger.info(f"{Fore.GREEN}Domains filtered: {len(domains)} -> {len(filtered_domains)} (Removed {rem_d}){Style.RESET_ALL}")
    else:
        logger.warning(f"{Fore.YELLOW}Domains file not found: {DOMAINS_FILE}{Style.RESET_ALL}")

    # Process IPs
    if IP_FILE.exists():
        with open(IP_FILE, 'r', encoding='utf-8') as f:
            ips = [line.strip() for line in f if line.strip()]
            
        filtered_ips, rem_i = filter_ips(ips, reader)
        
        with open(IP_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(filtered_ips) + '\n')
        logger.info(f"{Fore.GREEN}IPs filtered: {len(ips)} -> {len(filtered_ips)} (Removed {rem_i}){Style.RESET_ALL}")
    else:
        logger.warning(f"{Fore.YELLOW}IP file not found: {IP_FILE}{Style.RESET_ALL}")

    if reader:
        reader.close()
    
    logger.info(f"{Fore.CYAN}Step 7 complete.{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
