import socket
import logging
import concurrent.futures
import threading
import gc
import time  # For introducing delay
import requests  # For making API calls to get ASN details
import ipaddress
from idna import encode as idna_encode
from queue import Queue

# Set up logging
logging.basicConfig(level=logging.DEBUG,  # Set the lowest level to capture all logs
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[
                        logging.FileHandler("general_ooni.log", mode='a'),
                        logging.StreamHandler()  # This will print logs to console as well
                    ])

# Additional error logging handler
error_logger = logging.getLogger("error")
error_handler = logging.FileHandler("error_ooni.log", mode='a')
error_handler.setLevel(logging.ERROR)
error_logger.addHandler(error_handler)

# Lock for writing to the output file in a thread-safe way
file_write_lock = threading.Lock()

# Queue to hold results for batch writing
results_queue = Queue()


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

# Function to get all CIDRs for a domain by resolving its IP addresses
def process_domain(domain, existing_cidrs):
    try:
        cidrs = set()
        ip_addresses = resolve_domain(domain)  # Resolve domain to its IP addresses
        for ip in ip_addresses:
            if not is_ip_in_existing_cidr(ip, existing_cidrs):
                cidrs.add(f"{ip}/32")
        return cidrs
    except Exception as e:
        error_logger.error(f"Error processing domain {domain}: {e}")
        return set()

# Function to read domains from domains.lst file
def read_domains_from_file(file_path="ooni_domains.lst"):
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
    domains = read_domains_from_file("ooni_domains.lst")
    if not domains:
        logging.info("No domains to process.")
        return

    existing_cidrs = set()  # Keep track of all CIDRs to exclude matching IPs

    # Start the file writer thread
    writer_thread = threading.Thread(target=write_cidrs_to_file, args=("ip_ooni.lst",))
    writer_thread.start()

    # Use ThreadPoolExecutor to use more threads (set to 16 threads for better utilization)
    with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
        future_to_domain = {executor.submit(process_domain, domain, existing_cidrs): domain for domain in domains}

        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                domain_cidrs = future.result()
                if domain_cidrs:
                    results_queue.put(domain_cidrs)
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