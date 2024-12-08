import socket
import concurrent.futures
import threading
import gc
#import time  # For introducing delay
#import requests  # For making API calls to get ASN details
import ipaddress
from idna import encode as idna_encode
from queue import Queue

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
    except Exception:
        return []

    for _ in range(max_retries):
        try:
            ip_list = socket.gethostbyname_ex(domain)[2]
            ip_set.update(ip_list)
        except socket.gaierror:
            pass
    return list(ip_set)

# Function to check if IP is already covered by an existing CIDR
def is_ip_in_existing_cidr(ip, cidrs):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in cidrs:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
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
    except Exception:
        return set()

# Function to read domains from domains.lst file
def read_domains_from_file(file_path="community.lst"):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f.readlines() if line.strip()]
        return domains
    except FileNotFoundError:
        return []

# Function to write CIDRs in batches to output file in a thread-safe way
def write_cidrs_to_file(filename="ip_community.lst"):
    while True:
        cidrs = results_queue.get()  # Fetch CIDRs from the queue
        if cidrs is None:  # Sentinel value to stop the thread
            break
        with file_write_lock:
            with open(filename, 'a', encoding='utf-8') as f:
                for cidr in cidrs:
                    f.write(f"{cidr}\n")
        results_queue.task_done()

# Multithreading to handle large domain lists efficiently
def main():
    # Enable garbage collection
    gc.enable()

    # Read the domains from domains.lst file
    domains = read_domains_from_file("community.lst")
    if not domains:
        return

    existing_cidrs = set()  # Keep track of all CIDRs to exclude matching IPs

    # Start the file writer thread
    writer_thread = threading.Thread(target=write_cidrs_to_file, args=("sum/input/ip_community.lst",))
    writer_thread.start()

    # Use ThreadPoolExecutor to use more threads (set to 16 threads for better utilization)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        future_to_domain = {executor.submit(process_domain, domain, existing_cidrs): domain for domain in domains}

        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                domain_cidrs = future.result()
                if domain_cidrs:
                    results_queue.put(domain_cidrs)
            except Exception:
                pass
            finally:
                # Collect garbage after each domain processing to free memory
                gc.collect()

    # Stop the writer thread by sending a sentinel value
    results_queue.put(None)
    writer_thread.join()

if __name__ == "__main__":
    main()