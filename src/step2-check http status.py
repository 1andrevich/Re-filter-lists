import csv
import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import time
import gc  # Garbage collection
import idna  # IDNA handling for Punycode domains

# Set up logging for both general and error logs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Create file handler for general log
file_handler = logging.FileHandler('availability_check.log')
file_handler.setLevel(logging.INFO)

# Create error log handler
error_handler = logging.FileHandler('errors.log')
error_handler.setLevel(logging.WARNING)

# Create formatter and add it to both handlers
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
error_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(error_handler)

# Checkpoint file to track the last processed domain
CHECKPOINT_FILE = 'checkpoint.txt'
OUTPUT_FILE = 'validated_domains.csv'  # New output file

# Function to handle Punycode and ensure DNS-compatible format
def dns_resolvable(domain):
    try:
        return idna.encode(domain).decode('utf-8')
    except idna.IDNAError as e:
        logger.error(f'Error converting {domain} to IDNA: {e}')
        return None

# Function to check if the redirect leads to the same domain
def is_same_domain(domain, redirect_url):
    try:
        redirect_domain = requests.utils.urlparse(redirect_url).hostname
        domain_normalized = requests.utils.urlparse(f'https://{domain}').hostname
        return redirect_domain == domain_normalized or redirect_domain.startswith('www.' + domain_normalized)
    except Exception as e:
        logger.error(f'Error comparing domain and redirect: {e}')
        return False

# Function to check HTTP/HTTPS availability
def check_http(url, original_domain):
    try:
        with requests.head(url, timeout=5, allow_redirects=False) as response:
            if 200 <= response.status_code < 300:  # Check for 2XX status codes
                logger.info(f'{url} is available (Status Code: {response.status_code})')
                return 'available', response.status_code
            elif response.status_code == 301:
                location = response.headers.get("Location", None)
                if location and is_same_domain(original_domain, location):
                    logger.info(f'{url} returned a 301 redirect to {location}, same domain, considering valid')
                    return 'available', response.status_code
                elif location:
                    try:
                        location = location.encode('latin1').decode('utf-8')  # Handle location header decoding manually
                        logger.warning(f'{url} returned a 301 redirect to {location}')
                    except UnicodeDecodeError:
                        logger.warning(f'{url} returned a 301 redirect with non-decodable Location header')
                else:
                    logger.warning(f'{url} returned a 301 redirect with no Location header')
                return 'redirect', response.status_code
            else:
                logger.warning(f'{url} returned error (Status Code: {response.status_code})')
                return 'unavailable', response.status_code
    except requests.Timeout:
        logger.error(f'HTTP request timed out for {url}')
        return 'timeout', None
    except requests.RequestException as e:
        logger.error(f'HTTP request failed for {url}: {e}')
        return 'unavailable', None

# Function to process a single domain
def process_domain(domain):
    if not domain:
        logger.warning('Encountered an empty line in the input file')
        return None

    logger.info(f'Processing domain: {domain}')
    
    # Ensure domain is DNS-resolvable
    dns_domain = dns_resolvable(domain)
    if not dns_domain:
        return None

    try:
        # First check HTTPS
        https_status, https_code = check_http(f'https://{dns_domain}', domain)
        
        # If HTTPS is not available, check HTTP (exclude redirects 301 from HTTP to HTTPS)
        if https_status != 'available':
            http_status, http_code = check_http(f'http://{dns_domain}', domain)
            if http_status == 'redirect':
                logger.info(f'{domain} redirects from HTTP to HTTPS, excluding from available domains.')
                return None  # Exclude HTTP redirects

            # Only consider HTTP status if HTTPS is not available
            is_available = http_status == 'available' and http_code is not None and 200 <= http_code < 300
        else:
            is_available = https_status == 'available'

        return {
            'domain': domain,
            'dns_domain': dns_domain,
            'https_status': https_status,
            'https_code': https_code,
            'is_available': is_available
        }
    except Exception as e:
        logger.error(f'Error processing domain {domain}: {e}')
        return None

# Function to append results to CSV files in real time
def append_to_csv_files(report_row, domain=None):
    try:
        # Append to report.csv
        with open('report.csv', mode='a', newline='') as report_file:
            report_writer = csv.writer(report_file)
            report_writer.writerow(report_row)

        # Append to validated_domains.csv if the domain is available
        if domain:
            with open(OUTPUT_FILE, mode='a', newline='') as domain_file:
                domain_writer = csv.writer(domain_file)
                domain_writer.writerow([domain])
    except Exception as e:
        logger.error(f'Error writing to CSV files: {e}')

# Function to save the current checkpoint
def save_checkpoint(domain):
    try:
        with open(CHECKPOINT_FILE, mode='w') as file:
            file.write(domain)
    except Exception as e:
        logger.error(f'Error saving checkpoint for domain {domain}: {e}')

# Function to get the last checkpoint
def get_last_checkpoint():
    try:
        if os.path.exists(CHECKPOINT_FILE):
            with open(CHECKPOINT_FILE, mode='r') as file:
                return file.read().strip()
        return None
    except Exception as e:
        logger.error(f'Error reading checkpoint file: {e}')
        return None

# Function to process the domains in batches and generate the report
def process_domains(file_path, batch_size=100):
    try:
        # Initialize or resume from the checkpoint
        last_domain = get_last_checkpoint()
        skip = True if last_domain else False

        logger.info(f'Starting processing of file: {file_path}')
        logger.info(f'Resuming from domain: {last_domain}' if last_domain else 'Starting fresh.')

        # Ensure output files exist and have headers
        if not os.path.exists('report.csv'):
            with open('report.csv', mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Domain', 'DNS-Resolvable Domain', 'HTTPS Status', 'HTTPS Code'])

        if not os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Domain'])

        # Read domains from the input file
        with open(file_path, mode='r', encoding='utf-8') as file:
            domains = [line.strip() for line in file]

        for i in range(0, len(domains), batch_size):
            batch = domains[i:i + batch_size]

            # Use ThreadPoolExecutor to process domains in parallel
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_domain = {executor.submit(process_domain, domain): domain for domain in batch}

                for future in as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    if skip and domain != last_domain:
                        continue
                    skip = False

                    try:
                        result = future.result()
                    except Exception as e:
                        logger.error(f'Error processing domain {domain}: {e}')
                        continue

                    if result:
                        report_row = [
                            result['domain'],
                            result['dns_domain'],
                            result['https_status'],
                            result['https_code'] if result['https_code'] else 'N/A'
                        ]
                        domain_available = result['dns_domain'] if result['is_available'] else None

                        # Append results to files
                        append_to_csv_files(report_row, domain_available)

                        # Save the current checkpoint
                        save_checkpoint(result['domain'])

            logger.info(f'Completed processing batch {i // batch_size + 1} / {len(domains) // batch_size + 1}')
            
            # Trigger garbage collection to free up memory
            gc.collect()
            
            time.sleep(1)  # Sleep briefly to allow system to recover between batches

        logger.info('Processing completed.')
    except FileNotFoundError as e:
        logger.error(f'Input file not found: {file_path}')
    except Exception as e:
        logger.error(f'An unexpected error occurred: {e}')

# Replace 'domain_clean.lst' with the path to your input file
process_domains('domain_clean.lst')
