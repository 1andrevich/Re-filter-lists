import requests
import csv
import re
import logging
from datetime import datetime, timedelta

# Set up logging for domain checks
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[logging.FileHandler("ooni_domain_fetch.log", mode='a'),
                              logging.StreamHandler()])

# Function to normalize domain by removing 'www.' but not subdomains like 'subdomain.domain.com'
def normalize_domain(domain):
    return domain.lstrip('www.') if domain.startswith('www.') else domain

# Function to fetch and process OONI domains with logging and anomaly checks
def fetch_and_process_ooni_domains(output_file):
    try:
        # Calculate the date range for the last 7 days
        today = datetime.now()
        until_date = today.strftime('%Y-%m-%d')
        since_date = (today - timedelta(days=7)).strftime('%Y-%m-%d')

        # Construct the URL for downloading the CSV file using the OONI API
        base_url = "https://api.ooni.io/api/v1/aggregation"
        params = {
            "axis_y": "domain",
            "axis_x": "measurement_start_day",
            "probe_cc": "RU",  # Replace 'RU' with the country code you're interested in
            "since": since_date,
            "until": until_date,
            "test_name": "web_connectivity",
            "time_grain": "day",
            "format": "CSV"
        }

        url = f"{base_url}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"

        # Fetch the CSV data from OONI
        response = requests.get(url)
        if response.status_code != 200:
            logging.error(f"Failed to download data from OONI API, status code: {response.status_code}")
            return

        # Process the CSV data
        domains = set()
        csv_data = response.content.decode('utf-8').splitlines()
        csv_reader = csv.DictReader(csv_data)

        pattern = r'^.*\.{2,}.*$'  # Pattern to match incorrect domains

        for row in csv_reader:
            domain = row['domain'].strip()
            anomaly_count = int(row['anomaly_count'])
            ok_count = int(row['ok_count'])

            # Log domain processing details
            logging.info(f"Checking domain: {domain} | Anomalies: {anomaly_count}, OK: {ok_count}, Anomaly Rate: {anomaly_count / (anomaly_count + ok_count) if (anomaly_count + ok_count) > 0 else 0:.2f}")

            # Filter out incorrect domains
            if re.match(pattern, domain):
                logging.info(f"Domain has incorrect format: {domain}")
                continue

            # Log and process based on anomaly vs OK count
            if anomaly_count > ok_count:
                normalized_domain = normalize_domain(domain)
                if normalized_domain not in domains:
                    domains.add(normalized_domain)
                    logging.info(f"Anomaly rate is high for the domain: {normalized_domain} - Adding to the list")
            else:
                logging.info(f"Site is accessible in Russia: {domain}")

        # Write the domains to the output file
        with open(output_file, 'w') as output:
            for domain in sorted(domains):  # Optionally sort the domains
                output.write(f"{domain}\n")

        print(f"Total unique domains written to {output_file}: {len(domains)}")

    except Exception as e:
        logging.error(f"Error occurred during fetching or processing: {e}")

# Replace with your output file path
output_file = 'ooni/ooni_domains.lst'

# Fetch and process OONI domains, and output to the specified file
fetch_and_process_ooni_domains(output_file)
