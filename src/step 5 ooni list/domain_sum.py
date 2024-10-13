import logging
from idna import encode as idna_encode

# Set up logging
logging.basicConfig(level=logging.DEBUG,  # Set the lowest level to capture all logs
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[
                        logging.FileHandler("domain_processing.log", mode='a'),
                        logging.StreamHandler()  # This will print logs to console as well
                    ])

# Function to read domains from a file
def read_domains_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f.readlines() if line.strip()]
        logging.info(f"Read {len(domains)} domains from {file_path}.")
        return domains
    except FileNotFoundError as e:
        logging.error(f"File not found: {file_path}, {e}")
        return []

# Function to convert domains to punycode
def convert_to_punycode(domains):
    punycode_domains = set()
    for domain in domains:
        try:
            punycode_domain = idna_encode(domain).decode('utf-8')
            punycode_domains.add(punycode_domain)
        except Exception as e:
            logging.error(f"Punycode conversion failed for domain {domain}: {e}")
    return punycode_domains

# Main function to process domain files and create the output file
def main():
    # Read domains from the three files
    domains1 = read_domains_from_file("sum/input/domains.lst")
    domains2 = read_domains_from_file("sum/input/ooni_domains.lst")
    domains3 = read_domains_from_file("sum/input/community.lst")

    # Combine all domains
    all_domains = set(domains1 + domains2 + domains3)

    # Convert to punycode and remove duplicates
    unique_domains = convert_to_punycode(all_domains)

    # Write the unique domains to the output file
    output_file = "sum/output/domains_all.lst"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for domain in sorted(unique_domains):
                f.write(f"{domain}\n")
        logging.info(f"Written {len(unique_domains)} unique domains to {output_file}.")
    except Exception as e:
        logging.error(f"Error writing to file {output_file}: {e}")

if __name__ == "__main__":
    main()