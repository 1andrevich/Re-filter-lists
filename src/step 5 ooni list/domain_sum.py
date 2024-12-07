from idna import encode as idna_encode

# Function to read domains from a file
def read_domains_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f.readlines() if line.strip()]
        return domains
    except FileNotFoundError:
        return []

# Function to convert domains to punycode
def convert_to_punycode(domains):
    punycode_domains = set()
    for domain in domains:
        try:
            punycode_domain = idna_encode(domain).decode('utf-8')
            punycode_domains.add(punycode_domain)
        except Exception:
            pass
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
    except Exception:
        pass

if __name__ == "__main__":
    main()