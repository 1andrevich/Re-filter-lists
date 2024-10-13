import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG,  # Set the lowest level to capture all logs
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[
                        logging.FileHandler("ip_processing.log", mode='a'),
                        logging.StreamHandler()  # This will print logs to console as well
                    ])

# Function to read IPs from a file
def read_ips_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            ips = [line.strip() for line in f.readlines() if line.strip()]
        logging.info(f"Read {len(ips)} IPs from {file_path}.")
        return ips
    except FileNotFoundError as e:
        logging.error(f"File not found: {file_path}, {e}")
        return []

# Main function to process IP files and create the output file
def main():
    # Read IPs from the three files
    ips1 = read_ips_from_file("input/ip.lst")
    ips2 = read_ips_from_file("input/ip_ooni.lst")
    ips3 = read_ips_from_file("input/ip_community.lst")
    ips4 = read_ips_from_file("input/discord_ips.lst")

    # Combine all IPs and remove duplicates
    unique_ips = set(ips1 + ips2 + ips3 + ips4)

    # Write the unique IPs to the output file
    output_file = "ips_all.lst"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for ip in sorted(unique_ips):
                f.write(f"{ip}\n")
        logging.info(f"Written {len(unique_ips)} unique IPs to {output_file}.")
    except Exception as e:
        logging.error(f"Error writing to file {output_file}: {e}")

if __name__ == "__main__":
    main()