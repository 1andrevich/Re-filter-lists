# Function to read IPs from a file
def read_ips_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            ips = [line.strip() for line in f.readlines() if line.strip()]
        return ips
    except FileNotFoundError:
        return []

# Main function to process IP files and create the output file
def main():
    # Read IPs from the three files
    ips1 = read_ips_from_file("sum/input/ip.lst")
    ips2 = read_ips_from_file("sum/input/ooni_ips.lst")
    ips3 = read_ips_from_file("sum/input/ip_community.lst")
    ips4 = read_ips_from_file("sum/input/discord_ips.lst")

    # Combine all IPs and remove duplicates
    unique_ips = set(ips1 + ips2 + ips3 + ips4)

    # Write the unique IPs to the output file
    output_file = "sum/input/ips_all.lst"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for ip in sorted(unique_ips):
                f.write(f"{ip}\n")
    except Exception:
        pass

if __name__ == "__main__":
    main()