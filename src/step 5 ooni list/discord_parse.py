import json

# Input file
input_file = "discord_all_ips.json"

# Read the JSON content from the file
try:
    with open(input_file, "r") as file:
        data = json.load(file)
except json.JSONDecodeError as e:
    print(f"Failed to decode JSON: {e}")
    exit()

# Open the output file
with open("discord_ips.lst", "w") as output_file:
    # Loop through the regions in the dictionary
    for region, entries in data.items():
        # Check if the value associated with the region is a list of dictionaries
        if isinstance(entries, list):
            for entry in entries:
                # Get the IP address and format it as /32
                ip = entry.get("ip")
                if ip:
                    output_file.write(f"{ip}/32\n")

print("IP addresses have been written to discord_ips.lst")
