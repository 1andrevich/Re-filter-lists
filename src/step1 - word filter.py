import csv

FRAUD_KEYWORDS = [
    'login', 'signin', 'bank', 'secure', 'verify', 'account', 'billing', 'password', 'invoice',
    'casino', 'bet', 'poker', 'blackjack', 'roulette', 'slots', 'winbig', 'jackpot', '1win', 'admiralx', 'escort', 'striptiz', 'massaj' , 'stavki', 'vulkan', 'sloty'
    'prostitutki', 'intim', 'kokain', 'xanax', 'xanaks', 'anasha', 'escort', 'pytana', 'prostitutka', 'metadon', 'mefedron', 'krokodil', 'amfetamin', 'drug', 'narcotic', 'meth', 'weed', 'vzyatka', 'bribe', 'russianbrides'
]

# Initialize lists for clean and filtered domains
clean_domains = []
filtered_domains = []

# Read the CSV file
with open('domains.csv', 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    
    # Make sure we're using the correct column 'Domain'
    for row in reader:
        domain = row['Domain'].strip()  # Use 'Domain' with a capital D
        if any(keyword in domain.lower() for keyword in FRAUD_KEYWORDS):
            filtered_domains.append(domain)
        else:
            clean_domains.append(domain)

# Write the clean domains to domain_clean.lst
with open('domain_clean.lst', 'w') as f:
    f.write('\n'.join(clean_domains))

# Write the filtered domains to domain_filtered.lst
with open('domain_filtered.lst', 'w') as f:
    f.write('\n'.join(filtered_domains))

print(f"Processed {len(clean_domains) + len(filtered_domains)} domains. Clean: {len(clean_domains)}, Filtered: {len(filtered_domains)}")
