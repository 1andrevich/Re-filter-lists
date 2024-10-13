import requests
from concurrent.futures import ThreadPoolExecutor
import gc
import re
import logging
import time
import sys

# Setup logging with real-time output to both file and console
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# File handler (writes logs to file)
file_handler = logging.FileHandler('domain_analysis.log', mode='a', encoding='utf-8')
file_handler.setLevel(logging.INFO)

# Stream handler (outputs to console/terminal in real-time)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.INFO)

# Format for log messages
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Apply the format to handlers
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# Updated Keywords
DRUG_KEYWORDS = [
    'drug', 'narcotic', 'buy drugs', 'купить наркотики', 'метамфетамин', 'weed', 'xanax',
    'xanaks', 'anasha', 'амфетамин', 'кокаин', 'метадон', 'mefedron', 'крокодил',
    'amfetamin', 'cocaine', 'каннабис', 'мариухана', 'марихуана', 'ecstasy', 'blacksprut'
]

CASINO_KEYWORDS = [
    'casino', 'gamble', 'казино', 'игры на деньги', 'покер', 'ставки', 'blackjack',
    'roulette', 'slots', 'jackpot', 'winbig', '1win', 'vulkan', 'адмирал', 'лотерея',
    'poker', 'sloty', 'рулетка', 'джекпот', 'ставка', 'слоты', 'бонусы', 'игровые автоматы', 'крутить'
]

INACTIVE_PHRASES = [
    'nginx', 'apache', 'site for sale', 'сайт продается', 'this domain is for sale',
    'under construction', 'в разработке', 'this website is under construction',
    'maintenance mode', 'технические работы', 'страница недоступна', 'coming soon', 'Купить этот домен.'
    'купить домен', 'купить этот домен', 'продам домен', 'domain for sale', 'Купить этот домен', 'Содержимое появится позже.'
    'domain is for sale', 'domain available', 'продажа домена', 'свободный домен', 'Site is created successfully!' ,
    'this site is for sale', 'временно недоступен', 'out of service', "www.w3.org/1999/xhtml" , 'Web server is returning an unknown error'
    'этот домен продается', 'домен выставлен на продажу', 'service unavailable', 'Website blankdomain.com is ready. The content is to be added' ,
    '503 service unavailable', 'закрыт на реконструкцию', 'сайт на реконструкции', 'Домен не прилинкован к директории на сервере'
    'domain expired', 'домен истек', 'сайт временно не работает', 'default page', 'Срок регистрации домена истек'
]

PHISHING_KEYWORDS = [
    'billing', 'invoice', 'banking', 'доступ к счету', 'инвестируй', 'зарабатывай' ,
    'вход в аккаунт', 'доход', 'кредит', 'требуется подтверждение', 'подтвердите данные',
    'биллинг', 'банковский аккаунт', 'Присоединяйтесь к проекту', 'Зарабатывайте'
]

ADULT_KEYWORDS = [
    'escort', 'проститутки', 'striptiz', 'массаж', 'massaj', 'интим услуги', 'девушки по вызову', 'Порно с детьми', 'Детское порно'
    'путана', 'проститутка', 'секс услуги', 'проститутки', 'adult dating', 'Rape', 'Kill', 'Gore', 'Порно с животными'
    'эскорт', 'проститутка', 'эротический массаж', 'Animal Porn', 'Zoo Porn', 'Child Porn', 'Snuff', 'Dead Porn'
]

ILLEGAL_KEYWORDS = [
    'fraud', 'подделка документов', 'russianbrides', 'русские невесты'
]

ALL_KEYWORDS = DRUG_KEYWORDS + CASINO_KEYWORDS + INACTIVE_PHRASES + PHISHING_KEYWORDS + ADULT_KEYWORDS + ILLEGAL_KEYWORDS

# User-agent to simulate real browser requests
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}


# Function to fetch the page using HTTPS first, then fallback to HTTP
def fetch_page(domain):
    for protocol in ['https://', 'http://']:
        try:
            url = f"{protocol}{domain}"
            response = requests.get(url, headers=HEADERS, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                return response.text
        except requests.RequestException as e:
            logger.error(f"Error fetching {url}: {e}")
    return None


# Function to check for unwanted content
def check_content(domain, content):
    found_keywords = [keyword for keyword in ALL_KEYWORDS if re.search(keyword, content, re.IGNORECASE)]

    # Only filter if at least 2 keywords are matched
    if len(found_keywords) >= 2:
        logger.info(f"Domain reported: {domain} contains suspicious content. Keywords: {', '.join(found_keywords[:5])}")
        return 'report'

    # Check for inactive phrases separately
    if any(re.search(phrase, content, re.IGNORECASE) for phrase in INACTIVE_PHRASES):
        logger.info(f"Domain removed: {domain} inactive or for sale.")
        return 'remove'

    return 'keep'


# Main processing function
def process_domain(domain, clean_file, filtered_file):
    content = fetch_page(domain)
    if content:
        status = check_content(domain, content)
        if status == 'keep':
            logger.info(f"Domain kept: {domain}. Summary of content: {content[:200]}...")
            # Write kept domain to clean file
            with open(clean_file, 'a') as cf:
                cf.write(f"{domain}\n")
        else:
            # Write filtered domain to filtered file
            with open(filtered_file, 'a') as ff:
                ff.write(f"{domain}\n")
        # Manually trigger garbage collection after processing each domain
        gc.collect()
    else:
        logger.info(f"Domain skipped or error: {domain} could not be fetched.")
        # Write skipped or error domain to clean file
        with open(clean_file, 'a') as cf:
            cf.write(f"{domain}\n")


# Main script runner
def run_script(domain_list):
    clean_file = 'clean_domains.lst'
    filtered_file = 'filtered_domains.lst'

    # Clear contents of the output files before starting
    open(clean_file, 'w').close()
    open(filtered_file, 'w').close()

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=750) as executor:
        # Pass clean and filtered file names as arguments to the processing function
        for domain in domain_list:
            executor.submit(process_domain, domain, clean_file, filtered_file)

    end_time = time.time()
    logger.info(f"Processing completed in {end_time - start_time:.2f} seconds.")


# Example usage
if __name__ == "__main__":
    with open('domains.lst') as f:
        domains = [line.strip() for line in f.readlines()]

    run_script(domains)
