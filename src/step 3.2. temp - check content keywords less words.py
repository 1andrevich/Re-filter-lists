import re
import codecs

# Define the new fraud-related keywords (new tags)
NEW_TAGS = ['drug', 'narcotic', 'buy drugs', 'купить наркотики', 'метамфетамин', 'weed', 'xanax',
    'xanaks', 'anasha', 'амфетамин', 'кокаин', 'метадон', 'mefedron', 'крокодил',
    'amfetamin', 'cocaine', 'каннабис', 'мариухана', 'марихуана', 'ecstasy', 'blacksprut'
    'casino', 'gamble', 'казино', 'игры на деньги', 'покер', 'blackjack',
    'roulette', 'slots', 'jackpot', 'winbig', 'vulkan', 'адмирал', 'лотерея',
    'poker', 'sloty', 'рулетка', 'джекпот', 'ставка', 'слоты', 'бонусы', 'игровые автоматы', 'крутить'
    'nginx', 'apache', 'site for sale', 'сайт продается', 'this domain is for sale',
    'under construction', 'в разработке', 'this website is under construction',
    'maintenance mode', 'технические работы', 'страница недоступна', 'coming soon', 'Купить этот домен.'
    'купить домен', 'купить этот домен', 'продам домен', 'domain for sale', 'Купить этот домен', 'Содержимое появится позже.'
    'domain is for sale', 'domain available', 'продажа домена', 'свободный домен', 'Site is created successfully!' ,
    'this site is for sale', 'временно недоступен', 'out of service', 'Web server is returning an unknown error'
    'этот домен продается', 'домен выставлен на продажу', 'service unavailable', 'Website blankdomain.com is ready. The content is to be added' ,
    '503 service unavailable', 'закрыт на реконструкцию', 'сайт на реконструкции', 'Домен не прилинкован к директории на сервере'
    'domain expired', 'домен истек', 'сайт временно не работает', 'default page', 'Срок регистрации домена истек'
    'доступ к счету', 'инвестируй', 'зарабатывай' ,
    'вход в аккаунт', 'требуется подтверждение', 'подтвердите данные',
    'биллинг', 'банковский аккаунт', 'Присоединяйтесь к проекту', 'Зарабатывайте'
    'escort', 'проститутки', 'striptiz', 'массаж', 'massaj', 'интим услуги', 'девушки по вызову', 'Порно с детьми', 'Детское порно'
    'путана', 'проститутка', 'секс услуги', 'adult dating', 'Порно с животными'
    'эскорт', 'эротический массаж', 'Animal Porn', 'Zoo Porn', 'Child Porn', 'Snuff', 'Dead Porn'
    'fraud', 'подделка документов', 'russianbrides', 'русские невесты']

# Initialize lists for reinstated domains and reports
reinstated_domains = []
reinstated_reports = []

# Regex pattern to extract domains and old tags from the log
domain_pattern = re.compile(r"Domain reported: (\S+) contains suspicious content\. Keywords: ([\w\s,]+)")

# Read the domain_analysis.log file and process each suspicious domain
with codecs.open('domain_analysis.log', 'r', encoding='utf-8') as log_file:
    for line in log_file:
        match = domain_pattern.search(line)
        if match:
            domain = match.group(1)
            old_tags = match.group(2).split(', ')  # Old tags found in the log entry

            # Check if none of the old tags are in the new tags list
            if not any(tag in NEW_TAGS for tag in old_tags):
                reinstated_domains.append(domain)
                # Prepare the report for this domain
                reinstated_reports.append(f"Domain: {domain}\nOld Tags: {', '.join(old_tags)}\nReason: None of the old tags matched the new tags.\n")

# Write reinstated domains to domain_reinstated.lst with UTF-8 encoding
with codecs.open('domain_reinstated.lst', 'w', encoding='utf-8') as f:
    f.write('\n'.join(reinstated_domains))

# Write the reinstated domain report to domain_reinstated_report.txt
with codecs.open('domain_reinstated_report.txt', 'w', encoding='utf-8') as report_file:
    report_file.write('\n'.join(reinstated_reports))

# Output the summary of reinstated domains
print(f"Processed log file. Reinstated domains: {len(reinstated_domains)}")
