#!/usr/bin/env python3



# -*- coding: utf-8 -*-



"""



Step 3 — Enhanced Content Analysis with Optimized Timeouts



- Fast aiohttp pass + auto-selected browser fallback


- Quality Check: Compares output against qc_domains.lst for validation



- False Positive Fixes: Improved patterns to avoid false positives from legitimate sites



- Dangerous Porn Focus: Only flags explicit child/animal/coercive material

- Enhanced Timeouts: Optimized for better success rates (30s total, 10s connect, 20s read)


Run:



  python step3-content-check.py --preflight   # quick smoke test



  python step3-content-check.py               # full pipeline with quality check



  python step3-content-check.py --no-preflight



  python step3-content-check.py --no-qc       # skip quality check



  python step3-content-check.py --low-mem     # safer defaults for low RAM/low swap



"""



import asyncio
import logging
import sys
import re
import time

from typing import Dict, Tuple, Optional, List, Set, Iterable



from datetime import datetime

import os
import shutil
import argparse
import random
from itertools import cycle
import subprocess
import socket
import tempfile
from pathlib import Path
import platform
import contextlib
import gc
from urllib.parse import urlparse

try:



    import psutil



except ImportError:



    psutil = None



import aiohttp



from aiohttp import ClientTimeout, ClientConnectorError, ClientSSLError



from tqdm import tqdm



from colorama import init, Fore, Style



try:



    from aiohttp_socks import ProxyConnector



    HAVE_SOCKS = True


except ImportError:


    HAVE_SOCKS = False


# =========================

# CONFIG / TUNING
#
# Central knobs for throughput, timeouts, and output locations.



# =========================



INPUT_FILE = "domains_new_2.lst"

QC_FILE = "qc_domains.lst"

PROXY_FILE = "proxies.txt"

DEFAULT_PROXY_PARALLEL_PER_HOST = 5

PROXY_PARALLEL_PER_HOST = int(os.environ.get("PROXY_PARALLEL_PER_HOST", DEFAULT_PROXY_PARALLEL_PER_HOST))

# When True, total concurrency is derived only from per-proxy parallelism (ignores global CONCURRENCY cap)

PROXY_PARALLEL_ONLY = os.environ.get("PROXY_PARALLEL_ONLY", "0").lower() in {"1", "true", "yes"}

REQUEST_DELAY_RANGE = (0.6, 1.6)

USE_RESCUE_STAGE = False

OUT_FILES = {

    "clean": "domains_new_3_pass.lst",

    "filtered": "domains_new_3_filtered.lst",

    "inactive": "domains_new_3_inactive.lst",

    "cloudflare": "domains_new_3_cloudflare.lst",

    "ssl_error": "domains_new_3_ssl_error.lst",

    "timeout": "domains_new_3_timeout.lst",

    "cdn_timeout": "domains_new_3_cdn_timeout.lst",

    "connection_error": "domains_new_3_connection_error.lst",

    "error": "domains_new_3_error.lst",

    "non_html": "domains_new_3_non_html.lst",
}



FINAL_OUTPUT_FILE = "domains.lst"

PASS_OUTPUT_FILE = OUT_FILES["clean"]

CONN_ERR_DETAIL_FILE = "domains_new_3_connection_error_detail.log"

# Fast pass - Enhanced timeouts for better success rates

DEFAULT_CONCURRENCY = 120

CONCURRENCY = int(os.environ.get('STEP3_CONCURRENCY', DEFAULT_CONCURRENCY))

MAX_RETRIES = 2

MAX_BYTES = 200_000

TOTAL_TIMEOUT = 30      # Increased from 12s for better success rates

CONNECT_TIMEOUT = 10    # Increased from 5s for slow DNS/connections

READ_TIMEOUT = 20       # Increased from 7s for content loading

CHUNK_SIZE = 8192

# Timeout Rescue (before fallback) - Even more generous timeouts

DEFAULT_RESCUE_CONCURRENCY = 120

RESCUE_CONCURRENCY = int(os.environ.get('STEP3_RESCUE_CONCURRENCY', DEFAULT_RESCUE_CONCURRENCY))

RESCUE_TOTAL_TIMEOUT = 45    # Increased from 25s

RESCUE_CONNECT_TIMEOUT = 15  # Increased from 8s

RESCUE_READ_TIMEOUT = 30     # Increased from 15s

RESCUE_FORCE_IPV4 = True

# CDN-specific rescue tuning

CDN_THROTTLE_DOMAINS = (

    'linkedin.com',
    'patreon.com',
)

CDN_HEADER_HINTS = (

    ('server', 'akamai'),

    ('server', 'akamai ghost'),

    ('server', 'akamaighost'),

    ('x-cache', 'akam'),

    ('x-akamai', ''),

    ('x-served-by', 'cache'),  # Fastly-style

    ('x-cache', ''),           # Generic cache marker

    ('x-cache-hits', ''),      # Generic cache marker
)

CDN_TIMEOUT_LABEL = 'cdn_timeout'

ACCEPTABLE_FINAL_STATUSES = {"clean", "filtered", "inactive"}

FINAL_STATUS_PREFERENCE = ("clean", "filtered", "inactive")

FAILOVER_STATUS_PREFERENCE = ("cloudflare", CDN_TIMEOUT_LABEL, "timeout", "connection_error", "ssl_error", "non_html", "error")

CDN_RESCUE_CONCURRENCY = 20

CDN_TOTAL_TIMEOUT = 75

CDN_CONNECT_TIMEOUT = 20

CDN_READ_TIMEOUT = 50

# Writer buffers

BATCH_LINES = 500

FLUSH_INTERVAL_SEC = 2.0

MAX_BUFFERED_LINES = 50_000

# Runtime tuning helpers

LOW_MEM_PROFILE = {

    "max_concurrency": 160,

    "rescue_concurrency": 60,

    "fallback_browsers": 2,

    "chunk_size": 4096,

    "max_bytes": 150_000,
}

PRIORITY_TLDS: Tuple[str, ...] = ("com", "media", "io")

def prioritize_domains(domains: List[str]) -> List[str]:

    buckets = {tld: [] for tld in PRIORITY_TLDS}

    rest: List[str] = []

    for dom in domains:

        parts = dom.rsplit('.', 1)

        tld = parts[1] if len(parts) == 2 else ''


        if tld in buckets:



            buckets[tld].append(dom)



        else:



            rest.append(dom)



    ordered: List[str] = []



    for tld in PRIORITY_TLDS:



        ordered.extend(buckets[tld])



    ordered.extend(rest)



    return ordered



def configure_runtime(


    *,

    max_concurrency: Optional[int] = None,

    rescue_concurrency: Optional[int] = None,

    fallback_browsers: Optional[int] = None,

    chunk_size: Optional[int] = None,

    max_bytes: Optional[int] = None,


) -> Dict[str, int]:

    """Apply runtime overrides for concurrency/download limits."""

    global CONCURRENCY, RESCUE_CONCURRENCY, FALLBACK_MAX_BROWSERS, CHUNK_SIZE, MAX_BYTES

    adjustments: Dict[str, int] = {}



    def _norm(value: Optional[int], minimum: int) -> Optional[int]:



        if value is None:



            return None



        try:



            value_int = int(value)



        except (TypeError, ValueError):



            return None



        return max(minimum, value_int)



    new_conc = _norm(max_concurrency, 10)



    if new_conc is not None and new_conc != CONCURRENCY:



        CONCURRENCY = new_conc



        adjustments["concurrency"] = new_conc



    new_rescue = _norm(rescue_concurrency, 10)



    if new_rescue is not None and new_rescue != RESCUE_CONCURRENCY:



        RESCUE_CONCURRENCY = new_rescue



        adjustments["rescue_concurrency"] = new_rescue



    new_fb = _norm(fallback_browsers, 1)



    if new_fb is not None and new_fb != FALLBACK_MAX_BROWSERS:



        FALLBACK_MAX_BROWSERS = new_fb



        adjustments["fallback_browsers"] = new_fb



    new_chunk = _norm(chunk_size, 1024)



    if new_chunk is not None and new_chunk != CHUNK_SIZE:



        CHUNK_SIZE = new_chunk



        adjustments["chunk_size"] = new_chunk



    new_max_bytes = _norm(max_bytes, 50_000)



    if new_max_bytes is not None and new_max_bytes != MAX_BYTES:



        MAX_BYTES = new_max_bytes



        adjustments["max_bytes"] = new_max_bytes



    return adjustments



def ensure_memory_headroom() -> Dict[str, float]:



    if psutil is None:



        return {}



    try:



        vm = psutil.virtual_memory()



        avail_gb = vm.available / (1024 ** 3)



    except Exception:



        return {}



    adjustments: Dict[str, float] = {}



    if avail_gb < 1.5:



        scaled = configure_runtime(**LOW_MEM_PROFILE)



        if scaled:



            adjustments.update(scaled)



    if avail_gb < 1.5 or adjustments:



        adjustments["available_gb"] = round(avail_gb, 2)



    return adjustments



async def memory_monitor(interval: float) -> None:



    if psutil is None:



        print_status("psutil not available; memory monitor disabled", "warning")



        return



    proc = psutil.Process()



    interval = max(interval, 1.0)



    try:



        while True:



            await asyncio.sleep(interval)



            with contextlib.suppress(Exception):



                rss = proc.memory_info().rss / (1024 ** 2)



                vm = psutil.virtual_memory()



                avail_gb = vm.available / (1024 ** 3)



                print_status(f"? Memory usage: RSS={rss:.1f} MiB, avail={avail_gb:.2f} GiB", "info")



    except asyncio.CancelledError:



        pass

FD_SAFETY_MARGIN = 64

FD_TARGET = 4096

def _get_fd_soft_limit() -> Optional[int]:



    if os.name == 'nt':



        try:



            import ctypes



            return int(ctypes.cdll.msvcrt._getmaxstdio())



        except Exception:



            return None



    try:

        import resource  # type: ignore

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)

        infinity = getattr(resource, 'RLIM_INFINITY', 2 ** 63 - 1)

        if soft in (0, infinity):



            soft = hard



        if soft in (0, infinity):



            return None



        return int(soft)



    except Exception:



        return None



def _attempt_raise_fd_limit(target: int) -> Optional[int]:



    if os.name == 'nt':



        try:



            import ctypes



            libc = ctypes.cdll.msvcrt



            current = int(libc._getmaxstdio())



            max_target = min(target, 2048)



            if current < max_target:



                new_limit = int(libc._setmaxstdio(max_target))



                if new_limit > current:



                    return new_limit



            return current



        except Exception:



            return None



    try:



        import resource  # type: ignore



        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)



        infinity = getattr(resource, 'RLIM_INFINITY', 2 ** 63 - 1)



        desired = target



        if hard not in (0, infinity):



            desired = min(desired, hard)



        if soft < desired:



            try:



                resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))



                return desired



            except Exception:



                return soft



        return soft



    except Exception:



        return None



def _estimate_fd_usage(conc: int, rescue: int, fallback: int) -> int:



    base = 128



    fallback_budget = max(64, fallback * 64)



    return base + conc * 2 + rescue * 2 + fallback_budget



def ensure_fd_headroom() -> Dict[str, int]:



    limit = _attempt_raise_fd_limit(FD_TARGET) or _get_fd_soft_limit()



    if limit is None:



        return {}



    safe_budget = max(limit - FD_SAFETY_MARGIN, 128)



    estimated = _estimate_fd_usage(CONCURRENCY, RESCUE_CONCURRENCY, FALLBACK_MAX_BROWSERS)



    if estimated <= safe_budget:



        return {'fd_limit': limit}



    scale = max(0.1, safe_budget / estimated)



    new_conc = max(10, int(CONCURRENCY * scale))



    new_rescue = max(5, int(RESCUE_CONCURRENCY * scale))



    new_fb = max(1, int(max(1, round(FALLBACK_MAX_BROWSERS * scale))))



    adjustments = configure_runtime(



        max_concurrency=new_conc,



        rescue_concurrency=new_rescue,



        fallback_browsers=new_fb



    )



    adjustments['fd_limit'] = limit



    return adjustments



# Scoring



WEIGHTS = {



    "DRUG_STRONG": 2.0,



    "DRUG_WEAK": 1.0,



    "CASINO": 1.0,



    "PHISHING": 1.5,



    "ILLEGAL": 2.0,



    "ADULT_STRONG": 6.0,



    "ADULT_WEAK": 2.0,



}



TITLE_BOOST = 2



THRESHOLD_SCORE = 12



MIN_KEYWORD_HITS = 3



CATEGORY_SUBSTRINGS = {



    "CASINO": ("казино", "casino", "слоты", "игровые автоматы", "игровые-автоматы", "1win", "1вин", "зеркало казино", "бездепозит", "vavada", "вавада", "pin-up", "pin up", "бурбон казино", "казино зеркало", "unlim casino"),



    "ILLEGAL": ("binary options", "investment plan", "double your money", "crypto investment", "Briansclub Dumps"),



    "DRUG_STRONG": ("купить наркот", "купить мефедрон", "купить кокаин", "купить героин", "мефедрон", "героин", "кокаин", "lsd", "mdma")



}

TITLE_BOOST = 2

DENSITY_THRESHOLD = 0.008

CRITICAL_PATTERNS = [



    r"\b(child\s*porn|детск\w*\s*порн\w*)\b",



    r"\b(zoo\s*porn|animal\s*porn|зоопорн\w*)\b",



    r"\b(snuff)\b",


]

CRITICAL_RE = [re.compile(p, re.I) for p in CRITICAL_PATTERNS]

INACTIVE_PATTERNS = [



    r"\b(this\s+domain\s+is\s+for\s+sale|сайт\s+продается|domain\s+for\s+sale|продажа\s+домена|parked\s+by)\b",



    r"\b(under\s+construction|сайт(?:\s+находится)?\s+в\s+разработке|maintenance\s+mode|temporarily\s+unavailable|under\s+maintenance)\b",



    r"\b(default\s+page|future\s+home\s+of|domain\s+default\s+page)\b",



    r"\b(page\s+not\s+found|404\s+not\s+found|error\s+523)\b",



    r"\b(website .* is ready|your website is ready)\b",



    r"\b(домен\s+истек|домен\s+зарегистрирован\s+и\s+припаркован)\b",



    r"\b(ip address could not be found|err_name_not_resolved|this site can.?t be reached)\b",



    r"^index of\s*/\s*$",



    r"\bexpired\b",



    r"\btoo many requests?\b",



    r"\btimeweb\b",



    r"\bсайт временно отключен\b",



    r"\bHugeDomains\.com\b",



    r"Why am I seeing this page\?",



    r"This domain is registered at NameSilo",



    r"Your domain is pointed to the server, but there",



    r"is a custom short domain",



    r"THIS WEBSITE IS OFFLINE",



    r"Домен не прилинкован",



    r"актуальный домен" ,



    r"Redirecting...",



    r"домен продаётся",



    r'^Домен (?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,}) продаётся$',



    r"Домен успешно зарегистрирован!",



    r"Домен успешно привязан к хостингу",



    r"Страница заблокирована по требованию Роскомнадзора или из-за нарушения правил хостинга!",



    r"OFFLINE ТЕХ РАБОТЫ",



    r"Buy domain",



    r"Domain Details Page",



    r"Success! Your new web server is ready to use",



    r"Click here to enter",



    r"503 Service Unavailable",



    r"\b[\w.-]+\s+is\s+for\s+sale\b",



]



INACTIVE_RE = [re.compile(p, re.I | re.S | re.M) for p in INACTIVE_PATTERNS]



# Drugs/adult WEAK/STRONG



DRUG_STRONG_RE = re.compile(



    r"(?is)\b(?:"



    r"(?:купить|заказать|доставка|buy|order|shipping)\s+(?:наркотики|порошок|таблетки|мефедрон|амфетамин|героин|кокаин|lsd|dmt|экстази|mdma|фентанил|оксикодон|оксиконтин|перкоцет)"



    r"|метамфетамин|mefedron|мефедрон|амфетамин|Diller|amfetamin|cocaine|кокаин|героин|heroin|(?:buy|sell|order|purchase|get)\s+(?:lsd|dmt|mdma)|фентанил|fentanyl|оксикодон|oxy(?:codone|contin)|percocet"



    r"|opium|опиум|психоделик(?:и)?|psychedelic(?:s)?"



    r"|blacksprut|кракен|kraken|kr2web|стероиды|Brutal+Market|Pharma|купить\s+стероиды"



    r"|kra(?:[1-9]|[1-9][0-9])"



    r"|кра(?:[1-9]|[1-9][0-9])"



    r")\b"



)



DRUG_WEAK_RE = re.compile(



    r"(?is)\b(?:drugs|наркотик(?:и)?|weed|cannabis|Мориарти сайт Мега|каннабис|семена конопли|Cемяныч|конопель|марихуана|cbd|мариухана|конопля|гашиш|спайс|анаша)\b"



)



ADULT_STRONG_RE = re.compile(



    r"(?is)\b(?:"



    r"child\s*porn"



    r"|child\s*sexual\s*abuse"



    r"|underage\s*(?:porn|sex|videos?)"



    r"|teen\s*(?:porn|sex)\s*(?:under\s*18)?"



    r"|animal\s*porn"



    r"|beastiality"



    r"|bestiality"



    r"|zoophil(?:ia|e)"



    r"|rape\s*porn"



    r"|forced\s*sex"



    r"|snuff\s*porn"



    r")\b"



)



ADULT_WEAK_RE = re.compile(



    r"(?is)\b(?:проститутк[иау]|индивидуалк[иуа]|эскорт|секс\s*знакомств[аыо]?)\b"



)



CASINO_RE = re.compile(



    r"\b(?:казино|игры на деньги|покер|poker|blackjack|roulette|slots|jackpot|winbig|1win|1XBET|vulkan|адмирал|лотерея|poker|sloty|рулетка|джекпот|слоты|бонусы|игровые автоматы|Обзор игрового автомата|крутить|1хбет зеркало|betting|bookmaker|ставки на спорт|ставка на спорт|ставки в казино|букмекер|ставки онлайн|casino mirror|казино зеркало|free spins|no deposit bonus|bonusesfinder|Актуальное зеркало|Казино ARKADA|Arkada Casino|Аркада Казино|Casino|R7 Casino|Обзор слота|1Win|Vavada|Вавада|казино онлайн|WebSite 2025|WebSite 2024|BETWINNER|Бетвиннер|Фортуна зеркало|Драгон Мани|Криптоказино|1ВИН|Онлайн-казино|вход на рабочее зеркало)\b",



    re.I,



)



PHISHING_RE = re.compile(



    r"\b(?:доступ к счету|инвестируй|зарабатывай|Начать з а р а б а т ы в а т ь|стабильный доход|Получите доступ к заработку в интернете|оформи займ|требуется подтверждение|Investment Platform|update billing|security alert|rutor.org закрыли|account verification|(?:urgent|immediate|click here to|verify now|act now)\s+(?:confirm your identity|verify your account)|limited access|suspicious activity detected|(?:your account\s(?:has|was|is|may)\s+(?:be\s+)?(?:suspended|locked|disabled|limited|compromised|blocked|closed)|your account\s(?:requires|needs)\s(?:verification|attention)|your account\s(?:security|login)\s(?:alert|warning)|account has been\s(?:suspended|locked|disabled|limited|compromised)|immediately verify|urgent verification)|phishing|phish)\b",



    re.I,



)



ILLEGAL_RE = re.compile(



    r"\b(?:поддельный паспорт|russianbrides|русские невесты|fake passport|counterfeit|поддельные документы|counterfeit goods|buy ssn|buy passport|fake id|darkmarket|darknet|\.onion|advcash|payeer|qiwi|webmoney|yoomoney|ccloan|payday|propisku|Carding Forum|Darkvapeshop|Darkshop|DARK2WEB|Darkweb|даркнет)\b",



    re.I,



)



CATEGORY_RES = [



    ("DRUG_STRONG", DRUG_STRONG_RE),



    ("DRUG_WEAK", DRUG_WEAK_RE),



    ("CASINO", CASINO_RE),



    ("PHISHING", PHISHING_RE),



    ("ILLEGAL", ILLEGAL_RE),



    ("ADULT_STRONG", ADULT_STRONG_RE),



    ("ADULT_WEAK", ADULT_WEAK_RE),



]



USER_AGENTS = [



    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",



    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",



    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",



]



# Fallback common



FALLBACK_BODY_MIN = 100



FALLBACK_HTTP_TIMEOUT = 15



# Use OS temp dir for cross-platform profile storage (more reliable on Linux servers and Windows)



TMP_PROFILE_BASE = Path(tempfile.gettempdir()) / "step3_profiles"



TMP_PROFILE_BASE.mkdir(parents=True, exist_ok=True)



# Arch-based selection



ARCH = platform.machine().lower()



IS_ARM = ARCH in ("aarch64", "arm64")



# Auto-scale fallback Selenium/UC workers (can override with FALLBACK_MAX_BROWSERS env)



if IS_ARM:



    DEFAULT_FALLBACK_BROWSERS = 1



else:



    cpu_guess = os.cpu_count() or 4



    DEFAULT_FALLBACK_BROWSERS = max(2, min(6, max(1, cpu_guess // 2)))



FALLBACK_MAX_BROWSERS = int(os.environ.get('FALLBACK_MAX_BROWSERS', DEFAULT_FALLBACK_BROWSERS))



# Disable browser fallback in this variant



ENABLE_BROWSER_FALLBACK = False



FB_CHUNK = 800 if IS_ARM else 1200  # domains per chunk



FB_CHUNK = 800 if IS_ARM else 1200  # domains per chunk



SUPPORTED_PY = {(3, 9), (3, 10), (3, 11), (3, 12)}



SUPPORTED_PY_STR = ", ".join(f"{a}.{b}" for a,b in sorted(SUPPORTED_PY))



# =========================



# Enhanced Logging & Progress
#
# File log strips ANSI colors; console keeps color for readability.



# =========================



LOG_FILE = Path(__file__).resolve().with_name("domain_step3_analysis.log")



class ColorStrippingFormatter(logging.Formatter):



    """Formatter that removes ANSI color codes for log files."""



    ansi = re.compile(r"\x1B\\[[0-?]*[ -/]*[@-~]")



    def format(self, record):



        formatted = super().format(record)



        return self.ansi.sub("", formatted)



init()



logger = logging.getLogger("content-checker")



logger.setLevel(logging.INFO)



logger.handlers.clear()



logger.propagate = False



file_fmt = ColorStrippingFormatter("%(asctime)s - %(levelname)s - %(message)s")



fh = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")



fh.setFormatter(file_fmt)



console_fmt = logging.Formatter("%(message)s")



sh = logging.StreamHandler(sys.stdout)



sh.setFormatter(console_fmt)



logger.addHandler(fh)



logger.addHandler(sh)



# Statistics tracking



stats = {



    'total': 0,



    'clean': 0,



    'filtered': 0,



    'inactive': 0,



    'cloudflare': 0,



    'ssl_error': 0,



    'timeout': 0,



    'cdn_timeout': 0,



    'connection_error': 0,



    'error': 0,



    'non_html': 0,



    'fallback_processed': 0



}


def print_header():



    """Print a colorful header for the script."""



    print(f"\n{Fore.CYAN}{'='*80}")



    print(f"{Fore.CYAN}{'STEP 3 - CONTENT ANALYSIS WITH ENHANCED PROGRESS TRACKING':^80}")



    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")



def print_status(message, status_type="info"):



    """Print colored status messages."""



    colors = {



        "info": Fore.BLUE,



        "success": Fore.GREEN,



        "warning": Fore.YELLOW,



        "error": Fore.RED,



        "progress": Fore.CYAN,



        "dns": Fore.MAGENTA,



        "http": Fore.CYAN,



        "fallback": Fore.MAGENTA



    }



    level_map = {



        "error": logging.ERROR,



        "warning": logging.WARNING,



    }



    level = level_map.get(status_type, logging.INFO)



    msg = f"{colors.get(status_type, Fore.WHITE)}{message}{Style.RESET_ALL}"



    logger.log(level, msg)



def normalize_host(host: Optional[str]) -> str:



    if not host:



        return ""



    return host.strip().lower().strip('.')



def host_matches_suffix(host: str, suffixes: Iterable[str]) -> bool:



    host = normalize_host(host)



    if not host:



        return False



    for suffix in suffixes:



        suffix_norm = normalize_host(suffix)



        if not suffix_norm:



            continue



        if host == suffix_norm or host.endswith('.' + suffix_norm):



            return True



    return False



def is_cdn_throttled_host(host: Optional[str]) -> bool:



    return host_matches_suffix(host or '', CDN_THROTTLE_DOMAINS)



def headers_hint_cdn(headers: Optional[Dict[str, str]]) -> bool:



    if not headers:



        return False



    for key, needle in CDN_HEADER_HINTS:



        value = headers.get(key)



        if value is None:



            for hk, hv in headers.items():



                if hk and hk.lower() == key.lower():



                    value = hv



                    break



        if value is None:



            continue



        if not needle:



            return True



        if needle.lower() in str(value).lower():



            return True



    return False



def extract_host_from_url(url: Optional[str]) -> str:



    if not url:



        return ""



    try:



        return urlparse(url).hostname or ""



    except Exception:



        return ""



def is_cdn_candidate(domain: str, headers: Optional[Dict[str, str]] = None, final_url: Optional[str] = None) -> bool:



    if is_cdn_throttled_host(domain):



        return True



    if final_url and is_cdn_throttled_host(extract_host_from_url(final_url)):



        return True



    if headers and headers_hint_cdn(headers):



        return True



    return False



def print_domain_status(domain, status, score=None, details=""):



    """Print domain status with appropriate colors."""



    colors = {



        "clean": Fore.GREEN,



        "filtered": Fore.RED,



        "inactive": Fore.CYAN,



        "cloudflare": Fore.BLUE,



        "ssl_error": Fore.YELLOW,



        "timeout": Fore.YELLOW,



        "cdn_timeout": Fore.MAGENTA,



        "connection_error": Fore.YELLOW,



        "error": Fore.RED,



        "non_html": Fore.YELLOW



    }



    symbols = {



        "clean": "✅",



        "filtered": "🚫",



        "inactive": "💤",



        "cloudflare": "☁️",



        "ssl_error": "🔒",



        "timeout": "⏰",



        "cdn_timeout": "⏰",



        "connection_error": "🔌",



        "error": "⚠️",



        "non_html": "📄"



    }



    color = colors.get(status, Fore.WHITE)



    symbol = symbols.get(status, "❓")



    score_str = f" ({score:.1f})" if score is not None else ""



    level_map = {



        "filtered": logging.WARNING,



        "inactive": logging.INFO,



        "cloudflare": logging.WARNING,



        "ssl_error": logging.WARNING,



        "timeout": logging.WARNING,



        "cdn_timeout": logging.WARNING,



        "connection_error": logging.WARNING,



        "error": logging.ERROR,



        "non_html": logging.WARNING



    }



    level = level_map.get(status, logging.INFO)



    msg = f"{color}{symbol} {status.upper():<17}{Style.RESET_ALL} {domain}{score_str} {details}"



    logger.log(level, msg)



def update_stats(status):



    """Update statistics counters."""



    if status in stats:



        stats[status] += 1



# =========================



# Helpers



# =========================



def strip_tags(html: str) -> str:



    html = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)



    html = re.sub(r"(?is)<style.*?>.*?</style>", " ", html)



    return re.sub(r"(?s)<[^>]+>", " ", html)



TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")



META_DESC_RE = re.compile(r'(?is)<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']')



HEADING_RE = re.compile(r"(?is)<h[1-3][^>]*>(.*?)</h[1-3]>")



WHITESPACE_RE = re.compile(r"\s+")



def collapse_whitespace(value: str) -> str:



    return WHITESPACE_RE.sub(" ", value).strip()



def extract_first_heading(html: str) -> str:



    match = HEADING_RE.search(html)



    if not match:



        return ""



    return collapse_whitespace(strip_tags(match.group(1)))



def build_text_snippet(text: str, max_words: int = 28, max_chars: int = 160) -> str:



    words = text.split()



    if not words:



        return ""



    snippet_words: List[str] = []



    total_chars = 0



    for word in words:



        next_chars = len(word) if total_chars == 0 else len(word) + 1



        if snippet_words and (len(snippet_words) >= max_words or total_chars + next_chars > max_chars):



            break



        if not snippet_words and len(word) > max_chars:



            snippet_words.append(word[:max_chars])



            total_chars = max_chars



            break



        snippet_words.append(word)



        total_chars += next_chars



        if len(snippet_words) >= max_words or total_chars >= max_chars:



            break



    snippet = " ".join(snippet_words)



    if len(snippet_words) < len(words):



        snippet = snippet.rstrip(".,;:- ") + " ..."



    return snippet



def sanitize_for_log(text: str, limit: int = 120) -> str:



    collapsed = collapse_whitespace(text)



    if len(collapsed) > limit:



        trimmed = collapsed[: max(limit - 3, 0)].rstrip(".,;:- ")



        if limit >= 3:



            collapsed = trimmed + "..."



        else:



            collapsed = trimmed



    return collapsed.replace('"', "'")



def summarize_clean_page(html: str) -> str:



    title, meta = extract_title_meta(html)



    heading = extract_first_heading(html)



    visible = collapse_whitespace(strip_tags(html))



    parts: List[Tuple[str, str]] = []



    if title:



        parts.append(("title", sanitize_for_log(title, 90)))



    if heading and (not title or heading.lower() != title.lower()):



        parts.append(("h1", sanitize_for_log(heading, 90)))



    if meta and (not title or meta.lower() != title.lower()):



        parts.append(("meta", sanitize_for_log(meta, 110)))



    snippet = build_text_snippet(visible)



    if snippet:



        parts.append(("text", sanitize_for_log(snippet, 150)))



    if not parts:



        return ""



    selected = parts[:4]



    return " ".join(f'{label}="{value}"' for label, value in selected)



def extract_title_meta(html: str) -> Tuple[str, str]:



    title_m = TITLE_RE.search(html)



    title = title_m.group(1).strip() if title_m else ""



    meta_m = META_DESC_RE.search(html)



    meta = meta_m.group(1).strip() if meta_m else ""



    return title, meta



def sample_matches(text: str, max_items: int = 5) -> List[str]:



    words = []



    for _, cre in CATEGORY_RES:



        words.extend([m.group(0) for m in cre.finditer(text)])



        if len(words) >= max_items:



            break



    return words[:max_items]



def is_html_content_type(ct: Optional[str]) -> bool:



    if not ct:



        return True



    ct = ct.lower()



    return ("text/html" in ct) or ("application/xhtml" in ct)



def looks_cloudflare(headers: aiohttp.typedefs.LooseHeaders) -> bool:



    h = {k.lower(): v for k, v in headers.items()} if headers else {}



    server = h.get("server", "")



    server_l = server.lower()



    if ("cloudflare" in server_l) or ("cf-ray" in h) or ("cf-cache-status" in h):



        return True



    # Treat other CDN/anti-DDoS blockers as Cloudflare-equivalent to trigger retries/fallback.



    akamai = ("akamai" in server_l) or any(k.startswith("x-akamai") or k.startswith("akamai-") for k in h)



    ddg = "ddos-guard" in server_l



    incapsula = ("incapsula" in server_l) or ("x-cdn" in h and "incapsula" in str(h.get("x-cdn", "")).lower()) or ("x-iinfo" in h)



    sucuri = ("sucuri" in server_l) or any(k.startswith("x-sucuri") for k in h)



    stackpath = ("stackpath" in server_l) or ("x-cdn" in h and "stackpath" in str(h.get("x-cdn", "")).lower())



    reblaze = any(k.startswith("x-reblaze") for k in h) or ("rbzid" in h)



    blazingfast = "blazingfast" in server_l



    fastly = ("fastly" in server_l) or ("x-served-by" in h and "fastly" in str(h.get("x-served-by", "")).lower())



    if akamai or ddg or incapsula or sucuri or stackpath or reblaze or blazingfast or fastly:



        return True



    return False



def short_reason(msg: str) -> str:



    m = (msg or "").lower()



    if "name or service not known" in m or "nodename nor servname" in m or "temporary failure in name resolution" in m:



        return "dns_failed"



    if "connect call failed" in m and ("refused" in m or "111" in m):



        return "refused"



    if "connection reset" in m or "reset by peer" in m:



        return "reset"



    if "network is unreachable" in m or "no route to host" in m:



        return "unreachable"



    return "other"



# =========================



# Quality Check



# =========================



def load_domains_from_file(filepath: str) -> Set[str]:



    """Load domains from a file and return as a set of lowercase domains."""



    if not os.path.exists(filepath):



        return set()



    domains = set()



    try:



        with open(filepath, "r", encoding="utf-8") as f:



            for line in f:



                domain = line.strip().lower()



                if domain:



                    domains.add(domain)



    except Exception as e:



        logger.warning(f"Failed to load domains from {filepath}: {e}")



    return domains



def build_final_output(final_path: Path, sources: Iterable[Path]) -> int:



    """Combine multiple domain lists into a single deduplicated file."""



    seen: Set[str] = set()



    ordered: List[str] = []



    for src in sources:



        src_path = Path(src)



        if not src_path.exists():



            continue



        try:



            lines = src_path.read_text(encoding="utf-8").splitlines()



        except UnicodeDecodeError:



            lines = src_path.read_text(encoding="cp1251", errors="ignore").splitlines()



        for line in lines:



            domain = line.strip()



            if not domain or domain in seen:



                continue



            seen.add(domain)



            ordered.append(domain)



    if ordered:



        final_path.write_text("\n".join(ordered) + "\n", encoding="utf-8")



    else:



        final_path.write_text("", encoding="utf-8")



    return len(ordered)



def perform_quality_check() -> Tuple[int, int, List[str], List[str]]:



    """



    Perform quality check by comparing QC file against clean domains output.



    Returns: (matched_count, total_count, matched_domains, missing_domains)



    """



    logger.info(f"{Fore.CYAN}Running Quality Check...{Style.RESET_ALL}")



    # Load QC reference domains



    qc_domains = load_domains_from_file(QC_FILE)



    if not qc_domains:



        logger.warning(f"{Fore.YELLOW}QC file {QC_FILE} not found or empty. Skipping quality check.{Style.RESET_ALL}")



        return 0, 0, [], []



    # Load clean domains from output



    clean_domains = load_domains_from_file(Path(FINAL_OUTPUT_FILE))



    # Find matches and missing domains



    matched_domains = []



    missing_domains = []



    for qc_domain in sorted(qc_domains):



        if qc_domain in clean_domains:



            matched_domains.append(qc_domain)



        else:



            missing_domains.append(qc_domain)



    total_count = len(qc_domains)



    matched_count = len(matched_domains)



    # Display results



    logger.info(f"{Fore.CYAN}Quality Check Results:{Style.RESET_ALL}")



    logger.info(f"  Score: {Fore.GREEN}{matched_count}/{total_count}{Style.RESET_ALL}")



    logger.info(f"  Success Rate: {Fore.GREEN}{(matched_count/total_count*100):.1f}%{Style.RESET_ALL}")



    if matched_domains:



        logger.info(f"  {Fore.GREEN}✓ Matched domains ({len(matched_domains)}):{Style.RESET_ALL}")



        for domain in matched_domains:



            logger.info(f"    {Fore.GREEN}✓{Style.RESET_ALL} {domain}")



    if missing_domains:



        logger.info(f"  {Fore.RED}✗ Missing domains ({len(missing_domains)}):{Style.RESET_ALL}")



        for domain in missing_domains:



            logger.info(f"    {Fore.RED}✗{Style.RESET_ALL} {domain}")



    # Check if any missing domains ended up in other output files



    if missing_domains:



        logger.info(f"  {Fore.YELLOW}Checking where missing domains ended up...{Style.RESET_ALL}")



        for missing_domain in missing_domains:



            found_in = []



            for category, filename in OUT_FILES.items():



                if category != "clean":



                    category_domains = load_domains_from_file(filename)



                    if missing_domain in category_domains:



                        found_in.append(category)



            if found_in:



                logger.info(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} {missing_domain} → {', '.join(found_in)}")



            else:



                logger.info(f"    {Fore.RED}✗{Style.RESET_ALL} {missing_domain} → not found in any output file")



    return matched_count, total_count, matched_domains, missing_domains



# =========================



# Scoring



# =========================



# Major legitimate domains that should have reduced scoring to avoid false positives



LEGITIMATE_DOMAINS = {



    'facebook.com', 'fb.com', 'instagram.com', 'twitter.com', 'x.com', 'youtube.com', 



    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',



    'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'linkedin.com',



    'tiktok.com', 'snapchat.com', 'discord.com', 'telegram.org', 'whatsapp.com',



    'paypal.com', 'stripe.com', 'shopify.com', 'wordpress.com', 'medium.com', 'metacritic.com'



}



def is_legitimate_domain(domain: str) -> bool:



    """Check if domain is a major legitimate platform."""



    domain_lower = domain.lower().strip()



    return domain_lower in LEGITIMATE_DOMAINS or any(domain_lower.endswith(f'.{leg_domain}') for leg_domain in LEGITIMATE_DOMAINS)



def score_content(html: str, domain: str = "") -> Tuple[float, Dict[str, int], Dict[str, int]]:



    title, meta = extract_title_meta(html)



    text_lower = html.lower()



    visible_text = strip_tags(html)



    words = visible_text.split()



    word_count = max(len(words), 1)



    for cre in CRITICAL_RE:



        if cre.search(visible_text):



            return 1e9, {}, {}



    hits_by_cat: Dict[str, int] = {}



    title_hits_by_cat: Dict[str, int] = {}



    total_score = 0.0



    keyword_hit_total = 0



    title_meta = (title + " " + meta).lower()



    visible_lower = visible_text.lower()



    combined_text = f"{title_meta} {visible_lower}"



    for cat, cre in CATEGORY_RES:



        w = WEIGHTS.get(cat, 1.0)



        body_hits = len(list(cre.finditer(text_lower)))



        tm_hits = len(list(cre.finditer(title_meta))) if title_meta else 0



        if body_hits or tm_hits:



            hits_by_cat[cat] = body_hits



            title_hits_by_cat[cat] = tm_hits



            keyword_hit_total += body_hits + tm_hits



            total_score += w * (body_hits + TITLE_BOOST * tm_hits)



    for cat, substrings in CATEGORY_SUBSTRINGS.items():



        if hits_by_cat.get(cat, 0) or title_hits_by_cat.get(cat, 0):



            continue



        if any(sub in combined_text for sub in substrings):



            hits_by_cat[cat] = max(hits_by_cat.get(cat, 0), 1)



            title_hits_by_cat[cat] = max(title_hits_by_cat.get(cat, 0), 1)



            keyword_hit_total += 1



            total_score += WEIGHTS.get(cat, 0) * TITLE_BOOST



    # Apply penalty for legitimate domains to reduce false positives



    density_threshold = DENSITY_THRESHOLD



    legitimate_domain = bool(domain and is_legitimate_domain(domain))



    if legitimate_domain:



        # Reduce score by 50% for legitimate domains to avoid false positives



        total_score *= 0.5



        density_threshold *= 2



    density = total_score / word_count



    if density > density_threshold and not legitimate_domain:



        total_score = max(total_score, THRESHOLD_SCORE)



    if keyword_hit_total < MIN_KEYWORD_HITS:



        total_score = 0.0



    return total_score, hits_by_cat, title_hits_by_cat



def detect_inactive(html: str, status: int) -> Optional[str]:



    if status in (404, 410, 451, 503):



        return f"status={status}"



    text = strip_tags(html)



    for cre in INACTIVE_RE:



        if cre.search(text):



            return f"pattern={cre.pattern}"



    return None



# =========================



# Fetcher (fast pass) with configurable rescue



# =========================



class ProxyPool:



    def __init__(self, proxies: List[str]):



        if not proxies:



            raise ValueError("No proxies provided")



        self.proxies = proxies



        self._cycle = cycle(proxies)



    def next_proxy(self) -> str:



        return next(self._cycle)



    def order_from(self, first: str) -> List[str]:



        if first not in self.proxies:



            return list(self.proxies)



        idx = self.proxies.index(first)



        return self.proxies[idx:] + self.proxies[:idx]



def load_proxies(proxy_file: str) -> List[str]:



    path = Path(proxy_file)



    if not path.exists():



        return []



    proxies: List[str] = []



    try:



        with open(path, 'r', encoding='utf-8') as f:



            for line in f:



                raw = line.strip()



                if not raw or raw.startswith('#'):



                    continue



                scheme = "http"



                body = raw



                if "://" in raw:



                    scheme, body = raw.split("://", 1)



                parts = body.split(":")



                if len(parts) >= 4:



                    host, port, user, pwd = parts[0], parts[1], parts[2], ":".join(parts[3:])



                    prox = f"{scheme}://{user}:{pwd}@{host}:{port}"



                elif len(parts) >= 2:



                    host, port = parts[0], parts[1]



                    prox = f"{scheme}://{host}:{port}"



                else:



                    prox = f"{scheme}://{body}"



                proxies.append(prox)



    except Exception as e:



        logger.error(f'Failed to read proxies from {proxy_file}: {e}')



    if any(p.lower().startswith('socks') for p in proxies) and not HAVE_SOCKS:



        logger.warning('Socks proxies requested but aiohttp_socks not installed; those entries will fail')



    return proxies



def compute_concurrency_limits(proxy_count: int) -> Tuple[int, int]:

    if proxy_count <= 0:

        return CONCURRENCY, CONCURRENCY

    per_host = max(1, PROXY_PARALLEL_PER_HOST)

    base_total = max(per_host * proxy_count, per_host)

    overall = base_total if PROXY_PARALLEL_ONLY else min(CONCURRENCY, base_total)

    per_proxy = max(2, overall // proxy_count)

    return overall, per_proxy


def mask_proxy(proxy: str) -> str:



    """Hide credentials; return scheme://host:port."""



    try:



        parsed = urlparse(proxy)



        scheme = parsed.scheme or "http"



        host = parsed.hostname or ""



        port = parsed.port



        if not host:



            return proxy



        return f"{scheme}://{host}{f':{port}' if port else ''}"



    except Exception:



        return proxy



def proxy_parts(proxy: str) -> Tuple[str, Optional[str], Optional[str], str, Optional[int]]:



    """Return (scheme, user, pwd, host, port)."""



    parsed = urlparse(proxy)



    return (



        parsed.scheme or "http",



        parsed.username,



        parsed.password,



        parsed.hostname or "",



        parsed.port,



    )



def proxy_arg_for_browser(proxy: Optional[str]) -> Optional[str]:



    if not proxy:



        return None



    scheme, user, pwd, host, port = proxy_parts(proxy)



    if not host:



        return None



    auth = ""



    if user:



        auth_user = user



        auth_pwd = pwd or ""



        auth = f"{auth_user}:{auth_pwd}@"



    return f"{scheme}://{auth}{host}{f':{port}' if port else ''}"



class Fetcher:
    # HTTP fetcher with retry/rescue support and optional proxy routing.



    def __init__(



        self,



        *,



        concurrency: int = CONCURRENCY,



        total_timeout: int = TOTAL_TIMEOUT,



        connect_timeout: int = CONNECT_TIMEOUT,



        read_timeout: int = READ_TIMEOUT,



        ttl_dns_cache: int = 300,



        force_ipv4: bool = False,



        proxy_url: Optional[str] = None,



    ):



        self.proxy_url = proxy_url



        self._use_request_proxy = False



        timeout = ClientTimeout(total=total_timeout, connect=connect_timeout, sock_read=read_timeout)



        resolver = None



        if force_ipv4:



            class IPv4Resolver(aiohttp.abc.AbstractResolver):



                async def resolve(self, host, port=0, family=socket.AF_INET):



                    loop = asyncio.get_event_loop()



                    infos = await loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)



                    out = []



                    for family, _, _, _, sockaddr in infos:



                        out.append({"hostname": host, "host": sockaddr[0], "port": port, "family": family, "proto": 0, "flags": 0})



                    return out



                async def close(self):



                    pass



            resolver = IPv4Resolver()



        else:



            try:



                from aiohttp.resolver import AsyncResolver



                resolver = AsyncResolver()



            except Exception:



                resolver = None



        if proxy_url and proxy_url.lower().startswith("socks"):



            if not HAVE_SOCKS:



                raise RuntimeError("aiohttp_socks is required for socks proxies")



            self.connector = ProxyConnector.from_url(proxy_url, limit=concurrency, ttl_dns_cache=ttl_dns_cache, rdns=True)



        else:



            self.connector = aiohttp.TCPConnector(



                limit=concurrency,



                ttl_dns_cache=ttl_dns_cache,



                resolver=resolver,



                enable_cleanup_closed=True,



                keepalive_timeout=15,



                happy_eyeballs_delay=0.25,



            )



            if proxy_url:



                self._use_request_proxy = True



        self.session = aiohttp.ClientSession(timeout=timeout, connector=self.connector, trust_env=False)



    async def close(self):



        await self.session.close()



        try:



            await self.connector.close()



        except Exception:



            pass



    async def _fetch_once(self, scheme: str, domain: str) -> Tuple[str, int, aiohttp.typedefs.LooseHeaders, str]:



        url = f"{scheme}://{domain}"



        headers = {



            "User-Agent": USER_AGENTS[hash(domain) % len(USER_AGENTS)],



            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",



            "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",



            "Cache-Control": "no-cache",



            "Pragma": "no-cache",



            "Connection": "close",



        }



        proxy_kwargs = {"proxy": self.proxy_url} if self.proxy_url and self._use_request_proxy else {}



        async with self.session.get(url, allow_redirects=True, headers=headers, **proxy_kwargs) as r:



            if not is_html_content_type(r.headers.get("Content-Type")):



                return "", r.status, r.headers, str(r.url)



            buf = bytearray()



            async for chunk in r.content.iter_chunked(CHUNK_SIZE):



                buf.extend(chunk)



                if len(buf) >= MAX_BYTES:



                    break



            charset = r.charset or "utf-8"



            try:



                text = buf.decode(charset, errors="ignore")



            except Exception:



                text = buf.decode("utf-8", errors="ignore")



            return text, r.status, r.headers, str(r.url)



    async def fetch(self, domain: str) -> Tuple[Optional[str], str, Optional[int], Optional[Dict[str, str]], Optional[str]]:



        domain_norm = normalize_host(domain)



        cdn_candidate = is_cdn_throttled_host(domain_norm)



        for scheme in ("https", "http"):



            for attempt in range(MAX_RETRIES + 1):



                try:



                    text, status, hdrs, final_url = await self._fetch_once(scheme, domain)



                    if not cdn_candidate:



                        cdn_candidate = is_cdn_candidate(domain, dict(hdrs), final_url)



                    if not is_html_content_type(hdrs.get("Content-Type")):



                        return None, "non_html", status, dict(hdrs), None



                    if looks_cloudflare(hdrs) and status in (403, 429, 503):



                        return None, "cloudflare", status, dict(hdrs), None



                    if status >= 500:



                        if attempt < MAX_RETRIES:



                            await asyncio.sleep(0.3 * (attempt + 1))



                            continue



                        return None, "error", status, dict(hdrs), None



                    if status in (403, 401, 429):



                        lbl = "cloudflare" if looks_cloudflare(hdrs) else "error"



                        return None, lbl, status, dict(hdrs), None



                    if status >= 400:



                        return text or "", "success", status, dict(hdrs), None



                    return text or "", "success", status, dict(hdrs), None



                except ClientSSLError:



                    return None, "ssl_error", None, None, None



                except asyncio.TimeoutError:



                    if attempt < MAX_RETRIES:



                        await asyncio.sleep(0.2 * (attempt + 1))



                        continue



                    label = CDN_TIMEOUT_LABEL if cdn_candidate else "timeout"



                    return None, label, None, None, None



                except ClientConnectorError as e:



                    if attempt == MAX_RETRIES and domain.count(".") == 1:



                        try:



                            text, status, hdrs, final_url = await self._fetch_once(scheme, "www." + domain)



                            if not cdn_candidate:



                                cdn_candidate = is_cdn_candidate("www." + domain, dict(hdrs), final_url)



                            if not is_html_content_type(hdrs.get("Content-Type")):



                                return None, "non_html", status, dict(hdrs), None



                            if status >= 400:



                                if status in (401, 403, 429):



                                    lbl = "cloudflare" if looks_cloudflare(hdrs) else "error"



                                    return None, lbl, status, dict(hdrs), None



                                return text or "", "success", status, dict(hdrs), None



                            return text or "", "success", status, dict(hdrs), None



                        except Exception:



                            pass



                    err_detail = str(e)



                    if attempt < MAX_RETRIES:



                        await asyncio.sleep(0.2 * (attempt + 1))



                        continue



                    return None, "connection_error", None, None, err_detail



                except Exception as e:



                    if attempt < MAX_RETRIES:



                        await asyncio.sleep(0.2 * (attempt + 1))



                        continue



                    return None, "error", None, None, str(e)



        return None, "error", None, None, None



class Writer:



    def __init__(self):



        self._buffers: Dict[str, List[str]] = {k: [] for k in OUT_FILES}



        self._locks: Dict[str, asyncio.Lock] = {k: asyncio.Lock() for k in OUT_FILES}



        self._flush_lock = asyncio.Lock()



        self._stop = asyncio.Event()



        self._flusher_task: Optional[asyncio.Task] = None



    @staticmethod



    def reset_files():



        for fn in OUT_FILES.values():



            Path(fn).write_text("", encoding="utf-8")



        Path(CONN_ERR_DETAIL_FILE).write_text("", encoding="utf-8")



        Path(FINAL_OUTPUT_FILE).write_text("", encoding="utf-8")



    async def start(self):



        self._flusher_task = asyncio.create_task(self._flush_loop())



    async def stop(self):



        self._stop.set()



        if self._flusher_task:



            await self._flusher_task



        await self.flush_all()



    async def write_line(self, key: str, line: str):



        buf = self._buffers[key]



        buf.append(line.strip())



        if len(buf) >= BATCH_LINES:



            await self.flush_one(key)



        total = sum(len(v) for v in self._buffers.values())



        if total >= MAX_BUFFERED_LINES:



            await self.flush_all()



    async def _flush_loop(self):



        try:



            while not self._stop.is_set():



                await asyncio.sleep(FLUSH_INTERVAL_SEC)



                await self.flush_all()



        except asyncio.CancelledError:



            pass



    async def flush_one(self, key: str):



        async with self._locks[key]:



            lines = self._buffers[key]



            if not lines:



                return



            fn = OUT_FILES[key]



            with open(fn, "a", encoding="utf-8") as f:



                f.write("\n".join(lines) + "\n")



            lines.clear()



    async def flush_all(self):



        async with self._flush_lock:



            for key in OUT_FILES:



                if self._buffers[key]:



                    await self.flush_one(key)



# =========================



# Fallback collection



# =========================



class FallbackCollector:



    def __init__(self):



        self.cloudflare: Set[str] = set()



        self.timeout: Set[str] = set()



        self.cdn_timeout: Set[str] = set()



        self.connection_error: Set[str] = set()



        self.ssl_error: Set[str] = set()



        self._lock = asyncio.Lock()



    async def add(self, reason: str, domain: str):



        async with self._lock:



            if reason == "cloudflare":



                self.cloudflare.add(domain)



            elif reason == "timeout":



                self.timeout.add(domain)



            elif reason == CDN_TIMEOUT_LABEL:



                self.cdn_timeout.add(domain)



            elif reason == "connection_error":



                self.connection_error.add(domain)



            elif reason == "ssl_error":



                self.ssl_error.add(domain)



    def ordered_list(self) -> List[str]:



        out, seen = [], set()



        for group in (self.cloudflare, self.cdn_timeout, self.timeout, self.connection_error, self.ssl_error):



            for d in group:



                if d not in seen:



                    out.append(d); seen.add(d)



        return out



# =========================



# SELENIUM fallback (works on ARM64 via Selenium Manager)



# =========================



from selenium import webdriver



from selenium.webdriver.chrome.options import Options as ChromeOptions



from selenium.webdriver.support.ui import WebDriverWait



from selenium.common.exceptions import TimeoutException, WebDriverException



def _selenium_options(profile_dir: Path, proxy_url: Optional[str] = None) -> ChromeOptions:



    opts = ChromeOptions()



    opts.add_argument("--headless=new")



    opts.add_argument("--no-sandbox")



    opts.add_argument("--disable-dev-shm-usage")



    opts.add_argument("--disable-gpu")



    opts.add_argument("--window-size=1920,1080")



    opts.add_argument("--disable-extensions")



    opts.add_argument("--disable-notifications")



    opts.add_argument("--disable-popup-blocking")



    opts.add_argument("--disable-software-rasterizer")



    opts.add_argument("--blink-settings=imagesEnabled=false")



    opts.add_argument("--disable-logging")



    opts.add_argument("--log-level=3")



    opts.add_argument("--lang=en-US,en;q=0.9,ru;q=0.8")



    # eager page load to reduce wait



    opts.set_capability("pageLoadStrategy", "eager")



    # Isolated profile



    opts.add_argument(f"--user-data-dir={str(profile_dir)}")



    opts.add_argument("--profile-directory=Default")



    proxy_arg = proxy_arg_for_browser(proxy_url)



    if proxy_arg:



        opts.add_argument(f"--proxy-server={proxy_arg}")



        opts.add_argument("--proxy-bypass-list=<-loopback>")



    return opts



def _new_selenium_browser(profile_dir: Path, proxy_url: Optional[str] = None):



    # Selenium Manager will fetch CfT + chromedriver for ARM64 automatically



    opts = _selenium_options(profile_dir, proxy_url)



    return webdriver.Chrome(options=opts)



def _selenium_fetch_html(br, domain: str) -> Tuple[Optional[str], str]:



    def _try(url: str) -> Optional[str]:



        try:



            br.get(url)



            WebDriverWait(br, FALLBACK_HTTP_TIMEOUT).until(



                lambda d: d.execute_script("return document.readyState") in ("interactive", "complete")



            )



            time.sleep(0.8)



            html = br.page_source or ""



            if len(html.strip()) >= FALLBACK_BODY_MIN:



                return html



            return None



        except TimeoutException:



            return None



        except WebDriverException:



            return None



    for scheme in ("https", "http"):



        html = _try(f"{scheme}://{domain}")



        if html: return html, "success"



    if domain.count(".") == 1:



        for scheme in ("https", "http"):



            html = _try(f"{scheme}://www.{domain}")



            if html: return html, "success"



    return None, "timeout"



class SeleniumPool:



    def __init__(self, size: int, proxies: List[str]):



        self.size = max(1, size)



        self.proxies = proxies



        self.browsers = []



        self.profiles = []



        self.proxy_for_idx: List[Optional[str]] = []



        self.queue: asyncio.Queue[int] = asyncio.Queue()



    async def start(self):



        for i in range(self.size):



            proxy = self.proxies[i % len(self.proxies)] if self.proxies else None



            prof = Path(tempfile.mkdtemp(prefix=f"sel_prof_{i}_", dir=str(TMP_PROFILE_BASE)))



            self.profiles.append(prof)



            br = await asyncio.to_thread(_new_selenium_browser, prof, proxy)



            self.browsers.append(br)



            self.proxy_for_idx.append(proxy)



            await self.queue.put(i)



            await asyncio.sleep(0.1)



    async def acquire(self) -> int:



        return await self.queue.get()



    async def release(self, idx: int):



        await self.queue.put(idx)



    async def close(self):



        for br in self.browsers:



            try:



                await asyncio.to_thread(br.quit)



            except Exception:



                pass



        # clean profiles



        for prof in self.profiles:



            try:



                if prof.exists():



                    for p in sorted(prof.glob("**/*"), reverse=True):



                        try: p.unlink()



                        except IsADirectoryError:



                            try: p.rmdir()



                            except Exception: pass



                        except Exception:



                            pass



                    try: prof.rmdir()



                    except Exception: pass



            except Exception:



                pass



        # help OS reclaim memory sooner on constrained hosts



        try:



            gc.collect()



        except Exception:



            pass



# =========================



# UC fallback (x86_64 only; optional import)



# =========================



def _which(cmd: str) -> Optional[str]:



    """Shallow wrapper around shutil.which for late import contexts."""



    try:



        return shutil.which(cmd)



    except Exception:



        return None



def _detect_chrome_binary() -> Optional[str]:



    """Try to locate a Chrome/Chromium binary on Linux.



    Order: env override -> common names via PATH -> common absolute paths.



    """



    # env override (allows user to set CHROME_PATH explicitly)



    for key in ("CHROME_PATH", "GOOGLE_CHROME_SHIM", "BROWSER"):



        p = os.environ.get(key)



        if p and os.path.exists(p):



            return p



    # common names available in PATH



    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):



        p = _which(name)



        if p:



            return p



    # common absolute locations



    for p in (



        "/usr/bin/google-chrome",



        "/usr/bin/google-chrome-stable",



        "/usr/bin/chromium",



        "/usr/bin/chromium-browser",



        "/opt/google/chrome/chrome",



    ):



        if os.path.exists(p):



            return p



    return None



def _selenium_manager_find_chrome() -> Optional[str]:



    """Ask Selenium Manager for a Chrome for Testing browser path if available.



    Works on Selenium >= 4.11. Falls back silently otherwise.



    """



    try:



        # Selenium 4.11+ provides SeleniumManager which can return a browser path



        from selenium.webdriver.common.selenium_manager import SeleniumManager  # type: ignore



        mgr = SeleniumManager()



        # Try several APIs for broader version compatibility



        try:



            # Newer API (returns dict)



            res = mgr.binary_paths("chrome")  # type: ignore[attr-defined]



            if isinstance(res, dict):



                p = res.get("browser_path") or res.get("browser")



                if p and os.path.exists(p):



                    return p



        except Exception:



            pass



        try:



            # Older API (returns str)



            p = mgr.browser_path("chrome")  # type: ignore[attr-defined]



            if isinstance(p, str) and os.path.exists(p):



                return p



        except Exception:



            pass



    except Exception:



        return None



    return None



def _detect_chrome_major() -> Optional[int]:



    candidates = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]



    for binname in candidates:



        try:



            out = subprocess.check_output([binname, "--version"], text=True, timeout=2)



            m = re.search(r"\b(\d+)\.", out)



            if m:



                return int(m.group(1))



        except Exception:



            continue



    return None



def _ensure_uc_import():



    try:



        import undetected_chromedriver as uc  # noqa: F401



        return True



    except Exception as e:



        logger.warning(f"undetected_chromedriver not available: {e}")



        return False



def _uc_options(profile_dir: Path, binary_path: Optional[str] = None, proxy_url: Optional[str] = None):



    import undetected_chromedriver as uc



    opts = uc.ChromeOptions()



    proxy_arg = proxy_arg_for_browser(proxy_url)



    if proxy_arg:



        opts.add_argument(f"--proxy-server={proxy_arg}")



        opts.add_argument("--proxy-bypass-list=<-loopback>")



    opts.add_argument("--headless=new")



    opts.add_argument("--no-sandbox")



    opts.add_argument("--disable-dev-shm-usage")



    opts.add_argument("--disable-gpu")



    opts.add_argument("--window-size=1920,1080")



    opts.add_argument("--disable-extensions")



    opts.add_argument("--disable-notifications")



    opts.add_argument("--disable-popup-blocking")



    opts.add_argument("--disable-software-rasterizer")



    opts.add_argument("--disable-logging")



    opts.add_argument("--log-level=3")



    opts.add_argument("--blink-settings=imagesEnabled=false")



    opts.add_argument("--disable-features=Translate")



    opts.add_argument("--disable-blink-features=AutomationControlled")



    opts.add_argument("--ignore-certificate-errors")



    opts.add_argument("--ignore-ssl-errors")



    opts.add_argument("--remote-debugging-port=0")



    opts.add_argument("--no-first-run")



    opts.add_argument("--no-default-browser-check")



    opts.add_argument("--lang=en-US,en;q=0.9,ru;q=0.8")



    opts.add_argument(f"--user-data-dir={str(profile_dir)}")



    opts.add_argument("--profile-directory=Default")



    # If we have a Chrome/Chromium binary, point UC at it explicitly



    if binary_path:



        try:



            # Ensure string type to satisfy UC/Selenium expectations



            opts.binary_location = str(binary_path)  # type: ignore[attr-defined]



        except Exception:



            pass



    return opts



def _new_uc_browser(profile_dir: Path, proxy_url: Optional[str] = None):



    import undetected_chromedriver as uc



    last_err = None



    major = _detect_chrome_major()



    # Try to locate a usable Chrome/Chromium binary; UC is much more reliable with an explicit binary



    binary = _detect_chrome_binary() or _selenium_manager_find_chrome()



    for attempt in range(1, 4):



        try:



            opts = _uc_options(profile_dir, binary, proxy_url)



            kw = {"options": opts, "headless": True, "use_subprocess": True}



            if major:



                kw["version_main"] = major



            return uc.Chrome(**kw)



        except WebDriverException as e:



            last_err = e



            try:



                cache_dir = Path.home() / ".local" / "share" / "undetected_chromedriver"



                if cache_dir.exists():



                    shutil.rmtree(cache_dir, ignore_errors=True)



            except Exception:



                pass



            time.sleep(0.6 * attempt)



    # Encourage GC after failed attempts (keeps memory stable on small hosts)



    try:



        gc.collect()



    except Exception:



        pass



    raise last_err if last_err else RuntimeError("UC launch failed")



def _uc_fetch_html(br, domain: str) -> Tuple[Optional[str], str]:



    def _try(url: str) -> Optional[str]:



        try:



            br.get(url)



            WebDriverWait(br, FALLBACK_HTTP_TIMEOUT).until(



                lambda d: d.execute_script("return document.readyState") in ("interactive", "complete")



            )



            time.sleep(1.0)



            html = br.page_source or ""



            if len(html.strip()) >= FALLBACK_BODY_MIN:



                return html



            return None



        except TimeoutException:



            return None



        except WebDriverException:



            return None



    for scheme in ("https", "http"):



        html = _try(f"{scheme}://{domain}")



        if html: return html, "success"



    if domain.count(".") == 1:



        for scheme in ("https", "http"):



            html = _try(f"{scheme}://www.{domain}")



            if html: return html, "success"



    return None, "timeout"



class UCPool:



    def __init__(self, size: int, proxies: List[str]):



        self.size = max(1, size)



        self.proxies = proxies



        self.browsers = []



        self.profiles = []



        self.proxy_for_idx: List[Optional[str]] = []



        self.queue: asyncio.Queue[int] = asyncio.Queue()



    async def start(self):



        for i in range(self.size):



            proxy = self.proxies[i % len(self.proxies)] if self.proxies else None



            prof = Path(tempfile.mkdtemp(prefix=f"uc_prof_{i}_", dir=str(TMP_PROFILE_BASE)))



            self.profiles.append(prof)



            br = await asyncio.to_thread(_new_uc_browser, prof, proxy)



            self.browsers.append(br)



            self.proxy_for_idx.append(proxy)



            await self.queue.put(i)



            await asyncio.sleep(0.2)



    async def acquire(self) -> int:



        return await self.queue.get()



    async def release(self, idx: int):



        await self.queue.put(idx)



    async def close(self):



        for br in self.browsers:



            try:



                await asyncio.to_thread(br.quit)



            except Exception:



                pass



        for prof in self.profiles:



            try:



                if prof.exists():



                    for p in sorted(prof.glob("**/*"), reverse=True):



                        try: p.unlink()



                        except IsADirectoryError:



                            try: p.rmdir()



                            except Exception: pass



                        except Exception:



                            pass



                    try: prof.rmdir()



                    except Exception: pass



            except Exception:



                pass



        try:



            gc.collect()



        except Exception:



            pass



# =========================



# Pipeline



# =========================



timeouts_pending: List[str] = []



cdn_timeouts_pending: List[str] = []



async def process_domain(



    domain: str,



    proxy_pool: ProxyPool,



    proxy_assignment: Dict[str, str],



    fetchers: Dict[str, Fetcher],



    writer: Writer,



    fb: FallbackCollector,



) -> None:



    attempts: List[Tuple[str, Optional[int], Optional[str], str]] = []



    preferred_proxy = proxy_assignment.get(domain) or proxy_pool.next_proxy()



    proxy_chain = proxy_pool.order_from(preferred_proxy)



    for proxy in proxy_chain:



        fetcher = fetchers.get(proxy)



        if fetcher is None:



            continue



        await asyncio.sleep(random.uniform(*REQUEST_DELAY_RANGE))



        html, status_label, http_status, hdrs, err_detail = await fetcher.fetch(domain)



        if status_label != "success":



            attempts.append((status_label, http_status, err_detail, proxy))



            continue



        try:



            inactive_reason = detect_inactive(html, http_status or 200)



            if inactive_reason:



                await writer.write_line("inactive", domain)



                print_domain_status(domain, "inactive", details=f"(inactive: {inactive_reason} via {mask_proxy(proxy)})")



                update_stats("inactive")



                return



            total_score, hits_by_cat, title_hits = score_content(html, domain)



            if total_score >= THRESHOLD_SCORE:



                await writer.write_line("filtered", domain)



                sample = ", ".join(sample_matches(html))



                print_domain_status(domain, "filtered", total_score, f"hits={hits_by_cat} sample=[{sample}] via {mask_proxy(proxy)}")



                update_stats("filtered")



            else:



                await writer.write_line("clean", domain)



                summary = summarize_clean_page(html)



                detail = f"{summary} via {mask_proxy(proxy)}" if summary else f"via {mask_proxy(proxy)}"



                print_domain_status(domain, "clean", total_score, detail)



                update_stats("clean")



            return



        except Exception as e:



            attempts.append(("error", http_status, str(e), proxy))



    if not attempts:



        await writer.write_line("error", domain)



        print_domain_status(domain, "error", details="No proxy attempts executed")



        update_stats("error")



        return



    final_status = None



    final_http: Optional[int] = None



    final_err: Optional[str] = None



    final_proxy = None



    for pref in FAILOVER_STATUS_PREFERENCE:



        for status_label, http_status, err_detail, proxy in attempts:



            if status_label == pref:



                final_status, final_http, final_err, final_proxy = status_label, http_status, err_detail, proxy



                break



        if final_status:



            break



    if final_status is None:



        final_status, final_http, final_err, final_proxy = attempts[-1]



    detail_parts: List[str] = []



    if final_http is not None:



        detail_parts.append(f"(HTTP {final_http})")



    if final_err:



        sr = short_reason(final_err)



        detail_parts.append(f"[{sr}]" if sr else f"[{final_err}]")



    if final_proxy:



        detail_parts.append(f"via {mask_proxy(final_proxy)}")



    detail = " ".join(detail_parts)



    if final_status == "connection_error" and final_err:



        try:



            with open(CONN_ERR_DETAIL_FILE, "a", encoding="utf-8") as f:



                f.write(f"{domain} | {short_reason(final_err)} | {final_err}\\n")



        except Exception:



            pass



    print_domain_status(domain, final_status, details=detail)



    await writer.write_line(final_status, domain)



    update_stats(final_status)



    if final_status in ("cloudflare", "timeout", CDN_TIMEOUT_LABEL, "connection_error", "ssl_error"):



        await fb.add(final_status, domain)



async def fallback_process_domain(domain: str, engine: str, pool, writer: Writer):



    idx = await pool.acquire()



    br = pool.browsers[idx]



    proxy_used = None



    if getattr(pool, "proxy_for_idx", None) and idx < len(pool.proxy_for_idx):



        proxy_used = pool.proxy_for_idx[idx]



    try:



        if engine == "selenium":



            html, status_label = await asyncio.to_thread(_selenium_fetch_html, br, domain)



        else:



            html, status_label = await asyncio.to_thread(_uc_fetch_html, br, domain)



        if status_label != "success" or not html:



            print_domain_status(domain, "error", details=f"(FALLBACK_UNAVAIL via {mask_proxy(proxy_used)} )" if proxy_used else "(FALLBACK_UNAVAIL)")



            return



        inactive_reason = detect_inactive(html, 200)



        if inactive_reason:



            await writer.write_line("inactive", domain)



            print_domain_status(domain, "inactive", details=f"(FB inactive: {inactive_reason} via {mask_proxy(proxy_used)})" if proxy_used else f"(FB inactive: {inactive_reason})")



            update_stats("inactive")



            return



        total_score, hits_by_cat, title_hits = score_content(html, domain)



        if total_score >= THRESHOLD_SCORE:



            await writer.write_line("filtered", domain)



            sample = ", ".join(sample_matches(html))



            print_domain_status(domain, "filtered", total_score, f"(FB via {mask_proxy(proxy_used)}) hits={hits_by_cat} sample=[{sample}]" if proxy_used else f"(FB) hits={hits_by_cat} sample=[{sample}]")



            update_stats("filtered")



        else:



            await writer.write_line("clean", domain)



            summary = summarize_clean_page(html)



            print_domain_status(domain, "clean", total_score, f"{summary} (FB via {mask_proxy(proxy_used)})" if summary and proxy_used else (f"(FB via {mask_proxy(proxy_used)})" if proxy_used else (f"{summary} (FB)" if summary else "(FB)")))



            update_stats("clean")



        stats['fallback_processed'] += 1



    except Exception as e:



        print_domain_status(domain, "error", details=f"(FB) Exception: {str(e)[:50]}")



        update_stats("error")



    finally:



        await pool.release(idx)



# =========================



# Preflight



# =========================



def check_py_version():



    v = sys.version_info



    if (v.major, v.minor) not in SUPPORTED_PY:



        raise RuntimeError(f"Unsupported Python {v.major}.{v.minor}. Supported: {SUPPORTED_PY_STR}")



def check_ulimit():



    try:



        out = subprocess.check_output(["bash", "-lc", "ulimit -n"], text=True, timeout=3).strip()



        val = int(out)



        if val < 8192:



            logger.warning(f"Open file limit is low: {val}. Recommend: ulimit -n 65535")



    except Exception:



        pass



def check_input_output():



    if not os.path.exists(INPUT_FILE):



        raise FileNotFoundError(f"INPUT_FILE not found: {INPUT_FILE}")



    with open(INPUT_FILE, "r", encoding="utf-8") as f:



        _ = f.readline()



    for k, fn in OUT_FILES.items():



        with open(fn, "a", encoding="utf-8") as f:



            pass



    with open(CONN_ERR_DETAIL_FILE, "a", encoding="utf-8") as f:



        pass



async def smoke_aiohttp():



    timeout = ClientTimeout(total=6, connect=3, sock_read=3)



    async with aiohttp.ClientSession(timeout=timeout) as s:



        async with s.get("https://example.com", allow_redirects=True) as r:



            if r.status >= 400:



                raise RuntimeError(f"aiohttp smoke: HTTP {r.status}")



            _ = await r.text()



    logger.info(f"{Fore.GREEN}aiohttp OK{Style.RESET_ALL}")



def smoke_selenium_sync():



    prof = Path(tempfile.mkdtemp(prefix="sel_smoke_", dir=str(TMP_PROFILE_BASE)))



    br = None



    try:



        br = _new_selenium_browser(prof, None)



        br.get("https://example.com")



        WebDriverWait(br, 10).until(lambda d: d.execute_script("return document.readyState") in ("interactive","complete"))



        html = br.page_source or ""



        if len(html) < 100:



            raise RuntimeError("Selenium smoke: short HTML")



        logger.info(f"{Fore.GREEN}Selenium Chrome OK (Chrome for Testing via Selenium Manager){Style.RESET_ALL}")



    finally:



        try:



            if br: br.quit()



        except Exception:



            pass



        # cleanup profile



        try:



            if prof.exists():



                for p in sorted(prof.glob("**/*"), reverse=True):



                    try: p.unlink()



                    except IsADirectoryError:



                        try: p.rmdir()



                        except Exception: pass



                    except Exception:



                        pass



                try: prof.rmdir()



                except Exception: pass



        except Exception:



            pass



def smoke_uc_sync_if_x86():



    if IS_ARM:



        return



    if not _ensure_uc_import():



        raise RuntimeError("undetected_chromedriver missing on x86_64")



    # Try launching UC once



    prof = Path(tempfile.mkdtemp(prefix="uc_smoke_", dir=str(TMP_PROFILE_BASE)))



    br = None



    try:



        br = _new_uc_browser(prof, None)



        br.get("https://example.com")



        WebDriverWait(br, 10).until(lambda d: d.execute_script("return document.readyState") in ("interactive","complete"))



        html = br.page_source or ""



        if len(html) < 100:



            raise RuntimeError("UC smoke: short HTML")



        logger.info(f"{Fore.GREEN}UC Chrome OK (x86_64){Style.RESET_ALL}")



    finally:



        try:



            if br: br.quit()



        except Exception:



            pass



        try:



            if prof.exists():



                for p in sorted(prof.glob("**/*"), reverse=True):



                    try: p.unlink()



                    except IsADirectoryError:



                        try: p.rmdir()



                        except Exception: pass



                    except Exception:



                        pass



                try: prof.rmdir()



                except Exception: pass



        except Exception:



            pass



async def preflight():



    logger.info(f"{Fore.CYAN}Running preflight checks...{Style.RESET_ALL}")



    check_py_version()



    check_ulimit()



    check_input_output()



    await smoke_aiohttp()



    # Browser smoke: on x86 prefer UC, but if UC fails try Selenium CfT



    if IS_ARM:



        await asyncio.to_thread(smoke_selenium_sync)



    else:



        try:



            await asyncio.to_thread(smoke_uc_sync_if_x86)



        except Exception as e:



            logger.warning(f"UC smoke failed: {e}. Trying Selenium as fallback...")



            await asyncio.to_thread(smoke_selenium_sync)



    logger.info(f"{Fore.GREEN}Preflight passed ✓{Style.RESET_ALL}")



# =========================



# Main



# =========================



async def main(no_qc: bool = False, monitor_interval: Optional[float] = None):
    # Orchestrates fast pass, rescue, optional fallback, and final merge.



    start_time = time.time()



    print_header()



    # uvloop if present



    try:



        import uvloop



        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())



        print_status("⚡ Using uvloop for enhanced performance", "success")



    except Exception:



        print_status("ℹ️  Using default event loop", "info")



    # Check input file



    if not Path(INPUT_FILE).exists():



        print_status(f"❌ Input file not found: {INPUT_FILE}", "error")



        return



    print_status(f"📂 Loading domains from {INPUT_FILE}...", "progress")



    with open(INPUT_FILE, "r", encoding="utf-8") as f:



        domains = [ln.strip().lower() for ln in f if ln.strip()]



    domains = list(dict.fromkeys(domains))



    domains = prioritize_domains(domains)



    proxies = load_proxies(PROXY_FILE)



    if not proxies:



        print_status(f"? No proxies found in {PROXY_FILE}", "error")



        return



    proxy_pool = ProxyPool(proxies)



    proxy_assignment = {dom: proxy_pool.next_proxy() for dom in domains}



    overall_concurrency, per_proxy_concurrency = compute_concurrency_limits(len(proxies))



    stats['total'] = len(domains)



    print_status(f"?? Loaded {len(proxies)} proxies from {PROXY_FILE}", "info")



    print_status(f"📊 Total domains to process: {stats['total']:,}", "info")



    print_status(f"🔧 Configuration: {overall_concurrency} concurrent overall, {per_proxy_concurrency} per proxy", "info")



    print()



    # Setup output files



    print_status("📁 Setting up output files...", "progress")



    for fn in OUT_FILES.values():



        Path(fn).write_text("", encoding="utf-8")



    Path(CONN_ERR_DETAIL_FILE).write_text("", encoding="utf-8")



    Path(FINAL_OUTPUT_FILE).write_text("", encoding="utf-8")



    print_status("?? Output files:", "info")



    for category, filename in OUT_FILES.items():



        print_status(f"   {category}: {filename}", "info")



    print_status(f"   combined: {FINAL_OUTPUT_FILE}", "info")



    print()



    fetchers: Dict[str, Fetcher] = {}



    for proxy in proxies:



        try:



            fetchers[proxy] = Fetcher(concurrency=per_proxy_concurrency, proxy_url=proxy, ttl_dns_cache=120)



        except Exception as e:



            print_status(f"? Skipping proxy {mask_proxy(proxy)}: {e}", "warning")



    if not fetchers:



        print_status("? No valid proxies after initialization", "error")



        return



    if len(fetchers) != len(proxies):



        overall_concurrency, per_proxy_concurrency = compute_concurrency_limits(len(fetchers))



    writer = Writer()



    fb = FallbackCollector()



    monitor_task: Optional[asyncio.Task] = None



    if monitor_interval:



        if psutil is None:



            print_status("psutil not available; memory monitor disabled", "warning")



        else:



            monitor_task = asyncio.create_task(memory_monitor(monitor_interval))



    await writer.start()



    sem = asyncio.Semaphore(overall_concurrency)



    try:



        # Fast pass



        print_status("🚀 Starting fast pass (aiohttp)...", "success")



        with tqdm(



            total=len(domains), 



            desc=f"{Fore.CYAN}Fast pass (aiohttp){Style.RESET_ALL}",



            unit="domain",



            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",



            colour="cyan",



            dynamic_ncols=True,



            smoothing=0.05



        ) as pbar:



            async def _wrapped(dom: str):



                async with sem:



                    await process_domain(dom, proxy_pool, proxy_assignment, fetchers, writer, fb)



                    pbar.update(1)



                    # Update description with live stats



                    if pbar.n % 1000 == 0 or pbar.n == len(domains):



                        pbar.set_description(



                            f"{Fore.CYAN}Fast pass (aiohttp){Style.RESET_ALL} "



                            f"{Fore.GREEN}(Clean: {stats['clean']:,}){Style.RESET_ALL} "



                            f"{Fore.RED}(Filtered: {stats['filtered']:,}){Style.RESET_ALL} "



                            f"{Fore.CYAN}(Inactive: {stats['inactive']:,}){Style.RESET_ALL} "



                            f"{Fore.BLUE}(Cloudflare: {stats['cloudflare']:,}){Style.RESET_ALL}"



                        )



            tasks = [asyncio.create_task(_wrapped(d)) for d in domains]



            for chunk_start in range(0, len(tasks), 2000):



                chunk = tasks[chunk_start:chunk_start+2000]



                await asyncio.gather(*chunk)



        await asyncio.gather(*(f.close() for f in fetchers.values()))



        # Timeout Rescue



        if USE_RESCUE_STAGE and timeouts_pending:



            print_status(f"🔄 Timeout rescue for {len(timeouts_pending)} domains (longer timeouts, IPv4, low concurrency)", "progress")



            rescue_fetcher = Fetcher(



                concurrency=RESCUE_CONCURRENCY,



                total_timeout=RESCUE_TOTAL_TIMEOUT,



                connect_timeout=RESCUE_CONNECT_TIMEOUT,



                read_timeout=RESCUE_READ_TIMEOUT,



                force_ipv4=RESCUE_FORCE_IPV4,



                ttl_dns_cache=60,



            )



            sem_rescue = asyncio.Semaphore(RESCUE_CONCURRENCY)



            async def _rescue_one(dom: str):



                async with sem_rescue:



                    html, status_label, http_status, hdrs, err_detail = await rescue_fetcher.fetch(dom)



                    if status_label == "success":



                        try:



                            inactive_reason = detect_inactive(html, http_status or 200)



                            if inactive_reason:



                                await writer.write_line("inactive", dom)



                                logger.info(f"{Fore.CYAN}INACTIVE(R)       {Style.RESET_ALL}{dom} reason={inactive_reason}")



                                return



                            total_score, hits_by_cat, title_hits = score_content(html, dom)



                            if total_score >= THRESHOLD_SCORE:



                                await writer.write_line("filtered", dom)



                                sample = ", ".join(sample_matches(html))



                                logger.info(f"{Fore.RED}FILTERED(R {total_score:.1f}) {Style.RESET_ALL}{dom} hits={hits_by_cat} title={title_hits} sample=[{sample}]")



                            else:



                                await writer.write_line("clean", dom)



                                summary = summarize_clean_page(html)



                                logger.info(f"{Fore.GREEN}CLEAN(R {total_score:.2f})   {Style.RESET_ALL}{dom}{(' ' + summary) if summary else ''}")



                        except Exception as e:



                            await writer.write_line("error", dom)



                            logger.error(f"{Fore.RED}ANALYZE ERROR(R)   {Style.RESET_ALL}{dom}: {e}")



                        return



                    if status_label == "timeout":



                        await writer.write_line("timeout", dom)



                        logger.info(f"{Fore.YELLOW}TIMEOUT(FINAL)     {Style.RESET_ALL}{dom}")



                    elif status_label == CDN_TIMEOUT_LABEL:



                        cdn_timeouts_pending.append(dom)



                        logger.info(f"{Fore.MAGENTA}CDN_TIMEOUT(PENDING){Style.RESET_ALL} {dom}")



                        return



                    elif status_label == "non_html":



                        await writer.write_line("non_html", dom)



                        logger.info(f"{Fore.YELLOW}NON_HTML(R)        {Style.RESET_ALL}{dom}")



                    elif status_label in ("cloudflare", "ssl_error"):



                        await writer.write_line(status_label, dom)



                        await fb.add(status_label, dom)



                        logger.info(f"{Fore.YELLOW}{status_label.upper()}(R){Style.RESET_ALL} {dom}")



                    elif status_label == "connection_error":



                        reason = short_reason(err_detail or "")



                        await writer.write_line("connection_error", dom)



                        try:



                            with open(CONN_ERR_DETAIL_FILE, "a", encoding="utf-8") as f:



                                f.write(f"{dom} | {reason} | {err_detail or ''}\n")



                        except Exception:



                            pass



                        logger.info(f"{Fore.YELLOW}CONNECTION_ERROR(R)[{reason}]{Style.RESET_ALL} {dom}")



                    else:



                        await writer.write_line("error", dom)



                        update_stats("error")



                        reason = short_reason(err_detail or "")



                        detail = f"[{reason}]" if reason else (f"[{err_detail}]" if err_detail else "")



                        suffix = f" {detail}" if detail else ""



                        logger.info(f"{Fore.YELLOW}ERROR(R)           {Style.RESET_ALL}{dom}{suffix}")



            with tqdm(



                total=len(timeouts_pending), 



                desc=f"{Fore.MAGENTA}Timeout rescue{Style.RESET_ALL}",



                unit="domain",



                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",



                colour="magenta",



                dynamic_ncols=True



            ) as pbar_r:



                tasks_r = [asyncio.create_task(_rescue_one(d)) for d in timeouts_pending]



                for chunk_start in range(0, len(tasks_r), 2000):



                    chunk = tasks_r[chunk_start:chunk_start+2000]



                    await asyncio.gather(*chunk)



                    pbar_r.update(len(chunk))



            await rescue_fetcher.close()



        if USE_RESCUE_STAGE and cdn_timeouts_pending:



            print_status(f"?? CDN throttle rescue for {len(cdn_timeouts_pending)} domains (low concurrency, extended timeouts)", "progress")



            cdn_fetcher = Fetcher(



                concurrency=CDN_RESCUE_CONCURRENCY,



                total_timeout=CDN_TOTAL_TIMEOUT,



                connect_timeout=CDN_CONNECT_TIMEOUT,



                read_timeout=CDN_READ_TIMEOUT,



                force_ipv4=RESCUE_FORCE_IPV4,



                ttl_dns_cache=120,



            )



            sem_cdn = asyncio.Semaphore(CDN_RESCUE_CONCURRENCY)



            async def _cdn_rescue_one(dom: str):



                async with sem_cdn:



                    html, status_label, http_status, hdrs, err_detail = await cdn_fetcher.fetch(dom)



                    if status_label == "success":



                        try:



                            inactive_reason = detect_inactive(html, http_status or 200)



                            if inactive_reason:



                                await writer.write_line("inactive", dom)



                                update_stats("inactive")



                                logger.info(f"{Fore.CYAN}INACTIVE(CDN)      {Style.RESET_ALL}{dom} reason={inactive_reason}")



                                return



                            total_score, hits_by_cat, title_hits = score_content(html, dom)



                            if total_score >= THRESHOLD_SCORE:



                                await writer.write_line("filtered", dom)



                                update_stats("filtered")



                                sample = ", ".join(sample_matches(html))



                                logger.info(f"{Fore.RED}FILTERED(CDN {total_score:.1f}) {Style.RESET_ALL}{dom} hits={hits_by_cat} title={title_hits} sample=[{sample}]")



                            else:



                                await writer.write_line("clean", dom)



                                update_stats("clean")



                                summary = summarize_clean_page(html)



                                logger.info(f"{Fore.GREEN}CLEAN(CDN {total_score:.2f})   {Style.RESET_ALL}{dom}{(' ' + summary) if summary else ''}")



                        except Exception as e:



                            await writer.write_line("error", dom)



                            update_stats("error")



                            logger.error(f"{Fore.RED}ANALYZE ERROR(CDN) {Style.RESET_ALL}{dom}: {e}")



                        return



                    if status_label in (CDN_TIMEOUT_LABEL, "timeout"):



                        await writer.write_line(CDN_TIMEOUT_LABEL, dom)



                        update_stats(CDN_TIMEOUT_LABEL)



                        logger.info(f"{Fore.MAGENTA}CDN_TIMEOUT(FINAL) {Style.RESET_ALL}{dom}")



                    elif status_label == "non_html":



                        await writer.write_line("non_html", dom)



                        update_stats("non_html")



                        logger.info(f"{Fore.YELLOW}NON_HTML(CDN)      {Style.RESET_ALL}{dom}")



                    elif status_label in ("cloudflare", "ssl_error"):



                        await writer.write_line(status_label, dom)



                        update_stats(status_label)



                        await fb.add(status_label, dom)



                        logger.info(f"{Fore.YELLOW}{status_label.upper()}(CDN){Style.RESET_ALL} {dom}")



                    elif status_label == "connection_error":



                        reason = short_reason(err_detail or "")



                        await writer.write_line("connection_error", dom)



                        update_stats("connection_error")



                        try:



                            with open(CONN_ERR_DETAIL_FILE, "a", encoding="utf-8") as f:



                                f.write(f"{dom} | {reason} | {err_detail or ''}\n")



                        except Exception:



                            pass



                        logger.info(f"{Fore.YELLOW}CONNECTION_ERROR(CDN)[{reason}]{Style.RESET_ALL} {dom}")



                    else:



                        await writer.write_line("error", dom)



                        update_stats("error")



                        reason = short_reason(err_detail or "")



                        detail = f"[{reason}]" if reason else (f"[{err_detail}]" if err_detail else "")



                        suffix = f" {detail}" if detail else ""



                        logger.info(f"{Fore.YELLOW}ERROR(CDN)         {Style.RESET_ALL}{dom}{suffix}")



            cdn_targets = list(dict.fromkeys(cdn_timeouts_pending))



            with tqdm(



                total=len(cdn_targets),



                desc=f"{Fore.MAGENTA}CDN timeout rescue{Style.RESET_ALL}",



                unit="domain",



                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",



                colour="magenta",



                dynamic_ncols=True



            ) as pbar_cdn:



                tasks_cdn = [asyncio.create_task(_cdn_rescue_one(d)) for d in cdn_targets]



                for chunk_start in range(0, len(tasks_cdn), 2000):



                    chunk = tasks_cdn[chunk_start:chunk_start+2000]



                    await asyncio.gather(*chunk)



                    pbar_cdn.update(len(chunk))



            await cdn_fetcher.close()



            cdn_timeouts_pending.clear()



        # Fallback with browser (chunked + pool restart)



        cf_targets = list(dict.fromkeys(sorted(fb.cloudflare)))



        if ENABLE_BROWSER_FALLBACK and cf_targets:



            print_status(f"🌐 Browser fallback via proxies for {len(cf_targets)} Cloudflare domains", "progress")



            fb_workers = max(1, min(FALLBACK_MAX_BROWSERS, len(proxies)))



            engine = "selenium" if IS_ARM else "uc"



            pool_cls = SeleniumPool if IS_ARM else UCPool



            pool = pool_cls(fb_workers, proxies)



            try:



                await pool.start()



                sem_fb = asyncio.Semaphore(fb_workers)



                with tqdm(



                    total=len(cf_targets),



                    desc=f"{Fore.GREEN}Browser fallback{Style.RESET_ALL}",



                    unit="domain",



                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",



                    colour="green",



                    dynamic_ncols=True



                ) as pbar_fb:



                    async def _fb(dom: str):



                        async with sem_fb:



                            await asyncio.sleep(random.uniform(*REQUEST_DELAY_RANGE))



                            await fallback_process_domain(dom, engine, pool, writer)



                            pbar_fb.update(1)



                    tasks_fb = [asyncio.create_task(_fb(d)) for d in cf_targets]



                for chunk_start in range(0, len(tasks_fb), 500):



                    chunk = tasks_fb[chunk_start:chunk_start+500]



                    await asyncio.gather(*chunk)



            finally:



                await pool.close()



        elif cf_targets:



            print_status(f"🌐 Browser fallback disabled; skipping {len(cf_targets)} Cloudflare domains", "warning")



    finally:



        if monitor_task:



            monitor_task.cancel()



            with contextlib.suppress(asyncio.CancelledError):



                await monitor_task



        await writer.stop()



        try:



            print_status("?? Building combined final output", "progress")



            combined_count = build_final_output(



                Path(FINAL_OUTPUT_FILE),



                [



                    Path(PASS_OUTPUT_FILE),



                    Path(OUT_FILES["cloudflare"]),



                    Path(OUT_FILES["cdn_timeout"]),



                ],



            )



            print_status(f"?? Final combined list: {combined_count} domains", "info")



        except Exception as e:



            print_status(f"?? Failed to build combined output: {e}", "error")



    elapsed = time.time() - start_time



    # Calculate final statistics



    domains_per_second = stats['total'] / elapsed if elapsed > 0 else 0



    clean_rate = (stats['clean'] / stats['total']) * 100 if stats['total'] > 0 else 0



    # Print final results



    print_status("\n" + "="*80, "success")



    print_status("📈 PROCESSING RESULTS", "success")



    print_status("="*80, "success")



    print_status(f"⏱️  Processing time: {elapsed:.2f} seconds", "info")



    print_status(f"📊 Total domains processed: {stats['total']:,}", "info")



    print_status(f"✅ Clean domains: {stats['clean']:,} ({clean_rate:.1f}%)", "success")



    print_status(f"🚫 Filtered domains: {stats['filtered']:,}", "error")



    print_status(f"💤 Inactive domains: {stats['inactive']:,}", "info")



    print_status(f"☁️  Cloudflare domains: {stats['cloudflare']:,}", "info")



    print_status(f"🔒 SSL error domains: {stats['ssl_error']:,}", "warning")



    print_status(f"⏰ Timeout domains: {stats['timeout']:,}", "warning")



    print_status(f"⏰ CDN timeout domains: {stats['cdn_timeout']:,}", "warning")



    print_status(f"🔌 Connection error domains: {stats['connection_error']:,}", "warning")



    print_status(f"⚠️  Error domains: {stats['error']:,}", "warning")



    print_status(f"📄 Non-HTML domains: {stats['non_html']:,}", "warning")



    print_status(f"🌐 Fallback processed: {stats['fallback_processed']:,}", "fallback")



    print_status(f"⚡ Processing speed: {domains_per_second:.0f} domains/second", "info")



    print_status("="*80, "success")



    # Quality Check



    if not no_qc:



        print_status("\n🔍 Running Quality Check...", "progress")



        matched_count, total_count, matched_domains, missing_domains = perform_quality_check()



        if total_count > 0:



            print_status(f"📊 Quality Check Summary: {matched_count}/{total_count} domains passed", "info")



    else:



        print_status("⚠️  Quality check skipped (--no-qc flag)", "warning")



# =========================



# Entrypoint



# =========================



if __name__ == "__main__":



    parser = argparse.ArgumentParser(description="Fast pass + auto fallback classifier with enhanced progress tracking")



    parser.add_argument("--preflight", action="store_true", help="Run only preflight checks and exit")



    parser.add_argument("--no-preflight", action="store_true", help="Skip preflight checks")



    parser.add_argument("--no-qc", action="store_true", help="Skip quality check at the end")



    parser.add_argument("--low-mem", action="store_true", help="Use conservative concurrency and download limits to reduce memory usage")



    parser.add_argument("--max-concurrency", type=int, help=f"Override fast-pass concurrency (default {CONCURRENCY})")



    parser.add_argument("--rescue-concurrency", type=int, help=f"Override rescue concurrency (default {RESCUE_CONCURRENCY})")

    parser.add_argument("--fallback-browsers", type=int, help=f"Override fallback browser cap (default {FALLBACK_MAX_BROWSERS})")

    parser.add_argument("--chunk-size", type=int, help=f"Override chunk size for streaming downloads (default {CHUNK_SIZE})")

    parser.add_argument("--max-bytes", type=int, help=f"Override per-request read cap in bytes (default {MAX_BYTES})")

    parser.add_argument("--proxy-parallel-per-host", type=int, help=f"Override per-proxy parallelism (default {PROXY_PARALLEL_PER_HOST})")

    parser.add_argument("--proxy-parallel-only", action="store_true", help="Derive total concurrency only from per-proxy parallelism (ignore global max)")

    parser.add_argument("--monitor-mem", nargs='?', type=float, const=30.0, help="Log RSS/available memory every N seconds (default: 30s)")

    args = parser.parse_args()


    applied_overrides: Dict[str, int] = {}



    if args.low_mem:



        applied_overrides.update(configure_runtime(**LOW_MEM_PROFILE))



    overrides: Dict[str, int] = {}



    if args.max_concurrency is not None:



        overrides["max_concurrency"] = args.max_concurrency



    if args.rescue_concurrency is not None:



        overrides["rescue_concurrency"] = args.rescue_concurrency



    if args.fallback_browsers is not None:



        overrides["fallback_browsers"] = args.fallback_browsers



    if args.chunk_size is not None:



        overrides["chunk_size"] = args.chunk_size



    if args.max_bytes is not None:



        overrides["max_bytes"] = args.max_bytes



    if overrides:

        applied_overrides.update(configure_runtime(**overrides))

    if args.proxy_parallel_per_host is not None:
        PROXY_PARALLEL_PER_HOST = max(1, args.proxy_parallel_per_host)
        applied_overrides["proxy_parallel_per_host"] = PROXY_PARALLEL_PER_HOST

    if args.proxy_parallel_only:
        PROXY_PARALLEL_ONLY = True
        applied_overrides["proxy_parallel_only"] = True

    fd_adjustments = ensure_fd_headroom()

    if fd_adjustments:

        applied_overrides.update(fd_adjustments)


    mem_adjustments = ensure_memory_headroom()



    if mem_adjustments:



        applied_overrides.update(mem_adjustments)



    if applied_overrides:



        info = ', '.join(f"{k}={v}" for k, v in applied_overrides.items())



        warn_keys = {"concurrency", "rescue_concurrency", "fallback_browsers"}



        status_type = 'warning' if (args.low_mem or warn_keys.intersection(applied_overrides)) else 'info'



        print_status(f"Runtime tuning applied: {info}", status_type)



    try:



        if args.preflight:



            print_header()



            asyncio.run(preflight())



            sys.exit(0)



        else:



            if not args.no_preflight:



                print_header()



                asyncio.run(preflight())



            asyncio.run(main(no_qc=args.no_qc, monitor_interval=args.monitor_mem))



    except KeyboardInterrupt:



        print_status("\n⚠️  Process interrupted by user", "warning")



    except Exception as e:



        print_status(f"\n❌ Startup error: {e}", "error")



        sys.exit(1)



