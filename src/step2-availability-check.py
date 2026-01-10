#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Step 2 - NS + quick HTTPS probe with Enhanced Progress Tracking
- DNS resolution with round-robin across multiple servers
- Parked domain detection with expanded NS filtering
- HTTPS redirect detection and filtering

Run:
  python step2-availability-check.py
"""

import asyncio
import dns.asyncresolver
import logging
import aiohttp
import gc
import sys
import time
import ipaddress
from pathlib import Path
from tqdm import tqdm
from colorama import init, Fore, Style, Back

# Configure logging
SCRIPT_DIR = Path(__file__).resolve().parent
LOG_FILE = SCRIPT_DIR / 'step2_availability.log'

logger = logging.getLogger('step2')
if not logger.handlers:
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

LOG_LEVELS = {
    'info': logging.INFO,
    'success': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'progress': logging.INFO,
    'dns': logging.INFO,
    'http': logging.INFO
}


# Initialize colorama
init(autoreset=True)
# DNS servers list
DNS_SERVERS = [
    '108.61.10.10', '173.199.96.96', '173.199.96.97',
    '76.76.2.0', '94.140.14.14', '1.0.0.1',
    '149.112.112.112', '8.8.8.8', '74.82.42.42',
    '8.26.56.26', '205.171.3.65', '216.146.35.35',
    '36.50.50.50', '185.228.168.9', '185.228.169.9',
    '9.9.9.9', '208.67.220.220','51.255.43.23',
    '77.48.234.103', '204.15.148.186','74.113.101.251',
    '14.198.168.140', '103.149.165.57', '92.205.63.50'
    '177.174.20.65', '88.149.212.184', '211.35.20.27',
    '201.143.181.110', '200.39.23.4', '207.248.224.71', 
    '81.9.198.12', '88.202.185.165', '212.113.0.3',
    '109.228.8.83', '62.255.208.69', '94.76.206.195',
    '78.129.243.105', '141.195.95.131', '83.173.203.174',
    '79.141.82.250', '194.209.90.8', '78.155.23.143',
    '31.10.243.92', '194.29.10.6', '195.186.4.192'
    

]

# Substrings indicating parked NS (expanded)
NS_FILTER_SUBSTRINGS = (
    "parking", "expired", ".afternic.com", "parklogic",
    ".parktons.com", ".above.com", ".ztomy.com",
    ".notneiron.com", ".ibspark.com", ".bodis.com",
    ".example.com",
    # Added from observed records
    "expired1.domainshop.ru", "expired2.domainshop.ru", "domainshop.ru",
    "ns1.shop.reg.ru", "ns2.shop.reg.ru", "parking.reg.ru",
)

# Configuration
CONCURRENCY = 2400
BATCH_SIZE = 2400
DNS_TIMEOUT = 3.2
HTTP_TIMEOUT = 3.2
SESSION_COUNT = 8

# Statistics tracking
stats = {
    'total': 0,
    'good': 0,
    'non_existent': 0,
    'parked': 0,
    'redirect': 0,
    'incorrect': 0,
    'errors': 0
}

BANNED_REDIRECT_PREFIXES = ("ww25.", "ww38.")
COMMON_SECOND_LEVEL_TLDS = {"co", "com", "org", "net", "gov", "ac", "edu", "mil"}


def get_registrable_domain(host: str) -> str:
    """Return a best-effort registrable domain for host."""
    if not host:
        return ""
    trimmed = host.strip(".")
    if not trimmed:
        return ""
    parts = trimmed.split(".")
    if len(parts) < 2:
        return trimmed
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in COMMON_SECOND_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_same_registered_domain(host: str, reference: str) -> bool:
    """Check whether host shares the same registrable domain as reference."""
    if not host or not reference:
        return False
    return get_registrable_domain(host) == get_registrable_domain(reference)


def has_banned_redirect_prefix(host: str) -> bool:
    """Return True if host starts with one of the ww25/ww38 prefixes."""
    if not host:
        return False
    return host.startswith(BANNED_REDIRECT_PREFIXES)

def format_progress_description() -> str:
    """Build the tqdm description with live statistics."""
    return (
        f"{Fore.CYAN}Processing domains{Style.RESET_ALL} "
        f"{Fore.GREEN}(OK: {stats['good']:,}){Style.RESET_ALL} "
        f"{Fore.RED}(Non-existent: {stats['non_existent']:,}){Style.RESET_ALL} "
        f"{Fore.BLUE}(Parked: {stats['parked']:,}){Style.RESET_ALL} "
        f"{Fore.YELLOW}(Redirect: {stats['redirect']:,}){Style.RESET_ALL} "
        f"{Fore.MAGENTA}(Incorrect: {stats['incorrect']:,}){Style.RESET_ALL}"
    )

def print_header():
    """Print a colorful header for the script."""
    header_text = 'STEP 2 - DNS & HTTPS PROBE WITH ENHANCED PROGRESS TRACKING'
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}{header_text:^70}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    logger.info(header_text)

def print_status(message, status_type="info"):
    """Print colored status messages."""
    colors = {
        "info": Fore.BLUE,
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "error": Fore.RED,
        "progress": Fore.CYAN,
        "dns": Fore.MAGENTA,
        "http": Fore.CYAN
    }
    log_level = LOG_LEVELS.get(status_type, logging.INFO)
    print(f"{colors.get(status_type, Fore.WHITE)}{message}{Style.RESET_ALL}")
    logger.log(log_level, message)

def print_domain_status(domain, status, details=""):
    """Print domain status with appropriate colors."""
    colors = {
        "good": Fore.GREEN,
        "non_existent": Fore.RED,
        "parked": Fore.BLUE,
        "redirect": Fore.YELLOW,
        "incorrect": Fore.MAGENTA,
        "error": Fore.RED
    }
    symbols = {
        "good": "?",
        "non_existent": "?",
        "parked": "???",
        "redirect": "??",
        "incorrect": "??",
        "error": "??"
    }
    color = colors.get(status, Fore.WHITE)
    symbol = symbols.get(status, "?")
    display_status = "OK" if status == "good" else status.upper()
    print(f"{color}{symbol} {display_status:<12} {domain}{Style.RESET_ALL} {details}")
    logger.info(f"{display_status}: {domain} {details}".strip())

def run_qc_check(script_dir: Path, output_files):
    """Compare QC domains against categorized outputs and report their status."""
    qc_file = script_dir / 'qc_domains.lst'

    if not qc_file.exists():
        print_status(f"?? QC check skipped: {qc_file} not found", "warning")
        return

    print_status("\n?? Running QC check against qc_domains.lst...", "progress")

    with open(qc_file, 'r', encoding='utf-8') as f:
        qc_domains = [line.strip() for line in f if line.strip()]

    if not qc_domains:
        print_status("?? qc_domains.lst is empty. Nothing to verify.", "warning")
        return

    categorized_sets = {}
    for category, path_obj in output_files.items():
        try:
            with open(path_obj, 'r', encoding='utf-8') as f:
                categorized_sets[category] = {line.strip().lower() for line in f if line.strip()}
        except FileNotFoundError:
            categorized_sets[category] = set()

    good_hits = []
    other_hits = {}
    missing = []

    for domain in qc_domains:
        domain_lower = domain.lower()
        matched_category = None
        for category, domain_set in categorized_sets.items():
            if domain_lower in domain_set:
                matched_category = category
                break

        if matched_category is None:
            print_status(f"   {domain} -> not found in any output list", "error")
            missing.append(domain)
        elif matched_category == 'good':
            print_status(f"   {domain} -> present in OK list", "success")
            good_hits.append(domain)
        else:
            print_status(f"   {domain} -> found in {matched_category} list", "warning")
            other_hits.setdefault(matched_category, []).append(domain)

    other_count = sum(len(v) for v in other_hits.values())
    status = 'success' if not other_count and not missing else ('warning' if not missing else 'error')
    print_status(
        f"?? QC summary: {len(good_hits)} OK, {other_count} in other lists, {len(missing)} missing",
        status
    )

# Global resolver (reuse sockets)
global_resolver = dns.asyncresolver.Resolver(configure=False)


async def _resolve_ns_single(label: str):
    """Resolve NS for a single label, returning records, server and reason."""
    retries = 0
    last_reason = None
    last_server = None
    while retries < len(DNS_SERVERS):
        try:
            idx = (hash(label) + retries) % len(DNS_SERVERS)
            last_server = DNS_SERVERS[idx]
            global_resolver.nameservers = [last_server]
            answer = await global_resolver.resolve(label, 'NS', lifetime=DNS_TIMEOUT)
            return [str(rdata).lower() for rdata in answer], last_server, None
        except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                dns.resolver.YXDOMAIN, dns.resolver.NoAnswer) as e:
            last_reason = f"{type(e).__name__}: {str(e)[:80]}"
            retries += 1
            await asyncio.sleep(0.005)
        except Exception as e:
            stats['errors'] += 1
            last_reason = f"{type(e).__name__}: {str(e)[:80]}"
            retries += 1
            await asyncio.sleep(0.005)
    return None, last_server, last_reason

async def resolve_ns(domain: str):
    """Resolve NS, falling back to parent labels when necessary."""
    cleaned = domain.strip('.')
    if not cleaned:
        return None, None, None, "empty domain"
    labels = cleaned.split('.')
    current = labels[:]
    last_reason = None
    last_server = None
    while current:
        candidate = '.'.join(current)
        records, server_used, reason = await _resolve_ns_single(candidate)
        if records:
            return records, candidate, server_used, None
        last_reason = reason
        last_server = server_used
        if len(current) <= 2:
            break
        current = current[1:]
    return None, None, last_server, last_reason or "no NS records found"

async def resolve_ip_records(domain: str) -> tuple[list[str], list[str]]:
    """Resolve A/AAAA and return records with the DNS servers used."""
    records: list[str] = []
    servers_used: list[str] = []
    for record_type in ('A', 'AAAA'):
        retries = 0
        while retries < len(DNS_SERVERS):
            try:
                idx = (hash(f"{domain}-{record_type}") + retries) % len(DNS_SERVERS)
                server = DNS_SERVERS[idx]
                global_resolver.nameservers = [server]
                answer = await global_resolver.resolve(domain, record_type, lifetime=DNS_TIMEOUT)
                records.extend(str(rdata) for rdata in answer)
                servers_used.append(server)
                break
            except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                    dns.resolver.YXDOMAIN, dns.resolver.NoAnswer):
                retries += 1
                await asyncio.sleep(0.005)
            except Exception:
                stats['errors'] += 1
                retries += 1
                await asyncio.sleep(0.005)
    return records, servers_used

def is_problematic_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or
            ip.is_unspecified or ip.is_link_local or getattr(ip, 'is_site_local', False))


async def check_domain(domain, sessions, pbar, pbar_lock: asyncio.Lock, 
                      good_file, non_existent_file, parked_file, redirect_file, incorrect_file):
    """Check a single domain for DNS, NS, and redirect status."""
    async with asyncio.Semaphore(CONCURRENCY):
        try:
            # DNS Resolution
            ns_records, ns_authority, ns_server, ns_error = await resolve_ns(domain)
            if not ns_records:
                stats['non_existent'] += 1
                reason = ns_error or "No NS response"
                detail = f"[DNS {ns_server}] {reason}" if ns_server else reason
                print_domain_status(domain, "non_existent", detail)
                non_existent_file.write(domain + "\n")
                async with pbar_lock:
                    pbar.update(1)
                return

            ns_note = ''
            if ns_authority and ns_authority.lower() != domain.lower():
                ns_note = f"(NS from {ns_authority}"
                if ns_server:
                    ns_note = f"{ns_note}, DNS {ns_server}"
                ns_note = f"{ns_note})"
            elif ns_server:
                ns_note = f"(DNS {ns_server})"

            # NS Filtering (Parked domains)
            if any(any(substr in ns for substr in NS_FILTER_SUBSTRINGS) for ns in ns_records):
                stats['parked'] += 1
                print_domain_status(domain, "parked", ns_note)
                parked_file.write(domain + "\n")
                async with pbar_lock:
                    pbar.update(1)
                return

            # A/AAAA sanity check
            ip_records, ip_servers = await resolve_ip_records(domain)
            if ip_records:
                bad_ips = [ip for ip in ip_records if is_problematic_ip(ip)]
                if bad_ips and len(bad_ips) == len(ip_records):
                    stats['incorrect'] += 1
                    server_info = f" [DNS {', '.join(sorted(set(ip_servers)))}]" if ip_servers else ""
                    details = f"IPs: {', '.join(bad_ips)}{server_info}"
                    if ns_note:
                        details = f"{details} {ns_note}"
                    print_domain_status(domain, "incorrect", details)
                    incorrect_file.write(domain + "\n")
                    async with pbar_lock:
                        pbar.update(1)
                    return

            # HTTPS Redirect Check
            session = sessions[hash(domain) % len(sessions)]
            try:
                url = f"https://{domain}"
                async with session.get(url, allow_redirects=True, timeout=HTTP_TIMEOUT) as resp:
                    domain_lower = domain.lower().rstrip('.')
                    final_host = (resp.url.host or '').lower().rstrip('.')
                    history_hosts = [
                        (history.url.host or '').lower().rstrip('.')
                        for history in resp.history
                        if getattr(history, "url", None)
                    ]

                    redirected = bool(resp.history)
                    ww_redirect = has_banned_redirect_prefix(final_host) or any(
                        has_banned_redirect_prefix(host) for host in history_hosts
                    )

                    same_domain_final = is_same_registered_domain(final_host, domain_lower)
                    same_domain_history = all(
                        is_same_registered_domain(host, domain_lower) for host in history_hosts if host
                    )

                    cross_domain = (not same_domain_final) or (not same_domain_history)

                    if redirected and (ww_redirect or cross_domain or not final_host):
                        stats['redirect'] += 1
                        note = ""
                        if ww_redirect:
                            note = " (blocked ww25/ww38 redirect)"
                        elif cross_domain:
                            note = " (external redirect)"
                        details = f"-> {resp.url}{note}"
                        if ns_note:
                            details = f"{details} {ns_note}"
                        print_domain_status(domain, "redirect", details)
                        redirect_file.write(domain + "\n")
                        async with pbar_lock:
                            pbar.update(1)
                        return
            except Exception:
                # Continue to mark as good - step 3 will handle content analysis
                pass

            # Domain passed all checks
            stats['good'] += 1
            print_domain_status(domain, "good", ns_note)
            good_file.write(domain + "\n")
            async with pbar_lock:
                pbar.update(1)

        except Exception as e:
            stats['errors'] += 1
            print_domain_status(domain, "error", f"Exception: {str(e)[:50]}")
            async with pbar_lock:
                pbar.update(1)


async def main():
    """Main execution function."""
    start_time = time.time()
    print_header()
    
    script_dir = Path(__file__).parent

    # Check input file
    input_file = script_dir / "domains_new_1.lst"
    if not input_file.exists():
        print_status(f"❌ Input file not found: {input_file}", "error")
        return
    
    # Load domains
    print_status(f"📂 Loading domains from {input_file}...", "progress")
    domains = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                domains.append(line)
    
    stats['total'] = len(domains)
    print_status(f"📊 Total domains to process: {stats['total']:,}", "info")
    print_status(f"🔧 Configuration: {CONCURRENCY} concurrent, {SESSION_COUNT} sessions, {DNS_TIMEOUT}s DNS timeout", "info")
    print()
    
    # Setup output files
    output_files = {
        'good': script_dir / 'domains_new_2.lst',
        'non_existent': script_dir / 'domains_non_existent.lst',
        'parked': script_dir / 'domains_parked.lst',
        'redirect': script_dir / 'domains_redirect.lst',
        'incorrect': script_dir / 'domains_incorrect.lst'
    }
    
    print_status("📁 Output files:", "info")
    for category, path_obj in output_files.items():
        print_status(f"   {category}: {path_obj}", "info")
    print()
    
    # Open output files
    file_handles = {}
    for category, path_obj in output_files.items():
        file_handles[category] = open(path_obj, "w", encoding="utf-8")
    
    # Setup HTTP sessions
    print_status("🌐 Setting up HTTP sessions...", "progress")
    session_timeout = aiohttp.ClientTimeout(total=8)
    default_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
        "Connection": "close",
    }
    
    sessions = [
        aiohttp.ClientSession(
            timeout=session_timeout,
            headers=default_headers,
            connector=aiohttp.TCPConnector(limit=600, enable_cleanup_closed=True)
        )
        for _ in range(SESSION_COUNT)
    ]
    
    print_status("🚀 Starting domain processing...", "success")
    print()
    
    # Process domains with enhanced progress bar
    pbar_lock = asyncio.Lock()
    
    with tqdm(
        total=len(domains),
        desc=f"{Fore.CYAN}Processing domains{Style.RESET_ALL}",
        unit="domain",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
        colour="cyan",
        dynamic_ncols=True,
        smoothing=0.05
    ) as pbar:
        pbar.set_description(format_progress_description())
        
        for i in range(0, len(domains), BATCH_SIZE):
            batch = domains[i:i+BATCH_SIZE]
            
            # Process batch
            tasks = [
                asyncio.create_task(
                    check_domain(
                        domain, sessions, pbar, pbar_lock,
                        file_handles['good'], file_handles['non_existent'],
                        file_handles['parked'], file_handles['redirect'], file_handles['incorrect']
                    )
                ) for domain in batch
            ]
            await asyncio.gather(*tasks)
            pbar.set_description(format_progress_description())
            
            # Periodic garbage collection
            if i % (BATCH_SIZE * 5) == 0:
                gc.collect()
    
    # Cleanup
    print_status("🧹 Cleaning up resources...", "progress")
    for session in sessions:
        await session.close()
    
    for file_handle in file_handles.values():
        file_handle.close()
    
    # Calculate final statistics
    elapsed_time = time.time() - start_time
    good_rate = (stats['good'] / stats['total']) * 100 if stats['total'] > 0 else 0
    
    # Print final results
    print_status("\n" + "="*70, "success")
    print_status("📈 PROCESSING RESULTS", "success")
    print_status("="*70, "success")
    print_status(f"⏱️  Processing time: {elapsed_time:.2f} seconds", "info")
    print_status(f"📊 Total domains processed: {stats['total']:,}", "info")
    print_status(f"✅ OK domains: {stats['good']:,} ({good_rate:.1f}%)", "success")
    print_status(f"❌ Non-existent domains: {stats['non_existent']:,}", "error")
    print_status(f"🅿️  Parked domains: {stats['parked']:,}", "info")
    print_status(f"↗️  Redirect domains: {stats['redirect']:,}", "warning")
    print_status(f"?? Incorrect IP domains: {stats['incorrect']:,}", "warning")
    print_status(f"⚠️  Errors: {stats['errors']:,}", "warning")
    print_status(f"📁 Files created:", "info")
    for category, path_obj in output_files.items():
        print_status(f"   • {category}: {path_obj}", "info")
    print_status("="*70, "success")
    
    # Performance metrics
    domains_per_second = stats['total'] / elapsed_time if elapsed_time > 0 else 0
    print_status(f"⚡ Processing speed: {domains_per_second:.0f} domains/second", "info")
    run_qc_check(script_dir, output_files)

if __name__ == "__main__":
    # Check system resources
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < 8192:
            print_status(f"⚠️  Low open files limit detected: {soft}. Consider 'ulimit -n 65535' for stability.", "warning")
    except Exception:
        pass
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_status("\n⚠️  Process interrupted by user", "warning")
    except Exception as e:
        print_status(f"\n❌ Unexpected error: {e}", "error")
        raise




