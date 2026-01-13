import concurrent.futures
import gc
import ipaddress
import logging
import os
import re
import socket
import tempfile
import threading
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from queue import Queue

import geoip2.database
import requests
from colorama import Fore, Style, init
from idna import encode as idna_encode
from tqdm import tqdm


GEOIP_DB_PATH = "GeoLite2-ASN.mmdb"
GEOLITE_URL = "https://github.com/FyraLabs/geolite2/releases/latest/download/GeoLite2-ASN.mmdb"
GEOLITE_META_PATH = "GeoLite2-ASN.mmdb.meta"

DOMAINS_FILE = "domains.lst"
SUMMARY_FILE = "ip.lst"

THREAD_COUNT = 35
MAX_RETRIES = 2


def configure_logging():
    # Centralized log setup with colored console output and a clean file log.
    init()

    class ColorStrippingFormatter(logging.Formatter):
        ansi = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

        def format(self, record):
            formatted = super().format(record)
            return self.ansi.sub("", formatted)

    class ColorFormatter(logging.Formatter):
        LEVEL_COLORS = {
            logging.DEBUG: Fore.CYAN,
            logging.INFO: Fore.GREEN,
            logging.WARNING: Fore.YELLOW,
            logging.ERROR: Fore.RED,
            logging.CRITICAL: Fore.MAGENTA,
        }

        def format(self, record):
            color = self.LEVEL_COLORS.get(record.levelno, "")
            reset = Style.RESET_ALL if color else ""
            message = super().format(record)
            return f"{color}{message}{reset}"

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.DEBUG)

    log_path = Path(__file__).resolve().with_name("ip_resolve.log")
    file_fmt = ColorStrippingFormatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    file_handler.setFormatter(file_fmt)

    console_fmt = ColorFormatter("%(message)s")
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_fmt)

    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    error_logger = logging.getLogger("error")
    error_logger.setLevel(logging.ERROR)
    return error_logger


def parse_http_datetime(value):
    # Convert HTTP Last-Modified header to a timestamp, if present.
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).timestamp()
    except Exception:
        return None


def read_meta(path):
    # Load simple key=value metadata for the GeoLite2 database.
    data = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                data[key.strip()] = val.strip()
    except FileNotFoundError:
        return {}
    except Exception as exc:
        logging.warning("Failed to read GeoLite2 meta file %s: %s", path, exc)
    return data


def write_meta(path, data):
    # Persist metadata so we can avoid unnecessary downloads.
    try:
        with open(path, "w", encoding="utf-8") as f:
            for key in sorted(data.keys()):
                f.write(f"{key}={data[key]}\n")
    except Exception as exc:
        logging.warning("Failed to write GeoLite2 meta file %s: %s", path, exc)


def fetch_remote_headers(url):
    # Lightweight check for freshness using ETag/Last-Modified headers.
    try:
        response = requests.head(url, allow_redirects=True, timeout=30)
        return {
            "etag": (response.headers.get("ETag") or "").strip(),
            "last_modified": (response.headers.get("Last-Modified") or "").strip(),
            "content_length": (response.headers.get("Content-Length") or "").strip(),
            "final_url": response.url,
            "status_code": response.status_code,
        }
    except Exception as exc:
        logging.warning("Failed to fetch GeoLite2 headers from %s: %s", url, exc)
        return {}


def download_file(url, dest_path):
    # Stream download to avoid loading large files into memory.
    with requests.get(url, stream=True, timeout=(10, 300)) as response:
        response.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)


def ensure_geolite_db(db_path, meta_path, url):
    # Update the GeoLite2 ASN database only when remote is newer.
    local_exists = os.path.isfile(db_path)
    meta = read_meta(meta_path)
    headers = fetch_remote_headers(url)

    etag_remote = headers.get("etag", "")
    last_modified_remote = headers.get("last_modified", "")
    content_length_remote = headers.get("content_length", "")
    remote_ts = parse_http_datetime(last_modified_remote)

    need_download = not local_exists
    if local_exists and headers:
        meta_etag = meta.get("etag", "")
        if etag_remote and meta_etag and etag_remote == meta_etag:
            need_download = False
        elif remote_ts is not None:
            local_mtime = os.path.getmtime(db_path)
            if local_mtime >= remote_ts:
                need_download = False

    if not need_download:
        return

    tmp_dir = os.path.dirname(os.path.abspath(db_path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix="geolite-", suffix=".mmdb", dir=tmp_dir)
    os.close(fd)
    try:
        download_file(url, tmp_path)
        os.replace(tmp_path, db_path)
        if remote_ts is not None:
            os.utime(db_path, (remote_ts, remote_ts))
        write_meta(
            meta_path,
            {
                "etag": etag_remote,
                "last_modified": last_modified_remote,
                "content_length": content_length_remote,
                "source_url": headers.get("final_url", url) if headers else url,
            },
        )
        logging.info("Updated GeoLite2 ASN database at %s", db_path)
    except Exception as exc:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        if local_exists:
            logging.warning(
                "Failed to update GeoLite2 ASN database: %s. Using existing file.",
                exc,
            )
        else:
            raise


# Company ASN allow/deny logic and domain mapping.
TRUSTED_ASNS = {
    15169,  # Google
    32934,  # Facebook (Meta)
    714,  # Apple
    8075,  # Microsoft
    2906,  # Netflix
    20940,  # Akamai
    394161,  # Tesla
    13414,  # Twitter
    19679,  # Dropbox
    14492,  # LinkedIn
}

HOSTING_ASNS = {
    13335,  # Cloudflare
    54113,  # Fastly
    16509,  # Amazon Web Services (AWS)
    15169,  # Google Cloud
    8075,  # Microsoft Azure
    14061,  # DigitalOcean
    20473,  # Vultr
    63949,  # Linode
    16276,  # OVH
    20940,  # Akamai
    24940,  # Hetzner
    19994,  # Rackspace
    37963,  # Alibaba Cloud
    35908,  # IBM Cloud
    31898,  # Oracle Cloud
    55293,  # Kinsta
    46606,  # HostGator
    26347,  # DreamHost
    26496,  # GoDaddy
    46606,  # Bluehost
}

COMPANY_DOMAINS = {
    "google.com": [15169],
    "youtube.com": [15169],
    "facebook.com": [32934],
    "instagram.com": [32934],
    "whatsapp.com": [32934],
    "apple.com": [714],
    "icloud.com": [714],
    "appleid.apple.com": [714],
    "microsoft.com": [8075],
    "windows.com": [8075],
    "live.com": [8075],
    "office.com": [8075],
    "onedrive.com": [8075],
    "linkedin.com": [14492],
    "netflix.com": [2906],
    "netflixcdn.net": [2906],
    "akamai.com": [20940],
    "akamai.net": [20940],
    "twitter.com": [13414],
    "x.com": [13414],
    "dropbox.com": [19679],
    "tesla.com": [394161],
}


def is_trusted_domain(domain, asn):
    # Treat subdomains of trusted companies as trusted when ASN matches.
    if domain in COMPANY_DOMAINS:
        return asn in COMPANY_DOMAINS[domain]
    for root_domain, asns in COMPANY_DOMAINS.items():
        if domain.endswith(f".{root_domain}"):
            return asn in asns
    return False


def resolve_domain(domain, error_logger, max_retries=MAX_RETRIES):
    # Resolve domain to IPs with punycode support and retries.
    ip_set = set()
    try:
        domain = idna_encode(domain).decode("utf-8")
    except Exception as exc:
        error_logger.error("Punycode conversion failed for domain %s: %s", domain, exc)
        return []

    for _ in range(max_retries):
        try:
            ip_list = socket.gethostbyname_ex(domain)[2]
            ip_set.update(ip_list)
            logging.info("Resolved %s to IPs: %s", domain, ip_list)
        except socket.gaierror as exc:
            error_logger.error("Could not resolve domain %s: %s", domain, exc)
    return list(ip_set)


def get_all_cidrs_from_bgpview(asn, error_logger):
    # Preferred ASN prefix source, with rate-limit backoff.
    try:
        url = f"https://api.bgpview.io/asn/{asn}/prefixes"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            return [prefix["prefix"] for prefix in data["data"]["ipv4_prefixes"]]
        if response.status_code == 429:
            error_logger.error(
                "Rate limit exceeded, waiting before retrying for ASN %s", asn
            )
            time.sleep(60)
            return get_all_cidrs_for_asn(asn, error_logger)
        if response.status_code == 403:
            error_logger.error("Access forbidden for ASN %s, status code 403.", asn)
        else:
            error_logger.error(
                "Failed to get CIDRs for ASN %s from BGPView, status code: %s",
                asn,
                response.status_code,
            )
        return []
    except Exception as exc:
        error_logger.error("Error retrieving CIDRs from BGPView for ASN %s: %s", asn, exc)
        return []


def get_all_cidrs_from_ripe(asn, error_logger):
    # RIPEstat fallback for ASN prefixes.
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            ipv4_prefixes = [
                prefix["prefix"]
                for prefix in data["data"]["prefixes"]
                if ":" not in prefix["prefix"]
            ]
            logging.info("Retrieved CIDRs for ASN %s from RIPEstat: %s", asn, ipv4_prefixes)
            return ipv4_prefixes
        error_logger.error(
            "Failed to get CIDRs for ASN %s from RIPEstat, status code: %s",
            asn,
            response.status_code,
        )
        return []
    except Exception as exc:
        error_logger.error("Error retrieving CIDRs from RIPEstat for ASN %s: %s", asn, exc)
        return []


def get_all_cidrs_from_ipinfo(asn, error_logger):
    # Last-resort ASN prefix source.
    try:
        url = f"https://ipinfo.io/{asn}"
        token = os.getenv("IPINFO_TOKEN", "").strip()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()
            ipv4_prefixes = data.get("prefixes", [])
            logging.info("Retrieved CIDRs for ASN %s from IPinfo: %s", asn, ipv4_prefixes)
            return ipv4_prefixes
        error_logger.error(
            "Failed to get CIDRs for ASN %s from IPinfo, status code: %s",
            asn,
            response.status_code,
        )
        return []
    except Exception as exc:
        error_logger.error("Error retrieving CIDRs from IPinfo for ASN %s: %s", asn, exc)
        return []


def get_all_cidrs_for_asn(asn, error_logger):
    # Try multiple sources until we get a result.
    cidrs = get_all_cidrs_from_bgpview(asn, error_logger)
    if not cidrs:
        cidrs = get_all_cidrs_from_ripe(asn, error_logger)
    if not cidrs:
        cidrs = get_all_cidrs_from_ipinfo(asn, error_logger)
    return cidrs


def get_cidr_for_ip(ip, reader, error_logger):
    # Map IP to ASN and network via GeoLite2.
    try:
        response = reader.asn(ip)
        asn = response.autonomous_system_number
        network = response.network
        logging.info("IP %s mapped to ASN %s, CIDR: %s", ip, asn, network)
        return asn, str(network)
    except Exception as exc:
        error_logger.error("Error retrieving CIDR for IP %s: %s", ip, exc)
        return None, None


def is_ip_in_existing_cidr(ip, cidrs, error_logger):
    # Avoid duplicating IPs already covered by known CIDR blocks.
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in cidrs:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError as exc:
        error_logger.error("Invalid IP or CIDR: %s - %s", ip, exc)
    return False


def summarize_ips(ips, error_logger):
    # Collapse /32s to a max of /28 for compact output.
    try:
        ips = sorted(ips, key=ipaddress.ip_address)
        networks = ipaddress.collapse_addresses(
            [ipaddress.ip_network(f"{ip}/32") for ip in ips]
        )
        summarized_networks = []
        for network in networks:
            if network.prefixlen < 28:
                summarized_networks.extend(network.subnets(new_prefix=28))
            else:
                summarized_networks.append(network)

        return summarized_networks
    except Exception as exc:
        error_logger.error("Error summarizing IPs: %s", exc)
        return []


def process_domain(domain, existing_cidrs, reader, error_logger):
    # Resolve a domain and emit CIDRs based on ASN trust/hosting rules.
    try:
        cidrs = set()
        ip_addresses = resolve_domain(domain, error_logger)
        hosting_ips = []
        for ip in ip_addresses:
            asn, cidr = get_cidr_for_ip(ip, reader, error_logger)
            if asn in TRUSTED_ASNS and is_trusted_domain(domain, asn):
                if not is_ip_in_existing_cidr(ip, existing_cidrs, error_logger):
                    cidrs.update(get_all_cidrs_for_asn(asn, error_logger))
            elif asn not in TRUSTED_ASNS or not is_trusted_domain(domain, asn):
                cidrs.add(f"{ip}/32")
            elif asn in HOSTING_ASNS:
                hosting_ips.append(ip)

        if hosting_ips:
            summarized_cidrs = summarize_ips(hosting_ips, error_logger)
            cidrs.update(str(cidr) for cidr in summarized_cidrs)

        return cidrs
    except Exception as exc:
        error_logger.error("Error processing domain %s: %s", domain, exc)
        return set()


def read_domains_from_file(file_path, error_logger):
    # Read domains list, skipping empty lines.
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            domains = [line.strip() for line in f if line.strip()]
        logging.info("Read %s domains from file.", len(domains))
        return domains
    except FileNotFoundError as exc:
        error_logger.error("File not found: %s, %s", file_path, exc)
        return []


def write_cidrs_to_file(filename, results_queue, file_write_lock):
    # Dedicated writer thread to serialize output appends.
    while True:
        cidrs = results_queue.get()
        if cidrs is None:
            break
        with file_write_lock:
            with open(filename, "a", encoding="utf-8") as f:
                for cidr in cidrs:
                    f.write(f"{cidr}\n")
            logging.info("Written %s CIDRs to %s", len(cidrs), filename)
        results_queue.task_done()


def _sort_key(value):
    try:
        net = ipaddress.ip_network(value, strict=False)
        return (0, int(net.network_address), net.prefixlen)
    except ValueError:
        return (1, value)


def dedupe_and_sort(input_path, output_path, log_path):
    counts = {}
    ordered = []
    try:
        with input_path.open("r", encoding="utf-8") as f:
            for line in f:
                value = line.strip()
                if not value:
                    continue
                counts[value] = counts.get(value, 0) + 1
                if counts[value] == 1:
                    ordered.append(value)
    except FileNotFoundError:
        logging.warning("Dedup input file not found: %s", input_path)
        return

    ordered.sort(key=_sort_key)
    with output_path.open("w", encoding="utf-8") as f:
        for line in ordered:
            f.write(f"{line}\n")

    dup_items = [(value, counts[value] - 1) for value in counts if counts[value] > 1]
    dup_items.sort(key=lambda item: (-item[1], _sort_key(item[0])))
    with log_path.open("w", encoding="utf-8") as f:
        for value, dupes in dup_items:
            f.write(f"{value} duplicates_removed={dupes}\n")

    logging.info("Wrote %s unique lines to %s", len(ordered), output_path)
    logging.info("Duplicate log: %s", log_path)


def main():
    # Orchestrate update, resolution, and output.
    error_logger = configure_logging()
    ensure_geolite_db(GEOIP_DB_PATH, GEOLITE_META_PATH, GEOLITE_URL)
    reader = geoip2.database.Reader(GEOIP_DB_PATH)

    gc.enable()
    domains = read_domains_from_file(DOMAINS_FILE, error_logger)
    if not domains:
        logging.info("No domains to process.")
        return

    existing_cidrs = set()
    file_write_lock = threading.Lock()
    results_queue = Queue()

    raw_fd, raw_path = tempfile.mkstemp(prefix="ip-raw-", suffix=".lst")
    os.close(raw_fd)
    raw_output = Path(raw_path)
    writer_thread = threading.Thread(
        target=write_cidrs_to_file, args=(str(raw_output), results_queue, file_write_lock)
    )
    writer_thread.start()

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_domain = {
            executor.submit(process_domain, domain, existing_cidrs, reader, error_logger): domain
            for domain in domains
        }

        with tqdm(
            total=len(domains),
            desc=f"{Fore.CYAN}Resolving domains{Style.RESET_ALL}",
            unit="domain",
            dynamic_ncols=True,
        ) as pbar:
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    domain_cidrs = future.result()
                    if domain_cidrs:
                        existing_cidrs.update(domain_cidrs)
                        logging.info("CIDRs found for %s: %s", domain, domain_cidrs)
                        results_queue.put(list(domain_cidrs))
                except Exception as exc:
                    error_logger.error("Error with domain %s: %s", domain, exc)
                finally:
                    pbar.update(1)
                    gc.collect()

    results_queue.put(None)
    writer_thread.join()
    reader.close()

    dedupe_and_sort(
        raw_output,
        Path(SUMMARY_FILE),
        Path("ip_duplicate.log"),
    )
    try:
        os.remove(raw_output)
    except OSError:
        logging.warning("Failed to remove temporary raw output file: %s", raw_output)


if __name__ == "__main__":
    main()
