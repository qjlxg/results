import csv
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


# ============================================================
# 配置
# ============================================================

BASE_DIR = Path(".")
INPUT_FILE = BASE_DIR / "domain_candidates.txt"
OUTPUT_FILE = BASE_DIR / "domain_check.csv"
MAX_WORKERS = 40
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 8
MAX_CONTENT_BYTES = 512 * 1024

USER_AGENT = (
    "Mozilla/5.0 "
    "(Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/151.0 Safari/537.36"
)


# ============================================================
# 垃圾 / 默认站点特征
# ============================================================

DEFAULT_PAGE_PATTERNS = [
    r"site\s+is\s+under\s+construction",
    r"website\s+under\s+construction",
    r"this\s+site\s+is\s+currently\s+under\s+construction",
    r"coming\s+soon",
    r"under\s+construction",
    r"domain\s+is\s+parked",
    r"domain\s+parking",
    r"parked\s+domain",
    r"this\s+domain\s+is\s+for\s+sale",
    r"domain\s+for\s+sale",
    r"buy\s+this\s+domain",
    r"account\s+suspended",
    r"site\s+suspended",
    r"website\s+suspended",
    r"apache2\s+ubuntu\s+default\s+page",
    r"nginx\s+welcome",
    r"welcome\s+to\s+nginx",
    r"it\s+works!",
    r"test\s+page\s+for\s+the\s+nginx",
    r"test\s+page\s+for\s+apache",
]


# ============================================================
# URL 清洗
# ============================================================

def normalize_domain(domain):
    domain = domain.strip().lower()
    if not domain:
        return None

    if domain.startswith("*."):
        domain = domain[2:]

    if "://" in domain:
        try:
            parsed = urlparse(domain)
            domain = parsed.hostname or ""
        except Exception:
            return None

    domain = domain.rstrip(".")

    if domain.count(":") == 1:
        host, port = domain.rsplit(":", 1)
        if port.isdigit():
            domain = host

    if not domain or len(domain) > 253 or "." not in domain:
        return None

    if not re.fullmatch(r"[a-z0-9.-]+", domain, re.IGNORECASE):
        return None

    return domain


# ============================================================
# 读取域名
# ============================================================

def load_domains():
    if not INPUT_FILE.exists():
        print(f"[!] 找不到输入文件: {INPUT_FILE}")
        return []

    domains = []
    seen = set()

    for line in INPUT_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        domain = normalize_domain(line)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)

    return domains


# ============================================================
# DNS
# ============================================================

def resolve_ip(domain):
    try:
        result = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        ips = sorted({item[4][0] for item in result})
        return ",".join(ips)
    except Exception:
        return ""


# ============================================================
# HTML 标题与正文清洗
# ============================================================

def extract_title(text):
    if not text:
        return ""
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:300]


def clean_text(text):
    if not text:
        return ""
    text = re.sub(r"<script\b[^>]*>.*?</script>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<style\b[^>]*>.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def detect_page_type(title, body):
    content = f"{title} {body}".lower()
    for pattern in DEFAULT_PAGE_PATTERNS:
        if re.search(pattern, content, flags=re.IGNORECASE):
            return "DEFAULT/PARKED"
    return "NORMAL"


# ============================================================
# 单域名检查
# ============================================================

def check_domain(domain):
    result = {
        "domain": domain,
        "dns_ips": "",
        "http_status": "",
        "https_status": "",
        "final_url": "",
        "title": "",
        "content_type": "",
        "server": "",
        "content_length": "",
        "page_type": "",
        "reachable": "NO",
        "error": "",
        "checked_at": "",
    }

    dns_ips = resolve_ip(domain)
    result["dns_ips"] = dns_ips
    if not dns_ips:
        result["error"] = "DNS_FAILED"
        return result

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close",
    }

    best_response = None
    errors = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                allow_redirects=True,
                verify=False,
                stream=True,
            )

            if scheme == "https":
                result["https_status"] = response.status_code
            else:
                result["http_status"] = response.status_code

            result["content_length"] = response.headers.get("Content-Length", "")

            if best_response is None or (scheme == "https" and response.status_code < 600):
                best_response = response

            if response.status_code < 600 and scheme == "https":
                break

        except Exception as e:
            errors.append(f"{scheme}:{type(e).__name__}")

    if best_response is None:
        result["error"] = ";".join(errors) if errors else "HTTP_FAILED"
        return result

    response = best_response
    result["reachable"] = "YES"
    result["final_url"] = response.url
    result["content_type"] = response.headers.get("Content-Type", "")
    result["server"] = response.headers.get("Server", "")

    body_bytes = b""
    try:
        for chunk in response.iter_content(chunk_size=16384):
            if not chunk:
                continue
            body_bytes += chunk
            if len(body_bytes) >= MAX_CONTENT_BYTES:
                body_bytes = body_bytes[:MAX_CONTENT_BYTES]
                break
    except Exception as e:
        errors.append(f"READ:{type(e).__name__}")

    try:
        encoding = response.encoding or "utf-8"
        body = body_bytes.decode(encoding, errors="replace")
    except Exception:
        body = body_bytes.decode("utf-8", errors="replace")

    title = extract_title(body)
    result["title"] = title

    text = clean_text(body)
    result["content_snippet"] = text[:500]
    result["page_type"] = detect_page_type(title, text)

    if errors:
        result["error"] = ";".join(errors)

    result["checked_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    return result


# ============================================================
# 保存 CSV
# ============================================================

def save_csv(results):
    fieldnames = [
        "domain",
        "dns_ips",
        "reachable",
        "http_status",
        "https_status",
        "final_url",
        "title",
        "page_type",
        "content_type",
        "server",
        "content_length",
        "content_snippet",
        "error",
        "checked_at",
    ]

    with open(OUTPUT_FILE, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in results:
            writer.writerow(item)


# ============================================================
# 主程序
# ============================================================

def main():
    print("=" * 70)
    print("[*] Domain Availability Checker (Filtered Version)")
    print("=" * 70)

    domains = load_domains()
    if not domains:
        print("[!] 没有可检查的域名")
        return

    print(f"[*] 唯一域名: {len(domains)}")
    print(f"[*] 并发线程: {min(MAX_WORKERS, len(domains))}")

    results = []
    reachable = 0
    default_pages = 0
    dns_failed = 0
    errors = 0

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(domains))) as executor:
        future_map = {executor.submit(check_domain, domain): domain for domain in domains}

        completed = 0
        for future in as_completed(future_map):
            domain = future_map[future]
            completed += 1

            try:
                result = future.result()
            except Exception as e:
                result = {
                    "domain": domain,
                    "dns_ips": "",
                    "reachable": "NO",
                    "http_status": "",
                    "https_status": "",
                    "final_url": "",
                    "title": "",
                    "page_type": "",
                    "content_type": "",
                    "server": "",
                    "content_length": "",
                    "content_snippet": "",
                    "error": f"WORKER:{type(e).__name__}",
                    "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }

            results.append(result)

            if result["reachable"] == "YES":
                reachable += 1
            if result["page_type"] == "DEFAULT/PARKED":
                default_pages += 1
            if result["error"] == "DNS_FAILED":
                dns_failed += 1
            if result["error"]:
                errors += 1

            if completed % 50 == 0 or completed == len(domains):
                print(
                    f"[*] 进度: {completed}/{len(domains)} | "
                    f"可访问: {reachable} | "
                    f"默认/垃圾页: {default_pages}"
                )

    # ========================================================
    # 核心过滤：只保留真正有用的、活的、有标题的网页
    # ========================================================
    filtered_results = [
        x for x in results 
        if x["reachable"] == "YES" 
        and x["page_type"] != "DEFAULT/PARKED" 
        and x["title"].strip() != ""
    ]

    filtered_results.sort(key=lambda x: x["domain"])

    # 保存精简后的 CSV
    save_csv(filtered_results)

    print()
    print("=" * 70)
    print("[+] 检查与过滤完成")
    print(f"[*] 检查总数: {len(domains)}")
    print(f"[*] 成功过滤并保留的有效域名数: {len(filtered_results)}")
    print(f"[+] 输出文件: {OUTPUT_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    main()
