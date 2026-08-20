import ipaddress
from pathlib import Path
from datetime import datetime
import requests
import dns.resolver
import re

# 文件路径定义
DOMAIN_FILE = Path("domain_seed.txt")
OUTPUT_FILE = Path("domain.txt")              # 纯净的最终 /24 CIDR 总库
MAPPING_FILE = Path("domain_ip_mapping.txt")  # 域名 -> IP -> /24 溯源关系
FILTERED_DOMAINS_FILE = Path("filtered_domains.txt") # 过滤掉的域名（Cloudflare/Vercel/GitHub等）
CIDR_HISTORY_FILE = Path("cidr_history.txt")  # CIDR 历史记录（带首次发现时间，去重）

# 静态过滤网段
STATIC_FILTER_NETWORKS = [
    ipaddress.ip_network("76.76.21.0/24"),      # Vercel
    ipaddress.ip_network("185.199.108.0/22"),   # GitHub Pages
]

def load_cf_networks():
    url = "https://www.cloudflare.com/ips-v4"
    try:
        r = requests.get(url, timeout=10)
        return [
            ipaddress.ip_network(x.strip())
            for x in r.text.splitlines()
            if x.strip()
        ]
    except Exception as e:
        print("[!] Cloudflare列表加载失败")
        return []

CF_NETWORKS = load_cf_networks()

def is_cloudflare(ip):
    try:
        addr = ipaddress.ip_address(ip)
        for net in CF_NETWORKS:
            if addr in net:
                return True
    except:
        pass
    return False

def is_static_filtered(ip):
    try:
        addr = ipaddress.ip_address(ip)
        for net in STATIC_FILTER_NETWORKS:
            if addr in net:
                return True
    except:
        pass
    return False

def is_filtered(ip):
    return is_cloudflare(ip) or is_static_filtered(ip)

def load_targets():
    if not DOMAIN_FILE.exists():
        print("[!] domain_seed.txt 不存在")
        return set(), set()

    domains = set()
    direct_ips = set()
    
    ip_only_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for line in DOMAIN_FILE.read_text(encoding="utf-8").splitlines():
        target = line.strip()

        if not target or target.startswith("#"):
            continue

        # 剥离协议和路径
        if "://" in target:
            target = target.split("://", 1)[1]
        target = target.split("/", 1)[0]
        
        # 剥离端口（兼容 IPv6 格式）
        if ":" in target and target.count(":") == 1:
            possible_ip, possible_port = target.rsplit(":", 1)
            if possible_port.isdigit():
                target = possible_ip

        # 检查是否为纯 IP
        match = ip_only_pattern.match(target)
        if match:
            raw_ip = match.group(1)
            try:
                ipaddress.ip_address(raw_ip)
                direct_ips.add(raw_ip)
                continue
            except ValueError:
                pass

        if target:
            domains.add(target)

    return sorted(domains), sorted(direct_ips)

def resolve_domain_recursive(domain, max_depth=5):
    """支持多级 CNAME 递归追溯的解析函数"""
    ips = set()
    current_queries = [domain]
    visited = set()

    for _ in range(max_depth):
        next_queries = []
        for q in current_queries:
            if q in visited:
                continue
            visited.add(q)

            # 尝试解析 A 记录
            try:
                answers = dns.resolver.resolve(q, "A", lifetime=5)
                for r in answers:
                    ip = str(r)
                    try:
                        ipaddress.ip_address(ip)
                        ips.add(ip)
                    except ValueError:
                        pass
            except Exception:
                pass

            # 尝试解析 CNAME 记录
            try:
                cnames = dns.resolver.resolve(q, "CNAME", lifetime=5)
                for r in cnames:
                    cname_target = str(r).rstrip(".")
                    if cname_target not in visited:
                        next_queries.append(cname_target)
            except Exception:
                pass

        if not next_queries:
            break
        current_queries = next_queries

    return ips

def ip_to_cidr(ip):
    try:
        net = ipaddress.ip_network(ip + "/24", strict=False)
        return str(net)
    except ValueError:
        return None

def load_existing_set(file_path):
    existing = set()
    if file_path.exists():
        for line in file_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                existing.add(line)
    return existing

def load_mapping_history():
    """加载历史映射关系，格式: domain -> ip -> cidr"""
    mapping = set()
    if MAPPING_FILE.exists():
        for line in MAPPING_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                mapping.add(line)
    return mapping

def load_cidr_history_dict():
    """加载 CIDR 历史记录，返回 {cidr: first_seen_date} 字典"""
    history = {}
    if CIDR_HISTORY_FILE.exists():
        for line in CIDR_HISTORY_FILE.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split(" ", 1)
            if len(parts) == 2:
                date_str, cidr = parts
                history[cidr] = date_str
    return history

def main():
    domains, direct_ips = load_targets()

    if not domains and not direct_ips:
        print("[!] 没有有效的内容")
        return

    old_cidrs = load_existing_set(OUTPUT_FILE)
    filtered_existing = load_existing_set(FILTERED_DOMAINS_FILE)
    old_mappings = load_mapping_history()
    cidr_history = load_cidr_history_dict()

    new_cidrs = set()
    new_mappings = set()
    filtered_collected = set(filtered_existing)
    
    today_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    print(f"[*] 域名数量: {len(domains)}, 直接IP数量: {len(direct_ips)}")

    # 1. 处理直接提取的 IP
    for ip in direct_ips:
        if is_filtered(ip):
            print(f"[-] 过滤直接IP -> {ip}")
            continue

        cidr = ip_to_cidr(ip)
        if cidr:
            new_cidrs.add(cidr)
            new_mappings.add(f"[Direct_IP] -> {ip} -> {cidr}")
            if cidr not in cidr_history:
                cidr_history[cidr] = today_str

    # 2. 处理域名解析 (带多级 CNAME 递归)
    for domain in domains:
        ips = resolve_domain_recursive(domain)

        if ips:
            print(f"[+] {domain} -> {','.join(ips)}")

        domain_has_valid_ip = False
        for ip in ips:
            if is_filtered(ip):
                print(f"[-] 过滤IP {domain} -> {ip}")
                filtered_collected.add(domain)
                continue

            domain_has_valid_ip = True
            cidr = ip_to_cidr(ip)
            if cidr:
                new_cidrs.add(cidr)
                new_mappings.add(f"{domain} -> {ip} -> {cidr}")
                if cidr not in cidr_history:
                    cidr_history[cidr] = today_str

        # 如果域名解析出的所有 IP 全被过滤，也归入过滤名单
        if not domain_has_valid_ip and ips:
            filtered_collected.add(domain)

    # 持久化：被过滤的域名清单
    if filtered_collected:
        FILTERED_DOMAINS_FILE.write_text(
            "\n".join(sorted(filtered_collected)) + "\n",
            encoding="utf-8"
        )

    # 持久化：溯源关系库
    all_mappings = old_mappings | new_mappings
    if all_mappings:
        MAPPING_FILE.write_text(
            "\n".join(sorted(all_mappings)) + "\n",
            encoding="utf-8"
        )

    # 计算真新增网段
    real_new = new_cidrs - old_cidrs

    # 持久化：纯净的 /24 CIDR 总库
    if new_cidrs:
        total_cidrs = sorted(old_cidrs | new_cidrs)
        OUTPUT_FILE.write_text("\n".join(total_cidrs) + "\n", encoding="utf-8")

    # 持久化：CIDR 历史去重（带首次发现时间，不重复累加）
    if cidr_history:
        history_lines = [f"{date} {cidr}" for cidr, date in sorted(cidr_history.items(), key=lambda x: x[1])]
        CIDR_HISTORY_FILE.write_text("\n".join(history_lines) + "\n", encoding="utf-8")

    print("===================")
    print(f"[+] 本轮真新增网段: {len(real_new)}")
    print(f"[+] 当前 domain.txt 总数: {len(old_cidrs | new_cidrs)}")

if __name__ == "__main__":
    main()
