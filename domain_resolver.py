import ipaddress
from pathlib import Path
from datetime import datetime
import requests
import dns.resolver
import re

DOMAIN_FILE = Path("domain_seed.txt")
OUTPUT_FILE = Path("domain.txt")
HISTORY_FILE = Path("domain_dns_history.txt")
CF_DOMAINS_FILE = Path("cloudflare_domains.txt")

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
    
    # 用于粗略匹配 IP 的正则
    ip_only_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for line in DOMAIN_FILE.read_text(encoding="utf-8").splitlines():
        target = line.strip()

        if not target or target.startswith("#"):
            continue

        # 智能过滤协议、路径
        if "://" in target:
            target = target.split("://", 1)[1]
        target = target.split("/", 1)[0]
        
        # 检查是否包含端口
        if ":" in target and not target.count(":") > 1: # 排除 IPv6
            possible_ip, possible_port = target.rsplit(":", 1)
            if possible_port.isdigit():
                target = possible_ip # 剥离端口

        # 验证其本身是否为纯 IP
        match = ip_only_pattern.match(target)
        if match:
            raw_ip = match.group(1)
            try:
                ipaddress.ip_address(raw_ip)
                direct_ips.add(raw_ip)
                continue
            except ValueError:
                pass

        # 剩下的当作域名处理
        if target:
            domains.add(target)

    return sorted(domains), sorted(direct_ips)

def resolve_domain(domain):
    ips = set()

    # A
    try:
        answers = dns.resolver.resolve(
            domain,
            "A",
            lifetime=5
        )

        for r in answers:
            ip = str(r)

            try:
                ipaddress.ip_address(ip)
                ips.add(ip)

            except:
                pass

    except Exception as e:
        print(f"[-] A记录解析失败 {domain}: {e}")

    # CNAME
    try:
        cname = dns.resolver.resolve(
            domain,
            "CNAME",
            lifetime=5
        )

        for r in cname:
            target = str(r).rstrip(".")

            try:
                answers = dns.resolver.resolve(
                    target,
                    "A",
                    lifetime=5
                )

                for x in answers:
                    ip = str(x)
                    try:
                        ipaddress.ip_address(ip)
                        ips.add(ip)
                    except:
                        pass

            except Exception as e:
                print(f"[-] CNAME目标A记录解析失败 {target}: {e}")

    except Exception as e:
        pass

    return ips

def ip_to_cidr(ip):
    try:
        net = ipaddress.ip_network(ip + "/24", strict=False)
        return str(net)
    except ValueError:
        return None

def load_existing():
    existing = set()
    if OUTPUT_FILE.exists():
        for line in OUTPUT_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                existing.add(line)
    return existing

def main():
    domains, direct_ips = load_targets()

    if not domains and not direct_ips:
        print("[!] 没有有效的内容")
        return

    old_cidrs = load_existing()
    new_cidrs = set()
    history = []
    cf_domains_collected = set()

    if CF_DOMAINS_FILE.exists():
        for line in CF_DOMAINS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                cf_domains_collected.add(line)

    print(f"[*] 域名数量: {len(domains)}, 直接IP数量: {len(direct_ips)}")

    # 1. 处理直接提取到的 IP
    for ip in direct_ips:
        history.append(
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [Direct_IP] {ip}"
        )

        if is_filtered(ip):
            print(f"[-] 过滤直接IP -> {ip}")
            continue

        cidr = ip_to_cidr(ip)
        if cidr:
            new_cidrs.add(cidr)

    # 2. 处理域名解析
    for domain in domains:
        ips = resolve_domain(domain)

        if ips:
            print(f"[+] {domain} -> {','.join(ips)}")

        for ip in ips:
            history.append(
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {domain} {ip}"
            )

            if is_filtered(ip):
                print(f"[-] 过滤IP {domain} -> {ip}")
                cf_domains_collected.add(domain)
                continue

            cidr = ip_to_cidr(ip)
            if cidr:
                new_cidrs.add(cidr)

    if cf_domains_collected:
        CF_DOMAINS_FILE.write_text(
            "\n".join(sorted(cf_domains_collected)) + "\n",
            encoding="utf-8"
        )

    real_new = new_cidrs - old_cidrs

    if new_cidrs:
        total = sorted(old_cidrs | new_cidrs)
        OUTPUT_FILE.write_text("\n".join(total) + "\n", encoding="utf-8")

    if history:
        old_history = set()
        if HISTORY_FILE.exists():
            old_history = set(
                HISTORY_FILE.read_text(
                    encoding="utf-8"
                ).splitlines()
            )

        old_history.update(history)

        HISTORY_FILE.write_text(
            "\n".join(sorted(old_history)) + "\n",
            encoding="utf-8"
        )

    print("===================")
    print(f"[+] 真新增网段: {len(real_new)}")
    print(f"[+] 当前 domain.txt 总数: {len(old_cidrs | new_cidrs)}")

if __name__ == "__main__":
    main()
