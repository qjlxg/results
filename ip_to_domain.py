import socket
import ssl
import re
import threading
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography import x509
from cryptography.x509.oid import NameOID

BASE_DIR = Path(".")
INPUT_FILE = BASE_DIR / "alive_latest.txt"

# 物理分流输出文件
OUTPUT_ALL = BASE_DIR / "domain_candidates.txt"
OUTPUT_PTR = BASE_DIR / "ptr_domains.txt"
OUTPUT_TLS = BASE_DIR / "tls_domains.txt"
OUTPUT_IPS = BASE_DIR / "tls_ips.txt"         
OUTPUT_MAPPING = BASE_DIR / "tls_mapping.txt"   # 带端口、域名、过期时间及 Issuer 的精确映射
OUTPUT_DNS_SEED = BASE_DIR / "dns_seed.txt"     # 专供下一步 DNS 解析扩展的纯域名种子池

# 高频代理/面板 TLS 端口
TLS_PORTS = [443, 8443, 2053, 2083, 2087, 2096, 9443]

# 黑名单过滤无价值通用/默认名称
IGNORE_DOMAINS = {
    "localhost",
    "example.com",
    "invalid",
    "cloudflare-dns.com",
    "default",
    "kubernetes.docker.internal",
    "nginx",
    "server"
}

# 使用 threading.local() 为多线程独立隔离 SSLContext
_tls_local = threading.local()

def get_ssl_context():
    """获取线程局部的 SSL 上下文"""
    if not hasattr(_tls_local, "context"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _tls_local.context = ctx
    return _tls_local.context

def extract_ip(target):
    """严格带转义的 IPv4 提取正则"""
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', target)
    return m.group(1) if m else None

def is_valid_domain(domain):
    """严谨的域名合法性校验（自动过滤纯 IP、黑名单及无效格式）"""
    if not domain:
        return False

    domain = domain.lower().strip()

    # 核心：利用 ipaddress 模块防止把 IP 当成域名通过
    try:
        ipaddress.ip_address(domain)
        return False
    except Exception:
        pass

    if domain in IGNORE_DOMAINS:
        return False
    
    if "." not in domain or domain.startswith(".") or domain.endswith("."):
        return False
        
    if len(domain) > 253:
        return False
        
    return True

def is_port_open(ip, port, timeout=0.5):
    """TCP 端口轻量预检（超时压至 0.5s 极速剪枝）"""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def get_tls_assets(ip, port=443, timeout=2):
    """多端口 TLS 深度解析：提取合法域名、IP SAN、证书到期时间及 Issuer 颁发者"""
    domains = set()
    ips = set()
    expire_date = "UNKNOWN"
    issuer_str = "UNKNOWN"
    
    # 先走轻量 TCP 探活，不通直接跳过
    if not is_port_open(ip, port, timeout=0.5):
        return domains, ips, expire_date, issuer_str
    
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            context = get_ssl_context()
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return domains, ips, expire_date, issuer_str

                cert = x509.load_der_x509_certificate(der_cert)

                # 提取证书绝对有效期
                try:
                    if hasattr(cert, "not_valid_after_utc"):
                        expire_date = cert.not_valid_after_utc.strftime("%Y-%m-%d")
                    else:
                        expire_date = cert.not_valid_after.strftime("%Y-%m-%d")
                except Exception:
                    pass

                # 提取证书颁发者 Issuer
                try:
                    issuer_str = cert.issuer.rfc4514_string()
                except Exception:
                    pass

                # 提取 SAN 扩展
                try:
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san = san_ext.value

                    # DNSName 提取与过滤
                    for name in san.get_values_for_type(x509.DNSName):
                        if name and not name.startswith("*"):
                            cleaned = name.lower()
                            if is_valid_domain(cleaned):
                                domains.add(cleaned)

                    # 独立提取证书内绑定的 IPAddress
                    for ipaddr in san.get_values_for_type(x509.IPAddress):
                        if ipaddr:
                            ips.add(str(ipaddr))
                except Exception:
                    pass

                # CN 备用提取
                try:
                    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    for item in cn:
                        if item.value:
                            cn_value = item.value.lower()
                            if not cn_value.startswith("*") and is_valid_domain(cn_value):
                                domains.add(cn_value)
                except Exception:
                    pass
    except Exception:
        pass
        
    return domains, ips, expire_date, issuer_str

def reverse_lookup(target):
    """综合反查核心逻辑"""
    ptr_results = set()
    tls_domains = set()
    tls_ips = set()
    mapping_results = set()
    dns_seeds = set()
    
    try:
        ip = extract_ip(target)
        if not ip:
            return target, ptr_results, tls_domains, tls_ips, mapping_results, dns_seeds

        # 1. PTR 反查
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname:
                cleaned_host = hostname.lower()
                if is_valid_domain(cleaned_host):
                    ptr_results.add(cleaned_host)
                    mapping_results.add(f"{ip}:PTR,{cleaned_host},UNKNOWN,PTR_REVERSE")
                    dns_seeds.add(cleaned_host)
        except Exception:
            pass

        # 2. 多端口 TLS 证书枚举
        for port in TLS_PORTS:
            domains, ips, expire_date, issuer_str = get_tls_assets(ip, port=port)
            
            for domain in domains:
                tls_domains.add(domain)
                mapping_results.add(f"{ip}:{port},{domain},{expire_date},{issuer_str}")
                dns_seeds.add(domain)
                
            for cert_ip in ips:
                tls_ips.add(cert_ip)
                mapping_results.add(f"{ip}:{port},{cert_ip},{expire_date},{issuer_str}")

    except Exception:
        pass
        
    return target, ptr_results, tls_domains, tls_ips, mapping_results, dns_seeds

def main():
    if not INPUT_FILE.exists():
        print(f"[!] 找不到输入文件: {INPUT_FILE}")
        return

    targets = [
        x.strip()
        for x in INPUT_FILE.read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]

    total_targets = len(targets)
    print(f"[*] 加载目标数: {total_targets}")

    # 动态限制线程数（50 线程平衡 Termux 手机性能）
    max_workers = min(50, total_targets) if total_targets > 0 else 1
    print(f"[*] 动态设定线程数: {max_workers}")

    all_ptr = set()
    all_tls_domains = set()
    all_tls_ips = set()
    all_mappings = set()
    all_dns_seeds = set()

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(reverse_lookup, t) for t in targets]

        for future in as_completed(futures):
            target, ptrs, tlss, ips, maps, seeds = future.result()
            if ptrs or tlss or ips:
                print(f"[+] {target} --> PTR:{len(ptrs)} TLS-Dom:{len(tlss)} TLS-IP:{len(ips)}")
                all_ptr.update(ptrs)
                all_tls_domains.update(tlss)
                all_tls_ips.update(ips)
                all_mappings.update(maps)
                all_dns_seeds.update(seeds)

    # 落地落盘保存
    OUTPUT_PTR.write_text("\n".join(sorted(all_ptr)) + "\n", encoding="utf-8")
    OUTPUT_TLS.write_text("\n".join(sorted(all_tls_domains)) + "\n", encoding="utf-8")
    OUTPUT_IPS.write_text("\n".join(sorted(all_tls_ips)) + "\n", encoding="utf-8")
    OUTPUT_MAPPING.write_text("\n".join(sorted(all_mappings)) + "\n", encoding="utf-8")
    OUTPUT_DNS_SEED.write_text("\n".join(sorted(all_dns_seeds)) + "\n", encoding="utf-8")
    
    all_combined_domains = all_ptr.union(all_tls_domains)
    OUTPUT_ALL.write_text("\n".join(sorted(all_combined_domains)) + "\n", encoding="utf-8")

    print("=" * 55)
    print(f"[*] PTR 域名收集 : {len(all_ptr)} 个 -> {OUTPUT_PTR.name}")
    print(f"[*] TLS 域名收集 : {len(all_tls_domains)} 个 -> {OUTPUT_TLS.name}")
    print(f"[*] 证书纯 IP 收集: {len(all_tls_ips)} 个 -> {OUTPUT_IPS.name}")
    print(f"[*] 精确映射留存 : {len(all_mappings)} 条 -> {OUTPUT_MAPPING.name}")
    print(f"[*] DNS 解析种子 : {len(all_dns_seeds)} 个 -> {OUTPUT_DNS_SEED.name}")
    print(f"[*] 总候选域名库 : {len(all_combined_domains)} 个 -> {OUTPUT_ALL.name}")
    print("=" * 55)

if __name__ == "__main__":
    main()
