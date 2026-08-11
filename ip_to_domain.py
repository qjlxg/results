import socket
import ssl
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = Path(".")
INPUT_FILE = BASE_DIR / "alive_latest.txt"
OUTPUT_FILE = BASE_DIR / "domain_candidates.txt"

def get_tls_sans(ip, port=443, timeout=3):
    """通过 TLS 证书反查（提取 SAN 域名）"""
    domains = set()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                # 提取 subjectAltName 中的 DNS 域名
                subject_alt_name = cert.get('subjectAltName', ())
                for entry_type, value in subject_alt_name:
                    if entry_type == 'DNS':
                        if value and not value.startswith("*"):  # 过滤泛域名通配符
                            domains.add(value.lower())
    except Exception:
        pass
    return domains

def reverse_lookup(target):
    """综合反查：PTR + TLS SAN"""
    results = set()
    try:
        ip = target.split(":")[0] if ":" in target else target
        
        # 简单验证是否为合法 IPv4
        if not any(char.isdigit() for char in ip):
            return ip, results

        # 1. PTR 反查
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname:
                results.add(hostname.lower())
        except Exception:
            pass

        # 2. TLS 证书 SAN 反查 (针对 443 端口)
        tls_domains = get_tls_sans(ip)
        if tls_domains:
            results.update(tls_domains)

    except Exception:
        pass
        
    return target, results

def main():
    if not INPUT_FILE.exists():
        print(f"[!] 找不到输入文件: {INPUT_FILE}")
        return

    targets = [
        x.strip()
        for x in INPUT_FILE.read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]

    print(f"[*] 加载目标数: {len(targets)}")
    all_domains = set()

    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(reverse_lookup, t) for t in targets]

        for future in as_completed(futures):
            target, domains = future.result()
            if domains:
                print(f"[+] {target} --> {list(domains)}")
                all_domains.update(domains)

    OUTPUT_FILE.write_text(
        "\n".join(sorted(all_domains)) + "\n",
        encoding="utf-8"
    )

    print(f"[*] 成功提取并保存 {len(all_domains)} 个候选域名到 {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
