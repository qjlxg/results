import socket
import ssl
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography import x509
from cryptography.x509.oid import NameOID

BASE_DIR = Path(".")
INPUT_FILE = BASE_DIR / "alive_latest.txt"

# 建议 6：输出建议分开保存，满足不同价值过滤
OUTPUT_ALL = BASE_DIR / "domain_candidates.txt"
OUTPUT_PTR = BASE_DIR / "ptr_domains.txt"
OUTPUT_TLS = BASE_DIR / "tls_domains.txt"

# 建议 3：扩充高频面板和代理节点 TLS 端口
TLS_PORTS = [443, 8443, 2053, 2083, 2087, 2096, 9443]

def extract_ip(target):
    """建议 1：更严谨的 IPv4 提取正则，防止误匹配"""
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', target)
    return m.group(1) if m else None

def get_tls_sans(ip, port=443, timeout=2):
    """建议 2 & 4：多端口 TLS 深度解析，支持 SAN(DNS/IP) 与 CN"""
    domains = set()
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            # 兼容处理：因 SNI 限制，若直连 IP 拿不到预期证书，可作为通用兜底
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return domains

                cert = x509.load_der_x509_certificate(der_cert)

                # 提取 DNSName
                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    for name in san.value.get_values_for_type(x509.DNSName):
                        if name and not name.startswith("*"):
                            domains.add(name.lower())
                except Exception:
                    pass

                # 建议 4 补充：提取证书中的 IPAddress 类型的 SAN
                try:
                    for ipaddr in san.value.get_values_for_type(x509.IPAddress):
                        if ipaddr:
                            domains.add(str(ipaddr))
                except Exception:
                    pass

                # 提取 CN 备用
                try:
                    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    for item in cn:
                        if item.value:
                            domains.add(item.value.lower())
                except Exception:
                    pass
    except Exception:
        pass
    return domains

def reverse_lookup(target):
    """综合反查：PTR 兜底 + 多端口 TLS 证书枚举"""
    ptr_results = set()
    tls_results = set()
    
    try:
        ip = extract_ip(target)
        if not ip:
            return target, ptr_results, tls_results

        # 1. PTR 反查（价值较低，但有广度）
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname:
                ptr_results.add(hostname.lower())
        except Exception:
            pass

        # 2. 多端口 TLS 证书反查（高价值域名）
        for port in TLS_PORTS:
            domains = get_tls_sans(ip, port=port)
            if domains:
                tls_results.update(domains)

    except Exception:
        pass
        
    return target, ptr_results, tls_results

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
    all_ptr = set()
    all_tls = set()

    # 建议 5：多线程调优（100 线程，2秒超时，适应大批量扫描）
    with ThreadPoolExecutor(max_workers=100) as pool:
        futures = [pool.submit(reverse_lookup, t) for t in targets]

        for future in as_completed(futures):
            target, ptrs, tlss = future.result()
            if ptrs or tlss:
                print(f"[+] {target} --> PTR:{len(ptrs)} TLS:{len(tlss)}")
                all_ptr.update(ptrs)
                all_tls.update(tlss)

    # 建议 6：分流保存不同价值的结果
    OUTPUT_PTR.write_text("\n".join(sorted(all_ptr)) + "\n", encoding="utf-8")
    OUTPUT_TLS.write_text("\n".join(sorted(all_tls)) + "\n", encoding="utf-8")
    
    # 全量合并总表
    all_combined = all_ptr.union(all_tls)
    OUTPUT_ALL.write_text("\n".join(sorted(all_combined)) + "\n", encoding="utf-8")

    print("=" * 40)
    print(f"[*] PTR 收集: {len(all_ptr)} 个 -> {OUTPUT_PTR.name}")
    print(f"[*] TLS 收集: {len(all_tls)} 个 -> {OUTPUT_TLS.name}")
    print(f"[*] 总候选库: {len(all_combined)} 个 -> {OUTPUT_ALL.name}")
    print("=" * 40)

if __name__ == "__main__":
    main()
