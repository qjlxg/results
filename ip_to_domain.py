import socket
import ssl
import re
import threading
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography import x509
from cryptography.x509.oid import NameOID


# ============================================================
# 基础配置
# ============================================================

BASE_DIR = Path(".")

INPUT_FILE = BASE_DIR / "alive_latest.txt"

# ============================================================
# 输出文件
# ============================================================

OUTPUT_ALL = BASE_DIR / "domain_candidates.txt"

OUTPUT_PTR = BASE_DIR / "ptr_domains.txt"

OUTPUT_TLS = BASE_DIR / "tls_domains.txt"

OUTPUT_LOW_VALUE = BASE_DIR / "domain_low_value.txt"

OUTPUT_INTERNAL = BASE_DIR / "domain_internal.txt"

OUTPUT_IPS = BASE_DIR / "tls_ips.txt"

OUTPUT_MAPPING = BASE_DIR / "tls_mapping.txt"

OUTPUT_DNS_SEED = BASE_DIR / "dns_seed.txt"


# ============================================================
# TLS 端口
# ============================================================

TLS_PORTS = [
    443,
    8443,
    2053,
    2083,
    2087,
    2096,
    9443,
]


# ============================================================
# 线程数
# ============================================================

MAX_WORKERS = 50


# ============================================================
# DNS / 域名过滤
# ============================================================

IGNORE_DOMAINS = {
    "localhost",
    "example.com",
    "example.net",
    "example.org",
    "invalid",
    "default",
    "cloudflare-dns.com",
    "kubernetes.docker.internal",
    "nginx",
    "apache",
    "server",
    "host",
    "localhost.localdomain",
}


# ------------------------------------------------------------
# 明确属于内部环境的后缀
# ------------------------------------------------------------

INTERNAL_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home",
    ".localdomain",
    ".internal.",
    ".local.",
    ".localhost.",

    # Docker / Kubernetes
    ".docker.internal",
    ".cluster.local",
    ".svc",
    ".svc.cluster.local",

    # Traefik / 容器环境常见内部域
    ".traefik.default",
    ".traefik",
)


# ------------------------------------------------------------
# 明确属于内部环境的关键词
# ------------------------------------------------------------

INTERNAL_KEYWORDS = (
    ".traefik.",
    ".kubernetes.",
    ".docker.",
    ".container.",
    ".pod.",
    ".svc.",
)


# ============================================================
# 服务商 hostname 后缀
#
# 注意：
# 这里只用于“低价值分类”，不直接删除。
#
# 例如：
# 273812.fornex.cloud
#
# 可能是真实公网 hostname，
# 只是通常不是业务站点。
# ============================================================

LOW_VALUE_SUFFIXES = (
    ".fornex.cloud",
)


# ============================================================
# 随机 / 内部名称判断
# ============================================================

# 常见超长十六进制字符串
HEX_LABEL_RE = re.compile(
    r"^[0-9a-f]{24,}$",
    re.IGNORECASE,
)


# ============================================================
# 每个线程独立 SSLContext
# ============================================================

_tls_local = threading.local()


def get_ssl_context():
    """
    每个线程使用独立 SSLContext。

    不验证证书，因为这里的目的只是读取服务器
    返回的 TLS 证书，而不是验证证书是否合法。
    """

    if not hasattr(_tls_local, "context"):

        ctx = ssl.create_default_context()

        ctx.check_hostname = False

        ctx.verify_mode = ssl.CERT_NONE

        _tls_local.context = ctx

    return _tls_local.context


# ============================================================
# 提取 IPv4
# ============================================================

def extract_ip(target):
    """
    从：

        1.2.3.4
        1.2.3.4:443

    等字符串中提取 IPv4。

    同时使用 ipaddress 做严格合法性检查。
    """

    if not target:
        return None

    m = re.search(
        r"(\d{1,3}(?:\.\d{1,3}){3})",
        target
    )

    if not m:
        return None

    ip_str = m.group(1)

    try:

        ipaddress.ip_address(ip_str)

        return ip_str

    except Exception:

        return None


# ============================================================
# 清洗域名
# ============================================================

def clean_domain(domain):

    if not domain:
        return None

    domain = str(domain).strip().lower()

    # 去掉首尾空白
    domain = domain.strip()

    # 通配符
    if domain.startswith("*."):
        domain = domain[2:]

    # 去掉最后一个点
    if domain.endswith("."):
        domain = domain[:-1]

    # 去掉可能出现的 URL 前缀
    domain = re.sub(
        r"^https?://",
        "",
        domain,
        flags=re.IGNORECASE,
    )

    # 如果后面出现路径，只保留 hostname
    domain = domain.split("/")[0]

    return domain


# ============================================================
# 域名格式严格检查
# ============================================================

def basic_domain_valid(domain):

    if not domain:
        return False

    # 长度
    if len(domain) > 253:
        return False

    # 不能是 IP
    try:

        ipaddress.ip_address(domain)

        return False

    except Exception:

        pass

    # 必须至少包含一个点
    if "." not in domain:
        return False

    # 首尾不能是点
    if domain.startswith("."):
        return False

    if domain.endswith("."):
        return False

    # 不能包含明显非法字符
    if re.search(
        r"[\s<>\"'`]",
        domain
    ):
        return False

    # 每一个 label 检查
    labels = domain.split(".")

    for label in labels:

        if not label:
            return False

        if len(label) > 63:
            return False

        if label.startswith("-"):
            return False

        if label.endswith("-"):
            return False

        if not re.fullmatch(
            r"[a-z0-9-]+",
            label,
            flags=re.IGNORECASE,
        ):
            return False

    return True


# ============================================================
# 内部域名判断
# ============================================================

def is_internal_domain(domain):

    if not domain:
        return True

    domain = domain.lower().strip()

    # 明确黑名单
    if domain in IGNORE_DOMAINS:
        return True

    # 内部后缀
    for suffix in INTERNAL_SUFFIXES:

        if domain.endswith(suffix):

            return True

    # 内部关键词
    for keyword in INTERNAL_KEYWORDS:

        if keyword in domain:

            return True

    # 特殊 .default
    if domain.endswith(".default"):

        return True

    return False


# ============================================================
# 低价值域名判断
# ============================================================

def is_low_value_domain(domain):

    if not domain:
        return False

    domain = domain.lower()

    for suffix in LOW_VALUE_SUFFIXES:

        if domain.endswith(suffix):

            return True

    return False


# ============================================================
# 域名分类
#
# 返回：
#
#     INVALID
#     INTERNAL
#     LOW_VALUE
#     NORMAL
# ============================================================

def classify_domain(domain):

    domain = clean_domain(domain)

    if not basic_domain_valid(domain):

        return None, "INVALID"

    if is_internal_domain(domain):

        return domain, "INTERNAL"

    if is_low_value_domain(domain):

        return domain, "LOW_VALUE"

    return domain, "NORMAL"


# ============================================================
# 判断 TCP 端口是否开放
#
# 保留这个函数作为简单 TCP 检查接口。
# ============================================================

def is_port_open(ip, port, timeout=0.5):

    try:

        with socket.create_connection(
            (ip, port),
            timeout=timeout,
        ):

            return True

    except Exception:

        return False


# ============================================================
# TLS 证书解析
# ============================================================

def get_tls_assets(
    ip,
    port=443,
    timeout=2,
):
    """
    直接：

        TCP connect
            ↓
        TLS handshake
            ↓
        获取默认 TLS 证书
            ↓
        SAN / CN / IP

    注意：

    这里使用 IP 作为 SNI。

    因此得到的是：

        该 IP 在当前 TLS 连接条件下
        返回的默认证书。

    并不能代表该 IP 上所有虚拟主机。
    """

    domains = set()

    ips = set()

    expire_date = "UNKNOWN"

    issuer_str = "UNKNOWN"

    try:

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        sock = socket.create_connection(
            (ip, port),
            timeout=timeout,
        )

        # ----------------------------------------------------
        # TLS
        # ----------------------------------------------------

        context = get_ssl_context()

        with context.wrap_socket(
            sock,
            server_hostname=ip,
        ) as ssock:

            der_cert = ssock.getpeercert(
                binary_form=True
            )

            if not der_cert:

                return (
                    domains,
                    ips,
                    expire_date,
                    issuer_str,
                )

            cert = x509.load_der_x509_certificate(
                der_cert
            )

            # ------------------------------------------------
            # 到期时间
            # ------------------------------------------------

            try:

                if hasattr(
                    cert,
                    "not_valid_after_utc"
                ):

                    expire_date = (
                        cert.not_valid_after_utc
                        .strftime("%Y-%m-%d")
                    )

                else:

                    expire_date = (
                        cert.not_valid_after
                        .strftime("%Y-%m-%d")
                    )

            except Exception:

                pass

            # ------------------------------------------------
            # Issuer
            # ------------------------------------------------

            try:

                issuer_str = (
                    cert.issuer.rfc4514_string()
                )

            except Exception:

                pass

            # ------------------------------------------------
            # SAN
            # ------------------------------------------------

            try:

                san_ext = (
                    cert.extensions
                    .get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                )

                san = san_ext.value

                # --------------------------------------------
                # DNS SAN
                # --------------------------------------------

                for name in san.get_values_for_type(
                    x509.DNSName
                ):

                    cleaned = clean_domain(name)

                    if not cleaned:
                        continue

                    domains.add(cleaned)

                # --------------------------------------------
                # IP SAN
                # --------------------------------------------

                for ipaddr in san.get_values_for_type(
                    x509.IPAddress
                ):

                    if ipaddr:

                        ips.add(
                            str(ipaddr)
                        )

            except Exception:

                pass

            # ------------------------------------------------
            # CN
            # ------------------------------------------------

            try:

                cn_attributes = (
                    cert.subject
                    .get_attributes_for_oid(
                        NameOID.COMMON_NAME
                    )
                )

                for item in cn_attributes:

                    if not item.value:
                        continue

                    cleaned = clean_domain(
                        item.value
                    )

                    if cleaned:

                        domains.add(cleaned)

            except Exception:

                pass

    except Exception:

        pass

    return (
        domains,
        ips,
        expire_date,
        issuer_str,
    )


# ============================================================
# 单 IP 反查
# ============================================================

def reverse_lookup(target):

    ptr_results = set()

    tls_domains = set()

    tls_ips = set()

    mapping_results = set()

    normal_domains = set()

    low_value_domains = set()

    internal_domains = set()

    dns_seeds = set()

    try:

        ip = extract_ip(target)

        if not ip:

            return (
                target,
                ptr_results,
                tls_domains,
                tls_ips,
                mapping_results,
                normal_domains,
                low_value_domains,
                internal_domains,
                dns_seeds,
            )

        # ====================================================
        # 1. PTR
        # ====================================================

        try:

            hostname, _, _ = socket.gethostbyaddr(ip)

            cleaned_host = clean_domain(
                hostname
            )

            domain, category = classify_domain(
                cleaned_host
            )

            if domain:

                if category == "NORMAL":

                    ptr_results.add(domain)

                    normal_domains.add(domain)

                    dns_seeds.add(domain)

                elif category == "LOW_VALUE":

                    ptr_results.add(domain)

                    low_value_domains.add(domain)

                elif category == "INTERNAL":

                    internal_domains.add(domain)

                mapping_results.add(
                    f"{ip}:PTR,"
                    f"{domain},"
                    f"UNKNOWN,"
                    f"PTR_REVERSE,"
                    f"{category}"
                )

        except Exception:

            pass

        # ====================================================
        # 2. TLS
        # ====================================================

        for port in TLS_PORTS:

            (
                domains,
                ips,
                expire_date,
                issuer_str,
            ) = get_tls_assets(
                ip,
                port=port,
            )

            # ------------------------------------------------
            # TLS DNS
            # ------------------------------------------------

            for raw_domain in domains:

                domain, category = classify_domain(
                    raw_domain
                )

                if not domain:
                    continue

                if category == "NORMAL":

                    tls_domains.add(domain)

                    normal_domains.add(domain)

                    dns_seeds.add(domain)

                elif category == "LOW_VALUE":

                    tls_domains.add(domain)

                    low_value_domains.add(domain)

                elif category == "INTERNAL":

                    internal_domains.add(domain)

                mapping_results.add(
                    f"{ip}:{port},"
                    f"{domain},"
                    f"{expire_date},"
                    f"{issuer_str},"
                    f"{category}"
                )

            # ------------------------------------------------
            # TLS IP SAN
            # ------------------------------------------------

            for cert_ip in ips:

                tls_ips.add(cert_ip)

                mapping_results.add(
                    f"{ip}:{port},"
                    f"{cert_ip},"
                    f"{expire_date},"
                    f"{issuer_str},"
                    f"CERT_IP"
                )

    except Exception:

        pass

    return (
        target,
        ptr_results,
        tls_domains,
        tls_ips,
        mapping_results,
        normal_domains,
        low_value_domains,
        internal_domains,
        dns_seeds,
    )


# ============================================================
# 主程序
# ============================================================

def main():

    if not INPUT_FILE.exists():

        print(
            f"[!] 找不到输入文件: "
            f"{INPUT_FILE}"
        )

        return

    # ========================================================
    # 读取目标
    # ========================================================

    targets = [
        x.strip()
        for x in INPUT_FILE.read_text(
            encoding="utf-8"
        ).splitlines()
        if x.strip()
    ]

    # ========================================================
    # IP 去重
    # ========================================================

    unique_targets = []

    seen_ips = set()

    for target in targets:

        ip = extract_ip(target)

        if not ip:
            continue

        if ip in seen_ips:
            continue

        seen_ips.add(ip)

        unique_targets.append(target)

    targets = unique_targets

    total_targets = len(targets)

    print(
        f"[*] 加载唯一 IP: "
        f"{total_targets}"
    )

    if total_targets == 0:

        print("[!] 没有有效 IP")

        return

    # ========================================================
    # 线程
    # ========================================================

    max_workers = min(
        MAX_WORKERS,
        total_targets,
    )

    print(
        f"[*] 工作线程: "
        f"{max_workers}"
    )

    # ========================================================
    # 全局结果
    # ========================================================

    all_ptr = set()

    all_tls_domains = set()

    all_tls_ips = set()

    all_mappings = set()

    all_normal_domains = set()

    all_low_value_domains = set()

    all_internal_domains = set()

    all_dns_seeds = set()

    # ========================================================
    # 并发
    # ========================================================

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as pool:

        futures = [
            pool.submit(
                reverse_lookup,
                target
            )
            for target in targets
        ]

        completed = 0

        for future in as_completed(
            futures
        ):

            completed += 1

            try:

                (
                    target,
                    ptrs,
                    tlss,
                    ips,
                    maps,
                    normal_domains,
                    low_value_domains,
                    internal_domains,
                    seeds,
                ) = future.result()

            except Exception as e:

                print(
                    f"[!] 任务异常: {e}"
                )

                continue

            if (
                ptrs
                or tlss
                or ips
            ):

                print(
                    f"[+] {target} --> "
                    f"PTR:{len(ptrs)} "
                    f"TLS-Dom:{len(tlss)} "
                    f"TLS-IP:{len(ips)}"
                )

            all_ptr.update(ptrs)

            all_tls_domains.update(tlss)

            all_tls_ips.update(ips)

            all_mappings.update(maps)

            all_normal_domains.update(
                normal_domains
            )

            all_low_value_domains.update(
                low_value_domains
            )

            all_internal_domains.update(
                internal_domains
            )

            all_dns_seeds.update(
                seeds
            )

            # ------------------------------------------------
            # 进度
            # ------------------------------------------------

            if (
                completed % 100 == 0
                or completed == total_targets
            ):

                print(
                    f"[*] 进度: "
                    f"{completed}/"
                    f"{total_targets}"
                )

    # ========================================================
    # 合并候选域名
    #
    # 注意：
    # 内部域名不进入候选库
    # ========================================================

    all_combined_domains = (
        all_normal_domains
        | all_low_value_domains
    )

    # ========================================================
    # 写文件
    # ========================================================

    OUTPUT_PTR.write_text(
        "\n".join(
            sorted(all_ptr)
        )
        + ("\n" if all_ptr else ""),
        encoding="utf-8",
    )

    OUTPUT_TLS.write_text(
        "\n".join(
            sorted(all_tls_domains)
        )
        + ("\n" if all_tls_domains else ""),
        encoding="utf-8",
    )

    OUTPUT_LOW_VALUE.write_text(
        "\n".join(
            sorted(all_low_value_domains)
        )
        + (
            "\n"
            if all_low_value_domains
            else ""
        ),
        encoding="utf-8",
    )

    OUTPUT_INTERNAL.write_text(
        "\n".join(
            sorted(all_internal_domains)
        )
        + (
            "\n"
            if all_internal_domains
            else ""
        ),
        encoding="utf-8",
    )

    OUTPUT_IPS.write_text(
        "\n".join(
            sorted(all_tls_ips)
        )
        + ("\n" if all_tls_ips else ""),
        encoding="utf-8",
    )

    OUTPUT_MAPPING.write_text(
        "\n".join(
            sorted(all_mappings)
        )
        + ("\n" if all_mappings else ""),
        encoding="utf-8",
    )

    OUTPUT_DNS_SEED.write_text(
        "\n".join(
            sorted(all_dns_seeds)
        )
        + ("\n" if all_dns_seeds else ""),
        encoding="utf-8",
    )

    OUTPUT_ALL.write_text(
        "\n".join(
            sorted(all_combined_domains)
        )
        + (
            "\n"
            if all_combined_domains
            else ""
        ),
        encoding="utf-8",
    )

    # ========================================================
    # 最终统计
    # ========================================================

    print()
    print("=" * 60)

    print(
        "[+] IP → Domain 反查完成"
    )

    print(
        f"[*] 唯一 IP: "
        f"{total_targets}"
    )

    print(
        f"[*] PTR 域名: "
        f"{len(all_ptr)}"
    )

    print(
        f"[*] TLS 域名: "
        f"{len(all_tls_domains)}"
    )

    print(
        f"[*] 正常/高价值域名: "
        f"{len(all_normal_domains)}"
    )

    print(
        f"[*] 低价值域名: "
        f"{len(all_low_value_domains)}"
    )

    print(
        f"[*] 内部域名已过滤: "
        f"{len(all_internal_domains)}"
    )

    print(
        f"[*] TLS 证书 IP: "
        f"{len(all_tls_ips)}"
    )

    print(
        f"[*] 精确映射: "
        f"{len(all_mappings)}"
    )

    print(
        f"[*] DNS Seed: "
        f"{len(all_dns_seeds)}"
    )

    print(
        f"[*] 总候选域名: "
        f"{len(all_combined_domains)}"
    )

    print("=" * 60)

    print(
        f"[+] {OUTPUT_ALL}"
    )

    print(
        f"[+] {OUTPUT_DNS_SEED}"
    )

    print(
        f"[+] {OUTPUT_LOW_VALUE}"
    )

    print(
        f"[+] {OUTPUT_INTERNAL}"
    )

    print(
        f"[+] {OUTPUT_MAPPING}"
    )

    print("=" * 60)


# ============================================================
# 启动
# ============================================================

if __name__ == "__main__":

    main()
