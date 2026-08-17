import ipaddress
import os
import requests
import random
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import Counter
import geoip2.database


# ============================================================
# 配置
# ============================================================

SOURCE_FILES = [
    "sources_cidr_seed.txt",
    "domain.txt",
    "duplicate-remove.txt",
]

OUTPUT_FILE = "targets.txt"

# 最终最多保留多少个 CIDR
SAMPLE_SIZE = 88000

CF_IP_URL = "https://www.cloudflare.com/ips-v4"

GEO_DB = "GeoLite2-Country.mmdb"

ALLOW_COUNTRIES = {
    "US",
    "JP",
    "HK",
    "CN",
    "TW",
    "SG",
    "KR",
    "TH",
    "CA",
    "DE",
    "VN",
}


# ============================================================
# 静态黑名单
# ============================================================

STATIC_BLACKLIST = (

    # --------------------------------------------------------
    # 公共 DNS / 特殊公共服务
    # --------------------------------------------------------

    "1.1.1.0/24",
    "1.0.0.0/24",
    "8.8.8.0/24",
    "8.8.4.0/24",
    "9.9.9.0/24",
    "4.2.2.0/24",

    "149.154.160.0/20",
    "91.108.4.0/22",

    # --------------------------------------------------------
    # RFC 特殊用途
    # --------------------------------------------------------

    "100.64.0.0/10",
    "169.254.0.0/16",

    "192.0.2.0/24",
    "192.88.99.0/24",

    "198.18.0.0/15",
    "198.51.100.0/24",

    "203.0.113.0/24",

    "240.0.0.0/4",

    # --------------------------------------------------------
    # 私网 / 本地 / 组播
    # --------------------------------------------------------

    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",

    "172.16.0.0/12",

    "192.168.0.0/16",

    "224.0.0.0/4",
)


# ============================================================
# 全局
# ============================================================

geo_reader = None


# ============================================================
# 自动黑名单
# ============================================================

def load_auto_blacklist():

    path = Path("blacklist_auto.txt")

    if not path.exists():
        return []

    result = []

    for line in path.read_text(
        encoding="utf-8"
    ).splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        result.append(line)

    return result


# ============================================================
# Cloudflare 实时网段
# ============================================================

def fetch_cloudflare_ips():

    try:

        print("[*] 正在从 Cloudflare 官网获取实时 IPv4 网段...")

        resp = requests.get(
            CF_IP_URL,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        if resp.status_code == 200:

            result = []

            for line in resp.text.splitlines():

                line = line.strip()

                if line:
                    result.append(line)

            print(
                f"[+] Cloudflare 实时网段: {len(result)}"
            )

            return result

    except Exception as e:

        print(
            f"[!] Cloudflare 获取失败: {e}"
        )

    print(
        "[!] 使用内置 Cloudflare 黑名单"
    )

    return [
        "104.16.0.0/12",
        "172.64.0.0/13",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "188.114.96.0/20",
        "190.93.240.0/20",
    ]


# ============================================================
# 读取源文件
# ============================================================

def load_and_merge_sources():

    merged = []
    seen = set()

    loaded_files = 0

    for src in SOURCE_FILES:

        if not os.path.exists(src):

            print(
                f"[!] 找不到输入文件: {src}"
            )

            continue

        loaded_files += 1

        count = 0

        with open(
            src,
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                if line in seen:
                    continue

                seen.add(line)

                merged.append(line)

                count += 1

        print(
            f"[*] {src}: {count} 条新记录"
        )

    if loaded_files == 0:
        return None

    print(
        f"[*] 原始合并去重后: {len(merged)} 条"
    )

    return merged


# ============================================================
# 严格解析 CIDR
# ============================================================

def parse_cidr_strict(value):

    value = value.strip()

    try:

        # 只允许 IPv4 CIDR
        network = ipaddress.ip_network(
            value,
            strict=True
        )

        if network.version != 4:
            return None, "非 IPv4"

        return network, None

    except ValueError as e:

        return None, str(e)


# ============================================================
# CIDR 与黑名单判断
# ============================================================

def cidr_overlaps_blacklist(network, blacklist):

    for blocked in blacklist:

        if network.overlaps(blocked):

            return True, blocked

    return False, None


# ============================================================
# GeoIP 多点检查
# ============================================================

def geoip_check_cidr(network):

    """
    不再只检查 CIDR 的第一个 IP。

    对 CIDR 检查：
        1. 网络地址
        2. 中间地址
        3. 最后地址

    三个位置都必须属于允许国家。

    注意：
    这不是逐 IP 100% 检查，而是高效率的严格抽样检查。
    """

    addresses = [
        network.network_address,
        network.network_address
        + (network.num_addresses // 2),

        network.broadcast_address,
    ]

    countries = []

    for addr in addresses:

        try:

            result = geo_reader.country(
                str(addr)
            )

            country = result.country.iso_code

            if not country:
                return False, None

            countries.append(country)

        except Exception:

            return False, None

    # 三个位置必须全部在允许国家
    for country in countries:

        if country not in ALLOW_COUNTRIES:

            return False, countries

    return True, countries


# ============================================================
# 父子 CIDR 去重
# ============================================================

def remove_overlapping_cidrs(networks):

    """
    删除被更大 CIDR 完全覆盖的子网。

    例如：

        31.151.128.0/18
        31.151.128.0/24
        31.151.129.0/24

    最终只保留：

        31.151.128.0/18
    """

    # 大网段优先
    networks = sorted(
        set(networks),
        key=lambda n: (
            n.prefixlen,
            int(n.network_address)
        )
    )

    result = []

    for network in networks:

        covered = False

        for existing in result:

            if network.subnet_of(existing):

                covered = True
                break

        if not covered:

            result.append(network)

    return result


# ============================================================
# 主程序
# ============================================================

def main():

    global geo_reader

    if not os.path.exists(GEO_DB):

        print(
            f"[!] 找不到 GeoIP 数据库: {GEO_DB}"
        )

        return

    raw_sources = load_and_merge_sources()

    if raw_sources is None:

        print(
            "[!] 没有找到任何输入文件"
        )

        return

    # --------------------------------------------------------
    # 构建黑名单
    # --------------------------------------------------------

    cf_ips = fetch_cloudflare_ips()

    auto_ips = load_auto_blacklist()

    blacklist_source = (
        list(STATIC_BLACKLIST)
        + cf_ips
        + auto_ips
    )

    blacklist = []

    invalid_blacklist = 0

    for value in blacklist_source:

        try:

            net = ipaddress.ip_network(
                value,
                strict=False
            )

            if net.version == 4:

                blacklist.append(net)

        except ValueError:

            invalid_blacklist += 1

    # 黑名单本身也去重
    blacklist = list(set(blacklist))

    print(
        f"[*] 黑名单网段: {len(blacklist)}"
    )

    if invalid_blacklist:

        print(
            f"[!] 无效黑名单: {invalid_blacklist}"
        )

    # --------------------------------------------------------
    # GeoIP
    # --------------------------------------------------------

    geo_reader = geoip2.database.Reader(
        GEO_DB
    )

    try:

        valid_networks = []

        invalid_count = 0
        blacklist_count = 0
        geo_fail_count = 0
        country_count = Counter()

        # ----------------------------------------------------
        # 第一阶段：严格 CIDR 解析
        # ----------------------------------------------------

        print(
            "\n[*] 第一阶段：严格验证 CIDR..."
        )

        for index, value in enumerate(
            raw_sources,
            1
        ):

            network, error = parse_cidr_strict(
                value
            )

            if network is None:

                invalid_count += 1

                print(
                    f"[!] 无效 CIDR: {value}"
                )

                continue

            # ------------------------------------------------
            # 黑名单：整个 CIDR 检查
            # ------------------------------------------------

            overlap, blocked = (
                cidr_overlaps_blacklist(
                    network,
                    blacklist
                )
            )

            if overlap:

                blacklist_count += 1

                continue

            # ------------------------------------------------
            # GeoIP：多点检查
            # ------------------------------------------------

            geo_ok, countries = (
                geoip_check_cidr(
                    network
                )
            )

            if not geo_ok:

                geo_fail_count += 1

                continue

            # ------------------------------------------------
            # 国家统计
            # ------------------------------------------------

            for country in set(countries):

                country_count[country] += 1

            valid_networks.append(network)

        print(
            f"[+] 严格 CIDR 验证完成"
        )

        print(
            f" - 原始记录: {len(raw_sources)}"
        )

        print(
            f" - 无效 CIDR: {invalid_count}"
        )

        print(
            f" - 黑名单/重叠: {blacklist_count}"
        )

        print(
            f" - GeoIP 淘汰: {geo_fail_count}"
        )

        print(
            f" - 初步有效 CIDR: {len(valid_networks)}"
        )

        # ----------------------------------------------------
        # 第二阶段：父子 CIDR 去重
        # ----------------------------------------------------

        print(
            "\n[*] 第二阶段：处理父子 CIDR 重叠..."
        )

        before_overlap = len(
            valid_networks
        )

        valid_networks = remove_overlapping_cidrs(
            valid_networks
        )

        removed_overlap = (
            before_overlap
            - len(valid_networks)
        )

        print(
            f"[+] 父子 CIDR 去重:"
            f" 删除 {removed_overlap}"
        )

        print(
            f"[+] 去重后 CIDR:"
            f" {len(valid_networks)}"
        )

        # ----------------------------------------------------
        # 第三阶段：随机抽样
        # ----------------------------------------------------

        if len(valid_networks) > SAMPLE_SIZE:

            print(
                f"\n[*] 有效 CIDR 超过 {SAMPLE_SIZE}"
            )

            print(
                f"[*] 随机抽取 {SAMPLE_SIZE} 个"
            )

            final_networks = random.sample(
                valid_networks,
                SAMPLE_SIZE
            )

        else:

            final_networks = valid_networks

        # ----------------------------------------------------
        # 排序
        # ----------------------------------------------------

        final_networks.sort(
            key=lambda n: (
                int(n.network_address),
                n.prefixlen
            )
        )

        # ----------------------------------------------------
        # 输出
        # ----------------------------------------------------

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            for network in final_networks:

                f.write(
                    f"{network}\n"
                )

        # ----------------------------------------------------
        # 统计
        # ----------------------------------------------------

        now = datetime.now(
            ZoneInfo("Asia/Shanghai")
        ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        retention_rate = (
            len(final_networks)
            / len(raw_sources)
            if raw_sources
            else 0
        )

        print(
            "\n========================================"
        )

        print(
            "[+] 源 CIDR 严格清理完成"
        )

        print(
            f" - 时间: {now}"
        )

        print(
            f" - 原始记录: {len(raw_sources)}"
        )

        print(
            f" - 无效 CIDR: {invalid_count}"
        )

        print(
            f" - 黑名单淘汰: {blacklist_count}"
        )

        print(
            f" - GeoIP 淘汰: {geo_fail_count}"
        )

        print(
            f" - 父子 CIDR 重叠删除: {removed_overlap}"
        )

        print(
            f" - 最终 CIDR: {len(final_networks)}"
        )

        print(
            f" - 整体保留率: {retention_rate:.1%}"
        )

        print(
            f" - 国家统计: {dict(country_count)}"
        )

        print(
            f" - 输出文件: {OUTPUT_FILE}"
        )

        print(
            "========================================"
        )

    finally:

        if geo_reader:

            geo_reader.close()


# ============================================================
# 启动
# ============================================================

if __name__ == "__main__":

    main()
