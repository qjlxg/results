from collections import Counter
from datetime import datetime
from pathlib import Path
import random
import ipaddress
import os
import sqlite3
from zoneinfo import ZoneInfo
import requests
import geoip2.database


# ============================================================
# 配置
# ============================================================

SOURCE_FILES = [
    "sources_cidr_seed.txt",
    "domain.txt",
    "candidates.txt",
    "duplicate-remove.txt",
]

OUTPUT_FILE = "targets.txt"          # 始终只存本次过滤出的“纯新数据”
HISTORY_TXT = "targets_history.txt"    # 长期累积的明文历史数据文件
DB_FILE = "targets_history.db"       # 辅助 SQLite 历史数据库

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
    "1.1.1.0/24",
    "1.0.0.0/24",
    "8.8.8.0/24",
    "8.8.4.0/24",
    "9.9.9.0/24",
    "4.2.2.0/24",
    "149.154.160.0/20",
    "91.108.4.0/22",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "240.0.0.0/4",
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
# 数据库与历史文件管理
# ============================================================

def init_db(conn):
    """初始化数据库表结构"""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cidr_history (
            cidr TEXT PRIMARY KEY,
            first_seen TEXT,
            last_seen TEXT,
            batch_id TEXT
        )
    """)
    conn.commit()


def get_historical_cidrs(conn):
    """获取数据库中已存在的所有 CIDR 集合"""
    cursor = conn.cursor()
    cursor.execute("SELECT cidr FROM cidr_history")
    return {row[0] for row in cursor.fetchall()}


def save_batch_to_db(conn, networks, batch_id, timestamp):
    """将本次运行的结果与历史对比，找出新数据并批量写入数据库"""
    cursor = conn.cursor()
    existing_set = get_historical_cidrs(conn)

    new_networks = []
    for net in networks:
        net_str = str(net)
        if net_str not in existing_set:
            new_networks.append(net_str)
            cursor.execute(
                """
                INSERT OR IGNORE INTO cidr_history (cidr, first_seen, last_seen, batch_id)
                VALUES (?, ?, ?, ?)
            """,
                (net_str, timestamp, timestamp, batch_id),
            )
        else:
            cursor.execute(
                """
                UPDATE cidr_history SET last_seen = ? WHERE cidr = ?
            """,
                (timestamp, net_str),
            )

    conn.commit()
    return new_networks


# ============================================================
# 自动黑名单与源文件处理
# ============================================================

def load_auto_blacklist():
    path = Path("blacklist_auto.txt")
    if not path.exists():
        return []
    result = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        result.append(line)
    return result


def fetch_cloudflare_ips():
    try:
        resp = requests.get(
            CF_IP_URL,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            return [
                line.strip()
                for line in resp.text.splitlines()
                if line.strip()
            ]
    except Exception:
        pass
    return [
        "104.16.0.0/12",
        "172.64.0.0/13",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "188.114.96.0/20",
        "190.93.240.0/20",
    ]


def load_and_merge_sources():
    merged = []
    seen = set()
    loaded_files = 0
    for src in SOURCE_FILES:
        if not os.path.exists(src):
            continue
        loaded_files += 1
        with open(src, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line in seen:
                    continue
                seen.add(line)
                merged.append(line)
    if loaded_files == 0:
        return None
    return merged


def parse_cidr_strict(value):
    try:
        network = ipaddress.ip_network(value.strip(), strict=True)
        if network.version != 4:
            return None
        return network
    except ValueError:
        return None


def cidr_overlaps_blacklist(network, blacklist):
    for blocked in blacklist:
        if network.overlaps(blocked):
            return True
    return False


def geoip_check_cidr(network):
    addresses = [
        network.network_address,
        network.network_address + (network.num_addresses // 2),
        network.broadcast_address,
    ]
    countries = []
    for addr in addresses:
        try:
            result = geo_reader.country(str(addr))
            country = result.country.iso_code
            if not country:
                return False, None
            countries.append(country)
        except Exception:
            return False, None
    for country in countries:
        if country not in ALLOW_COUNTRIES:
            return False, countries
    return True, countries


def remove_overlapping_cidrs(networks):
    networks = sorted(
        set(networks), key=lambda n: (n.prefixlen, int(n.network_address))
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
        print(f"[!] 找不到 GeoIP 数据库: {GEO_DB}")
        return

    raw_sources = load_and_merge_sources()
    if raw_sources is None:
        print("[!] 没有找到任何输入文件")
        return

    # 1. 准备黑名单
    cf_ips = fetch_cloudflare_ips()
    auto_ips = load_auto_blacklist()
    blacklist = []
    for val in list(STATIC_BLACKLIST) + cf_ips + auto_ips:
        try:
            net = ipaddress.ip_network(val, strict=False)
            if net.version == 4:
                blacklist.append(net)
        except ValueError:
            pass
    blacklist = list(set(blacklist))

    # 2. 核心清洗
    geo_reader = geoip2.database.Reader(GEO_DB)
    try:
        valid_networks = []
        country_count = Counter()

        for value in raw_sources:
            network = parse_cidr_strict(value)
            if not network:
                continue
            if cidr_overlaps_blacklist(network, blacklist):
                continue
            geo_ok, countries = geoip_check_cidr(network)
            if not geo_ok:
                continue
            for c in set(countries):
                country_count[c] += 1
            valid_networks.append(network)

        # 去重与抽样
        valid_networks = remove_overlapping_cidrs(valid_networks)
        if len(valid_networks) > SAMPLE_SIZE:
            final_networks = random.sample(valid_networks, SAMPLE_SIZE)
        else:
            final_networks = valid_networks

        final_networks.sort(key=lambda n: (int(n.network_address), n.prefixlen))

        # ====================================================
        # 3. 持久化处理与新旧对比
        # ====================================================
        now_dt = datetime.now(ZoneInfo("Asia/Shanghai"))
        timestamp_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        batch_id = now_dt.strftime("%Y%m%d_%H%M%S")

        # 数据库比对与写入
        db_conn = sqlite3.connect(DB_FILE)
        init_db(db_conn)
        new_net_strs = save_batch_to_db(
            db_conn, final_networks, batch_id, timestamp_str
        )
        db_conn.close()

        # 4. 更新 targets.txt（只保存本次产生的“纯新数据”）
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for net_str in new_net_strs:
                f.write(f"{net_str}\n")

        # 5. 将本次发现的新数据追加到长期历史文本文件 targets_history.txt 中
        if new_net_strs:
            with open(HISTORY_TXT, "a", encoding="utf-8") as f:
                for net_str in new_net_strs:
                    f.write(f"{net_str}\n")

        # 6. 打印统计报告
        print("\n========================================")
        print("[+] CIDR 智能去重与比对完成")
        print(f" - 运行批次ID: {batch_id}")
        print(f" - 本次清洗产出总量: {len(final_networks)}")
        print(f" - 经历史比对发现【新数据】: {len(new_net_strs)} 条")
        print(f" - 专属新数据文件: {OUTPUT_FILE}")
        print(f" - 长期历史明文文件: {HISTORY_TXT} (已自动追加)")
        print(f" - 辅助历史数据库: {DB_FILE}")
        print(f" - 国家统计: {dict(country_count)}")
        print("========================================")

    finally:
        if geo_reader:
            geo_reader.close()


if __name__ == "__main__":
    main()
