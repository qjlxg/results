import ipaddress
import os
import requests
import random
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import Counter
import geoip2.database

# ==========================
# 配置部分
# ==========================
SOURCE_FILES = [
    "sources_cidr_seed.txt",
    "domain.txt",
    "duplicate-remove.txt",
]
OUTPUT_FILE = "targets.txt"
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
    "VN"
}
# 静态黑名单：包含公共DNS、标准私网与本地地址、以及 RFC 规定的特殊用途/保留地址
STATIC_BLACKLIST = (
    # --- 公共服务与 DNS ---
    "1.1.1.0/24", "1.0.0.0/24", "8.8.8.0/24", "8.8.4.0/24", "9.9.9.0/24", "4.2.2.0/24",
    "149.154.160.0/20", "91.108.4.0/22",
    # --- RFC 特殊用途/保留地址 ---
    "100.64.0.0/10", # Carrier Grade NAT
    "169.254.0.0/16", # Link Local
    "192.0.2.0/24", # TEST-NET-1
    "192.88.99.0/24", # 6to4 Relay
    "198.18.0.0/15", # Benchmark
    "198.51.100.0/24", # TEST-NET-2
    "203.0.113.0/24", # TEST-NET-3
    "240.0.0.0/4", # Reserved
    # --- 标准私网与本地地址 ---
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4"
)
geo_reader = None

def load_auto_blacklist():
    path = Path("blacklist_auto.txt")
    if not path.exists():
        return []
    cidrs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            cidrs.append(line)
    return cidrs

def fetch_cloudflare_ips():
    try:
        print("[*] 正在从官网拉取 Cloudflare 实时 IP 段...")
        resp = requests.get(
            CF_IP_URL,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            return [line.strip() for line in resp.text.split('\n') if line.strip()]
    except Exception as e:
        print(f"[!] 无法获取 CF 实时列表: {e}，将使用预设黑名单。")
    return [
        "104.16.0.0/12",
        "172.64.0.0/13",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "188.114.96.0/20",
        "190.93.240.0/20",
    ]

def load_and_merge_sources():
    """读取多个来源文件，合并并保持原序去重"""
    merged = []
    seen = set()
    loaded_files = 0
    for src in SOURCE_FILES:
        if not os.path.exists(src):
            print(f"[!] 警告: 找不到输入文件 {src}，跳过")
            continue
        loaded_files += 1
        with open(src, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and line not in seen:
                    seen.add(line)
                    merged.append(line)
        print(f"[*] 已加载 {src}")
    if loaded_files == 0:
        return None
    print(f"[*] 合并去重后共 {len(merged)} 条记录（来自 {loaded_files} 个文件）")
    return merged

def main():
    global geo_reader
    if not os.path.exists(GEO_DB):
        print(f"[!] 找不到 {GEO_DB}，无法进行国家过滤")
        return
    raw_ips = load_and_merge_sources()
    if raw_ips is None:
        print(f"[!] 错误: 所有输入文件均不存在，退出")
        return
    geo_reader = geoip2.database.Reader(GEO_DB)
    try:
        # 1. 构建详细黑名单
        cf_ips = fetch_cloudflare_ips()
        auto_ips = load_auto_blacklist()
        combined_list = list(set(cf_ips + list(STATIC_BLACKLIST) + auto_ips))
        
        blacklist = []
        for cidr in combined_list:
            try:
                # 使用 strict=False 自动修正不规范的网段定义
                net = ipaddress.ip_network(cidr, strict=False)
                blacklist.append(net)
            except ValueError:
                print(f"[!] 跳过无效的黑名单格式: {cidr}")
        print(f"[*] 成功加载 {len(blacklist)} 条深度过滤规则。")
        
        # 2. 已在 load_and_merge_sources 中完成合并去重
        safe_list = []
        removed_count = 0
        invalid_count = 0
        geo_fail_count = 0
        country_count = Counter()
        
        for ip_str in raw_ips:
            try:
                pure_ip = ip_str.split(':')[0].split('/')[0]
                addr = ipaddress.ip_address(pure_ip)
                
                is_blacklisted = False
                for net in blacklist:
                    if addr in net:
                        is_blacklisted = True
                        break
                if is_blacklisted:
                    removed_count += 1
                    continue
                
                try:
                    country_result = geo_reader.country(pure_ip)
                    country = country_result.country.iso_code
                    if country in ALLOW_COUNTRIES:
                        country_count[country] += 1
                        safe_list.append(ip_str)
                    else:
                        removed_count += 1
                except Exception:
                    geo_fail_count += 1
                    removed_count += 1
                    continue
            except Exception:
                invalid_count += 1
                continue
        # 3. 随机抽样
        if len(safe_list) > SAMPLE_SIZE:
            print(f"[*] 从 {len(safe_list)} 条安全 IP 中随机抽取 {SAMPLE_SIZE} 条...")
            final_list = random.sample(safe_list, SAMPLE_SIZE)
        else:
            final_list = safe_list
        # 4. 保存结果
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(final_list) + "\n")
        # 5. 统计与日志
        now = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
        retention_rate = len(final_list) / len(raw_ips) if raw_ips else 0
        print(f"[+] 深度清理完成！")
        print(f" - 时间: {now}")
        print(f" - 原始总量: {len(raw_ips)}")
        print(f" - 剔除数量: {removed_count}")
        print(f" - 无效格式: {invalid_count}")
        print(f" - GeoIP无法识别: {geo_fail_count}")
        print(f" - 最终保留: {len(final_list)}")
        print(f" - 整体保留率: {retention_rate:.1%}")
        print(f" - 国家分布统计: {dict(country_count)}")
    finally:
        if geo_reader:
            geo_reader.close()

if __name__ == "__main__":
    main()
