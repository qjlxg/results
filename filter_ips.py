import ipaddress
import os
import requests
import random
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import Counter
import geoip2.database

# ==========================
# 配置部分
# ==========================
SOURCE_FILE = "ip.txt"    
OUTPUT_FILE = "bip.txt"        
SAMPLE_SIZE = 18000            
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

# 静态黑名单：包含公共DNS、云巨头骨干网、以及 RFC 规定的特殊用途/保留地址
STATIC_BLACKLIST = (
    # --- 公共服务与 DNS ---
    "1.1.1.0/24", "1.0.0.0/24", "8.8.8.0/24", "8.8.4.0/24", "9.9.9.0/24", "4.2.2.0/24",
    "149.154.160.0/20", "91.108.4.0/22", 
    # --- Amazon AWS ---
    "3.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8", "18.0.0.0/8", "34.192.0.0/10", 
    "35.153.0.0/16", "44.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8", "108.128.0.0/13",
    # --- Microsoft Azure ---
    "13.64.0.0/11", "20.33.0.0/12", "20.180.0.0/12", "23.96.0.0/13", "40.74.0.0/15",
    "40.76.0.0/14", "40.80.0.0/12", "40.112.0.0/13", "51.0.0.0/8", "52.145.0.0/16",
    "104.40.0.0/13", "137.116.0.0/14", "168.61.0.0/16",
    # --- Google Cloud ---
    "34.0.0.0/8", "35.184.0.0/13", "35.192.0.0/12", "35.208.0.0/12", "104.154.0.0/15",
    "104.196.0.0/14", "130.211.0.0/16", "209.85.128.0/17",
    # --- Oracle Cloud ---
    "129.144.0.0/12", "130.61.0.0/16", "132.145.0.0/16", "138.1.0.0/16", 
    "140.238.0.0/16", "150.136.0.0/16", "150.230.0.0/16", "152.67.0.0/16",
    "158.101.0.0/16", "168.138.0.0/16", "193.122.0.0/15",
    # --- Hetzner & DigitalOcean ---
    "5.9.0.0/16", "78.46.0.0/15", "88.198.0.0/16", "95.216.0.0/15", "116.202.0.0/15",
    "64.225.0.0/16", "68.183.0.0/16", "104.248.0.0/16", "128.199.0.0/16", "159.203.0.0/16",
    "137.184.0.0/16", "142.93.0.0/16", "143.110.0.0/16", "143.198.0.0/16", "146.190.0.0/16", "157.245.0.0/16", "159.65.0.0/16", "159.89.0.0/16", "161.35.0.0/16", "165.22.0.0/16", "165.227.0.0/16", "167.71.0.0/16", "167.99.0.0/16", "174.138.0.0/16", "178.128.0.0/16", "206.189.0.0/16",
    # --- Vultr (新增) ---
    "45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/15", "66.42.0.0/16", "95.179.128.0/17", "108.61.0.0/16", "140.82.0.0/16", "144.202.0.0/16", "149.28.0.0/16", "155.138.128.0/17", "207.148.0.0/16",
    # --- Linode / Akamai Cloud ---
    "45.33.0.0/16", "45.56.0.0/14", "66.175.208.0/20", "96.126.96.0/19", "139.144.0.0/16", "172.104.0.0/13", "173.255.192.0/18", "192.155.80.0/20",
    # --- Contabo ---
    "161.97.0.0/16", "185.191.0.0/16", "194.163.128.0/17", "213.136.64.0/18",
    # --- Leaseweb ---
    "5.79.64.0/18", "31.31.32.0/19", "37.48.64.0/18", "46.165.192.0/18", "78.159.112.0/20", "95.211.0.0/16", "103.23.128.0/22", "136.144.0.0/16", "178.162.128.0/17",
    # --- 国内云测试/公共段 ---
    "119.28.0.0/15", "150.109.0.0/16",
    # --- OVH (新增补全) ---
    "51.38.0.0/16", "51.68.0.0/16", "51.75.0.0/16", "51.77.0.0/16", "51.79.0.0/16", "135.125.0.0/16", "141.94.0.0/16", "145.239.0.0/16", "146.59.0.0/16", "176.31.0.0/16", "178.32.0.0/15", "188.165.0.0/16", "213.186.32.0/19",
    # --- Akamai (新增) ---
    "23.32.0.0/11",
    "23.64.0.0/14",
    "23.72.0.0/13",
    "23.192.0.0/11",
    # --- Fastly (新增) ---
    "151.101.0.0/16",
    # --- RFC 特殊用途/保留地址 (新增) ---
    "100.64.0.0/10",    # Carrier Grade NAT
    "169.254.0.0/16",   # Link Local
    "192.0.2.0/24",     # TEST-NET-1
    "192.88.99.0/24",   # 6to4 Relay
    "198.18.0.0/15",    # Benchmark
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",   # TEST-NET-3
    "240.0.0.0/4",      # Reserved
    # --- Cloudflare 老网段补充 ---
    "197.234.240.0/22",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    # --- 标准私网与本地地址 ---
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4"
)

geo_reader = None

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

def main():
    global geo_reader
    if not os.path.exists(GEO_DB):
        print(f"[!] 找不到 {GEO_DB}，无法进行国家过滤")
        return

    if not os.path.exists(SOURCE_FILE):
        print(f"[!] 错误: 找不到输入文件 {SOURCE_FILE}")
        return

    geo_reader = geoip2.database.Reader(GEO_DB)

    try:
        # 1. 构建详细黑名单
        cf_ips = fetch_cloudflare_ips()
        combined_list = list(set(cf_ips + list(STATIC_BLACKLIST)))
        
        blacklist = []
        for cidr in combined_list:
            try:
                # 使用 strict=False 自动修正像 20.180.0.0/12 这种不规范的网段定义
                net = ipaddress.ip_network(cidr, strict=False)
                blacklist.append(net)
            except ValueError:
                print(f"[!] 跳过无效的黑名单格式: {cidr}")

        print(f"[*] 成功加载 {len(blacklist)} 条深度过滤规则。")
        
        # 2. 读取并去重 (保持原序去重)
        with open(SOURCE_FILE, "r", encoding="utf-8") as f:
            raw_ips = list(dict.fromkeys(line.strip() for line in f if line.strip()))

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
        print(f"    - 时间: {now}")
        print(f"    - 原始总量: {len(raw_ips)}")
        print(f"    - 剔除数量: {removed_count}")
        print(f"    - 无效格式: {invalid_count}")
        print(f"    - GeoIP无法识别: {geo_fail_count}")
        print(f"    - 最终保留: {len(final_list)}")
        print(f"    - 整体保留率: {retention_rate:.1%}")
        print(f"    - 国家分布统计: {dict(country_count)}")
    finally:
        if geo_reader:
            geo_reader.close()

if __name__ == "__main__":
    main()
