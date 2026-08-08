import re
import json
import base64
import hashlib
import ipaddress
import requests
import socket
from pathlib import Path
from datetime import datetime
import time
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor, as_completed

# ====================== 配置 ======================
CONFIG_DIR = Path("config")
DATA_DIR = Path("data")
CACHE_DIR = DATA_DIR / "source_cache"
IP_FILE = Path("sources_cidr_seed.txt")
FRESH_LOG = DATA_DIR / "fresh_seeds_log.json"
SOURCES_FILE = Path("sources.txt")
STATS_CSV_FILE = DATA_DIR / "source_stats.csv"

# 请求头
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

# 并发配置
MAX_WORKERS = 20
TIMEOUT = 3

# 垃圾/公共网段黑名单
BAD_NETWORKS = [
    "1.1.1.0/24",
    "8.8.8.0/24",
    "8.8.4.0/24",
    "9.9.9.0/24",
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# ==================== 辅助函数 ====================
def load_sources():
    if not SOURCES_FILE.exists():
        print(f"警告: {SOURCES_FILE} 不存在")
        return []
    return [line.strip() for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith('#')]

def is_bad_network(net_str: str) -> bool:
    try:
        obj = ipaddress.ip_network(net_str, strict=False)
        if obj.is_private or obj.is_loopback or obj.is_reserved:
            return True
        return any(
            obj.subnet_of(ipaddress.ip_network(x))
            for x in BAD_NETWORKS
        )
    except:
        return True

def extract_nodes_and_subscriptions(text: str):
    """
    精准提取：只解析标准代理节点格式或合法的 CIDR 种子，
    彻底抛弃盲目把网页 HTML 网页版本号当作 IP 的垃圾逻辑。
    支持：vmess / vless / trojan / ss / ssr / hysteria / hysteria2 / hy2 / tuic
    以及字典/JSON 中的 server 字段。
    """
    found_items = set()

    def try_add_host(host: str):
        """把主机（IP 或域名）转为 /24 并加入结果（仅 IPv4）"""
        if not host:
            return
        host = str(host).strip().strip("[]")
        if not host:
            return
        try:
            ip_obj = ipaddress.ip_address(host)
            if ip_obj.version != 4:  # 只处理 IPv4
                return
            net = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
            cidr = str(net)
            if not is_bad_network(cidr):
                found_items.add(cidr)
        except ValueError:
            # 域名解析
            try:
                resolved_ip = socket.gethostbyname(host)
                ip_obj = ipaddress.ip_address(resolved_ip)
                if ip_obj.version != 4:
                    return
                net = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
                cidr = str(net)
                if not is_bad_network(cidr):
                    found_items.add(cidr)
            except Exception:
                pass

    # 1. 按行解析标准节点链接 + 字典格式
    lines = text.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # ---------- 协议链接 ----------
        prefixes = [
            "vmess://", "vless://", "trojan://", "ss://", "ssr://",
            "hysteria://", "hysteria2://", "hy2://", "tuic://"
        ]
        if any(line.startswith(p) for p in prefixes):
            try:
                protocol = line.split("://", 1)[0].lower()
                remain = line.split("://", 1)[1].split("#")[0]  # 去掉备注

                host = None

                if protocol == "vmess":
                    # vmess://base64(json) → 取 add 字段
                    try:
                        padded = remain + "=" * ((4 - len(remain) % 4) % 4)
                        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                        conf = json.loads(decoded)
                        host = conf.get("add") or conf.get("host")
                    except Exception:
                        pass

                elif protocol == "ssr":
                    # ssr://base64(host:port:protocol:method:obfs:...)
                    try:
                        padded = remain + "=" * ((4 - len(remain) % 4) % 4)
                        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                        host = decoded.split(":")[0]
                    except Exception:
                        pass

                else:
                    # vless / trojan / ss / hysteria / hysteria2 / hy2 / tuic
                    # 格式通常为 uuid@host:port 或 host:port
                    if "@" in remain:
                        host_port = remain.split("@", 1)[1].split("/")[0].split("?")[0]
                    else:
                        host_port = remain.split("/")[0].split("?")[0]

                    if ":" in host_port:
                        host = host_port.rsplit(":", 1)[0].strip("[]")
                    else:
                        host = host_port.strip("[]")

                if host:
                    try_add_host(host)
            except Exception:
                continue

        # ---------- 字典 / JSON 中的 server 字段 ----------
        for m in re.findall(r"""['"]server['"]\s*:\s*['"]([^'"]+)['"]""", line, re.I):
            try_add_host(m)
        for m in re.findall(r"""['"]server['"]\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})""", line, re.I):
            try_add_host(m)

        # ---------- 明文 CIDR ----------
        cidr_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:2[0-9]|3[0-2])\b', line)
        for match in cidr_matches:
            try:
                net = ipaddress.ip_network(match, strict=False)
                cidr = str(net)
                if not is_bad_network(cidr):
                    found_items.add(cidr)
            except:
                continue

    # 2. 尝试整体 Base64 解码（针对标准 Base64 机场订阅）
    clean_s = re.sub(r'[^A-Za-z0-9+/=]', '', text)
    if len(clean_s) >= 20:
        try:
            missing = len(clean_s) % 4
            if missing:
                clean_s += '=' * (4 - missing)
            decoded = base64.b64decode(clean_s).decode("utf-8", errors="ignore")
            if decoded and decoded != text:
                found_items.update(extract_nodes_and_subscriptions(decoded))
        except:
            pass
    return found_items

def collect_from_url(url: str):
    """单个URL抓取"""
    # 自动补全协议头，避免 No connection adapters 报错
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()
    cache_file = CACHE_DIR / f"{url_hash}.json"

    session = requests.Session()
    session.headers.update(HEADERS)

    target_url = url
    if "github.com" in url and "/blob/" in url:
        target_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

    try:
        print(f"[+] 正在抓取: {url}")
        resp = session.get(target_url, timeout=TIMEOUT)

        if resp.status_code != 200:
            print(f"    └─ [异常] {url} -> 状态码: {resp.status_code}")
            return url, set()

        content_text = resp.text
        content_hash = hashlib.md5(content_text.encode("utf-8")).hexdigest()

        # 检查缓存
        if cache_file.exists():
            try:
                cache_data = json.loads(cache_file.read_text(encoding="utf-8"))
                if cache_data.get("hash") == content_hash:
                    items = set(cache_data.get("items", []))
                    print(f"    └─ [缓存] {url} -> 读取到 {len(items)} 个有效网段")
                    return url, items
            except:
                pass

        # 精准提取
        found = extract_nodes_and_subscriptions(content_text)

        # 写入缓存
        try:
            cache_payload = {
                "url": url,
                "hash": content_hash,
                "time": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(),
                "items": list(found)
            }
            cache_file.write_text(json.dumps(cache_payload, ensure_ascii=False), encoding="utf-8")
        except:
            pass

        count = len(found)
        print(f"    └─ [成功] {url} -> 提取到 {count} 个有效网段")
        return url, found

    except requests.exceptions.Timeout:
        print(f"    └─ [超时] {url} (超过 {TIMEOUT} 秒未响应)")
        return url, set()
    except Exception as e:
        print(f"    └─ [失败] {url} -> 错误: {e}")
        return url, set()

def main():
    print(f"[{datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')}] 开始收集新鲜种子...\n")

    SOURCES = load_sources()
    if not SOURCES:
        print("没有找到数据源，退出。")
        return

    all_new_items = set()
    start_time = time.time()

    # ============== 并发抓取 ==============
    url_to_count = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(collect_from_url, url): url for url in SOURCES}
        
        for future in as_completed(future_to_url):
            url, items = future.result()
            all_new_items.update(items)
            url_to_count[url] = len(items)

    elapsed = time.time() - start_time

    # ============== 保存结果 ==============
    existing = set()
    if IP_FILE.exists():
        existing = {line.strip() for line in IP_FILE.read_text(encoding="utf-8").splitlines() if line.strip()}

    really_new = all_new_items - existing
    combined = existing.union(all_new_items)
    clean_combined = sorted(x for x in combined if x)

    IP_FILE.write_text("\n".join(clean_combined), encoding="utf-8")

    # 统计CSV保存
    DATA_DIR.mkdir(exist_ok=True)
    try:
        csv_lines = ["url,count,time"]
        current_time_str = datetime.now(ZoneInfo("Asia/Shanghai")).isoformat()
        for u in SOURCES:
            c = url_to_count.get(u, 0)
            csv_lines.append(f'"{u}",{c},"{current_time_str}"')
        STATS_CSV_FILE.write_text("\n".join(csv_lines), encoding="utf-8")
    except:
        pass

    # 日志
    log_entry = {
        "time": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(),
        "new_count": len(really_new),
        "total_now": len(clean_combined),
        "sources_checked": len(SOURCES),
        "duration_seconds": round(elapsed, 2)
    }
    try:
        history = json.loads(FRESH_LOG.read_text(encoding="utf-8")) if FRESH_LOG.exists() else []
        history.append(log_entry)
        FRESH_LOG.write_text(json.dumps(history[-100:], indent=2, ensure_ascii=False), encoding="utf-8")
    except:
        pass

    print("\n" + "=" * 60)
    print(f"收集完成！用时 {elapsed:.1f} 秒")
    print(f"本次新增有效网段: {len(really_new)} 个")
    print(f"当前总种子数: {len(clean_combined)} 个")
    print(f"已更新 → {IP_FILE}")
    print(f"统计已保存 → {STATS_CSV_FILE}")
    print("=" * 60)

if __name__ == "__main__":
    main()
