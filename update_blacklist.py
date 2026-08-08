#!/usr/bin/env python3
"""
独立黑名单更新脚本
定时从官方源下载 AWS / Azure / GCP / Cloudflare 等 IP 段
输出到 blacklist_auto.txt，供主过滤脚本读取
"""

import requests
import ipaddress
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo

# ====================== 配置 ======================
OUTPUT_FILE = Path("blacklist_auto.txt")
TIMEOUT = 15

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BlacklistUpdater/1.0)"
}

# 官方来源
SOURCES = {
    "cloudflare": "https://www.cloudflare.com/ips-v4",
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "gcp": "https://www.gstatic.com/ipranges/cloud.json",
    # Azure 官方是下载链接，偶尔会变，用一组相对稳定的公开整理源作补充也可
    "azure": "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20240401.json",
}


def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except Exception:
        return False


def fetch_cloudflare() -> set:
    print("[*] 拉取 Cloudflare ...")
    try:
        resp = requests.get(SOURCES["cloudflare"], headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
        cidrs = {line.strip() for line in resp.text.splitlines() if line.strip()}
        print(f"    → {len(cidrs)} 条")
        return {c for c in cidrs if is_valid_cidr(c)}
    except Exception as e:
        print(f"    [失败] {e}")
        return set()


def fetch_aws() -> set:
    print("[*] 拉取 AWS ...")
    try:
        resp = requests.get(SOURCES["aws"], headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        cidrs = set()
        for prefix in data.get("prefixes", []):
            c = prefix.get("ip_prefix")
            if c:
                cidrs.add(c)
        print(f"    → {len(cidrs)} 条")
        return {c for c in cidrs if is_valid_cidr(c)}
    except Exception as e:
        print(f"    [失败] {e}")
        return set()


def fetch_gcp() -> set:
    print("[*] 拉取 GCP ...")
    try:
        resp = requests.get(SOURCES["gcp"], headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        cidrs = set()
        for item in data.get("prefixes", []):
            c = item.get("ipv4Prefix")
            if c:
                cidrs.add(c)
        print(f"    → {len(cidrs)} 条")
        return {c for c in cidrs if is_valid_cidr(c)}
    except Exception as e:
        print(f"    [失败] {e}")
        return set()


def fetch_azure() -> set:
    """
    Azure 官方 ServiceTags 文件名带日期，经常变化。
    这里做容错：失败就跳过，不影响其他来源。
    """
    print("[*] 拉取 Azure ...")
    try:
        resp = requests.get(SOURCES["azure"], headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code != 200:
            print(f"    [跳过] HTTP {resp.status_code}（链接可能过期）")
            return set()
        data = resp.json()
        cidrs = set()
        for value in data.get("values", []):
            props = value.get("properties", {})
            for c in props.get("addressPrefixes", []):
                if ":" not in c:  # 只留 IPv4
                    cidrs.add(c)
        print(f"    → {len(cidrs)} 条")
        return {c for c in cidrs if is_valid_cidr(c)}
    except Exception as e:
        print(f"    [失败] {e}")
        return set()


def main():
    print(f"[{datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')}] 开始更新云厂商黑名单...\n")

    all_cidrs = set()
    all_cidrs |= fetch_cloudflare()
    all_cidrs |= fetch_aws()
    all_cidrs |= fetch_gcp()
    all_cidrs |= fetch_azure()

    if not all_cidrs:
        print("\n[!] 未获取到任何有效网段，保留旧文件不覆盖")
        return

    # 排序后写入，方便 diff 和查看
    sorted_cidrs = sorted(all_cidrs, key=lambda x: ipaddress.ip_network(x, strict=False))

    header = [
        f"# Auto-generated cloud provider blacklist",
        f"# Updated: {datetime.now(ZoneInfo('Asia/Shanghai')).isoformat()}",
        f"# Total: {len(sorted_cidrs)}",
        f"# Sources: Cloudflare / AWS / GCP / Azure",
        "#"
    ]

    OUTPUT_FILE.write_text(
        "\n".join(header + sorted_cidrs) + "\n",
        encoding="utf-8"
    )

    print(f"\n[+] 更新完成 → {OUTPUT_FILE}")
    print(f"    共写入 {len(sorted_cidrs)} 条云厂商网段")


if __name__ == "__main__":
    main()
