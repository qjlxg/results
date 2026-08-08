#!/usr/bin/env python3
"""
双通道自动发现优质聚合源
- 通道1：从高产缓存反向挖掘子链接
- 通道2：GitHub Code Search
结果只写入 candidates.txt，不污染正式源
"""

import re
import json
import os
import hashlib
import requests
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# ====================== 配置 ======================
SOURCES_FILE = Path("sources.txt")
CANDIDATES_FILE = Path("candidates.txt")
DATA_DIR = Path("data")
CACHE_DIR = DATA_DIR / "source_cache"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

# 反向挖掘：认为「高产」的阈值
HIGH_YIELD_THRESHOLD = 20
# 反向挖掘并发
MAX_WORKERS = 8
TIMEOUT = 8

# GitHub Search 关键词（可按需增减）
GITHUB_QUERIES = [
    "filename:sub.txt proxy OR clash OR v2ray OR subscription",
    "filename:clash.yaml OR filename:proxy.yaml stars:>2",
    "path:/ sub OR subscription extension:txt pushed:>2025-01-01",
    "v2ray OR clash OR hysteria subscription extension:txt",
]

# 订阅链接特征正则
URL_PATTERN = re.compile(
    r'https?://[^\s\'"<>\\]{10,200}'
    r'(?:sub|api|proxies|yaml|txt|json|clash|v2ray|subscribe|pool|nodes?)'
    r'[^\s\'"<>\\]*',
    re.I
)

# ====================== 工具函数 ======================
def load_existing() -> set:
    """加载已有正式源 + 候选源，用于去重"""
    existing = set()
    for f in [SOURCES_FILE, CANDIDATES_FILE]:
        if f.exists():
            for line in f.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    existing.add(line)
    return existing


def is_valid_candidate(url: str) -> bool:
    """简单质量过滤"""
    if not url.startswith(("http://", "https://")):
        return False
    # 排除常见无用域名
    bad_domains = [
        "github.com/login", "githubusercontent.com", "raw.githubusercontent.com/settings",
        "example.com", "localhost", "127.0.0.1", "0.0.0.0"
    ]
    if any(b in url for b in bad_domains):
        return False
    # 太短或明显不是订阅
    if len(url) < 20:
        return False
    return True


def extract_urls_from_text(text: str) -> set:
    """从文本中提取可能的订阅链接"""
    found = set()
    for m in URL_PATTERN.findall(text):
        # 清理末尾可能的标点
        url = m.rstrip(".,;:)\"'")
        if is_valid_candidate(url):
            found.add(url)
    return found


# ====================== 通道1：反向挖掘 ======================
def get_high_yield_urls() -> list:
    """从缓存中找出高产源的原始 URL"""
    high_yield = []
    if not CACHE_DIR.exists():
        return high_yield

    for cache_file in CACHE_DIR.glob("*.json"):
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            items = data.get("items", [])
            url = data.get("url", "")
            if url and len(items) >= HIGH_YIELD_THRESHOLD:
                high_yield.append(url)
        except Exception:
            continue
    return high_yield


def fetch_and_extract(url: str) -> set:
    """抓取单个高产源并提取其中的子链接"""
    try:
        # GitHub blob 转 raw
        target = url
        if "github.com" in url and "/blob/" in url:
            target = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

        resp = requests.get(target, headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code != 200:
            return set()
        return extract_urls_from_text(resp.text)
    except Exception:
        return set()


def reverse_mining(existing: set) -> set:
    """通道1主逻辑"""
    print("[通道1] 开始反向挖掘高产源中的子链接...")
    high_yield_urls = get_high_yield_urls()
    print(f"  发现 {len(high_yield_urls)} 个高产源（阈值 ≥ {HIGH_YIELD_THRESHOLD}）")

    discovered = set()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_and_extract, url): url for url in high_yield_urls}
        for future in as_completed(futures):
            urls = future.result()
            discovered.update(urls)

    new_ones = {u for u in discovered if u not in existing and is_valid_candidate(u)}
    print(f"  反向挖掘得到 {len(new_ones)} 个新候选链接")
    return new_ones


# ====================== 通道2：GitHub Search ======================
def github_search(existing: set) -> set:
    """通道2主逻辑"""
    print("[通道2] 开始 GitHub Code Search...")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SourceDiscover/1.0"
    }
    if token:
        headers["Authorization"] = f"token {token}"
        print("  已使用 GITHUB_TOKEN，额度更高")
    else:
        print("  未检测到 GITHUB_TOKEN，将使用未认证额度（较低）")

    discovered = set()
    for query in GITHUB_QUERIES:
        try:
            # 只取最近更新的
            q = f"{query} pushed:>2025-06-01"
            url = "https://api.github.com/search/code"
            params = {"q": q, "per_page": 30, "sort": "indexed"}

            resp = requests.get(url, headers=headers, params=params, timeout=15)
            if resp.status_code != 200:
                print(f"  搜索失败 [{resp.status_code}]: {query[:40]}...")
                continue

            items = resp.json().get("items", [])
            for item in items:
                html_url = item.get("html_url", "")
                if "github.com" in html_url and "/blob/" in html_url:
                    raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                    if is_valid_candidate(raw_url) and raw_url not in existing:
                        discovered.add(raw_url)

            print(f"  查询「{query[:40]}...」→ 找到 {len(items)} 条")
        except Exception as e:
            print(f"  搜索异常: {e}")
            continue

    print(f"  GitHub Search 共得到 {len(discovered)} 个新候选链接")
    return discovered


# ====================== 主流程 ======================
def main():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 开始自动发现候选源...\n")

    existing = load_existing()
    print(f"当前已有正式源+候选源共 {len(existing)} 个\n")

    all_new = set()

    # 通道1
    all_new.update(reverse_mining(existing))

    # 通道2
    all_new.update(github_search(existing))

    # 最终去重（防止两通道重复）
    all_new = {u for u in all_new if u not in existing and is_valid_candidate(u)}

    if not all_new:
        print("\n未发现新的候选源。")
        return

    # 写入 candidates.txt
    CANDIDATES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CANDIDATES_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n# ===== 自动发现于 {datetime.now().strftime('%Y-%m-%d %H:%M')} =====\n")
        for url in sorted(all_new):
            f.write(url + "\n")

    print(f"\n✅ 成功写入 {len(all_new)} 个新候选源 → {CANDIDATES_FILE}")
    print("请人工或后续脚本审核后再晋升到 sources.txt")


if __name__ == "__main__":
    main()
