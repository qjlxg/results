#!/usr/bin/env python3
"""
双通道自动发现优质聚合源（深度存活过滤版）
- 通道1：从高产缓存反向挖掘子链接
- 通道2：GitHub Repository 搜索 + 常见路径
- 验证机制：对所有找到的候选链接进行并发存活与内容有效性检查（状态码200 且非空）
结果只写入 candidates.txt
"""

import re
import json
import os
import requests
from pathlib import Path
from datetime import datetime
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

HIGH_YIELD_THRESHOLD = 8          # 反向挖掘高产阈值
MAX_WORKERS = 16                  # 提高并发以加速验证
TIMEOUT = 6                       # 验证超时时间（秒）

# GitHub 仓库搜索关键词
REPO_QUERIES = [
    "clash subscription",
    "v2ray free nodes",
    "proxy subscription",
    "free proxy pool",
    "hysteria subscription",
]

# 常见可能存在的订阅文件路径
COMMON_PATHS = [
    "sub", "sub.txt", "subscribe", "subscription",
    "clash.yaml", "clash.yml", "proxy.yaml",
    "v2ray.txt", "nodes.txt", "proxies.txt",
    "README.md"
]

URL_PATTERN = re.compile(
    r'https?://[^\s\'"<>\\]{12,250}'
    r'(?:sub|api|proxies|yaml|txt|json|clash|v2ray|subscribe|pool|nodes?)'
    r'[^\s\'"<>\\]*',
    re.I
)

# ====================== 工具函数 ======================
def load_existing() -> set:
    existing = set()
    for f in [SOURCES_FILE, CANDIDATES_FILE]:
        if f.exists():
            for line in f.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    existing.add(line)
    return existing


def is_valid_candidate(url: str) -> bool:
    if not url.startswith(("http://", "https://")):
        return False
    bad = ["github.com/login", "example.com", "localhost", "127.0.0.1", "0.0.0.0"]
    if any(b in url for b in bad):
        return False
    if len(url) < 20:
        return False
    return True


def extract_urls_from_text(text: str) -> set:
    found = set()
    for m in URL_PATTERN.findall(text or ""):
        url = m.rstrip(".,;:)\"'")
        if is_valid_candidate(url):
            found.add(url)
    return found


# ====================== 通道1：反向挖掘 ======================
def get_high_yield_urls() -> list:
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
    try:
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
    print("[通道1] 开始反向挖掘高产源中的子链接...")
    high_yield_urls = get_high_yield_urls()
    print(f"  发现 {len(high_yield_urls)} 个高产源（阈值 ≥ {HIGH_YIELD_THRESHOLD}）")

    discovered = set()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_and_extract, url): url for url in high_yield_urls}
        for future in as_completed(futures):
            discovered.update(future.result())

    new_ones = {u for u in discovered if u not in existing and is_valid_candidate(u)}
    print(f"  反向挖掘得到 {len(new_ones)} 个新候选链接")
    return new_ones


# ====================== 通道2：GitHub 仓库搜索 ======================
def github_repo_search(existing: set) -> set:
    print("[通道2] 开始 GitHub Repository 搜索...")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SourceDiscover/1.2"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
        print("  已使用 GITHUB_TOKEN")
    else:
        print("  未检测到 GITHUB_TOKEN，使用未认证额度")

    discovered = set()

    for query in REPO_QUERIES:
        try:
            url = "https://api.github.com/search/repositories"
            params = {
                "q": f"{query} pushed:>2025-01-01",
                "sort": "updated",
                "order": "desc",
                "per_page": 15
            }
            resp = requests.get(url, headers=headers, params=params, timeout=15)
            if resp.status_code != 200:
                print(f"  搜索失败 [{resp.status_code}]: {query}")
                continue

            repos = resp.json().get("items", [])
            print(f"  查询「{query}」→ 找到 {len(repos)} 个仓库")

            for repo in repos:
                full_name = repo.get("full_name", "")
                default_branch = repo.get("default_branch", "main")
                if not full_name:
                    continue

                for path in COMMON_PATHS:
                    raw_url = f"https://raw.githubusercontent.com/{full_name}/{default_branch}/{path}"
                    if raw_url not in existing and is_valid_candidate(raw_url):
                        discovered.add(raw_url)

        except Exception as e:
            print(f"  搜索异常: {e}")
            continue

    print(f"  GitHub 搜索共生成 {len(discovered)} 个候选链接（含常见路径）")
    return discovered


# ====================== 存活验证与质量过滤 ======================
def verify_single_candidate(url: str) -> str:
    """验证单个链接是否可用：状态码 200 且返回内容长度大于 15 字节"""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code == 200 and len(resp.text.strip()) > 15:
            return url
    except Exception:
        pass
    return None


def verify_candidates(candidates: set) -> set:
    """并发验证候选链接列表"""
    print(f"\n[存活过滤] 开始对 {len(candidates)} 个候选链接进行可用性验证（并发数: {MAX_WORKERS}）...")
    valid_urls = set()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(verify_single_candidate, url): url for url in candidates}
        completed_count = 0
        for future in as_completed(futures):
            completed_count += 1
            if completed_count % 50 == 0:
                print(f"  进度: 已验证 {completed_count}/{len(candidates)} ...")
            result = future.result()
            if result:
                valid_urls.add(result)

    print(f"  存活过滤完成：有效源 {len(valid_urls)} 个（剔除了 {len(candidates) - len(valid_urls)} 个失效/空链接）")
    return valid_urls


# ====================== 主流程 ======================
def main():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 开始自动发现与验证候选源...\n")

    existing = load_existing()
    print(f"当前已有正式源+候选源共 {len(existing)} 个\n")

    all_new = set()
    all_new.update(reverse_mining(existing))
    all_new.update(github_repo_search(existing))

    # 基础去重
    all_new = {u for u in all_new if u not in existing and is_valid_candidate(u)}

    if not all_new:
        print("\n未发现新的候选源。")
        return

    # 新增：严格的存活与内容质量过滤
    valid_new = verify_candidates(all_new)

    if not valid_new:
        print("\n经存活验证，没有发现任何可用的新候选源。")
        return

    CANDIDATES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CANDIDATES_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n# ===== 自动发现与验证于 {datetime.now().strftime('%Y-%m-%d %H:%M')} =====\n")
        for url in sorted(valid_new):
            f.write(url + "\n")

    print(f"\n✅ 成功写入 {len(valid_new)} 个高质量有效候选源 → {CANDIDATES_FILE}")


if __name__ == "__main__":
    main()
