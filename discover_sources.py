#!/usr/bin/env python3
"""
双通道自动发现优质聚合源（加强过滤版）
- 通道1：从高产缓存反向挖掘子链接
- 通道2：GitHub Repository 搜索 + 常见路径
- 最终对所有候选链接做存活+内容长度检查，只保留有效链接
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

HIGH_YIELD_THRESHOLD = 8
MAX_WORKERS = 8
VALIDATE_WORKERS = 16          # 验证阶段并发数
TIMEOUT = 8
MIN_CONTENT_LENGTH = 150       # 内容太短视为无效

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


def check_url_alive(url: str) -> bool:
    """检查链接是否真正可用（状态码200 + 内容足够长）"""
    try:
        # 先尝试 HEAD（更快）
        resp = requests.head(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        if resp.status_code == 200:
            # 有些服务器 HEAD 不返回 Content-Length，再补一次 GET
            content_length = resp.headers.get("Content-Length")
            if content_length and content_length.isdigit() and int(content_length) >= MIN_CONTENT_LENGTH:
                return True

        # HEAD 不靠谱或长度不够，改用 GET
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, stream=True)
        if resp.status_code != 200:
            return False

        # 只读前面一部分内容判断长度
        content = resp.raw.read(512, decode_content=True)
        return len(content) >= MIN_CONTENT_LENGTH

    except Exception:
        return False


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
                "per_page": 10          # 适当降低，减少无效路径
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


# ====================== 验证过滤 ======================
def validate_candidates(candidates: set) -> set:
    """并发检查候选链接是否真正可用"""
    if not candidates:
        return set()

    print(f"\n[验证] 开始检查 {len(candidates)} 个候选链接的存活状态...")
    valid = set()
    checked = 0

    with ThreadPoolExecutor(max_workers=VALIDATE_WORKERS) as executor:
        future_to_url = {executor.submit(check_url_alive, url): url for url in candidates}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            checked += 1
            try:
                if future.result():
                    valid.add(url)
            except Exception:
                pass

            # 每检查 50 个输出一次进度
            if checked % 50 == 0 or checked == len(candidates):
                print(f"  进度: {checked}/{len(candidates)}，当前有效: {len(valid)}")

    print(f"  验证完成，有效链接: {len(valid)} 个")
    return valid


# ====================== 主流程 ======================
def main():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 开始自动发现候选源...\n")

    existing = load_existing()
    print(f"当前已有正式源+候选源共 {len(existing)} 个\n")

    all_new = set()
    all_new.update(reverse_mining(existing))
    all_new.update(github_repo_search(existing))

    # 去重
    all_new = {u for u in all_new if u not in existing and is_valid_candidate(u)}
    print(f"\n去重后待验证链接: {len(all_new)} 个")

    # 关键：存活+内容过滤
    valid_new = validate_candidates(all_new)

    if not valid_new:
        print("\n未发现有效的新候选源。")
        return

    # 写入文件
    CANDIDATES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CANDIDATES_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n# ===== 自动发现于 {datetime.now().strftime('%Y-%m-%d %H:%M')} "
                f"(已验证存活) =====\n")
        for url in sorted(valid_new):
            f.write(url + "\n")

    print(f"\n✅ 成功写入 {len(valid_new)} 个有效候选源 → {CANDIDATES_FILE}")


if __name__ == "__main__":
    main()
