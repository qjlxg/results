import csv
import re
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# 配置
# ============================================================

BASE_DIR = Path(".")
INPUT_FILE = BASE_DIR / "domain_check.csv"
OUTPUT_FILE = BASE_DIR / "nodes_filtered.csv"
MAX_WORKERS = 10                  # 深度抓取时的并发线程数
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
MAX_DEEP_CONTENT_BYTES = 800 * 1024 # 每个网址最多抓取 10KB 内容用于分析

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# 初筛关键词
KEYWORDS = [
    "clash",
    "sub",
    "api",
    "v2ray",
    "trojan",
    "proxy",
    "node",
    "ssr",
    "sing-box",
    "xray",
    "subscription",
    "config",
    "vmess",
    "vless",
    "panel",
]


def deep_fetch_content(url):
    """
    针对筛选出来的网址进行二次深度访问，获取其实际正文（可能包含节点或订阅内容）
    """
    if not url:
        return ""
    
    # 确保 URL 有协议头
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            verify=False,
            allow_redirects=True,
            stream=True
        )
        
        # 只接收文本或常见配置类型的返回
        content_type = response.headers.get("Content-Type", "").lower()
        
        body_bytes = b""
        for chunk in response.iter_content(chunk_size=4096):
            if not chunk:
                continue
            body_bytes += chunk
            if len(body_bytes) >= MAX_DEEP_CONTENT_BYTES:
                break
                
        encoding = response.encoding or "utf-8"
        text = body_bytes.decode(encoding, errors="replace")
        
        # 简单清洗多余的 HTML 标签，如果是纯文本/JSON/YAML订阅则直接保留
        if "html" not in content_type:
            # 可能是纯文本订阅、YAML、JSON 格式节点，直接返回原文
            return text.strip()
        else:
            # 如果是网页，提取其主要文本片段
            text = re.sub(r"<script\b[^>]*>.*?</script>", " ", text, flags=re.IGNORECASE | re.DOTALL)
            text = re.sub(r"<style\b[^>]*>.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
            text = re.sub(r"<[^>]+>", " ", text)
            text = re.sub(r"\s+", " ", text).strip()
            return text[:2000] # 保留前 2000 字符
            
    except Exception as e:
        return f"[Error fetching deep content: {type(e).__name__}]"


def main():
    print("=" * 70)
    print("[*] Node & Subscription Deep Fetcher & Filter")
    print("=" * 70)

    if not INPUT_FILE.exists():
        print(f"[!] 找不到输入文件: {INPUT_FILE}，请先运行基础检查脚本。")
        return

    pattern = re.compile("|".join(KEYWORDS), re.IGNORECASE)

    candidate_rows = []

    # 1. 第一步：通过关键词初筛
    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

        for row in reader:
            target_text = (
                f"{row.get('domain', '')} "
                f"{row.get('title', '')} "
                f"{row.get('final_url', '')} "
                f"{row.get('content_snippet', '')}"
            )
            if pattern.search(target_text):
                candidate_rows.append(row)

    print(f"[*] 关键词初筛命中目标数: {len(candidate_rows)}")
    print(f"[*] 开始进行二次深度内容抓取...")

    # 扩展 CSV 字段，增加 deep_content
    if fieldnames and "deep_content" not in fieldnames:
        fieldnames.append("deep_content")
    elif not fieldnames:
        fieldnames = [
            "domain", "dns_ips", "reachable", "http_status", "https_status",
            "final_url", "title", "page_type", "content_type", "server",
            "content_length", "content_snippet", "error", "checked_at", "deep_content"
        ]

    matched_results = []

    # 2. 第二步：多线程深度抓取网页/订阅内容
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {}
        for row in candidate_rows:
            target_url = row.get("final_url") or f"https://{row.get('domain')}"
            future = executor.submit(deep_fetch_content, target_url)
            future_map[future] = row

        completed = 0
        for future in as_completed(future_map):
            row = future_map[future]
            completed += 1
            try:
                deep_text = future.result()
            except Exception:
                deep_text = ""

            row["deep_content"] = deep_text
            
            # 只有当深度抓取到了内容，或者有价值的线索时才保留
            if deep_text and not deep_text.startswith("[Error"):
                matched_results.append(row)

            if completed % 20 == 0 or completed == len(candidate_rows):
                print(f"[*] 深度抓取进度: {completed}/{len(candidate_rows)}")

    # 3. 写入最终结果
    with open(OUTPUT_FILE, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in matched_results:
            writer.writerow(item)

    print()
    print("=" * 70)
    print(f"[+] 深度抓取与过滤完成")
    print(f"[+] 最终有效保存数: {len(matched_results)}")
    print(f"[+] 输出文件: {OUTPUT_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    main()
