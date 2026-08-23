import csv
import re
from pathlib import Path

# ============================================================
# 配置
# ============================================================

BASE_DIR = Path(".")
INPUT_FILE = BASE_DIR / "domain_check.csv"      # 上一步生成的总表
OUTPUT_FILE = BASE_DIR / "nodes_filtered.csv"   # 过滤后的节点/订阅相关资产表

# 精准关键词列表（涵盖节点、订阅、代理、协议、面板等）
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


def main():
    print("=" * 70)
    print("[*] Node & Subscription Keyword Filter")
    print("=" * 70)

    if not INPUT_FILE.exists():
        print(f"[!] 找不到输入文件: {INPUT_FILE}，请先运行基础检查脚本。")
        return

    # 编译正则表达式，忽略大小写
    pattern = re.compile("|".join(KEYWORDS), re.IGNORECASE)

    matched_results = []
    total_rows = 0

    # 读取总表并进行关键词匹配
    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

        for row in reader:
            total_rows += 1
            # 综合检查：域名、网页标题、最终跳转URL、正文摘要是否包含关键词
            target_text = (
                f"{row.get('domain', '')} "
                f"{row.get('title', '')} "
                f"{row.get('final_url', '')} "
                f"{row.get('content_snippet', '')}"
            )

            if pattern.search(target_text):
                matched_results.append(row)

    # 写入筛选后的结果
    if fieldnames is None:
        fieldnames = [
            "domain", "dns_ips", "reachable", "http_status", "https_status",
            "final_url", "title", "page_type", "content_type", "server",
            "content_length", "content_snippet", "error", "checked_at"
        ]

    with open(OUTPUT_FILE, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in matched_results:
            writer.writerow(item)

    print(f"[*] 扫描总行数: {total_rows}")
    print(f"[+] 成功匹配并筛选出潜在目标数: {len(matched_results)}")
    print(f"[+] 输出文件: {OUTPUT_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    main()
