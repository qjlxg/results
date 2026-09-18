#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_nodes.py
多源代理节点订阅聚合脚本（支持明文 / Base64 / Clash YAML）
按协议分类保存，每 500 节点自动拆分，支持并行、去重、增量跳过
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

import requests
import yaml

# ======================== 配置区域 ========================
SUBSCRIPTIONS_FILE = Path("sources.txt")          # 订阅源列表
NODES_DIR = Path("nodes")                               # 所有生成文件放这里
STATS_CSV = NODES_DIR / "stats.csv"                     # 每次运行统计
CHANGELOG = NODES_DIR / "changelog.md"                  # 变化记录
HASH_FILE = NODES_DIR / "source_hashes.json"            # 内容哈希（用于跳过）
MAX_WORKERS = 12                                        # 并行线程数
NODES_PER_FILE = 500                                    # 每个文件最多节点数
REQUEST_TIMEOUT = 25                                    # 单个源超时秒数
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/150.0.0.0 Safari/537.36"
)

# 支持的协议前缀（用于最终分类）
SUPPORTED_PROTOCOLS = {
    "ss", "ssr", "vmess", "vless", "trojan",
    "hysteria", "hysteria2", "hy2", "tuic", "wireguard", "wg"
}

# 北京时间
BEIJING_TZ = timezone(timedelta(hours=8))


# ======================== 工具函数 ========================
def now_beijing() -> str:
    return datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S")


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def safe_b64decode(data: str) -> Optional[str]:
    """尝试 Base64 解码，失败返回 None"""
    data = data.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    # 补全 padding
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        decoded = base64.b64decode(data, validate=False)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None


def is_mostly_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t")
    return printable / len(text) > 0.85


# ======================== 订阅源读取 ========================
def load_subscriptions() -> List[str]:
    if not SUBSCRIPTIONS_FILE.exists():
        print(f"[错误] 找不到订阅列表文件: {SUBSCRIPTIONS_FILE}")
        sys.exit(1)
    urls = []
    with open(SUBSCRIPTIONS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    print(f"[信息] 共加载 {len(urls)} 个订阅源")
    return urls


# ======================== 网络拉取 ========================
def fetch_url(url: str) -> Tuple[str, Optional[str], Optional[str]]:
    """
    返回: (url, content, error)
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        resp.raise_for_status()
        # 优先尝试 utf-8，失败则用 content 猜测
        try:
            text = resp.content.decode("utf-8")
        except UnicodeDecodeError:
            text = resp.content.decode("utf-8", errors="ignore")
        return url, text, None
    except Exception as e:
        return url, None, str(e)


# ======================== 节点提取核心 ========================
SHARE_LINK_PATTERN = re.compile(
    r"(?:^|[\s\"'<>])("
    r"(?:ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic|wireguard|wg)://[^\s\"'<>]+"
    r")",
    re.IGNORECASE | re.MULTILINE,
)


def extract_share_links(text: str) -> List[str]:
    """从任意文本中提取所有分享链接"""
    links = []
    for m in SHARE_LINK_PATTERN.finditer(text):
        link = m.group(1).rstrip(".,;)]}>'\"")
        if link:
            links.append(link)
    return links


def parse_clash_yaml(text: str) -> List[str]:
    """解析 Clash / Mihomo YAML，提取 proxies 并尽量转成分享链接"""
    links = []
    try:
        # 有些文件前面有注释或 BOM
        text = text.lstrip("\ufeff")
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            return links
        proxies = data.get("proxies") or data.get("Proxy") or []
        if not isinstance(proxies, list):
            return links

        for p in proxies:
            if not isinstance(p, dict):
                continue
            link = clash_proxy_to_share_link(p)
            if link:
                links.append(link)
    except Exception:
        pass
    return links


def clash_proxy_to_share_link(p: dict) -> Optional[str]:
    """把 Clash 节点字典尽量转成标准分享链接（简化版，覆盖主流）"""
    t = (p.get("type") or "").lower()
    name = p.get("name") or "node"
    server = p.get("server") or p.get("servername") or ""
    port = p.get("port")
    if not server or not port:
        return None

    try:
        if t == "ss":
            # ss://method:password@server:port#name
            method = p.get("cipher") or p.get("method") or "aes-256-gcm"
            password = p.get("password") or ""
            userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
            return f"ss://{userinfo}@{server}:{port}#{name}"

        elif t == "ssr":
            # 简化处理，很多源已不再提供 ssr
            return None

        elif t == "vmess":
            # 构造标准 vmess json 再 base64
            conf = {
                "v": "2",
                "ps": name,
                "add": server,
                "port": str(port),
                "id": p.get("uuid") or p.get("id") or "",
                "aid": str(p.get("alterId") or p.get("alterid") or 0),
                "scy": p.get("cipher") or "auto",
                "net": p.get("network") or "tcp",
                "type": p.get("type") or "none",
                "host": (p.get("ws-opts") or {}).get("headers", {}).get("Host") or p.get("host") or "",
                "path": (p.get("ws-opts") or {}).get("path") or p.get("path") or "",
                "tls": "tls" if p.get("tls") else "",
                "sni": p.get("servername") or p.get("sni") or "",
            }
            raw = json.dumps(conf, ensure_ascii=False, separators=(",", ":"))
            b64 = base64.b64encode(raw.encode()).decode()
            return f"vmess://{b64}"

        elif t == "vless":
            uuid = p.get("uuid") or ""
            params = []
            if p.get("tls"):
                params.append("security=tls")
            if p.get("flow"):
                params.append(f"flow={p['flow']}")
            if p.get("network"):
                params.append(f"type={p['network']}")
            if p.get("servername") or p.get("sni"):
                params.append(f"sni={p.get('servername') or p.get('sni')}")
            query = "&".join(params)
            return f"vless://{uuid}@{server}:{port}?{query}#{name}"

        elif t == "trojan":
            password = p.get("password") or ""
            params = []
            if p.get("sni") or p.get("servername"):
                params.append(f"sni={p.get('sni') or p.get('servername')}")
            query = "&".join(params)
            return f"trojan://{password}@{server}:{port}?{query}#{name}"

        elif t in ("hysteria", "hysteria2", "hy2"):
            # hysteria2://auth@server:port?params#name
            auth = p.get("password") or p.get("auth") or ""
            protocol = "hysteria2" if t != "hysteria" else "hysteria"
            return f"{protocol}://{auth}@{server}:{port}#{name}"

        elif t == "tuic":
            uuid = p.get("uuid") or ""
            password = p.get("password") or ""
            return f"tuic://{uuid}:{password}@{server}:{port}#{name}"

    except Exception:
        return None
    return None


def detect_and_parse(content: str) -> List[str]:
    """
    自动检测格式并解析出所有分享链接
    优先级：
    1. 直接包含大量分享链接 → 提取
    2. 看起来是 Base64 → 解码后再提取
    3. 看起来是 YAML → 按 Clash 解析
    """
    content = content.strip()
    if not content:
        return []

    # 1. 先直接提取（很多源已经是明文链接列表）
    links = extract_share_links(content)
    if len(links) >= 3:          # 有一定数量就认为有效
        return links

    # 2. 尝试 Base64
    decoded = safe_b64decode(content)
    if decoded and is_mostly_printable(decoded):
        links = extract_share_links(decoded)
        if links:
            return links
        # 解码后可能是 YAML
        if "proxies:" in decoded or "Proxy:" in decoded:
            return parse_clash_yaml(decoded)

    # 3. 直接当 YAML 解析
    if "proxies:" in content or "Proxy:" in content or content.lstrip().startswith("{"):
        return parse_clash_yaml(content)

    # 4. 再试一次 Base64（有些源是双重编码或带换行）
    if not links:
        # 去掉可能的前缀注释后重试
        pure = re.sub(r"^#.*$", "", content, flags=re.MULTILINE).strip()
        decoded = safe_b64decode(pure)
        if decoded:
            links = extract_share_links(decoded)
            if not links and ("proxies:" in decoded or "Proxy:" in decoded):
                links = parse_clash_yaml(decoded)

    return links


def normalize_link(link: str) -> str:
    """简单规范化，用于去重（去掉 # 后面的备注差异）"""
    link = link.strip()
    if "#" in link:
        # 保留协议部分，备注可以不同但内容相同
        base = link.split("#", 1)[0]
        return base
    return link


def get_protocol(link: str) -> str:
    """从分享链接提取协议名"""
    m = re.match(r"^([a-z0-9]+)://", link, re.IGNORECASE)
    if not m:
        return "unknown"
    proto = m.group(1).lower()
    if proto == "hy2":
        return "hysteria2"
    if proto == "wg":
        return "wireguard"
    return proto


# ======================== 主流程 ========================
def load_previous_hashes() -> Dict[str, str]:
    if HASH_FILE.exists():
        try:
            with open(HASH_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_hashes(hashes: Dict[str, str]):
    NODES_DIR.mkdir(parents=True, exist_ok=True)
    with open(HASH_FILE, "w", encoding="utf-8") as f:
        json.dump(hashes, f, ensure_ascii=False, indent=2)


def process_one_source(url: str, prev_hashes: Dict[str, str]) -> dict:
    """处理单个订阅源，返回统计信息"""
    result = {
        "url": url,
        "count": 0,
        "status": "ok",
        "error": "",
        "skipped": False,
        "hash": "",
        "links": [],
    }

    url, content, err = fetch_url(url)
    if err or content is None:
        result["status"] = "error"
        result["error"] = err or "empty content"
        return result

    h = content_hash(content)
    result["hash"] = h

    # 增量跳过
    if prev_hashes.get(url) == h:
        result["skipped"] = True
        result["status"] = "skipped"
        return result

    links = detect_and_parse(content)
    # 去重本源内部
    seen = set()
    unique = []
    for link in links:
        norm = normalize_link(link)
        if norm not in seen:
            seen.add(norm)
            unique.append(link)

    result["count"] = len(unique)
    result["links"] = unique
    return result


def save_nodes_by_protocol(all_links: List[str]):
    """按协议建子目录 + 每 500 个拆分文件"""
    NODES_DIR.mkdir(parents=True, exist_ok=True)

    # 清空旧的协议子目录（保留 stats / changelog / hash）
    for item in NODES_DIR.iterdir():
        if item.is_dir():
            for f in item.glob("*.txt"):
                f.unlink()
            try:
                item.rmdir()  # 目录空了就删掉
            except OSError:
                pass

    groups: Dict[str, List[str]] = {}
    for link in all_links:
        proto = get_protocol(link)
        groups.setdefault(proto, []).append(link)

    total_files = 0
    for proto, links in sorted(groups.items()):
        if not links:
            continue
        unique = list(dict.fromkeys(links))
        proto_dir = NODES_DIR / proto
        proto_dir.mkdir(parents=True, exist_ok=True)

        for i in range(0, len(unique), NODES_PER_FILE):
            chunk = unique[i : i + NODES_PER_FILE]
            idx = i // NODES_PER_FILE + 1
            filename = proto_dir / f"{idx:03d}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk) + "\n")
            total_files += 1
            print(f"  → 写入 {proto}/{filename.name}  ({len(chunk)} 个节点)")

    print(f"[完成] 共生成 {total_files} 个文件，覆盖 {len(groups)} 种协议")



def write_stats(results: List[dict]):
    NODES_DIR.mkdir(parents=True, exist_ok=True)
    file_exists = STATS_CSV.exists()
    with open(STATS_CSV, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "url", "count", "status", "error", "skipped"])
        ts = now_beijing()
        for r in results:
            writer.writerow([
                ts,
                r["url"],
                r["count"],
                r["status"],
                r.get("error", ""),
                r.get("skipped", False),
            ])


def write_changelog(results: List[dict], prev_hashes: Dict[str, str]):
    NODES_DIR.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append(f"## 运行时间：{now_beijing()} (北京时间)\n")

    updated = [r for r in results if not r.get("skipped") and r["status"] == "ok"]
    skipped = [r for r in results if r.get("skipped")]
    errors = [r for r in results if r["status"] == "error"]

    lines.append(f"- 成功更新：{len(updated)} 个源")
    lines.append(f"- 内容未变跳过：{len(skipped)} 个源")
    lines.append(f"- 拉取失败：{len(errors)} 个源\n")

    if updated:
        lines.append("### 本次有更新的源\n")
        for r in updated:
            lines.append(f"- `{r['url']}` → **{r['count']}** 个节点")
        lines.append("")

    if errors:
        lines.append("### 失败的源\n")
        for r in errors:
            lines.append(f"- `{r['url']}` : {r.get('error', '')}")
        lines.append("")

    old = ""
    if CHANGELOG.exists():
        old = CHANGELOG.read_text(encoding="utf-8")
    with open(CHANGELOG, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n---\n\n" + old)


def main():
    print(f"========== collect_nodes 开始运行 {now_beijing()} ==========")
    NODES_DIR.mkdir(parents=True, exist_ok=True)

    urls = load_subscriptions()
    prev_hashes = load_previous_hashes()

    results = []
    all_links: List[str] = []
    seen_global: Set[str] = set()

    print(f"[信息] 开始并行拉取（workers={MAX_WORKERS}）...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(process_one_source, url, prev_hashes): url for url in urls}
        for future in as_completed(future_map):
            r = future.result()
            results.append(r)
            status = r["status"]
            if r.get("skipped"):
                print(f"  [跳过] {r['url'][:60]}... (内容未变化)")
            elif status == "error":
                print(f"  [失败] {r['url'][:60]}... → {r.get('error')}")
            else:
                print(f"  [成功] {r['url'][:60]}... → {r['count']} 节点")
                for link in r["links"]:
                    norm = normalize_link(link)
                    if norm not in seen_global:
                        seen_global.add(norm)
                        all_links.append(link)

    # 更新哈希（只记录成功或跳过的）
    new_hashes = dict(prev_hashes)
    for r in results:
        if r["hash"] and r["status"] in ("ok", "skipped"):
            new_hashes[r["url"]] = r["hash"]
    save_hashes(new_hashes)

    print(f"\n[信息] 全局去重后共 {len(all_links)} 个有效节点")
    save_nodes_by_protocol(all_links)
    write_stats(results)
    write_changelog(results, prev_hashes)

    print(f"========== 运行结束 {now_beijing()} ==========")


if __name__ == "__main__":
    main()
