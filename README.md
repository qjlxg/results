# results

| 文件                          | 作用                       | 平时是否需要看     |
| --------------------------- | ------------------------ | ----------- |
| **`domain_candidates.txt`** | 主候选域名库                   | **✅ 主要看这个** |
| `dns_seed.txt`              | 给下一步 DNS 扩展使用的高质量域名      | 一般不用手看      |
| `domain_low_value.txt`      | `fornex.cloud` 等低价值域名    | 偶尔检查        |
| `domain_internal.txt`       | `traefik.default` 等内部域名  | 基本不用看       |
| `ptr_domains.txt`           | PTR 来源域名                 | 排查时看        |
| `tls_domains.txt`           | TLS 证书发现的域名              | 排查时看        |
| `tls_mapping.txt`           | IP、端口、域名、证书、Issuer 的详细关系 | **需要溯源时看**  |
| `tls_ips.txt`               | 证书里的 IP SAN              | 一般不用看       |


不过还有一个区别

如果你下一步是：

拿这些域名继续 DNS 解析，寻找新的 IP / 网段

那就应该使用：

dns_seed.txt

而不是：

domain_candidates.txt

因为新版脚本专门把 dns_seed.txt 做成了高质量 DNS 种子池。

所以可以简单记：

我自己想看有哪些域名
        ↓
domain_candidates.txt

脚本下一步要继续扩展
        ↓
dns_seed.txt

我想查某个域名为什么来的
        ↓
tls_mapping.txt

你平时人工查看，直接看 domain_candidates.txt 就行。
