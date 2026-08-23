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
