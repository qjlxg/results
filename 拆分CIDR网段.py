import ipaddress

# 定义目标端口列表
PORTS = [
    80, 443, 777, 1220, 2000, 2052, 2053, 2080, 2082, 2083, 2086, 2087, 2096,
    3000, 5000, 6000, 6001, 7777, 8000, 8001, 8006, 8080, 8081, 8082, 8083,
    8088, 8089, 8123, 8388, 8443, 8843, 8880, 8888, 8899, 8900, 9090, 9443,
    9999, 10006, 10080, 10443, 18080, 19888, 25500, 40003, 50001, 54321, 60000
]

def expand_ip_with_ports(input_file="targets.txt", output_file="output.txt"):
    with open(input_file, "r", encoding="utf-8") as f_in, \
         open(output_file, "w", encoding="utf-8") as f_out:
        
        for line in f_in:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            try:
                # 解析 IP 或 CIDR 网段（strict=False 兼容非标准网段）
                network = ipaddress.ip_network(line, strict=False)
                
                # 遍历网段内所有 IP
                for ip in network:
                    ip_str = str(ip)
                    # 组合端口并写入
                    for port in PORTS:
                        f_out.write(f"{ip_str}:{port}\n")
            except ValueError:
                print(f"跳过无效的 IP/网段: {line}")

if __name__ == "__main__":
    expand_ip_with_ports("targets.txt", "output.txt")
    print("处理完成！结果已保存至 output.txt")