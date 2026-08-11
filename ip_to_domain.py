import socket
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


BASE_DIR = Path(".")
INPUT_FILE = BASE_DIR / "alive_latest.txt"
OUTPUT_FILE = BASE_DIR / "domain_results.txt"


def reverse_lookup(target):

    try:
        ip = target

        if ":" in ip:
            ip = ip.split(":")[0]

        hostname, _, _ = socket.gethostbyaddr(ip)

        return ip, hostname

    except:
        return None



def main():

    if not INPUT_FILE.exists():
        print("文件不存在")
        return


    targets = [
        x.strip()
        for x in INPUT_FILE.read_text().splitlines()
        if x.strip()
    ]


    print(f"[*] 加载 {len(targets)} 个目标")


    domains=set()


    with ThreadPoolExecutor(max_workers=100) as pool:

        tasks=[
            pool.submit(reverse_lookup,x)
            for x in targets
        ]


        for task in as_completed(tasks):

            result=task.result()

            if result:

                ip,domain=result

                print(
                    f"[+] {ip} --> {domain}"
                )

                domains.add(domain)



    OUTPUT_FILE.write_text(
        "\n".join(sorted(domains)),
        encoding="utf-8"
    )


    print(
        f"[*] 保存 {len(domains)} 个域名"
    )



if __name__=="__main__":
    main()
