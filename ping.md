好的，为了满足您的要求，我对脚本进行了以下优化：

1. 输出结果更友好阅读：使用格式化输出，将结果以表格形式显示，并对可达和不可达的 IP 地址进行分类和统计。
2. 方便终端调用脚本：使用 argparse 模块改进命令行参数解析，支持更直观的参数输入，并提供帮助信息。同时，添加了 shebang 行和可执行权限，使脚本可以直接在终端运行。

下面是优化后的脚本：

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
import subprocess
import platform
import ipaddress
import sys
import argparse

def ping(host, reachable_ips, unreachable_ips):
    """
    ping 单个主机，并根据结果添加到对应的列表
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    # 设置每次请求的等待超时时间，Windows 使用 '-w'，Linux/Unix 使用 '-W'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    command = ['ping', param, '1', timeout_param, '1', str(host)]
    result = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if result == 0:
        reachable_ips.append(str(host))
    else:
        unreachable_ips.append(str(host))

def expand_ips(ip_input):
    """
    根据输入生成 IP 地址列表，支持单个 IP、范围和子网掩码
    """
    ip_list = []
    try:
        if '-' in ip_input:
            # IP 范围，如：192.168.1.1-192.168.1.254
            start_ip_str, end_ip_str = ip_input.split('-')
            start_ip = ipaddress.IPv4Address(start_ip_str.strip())
            end_ip = ipaddress.IPv4Address(end_ip_str.strip())
            if int(end_ip) < int(start_ip):
                print("错误：结束 IP 应该大于或等于开始 IP")
                sys.exit(1)
            for ip_int in range(int(start_ip), int(end_ip) + 1):
                ip_list.append(ipaddress.IPv4Address(ip_int))
        else:
            # CIDR 表示法或单个 IP
            network = ipaddress.ip_network(ip_input, strict=False)
            ip_list = list(network.hosts())
    except ValueError as e:
        print(f"输入有误：{e}")
        sys.exit(1)
    return ip_list

def main():
    parser = argparse.ArgumentParser(description='批量 ping IP 地址脚本')
    parser.add_argument('ip', metavar='IP', nargs=1, help='IP 地址、IP 范围或 CIDR 表示法')
    args = parser.parse_args()

    ip_input = args.ip[0]
    hosts = expand_ips(ip_input)

    reachable_ips = []
    unreachable_ips = []
    threads = []

    for host in hosts:
        thread = threading.Thread(target=ping, args=(host, reachable_ips, unreachable_ips))
        threads.append(thread)
        thread.start()

    # 等待所有线程完成
    for thread in threads:
        thread.join()

    # 输出结果
    print("\nPing 测试结果：\n")
    print("{:<15} {:<}".format('IP 地址', '状态'))
    print("-" * 30)
    for ip in sorted(reachable_ips, key=lambda ip: ipaddress.IPv4Address(ip)):
        print("{:<15} {:<}".format(ip, '可达'))
    for ip in sorted(unreachable_ips, key=lambda ip: ipaddress.IPv4Address(ip)):
        print("{:<15} {:<}".format(ip, '不可达'))

    # 输出统计信息
    print("\n统计信息：")
    print(f"总共检测 IP 数量：{len(hosts)}")
    print(f"可达 IP 数量：{len(reachable_ips)}")
    print(f"不可达 IP 数量：{len(unreachable_ips)}")

if __name__ == '__main__':
    main()

优化说明：

1. 输入优化：

• 命令行参数解析：使用 argparse 模块处理命令行参数，提供了更好的用户体验和帮助信息。
• 支持多种 IP 输入格式：脚本支持单个 IP、IP 范围（如 192.168.1.1-192.168.1.254）、CIDR 表示法（如 192.168.1.0/24）等多种输入方式。

2. 输出优化：

• 结果格式化：使用对齐的表格形式输出，方便阅读。
• 排序输出：对 IP 地址进行排序，输出更有序。
• 统计信息：在结果末尾添加统计信息，显示总的检测数量、可达和不可达的 IP 数量。

3. 终端调用优化：

• Shebang 行：在脚本顶部添加了 #!/usr/bin/env python3，使脚本可以直接在 Unix/Linux/macOS 终端执行。
• 可执行权限：保存脚本后，给予执行权限，使其可直接运行。
• 帮助信息：使用 argparse，在终端中添加 -h 或 --help 参数，可以查看脚本的使用说明。

使用方法：

1. 保存脚本：
将上述代码保存为 ping_hosts.py。
2. 给予执行权限（在 Unix/Linux/macOS 系统上）：
chmod +x ping_hosts.py

3. 运行脚本：
在终端中，运行以下命令：
./ping_hosts.py <IP 输入>

或者（通过 Python 解释器运行）：
python3 ping_hosts.py <IP 输入>

示例：
	• 单个 IP：
./ping_hosts.py 192.168.1.1

	• IP 范围：
./ping_hosts.py 192.168.1.1-192.168.1.254

	• CIDR 表示法：
./ping_hosts.py 192.168.1.0/24

4. 查看帮助信息：
./ping_hosts.py -h

输出：
usage: ping_hosts.py [-h] IP

批量 ping IP 地址脚本

positional arguments:
  IP          IP 地址、IP 范围或 CIDR 表示法

optional arguments:
  -h, --help  show this help message and exit

5. 查看结果：
脚本会输出类似如下的结果：
Ping 测试结果：

IP 地址         状态
------------------------------
192.168.1.1     可达
192.168.1.2     不可达
192.168.1.3     可达
...

统计信息：
总共检测 IP 数量：254
可达 IP 数量：2
不可达 IP 数量：252


注意事项：

• 跨平台支持：脚本适用于 Windows、Linux 和 macOS 系统。请确保您的系统安装了 Python 3。
• 权限问题：在某些操作系统中，执行 ping 命令可能需要管理员或超级用户权限。请确保您有足够的权限运行脚本。
• 网络环境：请保证所检测的 IP 地址处于可访问的网络环境，以获得准确的检测结果。
• 执行效率：对于大量 IP 地址的检测，脚本使用了多线程技术，但线程数量过多可能会影响系统性能。根据实际情况，您可以进一步优化线程的使用（如使用线程池）。

扩展建议：

1. 使用线程池优化性能：

使用 concurrent.futures.ThreadPoolExecutor 限制最大并发线程数，防止线程过多导致系统资源耗尽。

修改 main() 函数中的线程创建部分：

from concurrent.futures import ThreadPoolExecutor

def main():
    # ...（前略）

    reachable_ips = []
    unreachable_ips = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for host in hosts:
            futures.append(executor.submit(ping, host, reachable_ips, unreachable_ips))

        # 等待所有任务完成
        for future in futures:
            future.result()

    # ...（后续代码）

在 ThreadPoolExecutor 中，您可以根据系统性能调整 max_workers 参数。

2. 输出颜色显示：

使用 colorama 库，对终端输出进行颜色高亮，使结果更加直观。

首先安装 colorama：

pip install colorama

修改输出部分：

from colorama import init, Fore, Style

init(autoreset=True)

# ...（在输出结果的部分）

print("\nPing 测试结果：\n")
print("{:<15} {:<}".format('IP 地址', '状态'))
print("-" * 30)
for ip in sorted(reachable_ips, key=lambda ip: ipaddress.IPv4Address(ip)):
    print("{:<15} {}{}".format(ip, Fore.GREEN, '可达'))
for ip in sorted(unreachable_ips, key=lambda ip: ipaddress.IPv4Address(ip)):
    print("{:<15} {}{}".format(ip, Fore.RED, '不可达'))

这样，可达的 IP 地址会以绿色显示，不可达的 IP 地址会以红色显示。

3. 保存结果到文件：

您可以将检测结果保存到文件中，方便后续分析。

在输出结果的部分，添加文件写入功能：

# 保存结果到文件
with open('ping_results.txt', 'w') as f:
    f.write("Ping 测试结果：\n\n")
    f.write("{:<15} {:<}\n".format('IP 地址', '状态'))
    f.write("-" * 30 + '\n')
    for ip in sorted(reachable_ips, key=lambda ip: ipaddress.IPv4Address(ip)):
        f.write("{:<15} {:<}\n".format(ip, '可达'))
    for ip in sorted(unreachable_ips, key=lambda ip: ipaddress.IPv4Address(ip)):
        f.write("{:<15} {:<}\n".format(ip, '不可达'))

    f.write("\n统计信息：\n")
    f.write(f"总共检测 IP 数量：{len(hosts)}\n")
    f.write(f"可达 IP 数量：{len(reachable_ips)}\n")
    f.write(f"不可达 IP 数量：{len(unreachable_ips)}\n")

print("\n结果已保存到文件：ping_results.txt")

这样，脚本会在当前目录下生成一个 ping_results.txt 文件，包含所有检测结果。

希望以上优化能够满足您的要求！如果您有任何疑问或需要进一步的帮助，请随时告诉我。