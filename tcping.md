好的，以下是一个用于批量监测 TCP 和 UDP 端口状态的 Python 脚本。此脚本可以扫描给定 IP 地址范围或单个 IP 地址上的指定端口，检查这些端口是否打开。

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ipaddress
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(ip, port, protocol):
    """
    扫描单个 IP 地址上的指定端口，返回端口状态
    """
    if protocol.lower() == 'tcp':
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 设置超时时间为1秒
    elif protocol.lower() == 'udp':
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
    else:
        return (ip, port, protocol.upper(), '未知协议')

    try:
        if protocol.lower() == 'tcp':
            result = sock.connect_ex((str(ip), port))
            if result == 0:
                return (ip, port, 'TCP', '开放')
            else:
                return (ip, port, 'TCP', '关闭')
        elif protocol.lower() == 'udp':
            sock.sendto(b'', (str(ip), port))
            try:
                data, _ = sock.recvfrom(1024)
                return (ip, port, 'UDP', '开放')
            except socket.timeout:
                return (ip, port, 'UDP', '开放或被屏蔽')
            except Exception:
                return (ip, port, 'UDP', '关闭')
    except Exception as e:
        return (ip, port, protocol.upper(), f'错误: {e}')
    finally:
        sock.close()

def expand_ips(ip_input):
    """
    根据输入生成 IP 地址列表，支持单个 IP、范围和子网掩码
    """
    ip_list = []
    try:
        if '-' in ip_input:
            # IP 范围，如：192.168.1.1-192.168.1.254 或 192.168.1.1-100
            start_ip_str, end_ip_str = ip_input.split('-')
            start_ip = ipaddress.IPv4Address(start_ip_str.strip())
            if '.' in end_ip_str:
                end_ip = ipaddress.IPv4Address(end_ip_str.strip())
            else:
                # 处理简写的范围，如：192.168.1.1-100
                octets = start_ip_str.strip().split('.')
                if len(octets) != 4:
                    raise ValueError("无效的起始 IP 地址")
                end_ip = ipaddress.IPv4Address('.'.join(octets[:3] + [end_ip_str.strip()]))
            if int(end_ip) < int(start_ip):
                raise ValueError("结束 IP 应该大于或等于开始 IP")
            for ip_int in range(int(start_ip), int(end_ip) + 1):
                ip_list.append(ipaddress.IPv4Address(ip_int))
        else:
            # CIDR 表示法或单个 IP
            network = ipaddress.ip_network(ip_input, strict=False)
            ip_list = list(network.hosts())
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"输入有误：{e}")
    return ip_list

def expand_ports(port_input):
    """
    根据输入生成端口列表，支持单个端口、范围和逗号分隔的列表
    """
    port_list = []
    try:
        parts = port_input.split(',')
        for part in parts:
            if '-' in part:
                # 端口范围，如：80-100
                start_port, end_port = map(int, part.split('-'))
                if end_port < start_port:
                    raise ValueError("结束端口应该大于或等于开始端口")
                port_list.extend(range(start_port, end_port + 1))
            else:
                # 单个端口
                port_list.append(int(part))
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"端口输入有误：{e}")
    return port_list

def main():
    parser = argparse.ArgumentParser(description='批量监测 TCP 和 UDP 端口状态的脚本')
    parser.add_argument('ip', metavar='IP', nargs=1, help='IP 地址、IP 范围或 CIDR 表示法')
    parser.add_argument('-p', '--ports', required=True, help='端口号，支持单个端口、范围（80-100）或逗号分隔的端口列表（80,443,8080）')
    parser.add_argument('-t', '--threads', type=int, default=100, help='使用的线程数 (默认: 100)')
    parser.add_argument('-proto', '--protocol', choices=['tcp', 'udp'], default='tcp', help='协议类型 (TCP 或 UDP，默认: TCP)')
    args = parser.parse_args()

    ip_input = args.ip[0]
    try:
        hosts = expand_ips(ip_input)
        ports = expand_ports(args.ports)
    except argparse.ArgumentTypeError as e:
        parser.error(str(e))

    print(f"\n开始扫描 {len(hosts)} 个 IP 地址的 {len(ports)} 个端口（协议: {args.protocol.upper()}）...\n")

    results = []

    # 创建任务列表
    tasks = []
    for ip in hosts:
        for port in ports:
            tasks.append((ip, port, args.protocol))

    # 执行多线程扫描
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_scan = {executor.submit(scan_port, ip, port, protocol): (ip, port) for ip, port, protocol in tasks}
        for future in as_completed(future_to_scan):
            result = future.result()
            results.append(result)

    # 按 IP 和端口排序结果
    results.sort(key=lambda x: (ipaddress.IPv4Address(x[0]), x[1]))

    # 输出结果
    print("{:<15} {:<7} {:<6} {:<}".format('IP 地址', '端口', '协议', '状态'))
    print("-" * 50)
    for res in results:
        ip, port, protocol, status = res
        print("{:<15} {:<7} {:<6} {:<}".format(str(ip), port, protocol, status))

    # 统计信息
    open_count = sum(1 for r in results if '开放' in r[3])
    closed_count = len(results) - open_count
    print("\n统计信息：")
    print(f"总共扫描端口数：{len(results)}")
    print(f"开放端口数：{open_count}")
    print(f"关闭端口数：{closed_count}")

if __name__ == '__main__':
    main()

修改要点：

• 在输出结果的 print 语句中，将 ip 变量用 str(ip) 包裹，以确保将 IPv4Address 对象转换为字符串。
print("{:<15} {:<7} {:<6} {:<}".format(str(ip), port, protocol, status))

• 在其他需要将 ip 输出或格式化的地方，也确保将其转换为字符串。例如，在 scan_port 函数中，如果有打印或日志记录 ip，也需要将其转换为字符串。（当前代码中没有其他地方需要修改）

测试结果：

使用修改后的脚本进行测试，应该能够正常运行并输出结果。例如：

$ python3 tcping.py 192.168.8.1 -p 80

开始扫描 1 个 IP 地址的 1 个端口（协议: TCP）...

IP 地址           端口      协议     状态
--------------------------------------------------
192.168.8.1       80       TCP    开放

统计信息：
总共扫描端口数：1
开放端口数：1
关闭端口数：0

总结：

• 在使用 ipaddress 模块的 IPv4Address 对象时，如果需要格式化输出，必须将其转换为字符串。
• 在较新的 Python 版本中，对 __format__ 方法的要求更加严格，需要显式地进行类型转换。
• 当遇到类似错误时，可以查看错误堆栈信息，找到出错的代码行，并检查涉及的变量类型和格式化方式。

建议：

• 为了避免类似的问题，建议在代码中养成对非字符串类型的变量在格式化输出时进行显式类型转换的习惯。
• 如果可能，尽量在开发和测试环境中使用与生产环境相同或相近的 Python 版本，避免版本差异带来的问题。

再次感谢您的耐心，如果您在使用中还有其他问题，请随时告诉我！

脚本说明：

• 功能概述： 该脚本允许您批量扫描指定 IP 地址范围内的指定端口，检测这些端口的状态（开放或关闭）。支持 TCP 和 UDP 协议。
• 主要特性：
	• 多线程扫描： 使用 ThreadPoolExecutor 来加速扫描过程，默认开启 100 个线程，可通过参数 -t 或 --threads 修改。
	• 灵活的 IP 地址输入： 支持单个 IP、IP 范围（如 192.168.1.1-192.168.1.254）、CIDR 表示法（如 192.168.1.0/24）。
	• 灵活的端口输入： 支持单个端口、端口范围（如 80-100）、逗号分隔的端口列表（如 22,80,443），以及它们的组合（如 22,80-85,443）。
	• 协议选择： 支持 TCP 和 UDP 协议，默认是 TCP，可通过参数指定协议类型。
• 使用方法：
python3 port_scanner.py IP地址选项 -p 端口选项 [其他参数]

示例：
	1. 扫描单个 IP 的多个端口（TCP 协议）：
python3 port_scanner.py 192.168.1.1 -p 22,80,443

	2. 扫描 IP 范围的特定端口（UDP 协议）：
python3 port_scanner.py 192.168.1.1-254 -p 53 -proto udp

	3. 扫描 CIDR 表示法的网络内的端口范围：
python3 port_scanner.py 192.168.1.0/24 -p 20-25

	4. 修改线程数量以加快扫描速度（注意不要过高，以免影响系统性能）：
python3 port_scanner.py 192.168.1.0/24 -p 80 -t 200

• 参数说明：
	• IP: 必须参数，指定要扫描的 IP 地址、IP 范围或网络。
	• -p, --ports: 必须参数，指定要扫描的端口，可以是单个端口、端口范围或逗号分隔的列表。
	• -t, --threads: 可选参数，指定并发线程数，默认 100。
	• -proto, --protocol: 可选参数，指定协议类型，tcp 或 udp，默认是 tcp。
• 注意事项：
	• 权限要求： 如果扫描的目标端口号小于 1024（如端口 80、443 等），可能需要以管理员或 root 权限运行脚本。
	• 网络环境： 脚本的运行结果可能会受到防火墙、路由等网络设备的影响，导致端口实际开放但被报告为关闭，或相反。
	• 合法性： 进行端口扫描可能涉及法律问题，务必确保您有权扫描目标 IP 地址范围内的主机和端口，避免非法或未经授权的扫描行为。
• 代码模块解读：
	• scan_port 函数：
	• 对于 TCP 协议，尝试连接指定 IP 和端口，如果连接成功，则端口开放，否则关闭。
	• 对于 UDP 协议，发送一个空的数据包到指定端口，观察是否有响应。由于 UDP 是无连接的协议，这种方法可能不准确。通常，如果没有响应，可能表示端口开放或被防火墙屏蔽；如果收到“端口不可达”的 ICMP 消息，则表示端口关闭。
	• 设置了超时时间为 1 秒，防止等待过久。
	• expand_ips 和 expand_ports 函数：
	• expand_ips 用于解析 IP 地址输入，支持的格式包括单个 IP、IP 范围、CIDR 表示法。
	• expand_ports 用于解析端口输入，支持单个端口、端口范围、逗号分隔的端口列表。
	• 多线程扫描：
	• 使用 ThreadPoolExecutor 创建线程池，将所有扫描任务提交到线程池中执行，提高扫描效率。
	• 结果处理和输出：
	• 将扫描结果按照 IP 地址和端口号排序，方便查看。
	• 输出包含 IP 地址、端口号、协议、端口状态的信息。
	• 提供了扫描的统计信息，包括总共扫描的端口数、开放端口数、关闭端口数。
• 运行环境：
	• Python 版本：Python 3.5 及以上（由于使用了 concurrent.futures 模块）
	• 依赖模块：标准库模块，无需安装额外的第三方库。

希望这个脚本能满足您的需求！如果您有任何问题或需要进一步的帮助，请随时提问。