#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import socket
import ipaddress
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def resolve_domain(domain):
    """解析域名并返回 IP 地址列表"""
    try:
        ip_list = socket.gethostbyname_ex(domain)[2]
        return ip_list
    except Exception as e:
        print(f"解析域名 {domain} 时出错：{e}")
        return []

def scan_port(ip, port, protocol):
    """扫描单个 IP 地址上的指定端口，返回端口状态"""
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
            return (ip, port, 'TCP', '开放' if result == 0 else '关闭')
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
    """根据输入生成 IP 地址列表，支持单个 IP、范围和子网掩码"""
    ip_list = []
    try:
        if '-' in ip_input:
            start_ip_str, end_ip_str = ip_input.split('-')
            start_ip = ipaddress.IPv4Address(start_ip_str.strip())
            if '.' in end_ip_str:
                end_ip = ipaddress.IPv4Address(end_ip_str.strip())
            else:
                octets = start_ip_str.strip().split('.')
                end_ip = ipaddress.IPv4Address('.'.join(octets[:3] + [end_ip_str.strip()]))
            if int(end_ip) < int(start_ip):
                raise ValueError("结束 IP 应该大于或等于开始 IP")
            ip_list.extend(ipaddress.IPv4Address(ip_int) for ip_int in range(int(start_ip), int(end_ip) + 1))
        else:
            network = ipaddress.ip_network(ip_input, strict=False)
            ip_list = list(network.hosts())
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"输入有误：{e}")
    return ip_list

def expand_ports(port_input):
    """根据输入生成端口列表，支持单个端口、范围和逗号分隔的列表"""
    port_list = []
    try:
        parts = port_input.split(',')
        for part in parts:
            if '-' in part:
                start_port, end_port = map(int, part.split('-'))
                if end_port < start_port:
                    raise ValueError("结束端口应该大于或等于开始端口")
                port_list.extend(range(start_port, end_port + 1))
            else:
                port_list.append(int(part))
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"端口输入有误：{e}")
    return port_list

def main():
    parser = argparse.ArgumentParser(description='批量监测 TCP 和 UDP 端口状态的脚本')
    parser.add_argument('host', metavar='HOST', nargs=1, help='域名或 IP 地址、IP 范围或 CIDR 表示法')
    parser.add_argument('-p', '--ports', required=True, help='端口号，支持单个端口、范围（80-100）或逗号分隔的端口列表（80,443,8080）')
    parser.add_argument('-t', '--threads', type=int, default=100, help='使用的线程数 (默认: 100)')
    parser.add_argument('-proto', '--protocol', choices=['tcp', 'udp'], default='tcp', help='协议类型 (TCP 或 UDP，默认: UDP)')  # 修改默认协议为 UDP
    args = parser.parse_args()

    host_input = args.host[0]
    if host_input.count('.') == 3:  # 检查是否为 IPv4 地址格式
        try:
            hosts = [ipaddress.IPv4Address(host_input)]
        except ValueError:
            parser.error("无效的 IP 地址")
    else:  # 认为是域名
        hosts = resolve_domain(host_input)

    # 检查分辨出的 IP 地址是否有效
    if not hosts:
        sys.exit("无法解析域名或找到有效的 IP 地址。")

    try:
        ports = expand_ports(args.ports)
    except argparse.ArgumentTypeError as e:
        parser.error(str(e))

    print(f"\n开始扫描 {len(hosts)} 个 IP 地址的 {len(ports)} 个端口（协议: {args.protocol.upper()}）...\n")

    results = []
    tasks = [(ip, port, args.protocol) for ip in hosts for port in ports]

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