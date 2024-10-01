#!/usr/local/bin/python3
# -*- coding: utf-8 -*-

import subprocess
import platform
import ipaddress
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def ping(host):
    """
    Ping 单个主机，返回主机和是否可达的布尔值
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    # 设置每次请求的等待超时时间，Windows 使用 '-w'，Linux/Unix 使用 '-W'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    command = ['ping', param, '1', timeout_param, '1', str(host)]
    result = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return str(host), result == 0  # 返回 (IP, 是否可达)

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

def main():
    parser = argparse.ArgumentParser(description='批量 ping IP 地址脚本')
    parser.add_argument('ip', metavar='IP', nargs=1, help='IP 地址、IP 范围或 CIDR 表示法')
    parser.add_argument('-t', '--threads', type=int, default=100, help='使用的线程数 (默认: 100)')
    args = parser.parse_args()

    ip_input = args.ip[0]
    try:
        hosts = expand_ips(ip_input)
    except argparse.ArgumentTypeError as e:
        parser.error(str(e))

    reachable_ips = []
    unreachable_ips = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_host = {executor.submit(ping, host): host for host in hosts}
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                ip, is_reachable = future.result()
                if is_reachable:
                    reachable_ips.append(ip)
                else:
                    unreachable_ips.append(ip)
            except Exception as e:
                print(f"Ping {host} 时发生异常：{e}")
                unreachable_ips.append(str(host))

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