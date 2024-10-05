
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ipaddress
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Union
from tqdm import tqdm  # 引入 tqdm 进行进度条显示


def resolve_domain(domain: str) -> List[str]:
    """
    解析域名并返回 IP 地址列表。

    Args:
        domain (str): 需要解析的域名。

    Returns:
        List[str]: 解析得到的 IP 地址列表，如果解析失败返回空列表。
    """
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        return ip_list
    except socket.gaierror as e:
        print(f"解析域名 {domain} 时出错：{e}")
        return []


def scan_port(ip: str, port: int, protocol: str) -> Tuple[str, int, str, str]:
    """
    扫描单个 IP 地址上的指定端口，返回端口状态。

    Args:
        ip (str): 目标 IP 地址。
        port (int): 目标端口号。
        protocol (str): 协议类型，'tcp' 或 'udp'。

    Returns:
        Tuple[str, int, str, str]: 包含 IP 地址、端口号、协议类型及状态的元组。
    """
    protocol = protocol.lower()
    status = '未知'
    try:
        if protocol == 'tcp':
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                status = '开放' if result == 0 else '关闭'
        elif protocol == 'udp':
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)  # 增加 UDP 的超时
                try:
                    # 发送空数据包
                    sock.sendto(b'', (ip, port))
                    # 尝试接收响应
                    data, _ = sock.recvfrom(1024)
                    status = '开放'
                except socket.timeout:
                    # 没有收到响应，可能是开放或被屏蔽
                    status = '开放或被屏蔽'
                except socket.error as e:
                    if e.errno == socket.errno.ECONNREFUSED:
                        status = '关闭'
                    else:
                        status = f'错误: {e}'
        else:
            status = '未知协议'
    except Exception as e:
        status = f'错误: {e}'
    return (ip, port, protocol.upper(), status)


def expand_ips(ip_input: str) -> List[str]:
    """
    根据输入生成 IP 地址列表，支持单个 IP、范围和子网掩码。

    Args:
        ip_input (str): 用户输入的 IP 地址、IP 范围或 CIDR 表示法。

    Returns:
        List[str]: 展开的 IP 地址列表。

    Raises:
        argparse.ArgumentTypeError: 如果输入格式不正确。
    """
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
            ip_list = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]
        else:
            network = ipaddress.ip_network(ip_input, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"输入有误：{e}")
    return ip_list


def expand_ports(port_input: str) -> List[int]:
    """
    根据输入生成端口列表，支持单个端口、范围和逗号分隔的列表。

    Args:
        port_input (str): 用户输入的端口号、范围或列表。

    Returns:
        List[int]: 展开的端口号列表。

    Raises:
        argparse.ArgumentTypeError: 如果输入格式不正确或端口号超出范围。
    """
    port_set = set()
    try:
        parts = port_input.split(',')
        for part in parts:
            if '-' in part:
                start_port, end_port = map(int, part.split('-'))
                if end_port < start_port or not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                    raise ValueError("端口范围应在1-65535之间，且结束端口应大于或等于开始端口")
                port_set.update(range(start_port, end_port + 1))
            else:
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValueError(f"端口 {port} 不在有效范围 1-65535")
                port_set.add(port)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"端口输入有误：{e}")
    return sorted(port_set)


def parse_arguments() -> argparse.Namespace:
    """
    解析命令行参数。

    Returns:
        argparse.Namespace: 解析后的命令行参数。
    """
    parser = argparse.ArgumentParser(description='批量监测 TCP 和 UDP 端口状态的脚本')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('host', metavar='HOST', nargs='?', help='域名或 IP 地址、IP 范围或 CIDR 表示法')
    group.add_argument('-f', '--file', help='主机文件，文件中每行一个主机（域名或 IP）')
    
    parser.add_argument('-p', '--ports', required=True, help='端口号，支持单个端口、范围（80-100）或逗号分隔的端口列表（80,443,8080）')
    parser.add_argument('-t', '--threads', type=int, default=100, help='使用的线程数 (默认: 100)')
    parser.add_argument('--type', choices=['tcp', 'udp'], default='tcp', help='协议类型 (TCP 或 UDP，默认: TCP)')
    
    return parser.parse_args()


def load_hosts_from_file(file_path: str) -> List[str]:
    """
    从文件中加载主机列表，文件中每行一个主机。

    Args:
        file_path (str): 文件路径。

    Returns:
        List[str]: 主机列表。

    Raises:
        argparse.ArgumentTypeError: 如果文件无法读取。
    """
    try:
        with open(file_path, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
        if not hosts:
            raise argparse.ArgumentTypeError(f"文件 {file_path} 是空的或没有有效的主机。")
        return hosts
    except Exception as e:
        raise argparse.ArgumentTypeError(f"无法读取文件 {file_path}：{e}")


def process_hosts_list(hosts_raw: List[str]) -> List[str]:
    """
    处理主机列表，解析域名为 IP 地址，扩展 IP 范围和 CIDR。

    Args:
        hosts_raw (List[str]): 原始主机列表。

    Returns:
        List[str]: 处理后的 IP 地址列表。
    """
    processed_hosts = []
    for entry in hosts_raw:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if '-' in entry or '/' in entry:
                # 处理 IP 范围或 CIDR
                expanded_ips = expand_ips(entry)
                processed_hosts.extend(expanded_ips)
            else:
                # 处理单个 IP 或域名
                try:
                    ipaddress.IPv4Address(entry)
                    processed_hosts.append(entry)
                except ipaddress.AddressValueError:
                    # 可能是域名，尝试解析
                    resolved_ips = resolve_domain(entry)
                    if resolved_ips:
                        processed_hosts.extend(resolved_ips)
                    else:
                        print(f"无法解析主机：{entry}")
        except argparse.ArgumentTypeError as e:
            print(f"处理主机 {entry} 时出错：{e}")
    # 去除重复的 IP 地址并排序
    processed_hosts = sorted(set(processed_hosts), key=lambda ip: ipaddress.IPv4Address(ip))
    return processed_hosts


def main():
    args = parse_arguments()

    # 获取主机列表
    hosts: List[str] = []
    if args.file:
        try:
            hosts_raw = load_hosts_from_file(args.file)
            hosts = process_hosts_list(hosts_raw)
        except argparse.ArgumentTypeError as e:
            print(e)
            sys.exit(1)
    elif args.host:
        try:
            if '-' in args.host or '/' in args.host:
                # 处理 IP 范围或 CIDR
                hosts = expand_ips(args.host)
            else:
                # 尝试将其作为单个 IP，如果失败则作为域名
                try:
                    ipaddress.IPv4Address(args.host)
                    hosts = [args.host]
                except ipaddress.AddressValueError:
                    resolved = resolve_domain(args.host)
                    if not resolved:
                        print(f"无法解析域名或找到有效的 IP 地址：{args.host}")
                        sys.exit(1)
                    hosts = resolved
        except argparse.ArgumentTypeError as e:
            print(e)
            sys.exit(1)

    if not hosts:
        print("未找到任何有效的 IP 地址供扫描。")
        sys.exit(1)

    # 解析端口输入
    try:
        ports = expand_ports(args.ports)
    except argparse.ArgumentTypeError as e:
        print(e)
        sys.exit(1)

    total_tasks = len(hosts) * len(ports)
    print(f"\n开始扫描 {len(hosts)} 个主机的 {len(ports)} 个端口（协议: {args.type.upper()}）...\n")

    results: List[Tuple[str, int, str, str]] = []
    tasks = [(ip, port, args.type) for ip in hosts for port in ports]

    # 初始化进度条
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, ip, port, protocol): (ip, port)
                   for ip, port, protocol in tasks}
        with tqdm(total=total_tasks, desc="扫描进度", unit="个") as pbar:
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                pbar.update(1)

    # 按 IP 和端口排序结果
    try:
        results.sort(key=lambda x: (ipaddress.IPv4Address(x[0]), x[1]))
    except ipaddress.AddressValueError as e:
        print(f"排序时出错：{e}")
        sys.exit(1)

    # 输出结果
    header = f"{'IP 地址':<15} {'端口':<7} {'协议':<6} {'状态'}"
    print("\n" + header)
    print("-" * len(header))
    for ip, port, protocol, status in results:
        print(f"{ip:<15} {port:<7} {protocol:<6} {status}")

    # 统计信息
    open_count = sum(1 for _, _, _, status in results if '开放' in status)
    closed_count = sum(1 for _, _, _, status in results if '关闭' in status)
    filtered_count = sum(1 for _, _, _, status in results if '开放或被屏蔽' in status)
    error_count = sum(1 for _, _, _, status in results if status.startswith('错误'))
    
    print("\n统计信息：")
    print(f"总共扫描端口数：{len(results)}")
    print(f"开放端口数：{open_count}")
    print(f"关闭端口数：{closed_count}")
    print(f"开放或被屏蔽端口数：{filtered_count}")
    if error_count > 0:
        print(f"错误端口数：{error_count}")


if __name__ == '__main__':
    main()