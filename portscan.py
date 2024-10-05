import socket
import ipaddress
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Union
from tqdm import tqdm


def resolve_domain(domain: str) -> List[str]:
    """
    解析域名并返回 IP 地址列表。
    """
    try:
        return [str(ip) for ip in ipaddress.ip_address_list(domain)]
    except socket.gaierror as e:
        print(f"解析域名 {domain} 时出错：{e}")
        return []


def scan_port(ip: str, port: int, protocol: str) -> Tuple[str, int, str, str]:
    """
    扫描单个 IP 地址上的指定端口，返回端口状态。
    """
    try:
        with socket.socket(socket.AF_INET, protocol == 'tcp' and socket.SOCK_STREAM or socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            if protocol == 'tcp':
                result = sock.connect_ex((ip, port))
                status = '开放' if result == 0 else '关闭'
            else:
                data, _ = sock.recvfrom(1024)
                status = '开放' if data else '关闭'
    except Exception as e:
        return ip, port, protocol.upper(), f"错误: {e}"

    return ip, port, protocol.upper(), status


def expand_ips(ip_input: str) -> List[str]:
    """
    根据输入生成 IP 地址列表，支持单个 IP、范围和子网掩码。
    """
    try:
        if '-' in ip_input:
            start_ip, end_ip = ip_input.split('-')
            start_ip = ipaddress.ip_address(start_ip)
            end_ip = ipaddress.ip_address(end_ip)
            return [str(ip) for ip in ipaddress.ip_range(start_ip, end_ip)]
        else:
            return [str(ip) for ip in ipaddress.ip_network(ip_input, strict=False).hosts()]
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"输入有误：{e}")


def expand_ports(port_input: str) -> List[int]:
    """
    根据输入生成端口列表，支持单个端口、范围和逗号分隔的列表。
    """
    ports = []
    try:
        parts = port_input.split(',')
        for part in parts:
            if '-' in part:
                start_port, end_port = map(int, part.split('-'))
                ports.extend(range(start_port, end_port + 1))
            else:
                port = int(part)
                ports.append(port)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"端口输入有误：{e}")

    return sorted(ports)


def parse_arguments() -> argparse.Namespace:
    """
    解析命令行参数。
    """
    parser = argparse.ArgumentParser(description='批量监测 TCP 和 UDP 端口状态的脚本')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('host', metavar='HOST', nargs='?', help='域名或 IP 地址、IP 范围或 CIDR 表示法')
    group.add_argument('-f', '--file', help='主机文件，文件中每行一个主机
