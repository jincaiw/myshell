#!/Users/wang/myshell/venv/bin/python
# -*- coding: utf-8 -*-

import argparse
import ipaddress
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None  # 如果未安装 tqdm，则不显示进度条


@dataclass
class HostEntry:
    """存储原始输入和解析后的 IP 地址"""
    original: str
    ip: str


@dataclass
class PingResult:
    """存储 Ping 结果和响应时间"""
    host: HostEntry
    is_reachable: bool
    response_time: Optional[float]  # 毫秒


class PingUtility:
    """执行 ICMP Ping 操作的实用类"""

    def __init__(self, count: int, timeout: int):
        self.platform = platform.system().lower()
        self.ping_count = count
        self.ping_timeout = timeout
        self.timeout_param = "-w" if self.platform == "windows" else "-W"
        self.count_param = "-n" if self.platform == "windows" else "-c"
        self.timeout_multiplier = 1000 if self.platform == "windows" else 1

    def _build_command(self, ip: str) -> List[str]:
        """根据操作系统构建 ping 命令"""
        return [
            "ping",
            self.count_param, str(self.ping_count),
            self.timeout_param, str(self.ping_timeout * self.timeout_multiplier),
            ip
        ]

    def _parse_response_time(self, output: str) -> Optional[float]:
        """解析 ping 输出获取响应时间"""
        match = re.search(r'time[=<]\s*(\d+\.?\d*)\s*ms', output, re.IGNORECASE)
        return float(match.group(1)) if match else None

    def ping_host(self, host: HostEntry) -> PingResult:
        """Ping 单个主机并返回结果"""
        try:
            cmd = self._build_command(host.ip)
            logging.debug(f"执行命令: {' '.join(cmd)}")
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            is_reachable = result.returncode == 0
            response_time = self._parse_response_time(result.stdout) if is_reachable else None
            return PingResult(host, is_reachable, response_time)
        except FileNotFoundError:
            logging.error("Ping 命令未找到。请确保系统中已安装 ping 工具。")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Ping 失败 {host.original} ({host.ip}): {e}")
            return PingResult(host, False, None)


def configure_logging(level: str, log_file: Optional[str] = None):
    """配置日志记录"""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers
    )


def resolve_domain(domain: str) -> Optional[str]:
    """将域名解析为 IP 地址"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        logging.error(f"无法解析域名 '{domain}'。")
        return None


def expand_input(input_str: str) -> List[HostEntry]:
    """根据输入字符串生成 HostEntry 列表"""
    try:
        if '-' in input_str and '/' not in input_str:
            # IP 范围
            start_ip, end_ip = map(str.strip, input_str.split('-'))
            start = int(ipaddress.IPv4Address(start_ip))
            end = int(ipaddress.IPv4Address(end_ip))
            if end < start:
                raise ValueError("结束 IP 应大于或等于起始 IP")
            return [HostEntry(str(ipaddress.IPv4Address(ip)), str(ipaddress.IPv4Address(ip))) for ip in range(start, end + 1)]
        elif '/' in input_str:
            # CIDR 网络
            network = ipaddress.IPv4Network(input_str, strict=False)
            return [HostEntry(str(host), str(host)) for host in network.hosts()]
        elif is_valid_ipv4(input_str):
            # 单个 IP
            return [HostEntry(input_str, input_str)]
        elif is_valid_domain(input_str):
            # 域名
            ip = resolve_domain(input_str)
            return [HostEntry(input_str, ip)] if ip else []
        else:
            logging.error(f"无效的输入格式: '{input_str}'")
            return []
    except Exception as e:
        logging.error(f"扩展输入 '{input_str}' 失败: {e}")
        return []


def is_valid_ipv4(ip: str) -> bool:
    """验证是否为有效的 IPv4 地址"""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """验证是否为有效的域名"""
    if is_valid_ipv4(domain) or len(domain) > 253:
        return False
    if domain.endswith('.'):
        domain = domain[:-1]
    return all(c.isalnum() or c in "-." for c in domain)


def read_inputs(file_path: str) -> List[str]:
    """从文件读取输入"""
    if not os.path.isfile(file_path):
        logging.error(f"文件 '{file_path}' 不存在。")
        sys.exit(1)
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logging.error(f"读取文件 '{file_path}' 失败: {e}")
        sys.exit(1)


def write_results(file, results: List[PingResult]):
    """将 Ping 结果写入文件"""
    reachable = [r for r in results if r.is_reachable]
    unreachable = [r for r in results if not r.is_reachable]

    file.write(f"可达 IP 数量：{len(reachable)}\n")
    file.write(f"不可达 IP 数量：{len(unreachable)}\n\n")

    file.write("可达的 IP 地址：\n")
    for res in reachable:
        time_info = f"{res.response_time:.2f}ms" if res.response_time else "无数据"
        file.write(f"{format_display(res.host)} 可达, 响应时间: {time_info}\n")

    file.write("\n不可达的 IP 地址：\n")
    for res in unreachable:
        file.write(f"{format_display(res.host)} 不可达\n")


def format_display(host: HostEntry) -> str:
    """格式化显示 HostEntry"""
    return f"{host.original} ({host.ip})" if host.original != host.ip else host.ip


def print_results(results: List[PingResult]):
    """打印 Ping 结果"""
    reachable = [r for r in results if r.is_reachable]
    unreachable = [r for r in results if not r.is_reachable]

    print("\nPing 测试结果：")
    print("-" * 40)
    print("可达的 IP 地址：")
    for res in reachable:
        time_info = f"{res.response_time:.2f}ms" if res.response_time else "无数据"
        print(f"{format_display(res.host)} 可达, 响应时间: {time_info}")

    print("\n不可达的 IP 地址：")
    for res in unreachable:
        print(f"{format_display(res.host)} 不可达")


def print_summary(total: int, results: List[PingResult]):
    """打印测试摘要"""
    reachable = [r for r in results if r.is_reachable]
    all_times = [r.response_time for r in reachable if r.response_time is not None]
    
    print("\n统计信息：")
    print("-" * 40)
    print(f"总检测 IP 数量：{total}")
    print(f"可达 IP 数量：{len(reachable)}")
    print(f"不可达 IP 数量：{total - len(reachable)}")
    
    if all_times:
        print(f"最小响应时间：{min(all_times):.2f}ms")
        print(f"最大响应时间：{max(all_times):.2f}ms")
        print(f"平均响应时间：{sum(all_times)/len(all_times):.2f}ms")
    else:
        print("无响应时间数据。")


def parse_arguments() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='批量 ICMP Ping 脚本',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('ip', nargs='?', help='IP 地址、IP 范围、CIDR 或域名')
    group.add_argument('-f', '--file', type=str, help='包含 IP 地址或域名的文件路径')
    parser.add_argument('-t', '--threads', type=int, default=100, help='线程数')
    parser.add_argument('-c', '--count', type=int, default=1, help='Ping 请求次数')
    parser.add_argument('--timeout', type=int, default=1, help='Ping 超时时间（秒）')
    parser.add_argument('--log-level', type=str, default='INFO', help='日志级别')
    parser.add_argument('--log-file', type=str, help='日志文件路径')
    return parser.parse_args()


def main():
    """主函数，执行批量 Ping 操作"""
    args = parse_arguments()
    configure_logging(args.log_level, args.log_file)

    inputs = read_inputs(args.file) if args.file else [args.ip]
    hosts = [host for inp in inputs for host in expand_input(inp)]
    
    if not hosts:
        logging.error("没有有效的主机进行 Ping 测试。")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"ping_results_{timestamp}.txt"

    pinger = PingUtility(count=args.count, timeout=args.timeout)
    results = []

    logging.info(f"开始 Ping 测试：{len(hosts)} 个主机，{args.threads} 线程。")
    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor, \
             open(output_file, 'w', encoding='utf-8') as file:
             
            file.write("统计信息：\n")
            file.write(f"总检测 IP 数量：{len(hosts)}\n")
            file.write(f"时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            futures = {executor.submit(pinger.ping_host, host): host for host in hosts}
            progress = tqdm(total=len(futures), desc="Ping 进度", unit="host") if tqdm else None

            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if progress:
                    progress.update(1)

            if progress:
                progress.close()

            write_results(file, results)

    except KeyboardInterrupt:
        logging.warning("用户中断操作。")
        sys.exit(1)
    except Exception as e:
        logging.error(f"执行 Ping 测试时发生错误: {e}")
        sys.exit(1)

    elapsed = time.time() - start_time
    print_results(results)
    print_summary(len(hosts), results)

    logging.info(f"Ping 测试完成，用时 {elapsed:.2f} 秒。结果保存在 '{output_file}'。")


if __name__ == '__main__':
    main()