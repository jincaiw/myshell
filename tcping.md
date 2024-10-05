根据您的要求，对之前提供的端口扫描脚本进行了进一步的优化和修改。具体更改包括：

1. **修改协议参数名称**：将命令行参数从 `--proto` 修改为 `--type`。
2. **修改默认协议**：将默认协议从 `UDP` 修改为 `TCP`。
3. **支持从文件读取主机**：新增 `--file`（或 `-f`）选项，允许用户从文件中读取主机列表。

以下是修改后的完整代码及相关说明。

---

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ipaddress
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Union


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
                sock.settimeout(1)
                sock.sendto(b'', (ip, port))
                try:
                    sock.recvfrom(1024)
                    status = '开放'
                except socket.timeout:
                    status = '开放或被屏蔽'
                except socket.error:
                    status = '关闭'
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


def main():
    args = parse_arguments()

    # 获取主机列表
    hosts: List[str] = []
    if args.file:
        try:
            hosts = load_hosts_from_file(args.file)
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

    print(f"\n开始扫描 {len(hosts)} 个主机的 {len(ports)} 个端口（协议: {args.type.upper()}）...\n")

    results: List[Tuple[str, int, str, str]] = []
    tasks = [(ip, port, args.type) for ip in hosts for port in ports]

    # 执行多线程扫描
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_scan = {executor.submit(scan_port, ip, port, protocol): (ip, port)
                         for ip, port, protocol in tasks}
        for future in as_completed(future_to_scan):
            result = future.result()
            results.append(result)

    # 按 IP 和端口排序结果
    results.sort(key=lambda x: (ipaddress.IPv4Address(x[0]), x[1]))

    # 输出结果
    header = f"{'IP 地址':<15} {'端口':<7} {'协议':<6} {'状态'}"
    print(header)
    print("-" * len(header))
    for ip, port, protocol, status in results:
        print(f"{ip:<15} {port:<7} {protocol:<6} {status}")

    # 统计信息
    open_count = sum(1 for _, _, _, status in results if '开放' in status)
    closed_count = len(results) - open_count
    print("\n统计信息：")
    print(f"总共扫描端口数：{len(results)}")
    print(f"开放端口数：{open_count}")
    print(f"关闭端口数：{closed_count}")


if __name__ == '__main__':
    main()
```

---

## 改进说明

### 1. 协议参数修改

- **参数名称**：将协议类型的命令行参数从 `--proto` 修改为 `--type`，以符合您的需求。
- **默认协议**：将默认协议由 `UDP` 修改为 `TCP`，即当用户未指定协议时，脚本默认使用 `TCP` 进行端口扫描。

```python
parser.add_argument('--type', choices=['tcp', 'udp'], default='tcp', help='协议类型 (TCP 或 UDP，默认: TCP)')
```

### 2. 支持从文件读取主机

- **新增参数**：引入 `--file`（或 `-f`）选项，允许用户从指定文件中读取主机列表。文件中每行一个主机，可以是域名或 IP 地址。
- **互斥参数组**：使用 `argparse` 的互斥参数组 `mutually_exclusive_group`，确保用户只能通过命令行指定单个主机或通过文件指定多个主机，不能同时使用两者。

```python
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('host', metavar='HOST', nargs='?', help='域名或 IP 地址、IP 范围或 CIDR 表示法')
group.add_argument('-f', '--file', help='主机文件，文件中每行一个主机（域名或 IP）')
```

- **读取文件逻辑**：新增 `load_hosts_from_file` 函数，从指定文件中读取主机列表，过滤空行并返回主机列表。

```python
def load_hosts_from_file(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
        if not hosts:
            raise argparse.ArgumentTypeError(f"文件 {file_path} 是空的或没有有效的主机。")
        return hosts
    except Exception as e:
        raise argparse.ArgumentTypeError(f"无法读取文件 {file_path}：{e}")
```

- **主机列表获取**：在 `main` 函数中，根据用户是否指定 `--file` 来获取主机列表。如果指定了文件，则从文件中读取，否则按照原有逻辑处理单个主机或主机范围。

### 3. 其他优化

- **类型提示**：继续使用类型提示，增强代码的可读性和可维护性。
- **文档字符串**：为新增的函数添加了详细的文档字符串，符合 Python 的文档规范。
- **错误处理**：在读取文件和解析主机、端口时，提供了详细的错误信息，帮助用户快速定位问题。
- **代码规范**：保持代码遵循 PEP8 规范，包括适当的缩进、空行和变量命名。
- **上下文管理器**：在 `scan_port` 函数中，使用 `with` 语句管理套接字的创建和关闭，确保资源的正确释放。

## 使用说明

### 1. 保存脚本

将上述代码保存为 `port_scanner.py`。

### 2. 给予执行权限（如果在类 Unix 系统上运行）

```bash
chmod +x port_scanner.py
```

### 3. 运行脚本

#### 通过命令行指定主机

- **扫描单个 IP 的 80 和 443 端口（默认协议 TCP）**：

    ```bash
    ./port_scanner.py 192.168.1.1 -p 80,443
    ```

- **扫描域名的 1-100 端口，使用 200 个线程，协议为 TCP**：

    ```bash
    ./port_scanner.py example.com -p 1-100 -t 200 --type tcp
    ```

- **扫描 192.168.1.1 到 192.168.1.255 的所有主机的 22 端口，协议为 UDP**：

    ```bash
    ./port_scanner.py 192.168.1.1-255 -p 22 --type udp
    ```

- **扫描 CIDR 范围内的主机的多个端口**：

    ```bash
    ./port_scanner.py 192.168.1.0/24 -p 80,443,8080
    ```

#### 通过文件指定主机列表

- **准备主机文件**：创建一个文本文件（例如 `hosts.txt`），每行一个主机，可以是域名或 IP 地址。例如：

    ```
    example.com
    192.168.1.1
    192.168.1.100-192.168.1.200
    10.0.0.0/24
    ```

- **运行脚本**：

    ```bash
    ./port_scanner.py -f hosts.txt -p 80,443,22 --type tcp
    ```

### 4. 参数说明

- `HOST`: 域名或 IP 地址、IP 范围或 CIDR 表示法。如果使用 `--file` 选项，则无需指定 `HOST`。
- `-f`, `--file`: 指定主机文件，文件中每行一个主机（域名或 IP）。
- `-p`, `--ports`: 端口号，支持单个端口、范围（如 `80-100`）或逗号分隔的端口列表（如 `80,443,8080`）。
- `-t`, `--threads`: 使用的线程数（默认: 100）。
- `--type`: 协议类型，选择 `tcp` 或 `udp`（默认: `tcp`）。

## 注意事项

- **UDP 扫描的局限性**：UDP 协议的无连接性使得判定端口状态较为复杂，很多开放的 UDP 端口可能不会响应，导致结果显示为“开放或被屏蔽”。这种情况下，更加深入的 UDP 扫描可能需要其他工具或方法。
  
- **权限问题**：某些端口的扫描可能需要管理员权限，尤其是低号码端口。
  
- **网络环境**：确保在合法授权的情况下进行端口扫描，避免违反相关法规和伦理规范。

## 总结

通过此次修改，脚本不仅支持通过文件批量读取主机列表，还对协议参数进行了调整，使其更符合用户需求。此外，保持了代码的可读性、可维护性和扩展性，同时增强了错误处理和用户友好性。希望这些改进能更好地满足您的需求。