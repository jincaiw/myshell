当然，这里是一个完整、优化并详细注释的 Python 脚本，用于监测网站的状态并将结果记录到日志文件中。这个脚本不仅满足您的需求，还包括一些最佳实践和优化，如日志轮转、多线程支持等。

### 功能概述

1. **加载 YAML 配置文件**：从指定的 `urls.yaml` 文件加载网站分组和 URL 列表。
2. **监测 URL 状态**：使用 `requests` 库发送 HTTP 请求，获取每个 URL 的状态码、响应时间等信息。
3. **记录日志**：使用 `logging` 模块将监测结果记录到日志文件中，并实现日志文件的按时间轮转（例如，每天一个日志文件，保留最近 7 天的日志）。
4. **多线程并发**：使用 `concurrent.futures.ThreadPoolExecutor` 实现多线程监测，提高监测效率。
5. **错误处理**：全面捕获和处理可能的异常，确保脚本的稳定性。

### 完整代码

```python
import requests
import time
import yaml
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_url_status(name, url, timeout=5):
    """
    检查 URL 的状态

    参数:
    name (str): 网站名称
    url (str): 要检查的 URL
    timeout (int): 请求超时时间（秒）

    返回:
    dict: 包含 URL 状态信息的字典
    """
    start_time = time.time()
    try:
        response = requests.get(url, timeout=timeout)
        elapsed_time = time.time() - start_time
        result = {
            'name': name,
            'url': url,
            'status_code': response.status_code,
            'reason': response.reason,
            'elapsed_time': round(elapsed_time, 2)
        }
        return result
    except requests.exceptions.Timeout:
        return {'name': name, 'url': url, 'status_code': None, 'reason': '请求超时', 'elapsed_time': None}
    except requests.exceptions.ConnectionError:
        return {'name': name, 'url': url, 'status_code': None, 'reason': '无法连接', 'elapsed_time': None}
    except requests.exceptions.RequestException as e:
        return {'name': name, 'url': url, 'status_code': None, 'reason': str(e), 'elapsed_time': None}

def load_yaml_data(file_path):
    """
    从 YAML 文件加载数据

    参数:
    file_path (str): YAML 文件的路径

    返回:
    dict: 解析后的 YAML 数据
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logging.error(f"文件 {file_path} 未找到")
    except yaml.YAMLError as e:
        logging.error(f"解析 YAML 文件 {file_path} 时出错: {e}")
    return {}

def load_groups_from_yaml(file_path):
    """
    从 YAML 文件加载分组列表

    参数:
    file_path (str): YAML 文件的路径

    返回:
    list: 分组列表
    """
    data = load_yaml_data(file_path)
    return data.get('groups', [])

def setup_logger(log_file_path):
    """
    配置日志记录器

    参数:
    log_file_path (str): 日志文件的路径
    """
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # 创建日志目录（如果不存在）
    log_dir = os.path.dirname(log_file_path)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # 创建定时轮转文件处理器（每天轮转一次，保留7天的日志）
    file_handler = TimedRotatingFileHandler(
        log_file_path,
        when='midnight',
        interval=1,
        backupCount=7,
        encoding='utf-8',
        delay=False,
        utc=False
    )
    file_handler.setLevel(logging.INFO)

    # 创建控制台处理器（可选）
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # 创建日志格式
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # 添加处理器到记录器
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

def print_and_log(message, level='info', group_name=None):
    """
    同时打印和记录日志消息

    参数:
    message (str): 消息内容
    level (str): 日志级别（'info' 或 'error'）
    group_name (str): 分组名称（用于日志记录）
    """
    if level == 'info':
        logging.info(f"{group_name} - {message}" if group_name else message)
    elif level == 'error':
        logging.error(f"{group_name} - {message}" if group_name else message)
    print(message)

def monitor_site(group_name, site):
    """
    监测单个网站并记录结果

    参数:
    group_name (str): 分组名称
    site (dict): 网站信息字典
    """
    name = site.get('name', '未命名网站')
    url = site.get('url')
    if not url:
        error_message = f"[错误] 网站: {name} - URL 未提供"
        print_and_log(error_message, level='error', group_name=group_name)
        return

    result = check_url_status(name, url)

    if result['status_code'] is None:
        message = f"[错误] 网站: {result['name']} - URL: {result['url']} - 原因: {result['reason']}"
        print_and_log(message, level='error', group_name=group_name)
    else:
        message = (f"[成功] 网站: {result['name']} - URL: {result['url']} - 状态码: {result['status_code']} - "
                   f"原因: {result['reason']} - 用时: {result['elapsed_time']} 秒")
        print_and_log(message, level='info', group_name=group_name)

def main():
    """
    主函数，用于加载配置、设置日志、并发监测网站
    """
    yaml_file_path = 'urls.yaml'       # 存放分组网站列表的 YAML 文件路径
    log_file_path = 'logs/monitor_results.log'  # 日志文件路径

    # 配置日志记录器
    setup_logger(log_file_path)

    # 加载分组和网站信息
    groups = load_groups_from_yaml(yaml_file_path)

    if not groups:
        logging.error("没有加载到任何分组信息。请检查 YAML 配置文件。")
        return

    # 使用 ThreadPoolExecutor 实现多线程监测，提高效率
    max_workers = min(32, os.cpu_count() + 4)  # 线程数量策略
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_site = {}
        for group in groups:
            group_name = group.get('name', '未命名分组')
            header_message = f"\n=== 分组: {group_name} ==="
            print_and_log(header_message, level='info', group_name=None)
            sites = group.get('sites', [])
            for site in sites:
                future = executor.submit(monitor_site, group_name, site)
                future_to_site[future] = site

        # 可选：等待所有任务完成，并处理可能的异常
        for future in as_completed(future_to_site):
            try:
                future.result()
            except Exception as e:
                site = future_to_site[future]
                name = site.get('name', '未命名网站')
                url = site.get('url', 'URL 未提供')
                error_message = f"[异常] 网站: {name} - URL: {url} - 异常: {str(e)}"
                logging.error(error_message)
                print(error_message)

if __name__ == '__main__':
    main()
```

### 详细说明

#### 1. 导入必要的模块

```python
import requests
import time
import yaml
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
```

- **requests**：用于发送 HTTP 请求。
- **time**：用于计算响应时间。
- **yaml**：用于解析 YAML 配置文件。
- **logging** 和 **TimedRotatingFileHandler**：用于日志记录和日志轮转。
- **concurrent.futures**：用于实现多线程监测，提高效率。

#### 2. 定义函数 `check_url_status`

此函数用于检查单个 URL 的状态，并返回一个包含相关信息的字典。

```python
def check_url_status(name, url, timeout=5):
    # ...（如上所示）
```

#### 3. 定义函数 `load_yaml_data` 和 `load_groups_from_yaml`

这两个函数用于加载和解析 YAML 配置文件，获取网站分组和 URL 列表。

```python
def load_yaml_data(file_path):
    # ...（如上所示）

def load_groups_from_yaml(file_path):
    # ...（如上所示）
```

#### 4. 配置日志记录器

使用 `logging` 模块和 `TimedRotatingFileHandler` 实现按时间（每天）轮转日志文件，保留最近 7 天的日志。

```python
def setup_logger(log_file_path):
    # ...（如上所示）
```

- **日志目录创建**：如果日志目录不存在，创建它。
- **日志轮转**：每天生成一个新的日志文件，保留最近 7 天的日志。
- **日志格式**：包括时间戳、日志级别和消息内容。
- **控制台输出**：日志同时输出到控制台和文件。

#### 5. 定义辅助函数 `print_and_log`

此函数用于同时在控制台打印消息并记录到日志文件中，简化代码重复。

```python
def print_and_log(message, level='info', group_name=None):
    # ...（如上所示）
```

- **level**：指定日志级别，可以是 `'info'` 或 `'error'`。
- **group_name**：可选参数，用于在日志中标识分组名称。

#### 6. 定义函数 `monitor_site`

此函数负责监测单个网站，并根据监测结果记录日志和打印输出。

```python
def monitor_site(group_name, site):
    # ...（如上所示）
```

- **错误处理**：检查 URL 是否提供，如果未提供，记录错误并跳过。
- **监测结果处理**：根据响应结果，记录成功或错误的信息。

#### 7. 定义主函数 `main`

主函数负责加载配置、设置日志记录器，并使用多线程并发地监测所有网站。

```python
def main():
    # ...（如上所示）
```

- **配置文件路径**：指定 YAML 配置文件和日志文件的路径。
- **加载分组和网站信息**：调用 `load_groups_from_yaml`。
- **多线程监测**：使用 `ThreadPoolExecutor` 提高监测效率，适用于网站数量较多的情况。
- **异常处理**：捕获并记录任何在监测过程中出现的异常，确保脚本的鲁棒性。

#### 8. 运行脚本

```python
if __name__ == '__main__':
    main()
```

### 示例 `urls.yaml` 文件

确保在脚本所在目录下有一个 `urls.yaml` 文件，内容示例：

```yaml
groups:
  - name: "生产环境"
    sites:
      - name: "示例网站"
        url: "http://example.com"
      - name: "另一个生产网站"
        url: "http://prod.example.com"

  - name: "测试环境"
    sites:
      - name: "测试网站1"
        url: "http://test1.example.com"
      - name: "测试网站2"
        url: "http://test2.example.com"

  - name: "区域性网站"
    sites:
      - name: "亚洲网站"
        url: "http://asia.example.com"
      - name: "欧洲网站"
        url: "http://europe.example.com"
```

### 运行脚本

确保安装了所需的 Python 库：

```bash
pip install requests pyyaml
```

运行脚本：

```bash
python monitor.py
```

### 日志文件示例

运行脚本后，会在 `logs` 目录下生成类似 `monitor_results.log` 的日志文件，其中内容如下：

```
2024-04-27 10:00:00,123 - INFO - 
=== 分组: 生产环境 ===
2024-04-27 10:00:00,456 - INFO - 生产环境 - [成功] 网站: 示例网站 - URL: http://example.com - 状态码: 200 - 原因: OK - 用时: 0.32 秒
2024-04-27 10:00:00,789 - INFO - 生产环境 - [成功] 网站: 另一个生产网站 - URL: http://prod.example.com - 状态码: 200 - 原因: OK - 用时: 0.45 秒

2024-04-27 10:00:01,123 - INFO - 
=== 分组: 测试环境 ===
2024-04-27 10:00:01,456 - INFO - 测试环境 - [成功] 网站: 测试网站1 - URL: http://test1.example.com - 状态码: 200 - 原因: OK - 用时: 0.30 秒
2024-04-27 10:00:01,789 - ERROR - 测试环境 - [错误] 网站: 测试网站2 - URL: http://test2.example.com - 原因: 请求超时

2024-04-27 10:00:02,123 - INFO - 
=== 分组: 区域性网站 ===
2024-04-27 10:00:02,456 - INFO - 区域性网站 - [成功] 网站: 亚洲网站 - URL: http://asia.example.com - 状态码: 200 - 原因: OK - 用时: 0.50 秒
2024-04-27 10:00:02,789 - INFO - 区域性网站 - [成功] 网站: 欧洲网站 - URL: http://europe.example.com - 状态码: 200 - 原因: OK - 用时: 0.60 秒
```

### 进一步优化建议

1. **配置文件路径参数化**：
   - 允许通过命令行参数指定 YAML 配置文件和日志文件路径，增加灵活性。

2. **通知系统集成**：
   - 在监测到错误时，集成邮件通知、Slack 消息等实时通知机制。

3. **更多监测指标**：
   - 除了状态码和响应时间，可以添加更多指标，如内容关键字检查、SSL 证书有效期监测等。

4. **容错机制**：
   - 例如，在网络异常或临时故障时，自动重试几次。

5. **报告生成**：
   - 定期生成监测报告，汇总过去一段时间的监测结果。

6. **配置文件验证**：
   - 在加载 YAML 配置文件时，增加验证步骤，确保配置文件的格式和内容正确。

7. **使用异步编程**：
   - 对于极大规模的 URL 列表，可以考虑使用 `asyncio` 和 `aiohttp` 实现异步监测，以进一步提升性能。

### 结论

通过上述完整代码，您可以高效地监测多个网站的状态，并将结果详细记录到日志文件中。脚本采用多线程并发，提高监测速度，并使用日志轮转机制，确保日志文件的可管理性和持久性。根据实际需求，您可以进一步扩展和优化该脚本，以满足更多高级功能。

如有任何进一步的问题或需要更多功能扩展，欢迎随时咨询！