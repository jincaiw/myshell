
import requests
import time
import yaml
import logging
from logging.handlers import TimedRotatingFileHandler
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
    配置日志记录器，使控制台和日志文件内容一致

    参数:
    log_file_path (str): 日志文件的路径
    """
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # 清除已有的处理器，避免重复记录
    if logger.hasHandlers():
        logger.handlers.clear()

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

    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # 创建日志格式
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # 添加处理器到记录器
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

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
        logging.error(f"{group_name} - {error_message}")
        return

    result = check_url_status(name, url)

    if result['status_code'] is None:
        message = f"[错误] 网站: {result['name']} - URL: {result['url']} - 原因: {result['reason']}"
        logging.error(f"{group_name} - {message}")
    else:
        message = (f"[成功] 网站: {result['name']} - URL: {result['url']} - 状态码: {result['status_code']} - "
                   f"原因: {result['reason']} - 用时: {result['elapsed_time']} 秒")
        logging.info(f"{group_name} - {message}")

def main():
    """
    主函数，用于加载配置、设置日志、并发监测网站
    """
    yaml_file_path = 'urls.yaml'             # 存放分组网站列表的 YAML 文件路径
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
            logging.info(header_message)  # 记录分组信息
            sites = group.get('sites', [])
            for site in sites:
                future = executor.submit(monitor_site, group_name, site)
                future_to_site[future] = site

        # 等待所有任务完成，并处理可能的异常
        for future in as_completed(future_to_site):
            try:
                future.result()
            except Exception as e:
                site = future_to_site[future]
                name = site.get('name', '未命名网站')
                url = site.get('url', 'URL 未提供')
                error_message = f"[异常] 网站: {name} - URL: {url} - 异常: {str(e)}"
                logging.error(error_message)

if __name__ == '__main__':
    main()
