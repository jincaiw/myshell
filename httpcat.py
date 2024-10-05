
import requests
import time
import yaml
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# 全局统计变量
success_count = 0
error_count = 0


def check_url_status(name, url, timeout=5):
    """检查 URL 状态"""
    start_time = time.time()
    try:
        response = requests.get(url, timeout=timeout)
        return {
            'name': name,
            'url': url,
            'status_code': response.status_code,
            'reason': response.reason,
            'elapsed_time': round(time.time() - start_time, 2)
        }
    except requests.RequestException as e:
        return {'name': name, 'url': url, 'status_code': None, 'reason': str(e), 'elapsed_time': None}


def setup_logger(log_file_path):
    """设置日志记录"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    if logger.handlers:
        for handler in logger.handlers:
            logger.removeHandler(handler)

    formatter = logging.Formatter('%(asctime)s - %(message)s')
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def monitor_site(site, log_number):
    """监测单个网站"""
    global success_count, error_count
    name = site.get('name', '未命名网站')
    url = site.get('url')

    if not url:
        logging.error(f"[{log_number}] [错误] 站点名称: {name} - URL 未提供")
        error_count += 1
        return

    result = check_url_status(name, url)
    status = '成功' if result['status_code'] else '错误'
    logging.info(f"[{log_number}] [{status}] 站点名称: {result['name']} - URL: {result['url']} - 原因: {result['reason']} - 用时: {result['elapsed_time']} 秒")

    if status == '成功':
        success_count += 1
    else:
        error_count += 1


def load_yaml_file(file_path):
    """加载 YAML 文件内容"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or []
    except (FileNotFoundError, yaml.YAMLError) as e:
        logging.error(f"Error loading YAML file {file_path}: {e}")
        return []


def main():
    global success_count, error_count

    yaml_file_path = 'urls.yaml'
    log_file_path = 'logs/monitor_results.log'
    log_number = 1

    setup_logger(log_file_path)
    sites = load_yaml_file(yaml_file_path)

    if not sites:
        logging.error("[1] 没有加载到任何网站信息。请检查 YAML 配置文件。")
        return

    max_workers = min(32, os.cpu_count() + 4)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(monitor_site, site, log_number + i): site for i, site in enumerate(sites)}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                site = futures[future]
                logging.error(f"[{log_number}] [异常] 站点名称: {site.get('name', '未命名网站')} - URL: {site.get('url', 'URL 未提供')} - 异常: {e}")
                error_count += 1
                log_number += 1

    logging.info(f"监测完成，成功次数: {success_count}，错误次数: {error_count}")


if __name__ == '__main__':
    main()