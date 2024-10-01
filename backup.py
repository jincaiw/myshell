#!/Users/wang/myshell/venv/bin/python
# -*- coding: utf-8 -*-

import os
import shutil
import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from logging.handlers import RotatingFileHandler
import signal
import sys
import time
import zipfile

# 创建日志记录器
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# 创建文件处理器，将日志写入文件，并设置日志轮转
file_handler = RotatingFileHandler('backup.log', maxBytes=10 * 1024 * 1024, backupCount=5)
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)

# 创建控制台处理器，将日志输出到控制台
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# 将处理器添加到日志记录器
logger.addHandler(file_handler)
logger.addHandler(console_handler)

def backup_file(source, destination):
    """
    备份单个文件，保留源文件格式

    参数:
    source (str): 要备份的源文件路径
    destination (str): 备份的目标目录路径
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest_file = os.path.join(destination, f"{os.path.basename(source)}_{timestamp}")
    if os.path.exists(dest_file):
        logger.warning(f"目标文件已存在: {dest_file}")
        return
    shutil.copy2(source, dest_file)
    logger.info(f"已备份文件: {source} 到 {dest_file}")

def backup_directory(source, destination):
    """
    备份目录，打包为.zip 格式

    参数:
    source (str): 要备份的源目录路径
    destination (str): 备份的目标目录路径
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_file = os.path.join(destination, f"{os.path.basename(source)}_{timestamp}.zip")
    if os.path.exists(zip_file):
        logger.warning(f"目标压缩文件已存在: {zip_file}")
        return
    with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(source):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, source)
                zipf.write(file_path, arcname)
    logger.info(f"已备份目录: {source} 到 {zip_file}")

def backup(source, destination):
    """
    执行备份操作，根据源是文件还是目录调用相应的备份函数

    参数:
    source (str): 要备份的源文件或目录路径
    destination (str): 备份的目标目录路径
    """
    if os.path.isfile(source):
        backup_file(source, destination)
    elif os.path.isdir(source):
        backup_directory(source, destination)
    else:
        logger.warning(f"{source} 不是有效的文件或目录。")

def schedule_backup(source, destination, interval):
    """
    安排备份任务

    参数:
    source (str): 要备份的源文件或目录路径
    destination (str): 备份的目标目录路径
    interval (int): 备份间隔（分钟）
    """
    scheduler = BackgroundScheduler()
    scheduler.add_job(backup, 'interval', minutes=interval, args=[source, destination])
    scheduler.start()
    logger.info(f"备份任务已安排，每 {interval} 分钟备份 {source} 到 {destination}。")
    logger.info(f"Scheduler state: {scheduler.state}")

def validate_input(source_path, destination_path):
    """
    验证输入的源路径和目标路径

    参数:
    source_path (str): 源文件或目录路径
    destination_path (str): 目标目录路径

    返回:
    bool: 验证结果，True 表示验证通过，False 表示验证失败
    """
    if not os.path.exists(source_path):
        logger.error(f"源路径 {source_path} 不存在。")
        return False
    if not os.access(source_path, os.R_OK):
        logger.error(f"源路径 {source_path} 不可读。")
        return False
    if not os.path.exists(destination_path):
        try:
            os.makedirs(destination_path)
        except OSError as e:
            logger.error(f"无法创建目标目录 {destination_path}: {e}")
            return False
    return True

def signal_handler(sig, frame):
    """
    处理中断信号

    参数:
    sig (int): 信号编号
    frame: 信号帧
    """
    logger.info("备份任务被用户中断。")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    source_path = input("请输入要备份的文件或目录路径: ")
    destination_path = input("请输入备份的目标目录路径: ")
    interval_minutes = int(input("请输入备份间隔（分钟）: "))

    if validate_input(source_path, destination_path):
        schedule_backup(source_path, destination_path, interval_minutes)

        try:
            # 先执行一次备份
            backup(source_path, destination_path)

            # 防止脚本退出
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            signal_handler(signal.SIGINT, None)
    else:
        logger.error("输入验证失败，备份任务未启动。")