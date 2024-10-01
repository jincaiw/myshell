import os
import shutil
import time
import schedule

def backup(source, destination):
    """
    备份指定的源目录或文件到目标目录
    """
    try:
        if os.path.isfile(source):
            # 如果是文件，直接复制
            shutil.copy2(source, destination)
            print(f"已备份文件: {source} 到 {destination}")
        elif os.path.isdir(source):
            # 如果是目录，进行目录复制
            dest_dir = os.path.join(destination, os.path.basename(source))
            shutil.copytree(source, dest_dir)
            print(f"已备份目录: {source} 到 {dest_dir}")
        else:
            print(f"{source} 不是有效的文件或目录。")
    except Exception as e:
        print(f"备份错误: {e}")

def schedule_backup(source, destination, interval):
    """
    安排定期备份
    """
    # 定义备份任务
    schedule.every(interval).minutes.do(backup, source, destination)

def run_scheduler():
    """
    运行调度程序
    """
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    source_path = input("请输入要备份的文件或目录路径: ")
    destination_path = input("请输入备份的目标目录路径: ")
    interval_minutes = int(input("请输入备份间隔（分钟）: "))

    # 确保目标目录存在
    os.makedirs(destination_path, exist_ok=True)

    # 开始定期备份
    schedule_backup(source_path, destination_path, interval_minutes)

    print(f"备份任务已安排，每 {interval_minutes} 分钟备份 {source_path} 到 {destination_path}。")
    
    # 运行调度器
    run_scheduler()
