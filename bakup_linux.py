import shutil
import os
import datetime
 
# 源文件路径
source = '/home/user/dir/'
# 备份路径
backup = '/home/user/backup/'
 
# 获取当前时间
now = datetime.datetime.now()
# 生成备份文件名
name = 'backup_' + now.strftime('%Y-%m-%d_%H-%M-%S') + '.zip'
 
# 使用shutil模块的make_archive函数，将source文件夹压缩成zip文件，并保存在backup路径下
shutil.make_archive(os.path.join(backup, name), 'zip', source)
