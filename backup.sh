#!/bin/sh

# 定义备份目录
backupdir="/wwwroot/backup/backup1/"

# 如果备份目录不存在，则创建
if [! -d $backupdir ];then
	mkdir $backupdir
fi

# 创建今天的备份目录
# mkdir today backup

# 获取当前时间并格式化
today=`date +%Y-%m-%d_%H_%M_%S`
# 构建备份文件路径
fpath=$backupdir$today 
echo $fpath
# 如果今天的备份目录不存在，则创建
if [! -d $fpath ];then
	mkdir $fpath
fi

# 删除超过一天的旧文件

find $backupdir -type f -mtime +1 -print -exec /bin/rm -f {} \;

# 从指定文件中读取要备份的文件列表
FL=`cat /wwwroot/backup/file_list_ftp`

# 遍历文件列表，逐个备份文件
for i in $FL ;do
	# 复制文件到今天的备份目录
	cp -Rp $i $fpath
done

# 备份当前脚本文件
cp -Rp $0 $fpath
# 备份文件列表文件
cp -Rp /wwwroot/backup/file_list_ftp $fpath

# 切换到备份目录
cd $backupdir
# 将今天的备份目录压缩成 tar.gz 文件
tar czf $today.tar.gz $today
# 删除今天的备份目录
rm -rf $today
# 切换回原来的目录
cd -

# 使用 FTP 上传备份文件

ftp -n<<!
open 192.168.1.12
user backup_q ftp111222
binary
lcd $backupdir
prompt off
mdelete *
mput *
bye
!
