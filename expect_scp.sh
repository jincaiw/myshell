#!/usr/bin/expect    -f
#设置ip地址参数
set ip [lindex $argv 0]
#设置超时时间
set timeout 1200
#启动scp命令，将192.168.10.10:/data/www/目录下的文件复制到/data/目录下
spawn    /usr/bin/scp -r 192.168.10.10:/data/www/  /data/
#判断是否需要输入yes/no
expect {
    "(yes/no)?" {send "yes\r"}
    "*password:" {send "www.aqzt.com\r"}
      }
#判断是否需要输入密码
expect "password:"
#输入密码
send "123456\r"
