::WIN 文件 备份 脚本
::## http://www.aqzt.com
::##email: ppabc@qq.com
::##robert yu
@title MySQL
@echo off
:: 关闭命令行窗口的回显功能
@@echo off
:: 设置变量 d 为当前日期，格式为年月日
set d=%date:~0,4%%date:~5,2%%date:~8,2%
:: 切换到 C:\Windows\SysWOW64 目录
cd C:\Windows\SysWOW64
:: 使用 RoboCopy 工具将本地 D:\test 文件复制备份到 \\192.168.10.111\test 目录
RoboCopy.exe /E D:\test \\192.168.10.111\test
:: 将备份完成的日期和时间信息追加到 D:\copy_log.txt 文件中
echo %d% test copy finish >>  D:\copy_log.txt
