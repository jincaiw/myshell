!/bin/bash
## 设置IP  2016-08-31
## http://www.aqzt.com
##email: ppabc@qq.com
##robert yu
##centos 6和centos 7

#nmcli con show |grep enp0s3 | awk -F '[ ]+' '{print $2}'
#nmcli device show enp0s3
#nmcli device show enp0s3 | awk 'NR==3'
#bash ip.sh enp0s3 10.0.2.18 255.255.255.0 10.0.2.2
#bash ip.sh enp0s8 192.168.56.104 255.255.255.0 192.168.56.1 dg

# 如果第一个参数为空，则提示用户输入正确的参数，并退出脚本
if [ "$1" == "" ];then
    echo "1 is empty.example:ip.sh eth0 192.168.1.10 255.255.255.0 192.168.1.1"
    exit 1
fi
# 如果第二个参数为空，则提示用户输入正确的参数，并退出脚本
if [ "$2" == "" ];then
    echo "2 is empty.example:ip.sh eth0 192.168.1.10 255.255.255.0 192.168.1.1"
    exit 1
fi
# 如果第三个参数为空，则提示用户输入正确的参数，并退出脚本
if [ "$3" == "" ];then
    echo "3 is empty.example:ip.sh eth0 192.168.1.10 255.255.255.0 192.168.1.1"
    exit 1
fi
# 如果第四个参数为空，则提示用户输入正确的参数，并退出脚本
if [ "$4" == "" ];then
    echo "4 is empty.example:ip.sh eth0 192.168.1.10 255.255.255.0 192.168.1.1"
    exit 1
fi

# 将第一个参数赋值给变量 ID1
ID1=$1
# 将第五个参数赋值给变量 ID5
ID5=$5

###删除网关或DNS
dg_ddg(){
# 如果第五个参数为 dg，则删除 /etc/sysconfig/network-scripts/ifcfg-$ID1 文件中的 GATEWAY= 行
if [ "$ID5" == "dg" ];then
    sed -i '/GATEWAY=/d' /etc/sysconfig/network-scripts/ifcfg-$ID1
fi
# 如果第五个参数为 ddg，则删除 /etc/sysconfig/network-scripts/ifcfg-$ID1 文件中的 GATEWAY=、DNS1= 和 DNS2= 行
if [ "$ID5" == "ddg" ];then
    sed -i '/GATEWAY=/d' /etc/sysconfig/network-scripts/ifcfg-$ID1
	sed -i '/DNS1=/d' /etc/sysconfig/network-scripts/ifcfg-$ID1
	sed -i '/DNS2=/d' /etc/sysconfig/network-scripts/ifcfg-$ID1
fi
# 如果第五个参数为 dd，则删除 /etc/sysconfig/network-scripts/ifcfg-$ID1 文件中的 DNS1= 和 DNS2= 行
if [ "$ID5" == "dd" ];then
	sed -i '/DNS1=/d' /etc/sysconfig/network-scripts/ifcfg-$ID1
	sed -i '/DNS2=/d' /etc/sysconfig/network-scripts/ifcfg-$ID1
fi
}

###系统判断
# 检查是否存在 /etc/redhat-release 文件
if [ -f /etc/redhat-release ];then
        # 如果存在，则将操作系统类型设置为 CentOS
        OS=CentOS
# 检查 CentOS 版本
check_OS1=`cat /etc/redhat-release | awk -F '[ ]+' '{print $3}' | awk -F '.' '{print $1}'`
check_OS2=`cat /etc/redhat-release | awk -F '[ ]+' '{print $4}' | awk -F '.' '{print $1}'`
# 如果是 CentOS 6，则将操作系统类型设置为 CentOS6
if [ "$check_OS1" == "6" ];then
    OS=CentOS6
fi
# 如果是 CentOS 7，则将操作系统类型设置为 CentOS7
if [ "$check_OS2" == "7" ];then
    OS=CentOS7
fi
# 如果既不是 CentOS 6 也不是 CentOS 7，则提示用户操作系统不受支持
elif [! -z "`cat /etc/issue | grep bian`" ];then
        OS=Debian
elif [! -z "`cat /etc/issue | grep Ubuntu`" ];then
        OS=Ubuntu
else
        echo -e "\033[31mDoes not support this OS, Please contact the author! \033[0m"
fi

# 如果操作系统是 CentOS6，则执行以下操作
	if [ $OS == 'CentOS6' ];then

###centos6修改
# 如果 /etc/sysconfig/network-scripts/ifcfg-$1 文件存在，则执行以下操作
if [ -f "/etc/sysconfig/network-scripts/ifcfg-$1" ]; then

# 记录当前时间
time=`date +%Y-%m-%d_%H_%M_%S`
# 备份 /etc/sysconfig/network-scripts/ifcfg-$1 文件到 /tmp/ifcfg-$1.$time
cp /etc/sysconfig/network-scripts/ifcfg-$1 /tmp/ifcfg-$1.$time


# 获取网卡的 MAC 地址
HWADDR=`/sbin/ip a|grep -B1 $1 | awk 'NR==3' |awk -F '[ ]+' '{print $3}'`
# 删除 /etc/sysconfig/network-scripts/ifcfg-$1 文件中的 BOOTPROTO=、HWADDR=、ONBOOT=、IPADDR=、NETMASK=、GATEWAY=、DNS1= 和 DNS2= 行
sed -i '/BOOTPROTO=/d' /etc/sysconfig/network-scripts/ifcfg-$1
sed -i '/HWADDR=/d' /etc/sysconfig/network-scripts/ifcfg-$1
sed -i '/ONBOOT=/d' /etc/sysconfig/network-scripts/ifcfg-$1
sed -i '/IPADDR=/d' /etc/sysconfig/network-scripts/ifcfg-$1
sed -i '/NETMASK=/d' /etc/sysconfig/network-scripts/ifcfg-$1
sed -i '/GATEWAY=/d' /etc/sysconfig/network-scripts/ifcfg-$1
sed -i '/DNS1=/d' /etc/sysconfig/network-scripts/ifcfg-$1
sed -i '/DNS2=/d' /etc/sysconfig/network-scripts/ifcfg-$1
# 在 /etc/sysconfig/network-scripts/ifcfg-$1 文件中添加 BOOTPROTO=static、HWADDR=$HWADDR、ONBOOT=yes、IPADDR=$2、NETMASK=$3、GATEWAY=$4、DNS1=114.114.114.114 和 DNS2=223.5.5.5 行
echo "BOOTPROTO=static" >>/etc/sysconfig/network-scripts/ifcfg-$1
echo "HWADDR=$HWADDR" >>/etc/sysconfig/network-scripts/ifcfg-$1
echo "ONBOOT=yes" >>/etc/sysconfig/network-scripts/ifcfg-$1
echo "IPADDR=$2" >>/etc/sysconfig/network-scripts/ifcfg-$1
echo "NETMASK=$3" >>/etc/sysconfig/network-scripts/ifcfg-$1
echo "GATEWAY=$4" >>/etc/sysconfig/network-scripts/ifcfg-$1
echo "DNS1=114.114.114.114" >>/etc/sysconfig/network-scripts/ifcfg-$1
echo "DNS2=223.5.5.5" >>/etc/sysconfig/network-scripts/ifcfg-$1

# 调用 dg_ddg 函数
dg_ddg

# 打印 /etc/sysconfig/





