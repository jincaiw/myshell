#!/bin/bash

if [ "$1" == "" ]; then
    echo "请提供网络接口名称（如 eth0）"
    exit 0
fi

while true; do
    eth="$1"
    RXpre=$(cat /proc/net/dev | grep "$eth" | tr : " " | awk '{print $2}')
    TXpre=$(cat /proc/net/dev | grep "$eth" | tr : " " | awk '{print $10}')

    if [ $? -ne 0 ]; then
        echo "无法获取 $eth 接口的流量数据"
        exit 1
    fi

    sleep 1

    RXnext=$(cat /proc/net/dev | grep "$eth" | tr : " " | awk '{print $2}')
    TXnext=$(cat /proc/net/dev | grep "$eth" | tr : " " | awk '{print $10}')

    if [ $? -ne 0 ]; then
        echo "无法获取 $eth 接口的流量数据"
        exit 1
    fi

    clear
    echo -e "\t RX `date +%k:%M:%S` TX"
    RX=$((RXnext - RXpre))
    TX=$((TXnext - TXpre))

    if [[ $RX -lt 1024 ]]; then
        RX="${RX}B/s"
    elif [[ $RX -gt 1048576 ]]; then
        RX=$(echo $RX | awk '{print $1/1048576 "MB/s"}')
    else
        RX=$(echo $RX | awk '{print $1/1024 "KB/s"}')
    fi

    if [[ $TX -lt 1024 ]]; then
        TX="${TX}B/s"
    elif [[ $TX -gt 1048576 ]]; then
        TX=$(echo $TX | awk '{print $1/1048576 "MB/s"}')
    else
        TX=$(echo $TX | awk '{print $1/1024 "KB/s"}')
    fi

    echo -e "$eth \t $RX   $TX "
done