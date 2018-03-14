# 为发掘更快IP而存在

## 使用
[ENV_SETTINGS] ./dsb\_hosts <hostnames\_file>

推荐启动方式:

> DEBUG=1 INTERVAL=30 ./dsb_hosts hostnames

## hostnames_file格式
```
<hostname1> <!black_ip1>  <!black_ip2> <1black_ip_prefix> ...
...
```

## 原理

一般国外的一些大站都会在世界各地部署节点(有不少是采用了CDN --- 源站的模式, 见过不少用akamai的). 一般ns都会根据本地DNS服务器的所处位置给予最合适的IP. 利用这一点向世界各地的DNS服务器发送dns解析请求, 将不同地区的IP收集起来, 然后再逐个ping之. 多ping几次取个最佳的IP, 写到/etc/hosts文件中. 

## 配置

DEBUG: 打印出debug信息

INTERVAL: 如果设置了该值, 程序会定期地循环工作

DNS: 本地dns服务器列表.以逗号","隔开, 默认已有168.126.63.1, 168.126.63.2, 168.95.1.1, 168.95.192.1, 203.80.96.10, 114.114.114.114, 8.8.8.8

## 配置需要加速的

## 注意事项

目前只支持osx和linux. 并且需要root权限

