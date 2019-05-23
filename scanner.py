#!/usr/bin/env python
# coding=utf-8
# -*- coding:utf-8 -*-
# 简单的数据包抓取
'''
    @Author：intbjwww
    根据ipv4的报文格式
    需要解析的字段有：
        1.版本
        2.头部长度
        3.服务类型
        4.总长度
        5.标识
        6.标志
        7.段偏移
        8.生存时间TTL
        9.协议
        10.头部校验和
        11.原地址和目的地址
    注：只解析了头部固定长度部分
'''
import optparse
from scapy.all import *
def Get_pcap(iface_name, count):
    dpkt = sniff(iface=iface_name, count=count)
    # wrpcap('dome.pacp', dpkt)
    # https://blog.csdn.net/mak0000/article/details/82697436
    return dpkt


def main():
    parser = optparse.OptionParser("用法：-i <网卡名称> -c <抓取数据包的数量>")
    parser.add_option('-i', dest='iface_name', type='string', help='此参数为网卡的名称,')
    parser.add_option('-c', dest='count', type='int', help='此参数为想要抓取数据包的个数，类型为整数')
    (options, args) = parser.parse_args()
    if options.iface_name is None or options.count is None:
        print(parser.usage)
        exit(0)
    iface_name = options.iface_name
    count = options.count
    dpkt = Get_pcap(iface_name, count)
    print(Get_pcap(iface_name, count))
    for i in range(count):
        try:
            print("[*] 第{}个IP报文：".format(i))
            print("[*]版本：".ljust(20,' ') + str(dpkt[i][IP].version).rjust(10,' '))
            print("[*] 头部长度：".ljust(20,' ') + str(dpkt[i][IP].len).rjust(10,' '))
            # print("| TTL值：".ljust(20,' ') + dpkt[i][IP].ttl.ljust(10,' '))
            print("[*] 源地址：".ljust(20,' ') + dpkt[i][IP].src.rjust(10,' '))
            print("[*]目的地址：".ljust(20,' ') + dpkt[i][IP].dst.rjust(10,' '))
        except:
            print("error")
if __name__ == '__main__':
    main()
