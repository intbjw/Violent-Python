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
def Analysis_pcap(dpkt,count):

    for i in range(count):
        try:
            print("第{}的数据包".format(i+1).center(40, '*'))
            Ether(dpkt[i])
            IP(dpkt[i].payload)
            protocol(dpkt[i].payload.payload)
            print("")
        except Exception as e:
            print(str(e))

def Ether(eth):

    print(' ' * 5 + eth.name.center(20, '#') + ' ' * 10 )
    print("[*] 源地址：".ljust(20, ' ') + eth.src.rjust(10, ' '))
    print("[*] 目的地址：".ljust(20, ' ') + eth.dst.rjust(10, ' '))

def IP(ip):
    print(' ' * 5 + ip.name.center(20, '#') + ' ' * 10)
    # 常见协议与相应的协议字段值间的转换
    proto_str = ''
    proto = ip.proto
    if proto == 1:
        proto_str = 'ICMP'
    elif proto == 6:
        proto_str = 'TCP'
    elif proto == 17:
        proto_str = 'UDP'
    else:
        proto_str = 'Other'

    if ip.name == 'IP':
        print("[*] 版本：".ljust(20, ' ') + str(ip.version))
        print("[*] 头部长度：".ljust(20, ' ') + str(ip.len))
        print("[*] TTL值：".ljust(20, ' ') + str(ip.ttl))
        print("[*] 协议名称".ljust(20, ' ') + proto_str)
        print("[*] 源地址：".ljust(20, ' ') + ip.src)
        print("[*] 目的地址：".ljust(20, ' ') + ip.dst)
    if ip.name == 'IPv6':
        print('sdadasdas')
        pass

def protocol(pro):

    print(' ' * 5 + pro.name.center(20, '#') + ' ' * 10)
    if pro.name == 'TCP':
        print("[*] 源端口号：".ljust(20, ' ') + str(pro.sport).rjust(10, ' '))
        print("[*] 目的端口号：".ljust(20, ' ') + str(pro.dport).rjust(10, ' '))
        print("[*] 序列号：".ljust(20, ' ') + str(pro.seq))
        print("[*] 应答号：".ljust(20, ' ') + str(pro.ack))
        print("[*] 数据偏移：".ljust(20, ' ') + str(pro.dataofs))
        print("[*] 保留：".ljust(20, ' ') + str(pro.reserved))
        # bug 状态控制码
        # print("[*] 标志：".ljust(20, ''))
        # print(pro.flags)
        print("[*] 窗口大小".ljust(20, ' ') + str(pro.window))
        print("[*] 校验和：".ljust(20, ' ') + str(pro.chksum))
    if pro.name == 'UDP':
        print("[*] 源端口号：".ljust(20, ' ') + str(pro.sport).rjust(10, ' '))
        print("[*] 目的端口号：".ljust(20, ' ') + str(pro.dport).rjust(10, ' '))
        print("[*] 长度：".ljust(20, ' ') + str(pro.len))
        print("[*] 检验和：".ljust(20, ' ') + str(pro.chksum))
    if pro.name == 'ICMP':
        pass

def main():
    parser = optparse.OptionParser("用法：-i <网卡名称> -c <抓取数据包的数量>")
    parser.add_option('-i', dest='iface_name', type='string', help='此参数为网卡的名称,')
    parser.add_option('-c', dest='count', type='int', help='此参数为想要抓取数据包的个数，类型为整数')
    parser.add_option('-f', dest='file_name', type='string', help='此参数为需要分析文件的名称')
    (options, args) = parser.parse_args()

    if options.iface_name is None and options.count is None and not(options is None):
        dpkt = rdpcap('./dome.pacp')
        print(dpkt)
        count = len(dpkt)
        Analysis_pcap(dpkt, count)
    else:
        if options.iface_name is None or options.count is None:
            print(parser.usage)
            exit(0)
        iface_name = options.iface_name
        count = options.count
        dpkt = Get_pcap(iface_name, count)
        print(dpkt)
        Analysis_pcap(dpkt, count)
        # wrpcap('dome.pacp', dpkt)


if __name__ == '__main__':
    main()
