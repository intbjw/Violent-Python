# 简单的数据包抓取
from scapy.all import *

dpkt = sniff(iface='en0', count=100)
wrpcap('dome.pacp', dpkt)
