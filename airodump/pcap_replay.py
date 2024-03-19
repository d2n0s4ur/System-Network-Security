#!/user/bin/python

from scapy.all import *
import sys
pkts = rdpcap(sys.argv[2])

try:
	max_num = int(sys.argv[3])
except:
	max_num = 0

if max_num > 0:
	sendp(pkts[:max_num], iface=sys.argv[1])
else:
	sendp(pkts, iface=sys.argv[1])
