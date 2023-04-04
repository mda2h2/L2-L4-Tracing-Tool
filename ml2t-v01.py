#! /usr/bin/env python3
"""
 If the specified wlan_type is mgt, then valid wlan_subtypes are:
              assoc-req,  assoc-resp,  reassoc-req,  reassoc-resp,  probe-req,
              probe-resp, beacon, atim, disassoc, auth and deauth.

              If the specified wlan_type is ctl, then valid wlan_subtypes are:
              ps-poll, rts, cts, ack, cf-end and cf-end-ack.

              If the specified wlan_type is  data,  then  valid  wlan_subtypes
              are:  data,  data-cf-ack,  data-cf-poll, data-cf-ack-poll, null,
              cf-ack, cf-poll, cf-ack-poll,  qos-data,  qos-data-cf-ack,  qos-
              data-cf-poll, qos-data-cf-ack-poll, qos, qos-cf-poll and qos-cf-
              ack-poll.

"""

import sys
from scapy.all import *
from collections import namedtuple,defaultdict

def packet_handler(pkt) :
    if (Dot11 in pkt and pkt.type == 1 and pkt.subtype == 9):
        acks.append(pkt)
    if (TCP in pkt):
         frames.append(pkt)
         # Differentiate TCP sender and receiver

mfilter='(tcp or type ctl) and not \
            (subtype ps-poll or subtype rts or subtype cts or\
            subtype ack or subtype cf-end or subtype cf-end-ack)'              

frames=[]
acks=[]

sndip='192.168.100.1'
rcvip='192.168.100.100'
sndmac='04:ce:14:0a:9c:68'
rcvmac='04:ce:14:0b:7e:69'

Endpoint = namedtuple('tcp',['id','ip','mac'])
sender = Endpoint('tx',sndip,sndmac)
receiver = Endpoint('rx',rcvip,rcvmac)

mlfilter= lambda r: (Dot11 in r and r[Dot11].type == 1 and\
      r[Dot11].subtype == 9) or (TCP in r)

all = sniff(offline='pcap/original.pcap',\
            #filter=mfilter, \
            lfilter=mlfilter,\
            prn=packet_handler)

print(len(acks))
print(len(frames))

#for p in all:
#    wrpcap('test.pcap',p,append=True)
