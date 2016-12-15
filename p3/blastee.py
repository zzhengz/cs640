#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from threading import *
import time

def dprint(mstr,switch=False):
    if switch is True:
        print(mstr)


def new_pkt(pkt):
    e = Ethernet()
    e.src = '40:00:00:00:00:02'
    e.dst = '20:00:00:00:00:01'
    ip = IPv4()
    ip.srcip = '192.168.200.1'
    ip.dstip = '192.168.100.1'
    ip.protocol = IPProtocol.UDP
    rawData = pkt.get_header('RawPacketContents').to_bytes()
    ACK = None
    if len(rawData)>13:
        ACK = RawPacketContents(rawData[:4]+rawData[6:14])
    else:
        padding = b'z'*(14-len(rawData))
        ACK = RawPacketContents(rawData[:4]+rawData[6:]+padding)
        
    return e + ip + UDP()+ ACK



def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    start = time.time()
    while True:
        gotpkt = True
        try:
            dev,pkt = net.recv_packet()
        except NoPackets:
            dprint("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            dprint("Got shutdown signal")
            break

        if gotpkt:
            dprint("at time:{}, receive packet: {}".format(time.time()-start,pkt)) 
            net.send_packet('blastee-eth0', new_pkt(pkt))

    net.shutdown()
