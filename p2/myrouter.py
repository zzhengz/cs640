#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.switchPortEthaddrList = [intf.ethaddr for intf in net.interfaces() ]
        self.switchPortIPaddrList = [intf.ipaddr for intf in net.interfaces() ]
        
        print(self.switchPortEthaddrList)
        for intf in net.interfaces():
            
            print(str(intf.name)+"--"+str(intf.ethaddr) + "--" + str(intf.ipaddr))


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break
            print("num of headers:")
            print(pkt.num_headers())
            print("has header Arp:")    #why Arp not ARP: has_header() takes class name as input to see if match exist
            print(pkt.has_header("Arp"))
            print("has header IPv4:")
            print(pkt.has_header("IPv4"))
            print("pkt:")
            print(pkt)
            print("pkt-type:")
            print(type(pkt))
            print("pkt-len:")
            print(len(pkt))
            print("pkt[0]:")
            print(pkt[0])
            print("pkt[1]:")
            print(pkt[1])
            print("type(pkt[1]):")
            print(type(pkt[1]))



            arpPkt = pkt.get_header("Arp")
            if arpPkt is None:
                return
            print("arpPkt:")
            print(arpPkt)
            print("type(arpPkt):")
            print(type(arpPkt))
            print("arpPkt.senderhwaddr:")
            print(arpPkt.senderhwaddr)
            print("arpPkt.targetprotoaddr")
            print(arpPkt.targetprotoaddr)
            print("type(arpPkt.senderhwaddr):")
            print(type(arpPkt.senderhwaddr))

            print("type(net):")
            print(type(self.net))
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))


        
            if arpPkt.targetprotoaddr in self.switchPortIPaddrList:
                targetIntf = self.net.interface_by_ipaddr(arpPkt.targetprotoaddr)
                response = create_ip_arp_reply(targetIntf.ethaddr,arpPkt.senderhwaddr,targetIntf.ipaddr,arpPkt.senderprotoaddr)
                self.net.send_packet(dev, response)
            else:
                for intf in self.net.interfaces():
                    if dev != intf.name:
                        self.net.send_packet(intf.name,pkt)


            print("#"*100)

def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
