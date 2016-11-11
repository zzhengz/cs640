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
        self.mapCache = dict()  #map: IP address -> HW address
        self.pendingICMP = dict()  #map: IP address -> ICMP packet
        self.net = net
        # other initialization stuff here
        self.switchPortEthaddrList = [intf.ethaddr for intf in net.interfaces() ]
        self.switchPortIPaddrList = [intf.ipaddr for intf in net.interfaces() ]
        self.ftable = self.build_ft()        
        print(self.switchPortEthaddrList)
        for intf in net.interfaces():
            print(str(intf.name)+"--"+str(intf.ethaddr) + "--" + str(intf.ipaddr))

        print(self.ftable)

        print("#"*100)


    def build_ft(self):
        ft = []
        for intf in self.net.interfaces():
            netaddr = IPv4Network('0.0.0.0/'+str(intf.netmask))
            ft.append([str(intf.ipaddr),str(intf.netmask),str(intf.ipaddr),netaddr.prefixlen,intf.name])
        
        #f = open('forwarding_table.txt', 'r')
        #for line in f:
        #    token = line.strip('\n').split(' ')
        #    netIp = IPv4Network(str(token[0])+'/'+str(token[1]))            
        #    ft.append([token[0],token[1],token[2],netIp.prefixlen, token[3]])

        ft = sorted(ft,key = lambda k:k[3], reverse = True) #sort forwarding table by prefixlen
        return ft

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
            print("packet incoming:")
            print(str(pkt))
            print("packet headers:")
            print(str(pkt.headers()))

            arpPkt = pkt.get_header("Arp")
            Ipv4Header = pkt.get_header("IPv4")
            if Ipv4Header is not None:
                Ipv4Header.ttl=Ipv4Header.ttl-1      #decrement ttl here
            ICMPHeader = pkt.get_header("ICMP")
            if ICMPHeader is not None:
                print("ICMPHeader:")
                print(ICMPHeader)
                print("ICMPHeader.icmptype:")
                print(ICMPHeader.icmptype)
                print("ICMPHeader.icmpdata.data:")
                print(ICMPHeader.icmpdata.data)
                
            if arpPkt is not None:
                if gotpkt:
                    log_debug("Got a packet: {}".format(str(pkt)))


            
                if arpPkt.operation == ArpOperation.Request and arpPkt.targetprotoaddr in self.switchPortIPaddrList:
                    targetIntf = self.net.interface_by_ipaddr(arpPkt.targetprotoaddr)
                    response = create_ip_arp_reply(targetIntf.ethaddr,arpPkt.senderhwaddr,targetIntf.ipaddr,arpPkt.senderprotoaddr)
                    self.net.send_packet(dev, response)
                elif arpPkt.operation == ArpOperation.Reply and arpPkt.targetprotoaddr in self.switchPortIPaddrList and arpPkt.senderprotoaddr in self.pendingICMP:
                
                    pktToSend,portToSend = self.pendingICMP[arpPkt.senderprotoaddr]
                    EthHeader = pktToSend.get_header("Ethernet")
                    EthHeader.dst = arpPkt.senderhwaddr  #update ethernet header's dst field
                    ICMPHeader = pktToSend.get_header("ICMP")
                    #ICMPHeader.icmpdata = ICMPEchoRequest()
                    #ICMPHeader.icmpdata = None
                    print("sending IP packet on arp received")
                    print("pktToSend:")
                    print(pktToSend)
                    print("portToSend:")
                    print(portToSend)
                    self.net.send_packet(portToSend, pktToSend)
                else:
                    pass
                    #for intf in self.net.interfaces():
                    #    if dev != intf.name:
                    #        self.net.send_packet(intf.name,pkt)
            elif Ipv4Header is not None:
                for ft_entry in self.ftable:
                    target = IPv4Address(ft_entry[0])
                    mask = IPv4Address(ft_entry[1])
                    dst = Ipv4Header.dst
                    if (int(target) & int(mask)) == (int(dst) & int(mask)):  #longest match found!
                        if dst in self.mapCache:
                            EthHeader = pkt.get_header("Ethernet")
                            EthHeader.dst = self.mapCache[dst]  #update ethernet header's dst field
                            self.net.send_packet(ft_entry[4], pkt)
                        else: # no IPaddr-HWaddr pair found in cache
                            senderIPaddr = target
                            targetIPaddr = dst
                            senderHWaddr = self.net.interface_by_ipaddr(target).ethaddr
                            arpRequest = create_ip_arp_request(senderHWaddr, senderIPaddr, targetIPaddr)
                            self.pendingICMP[targetIPaddr] = [pkt,ft_entry[4]]
                            self.net.send_packet(ft_entry[4], arpRequest)
                        break


                if Ipv4Header.dst not in self.switchPortIPaddrList:
                    #for intf in self.net.interfaces():
                    pass
            print("#"*100)
def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
