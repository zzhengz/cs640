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

class Task(object):
    def __init__(self, pktToSend = None, arpToSend = None, port = None,timeStamp=None):
        self.pktToSend = [pktToSend]
        self.arpToSend = arpToSend
        self.timeStamp = timeStamp
        self.port = port
        self.retries = 0

class Router(object):
    def __init__(self, net):

        self.mapCache = dict()  #map: IP address -> HW address
        self.taskQueue = []
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
        
        f = open('forwarding_table.txt', 'r')
        for line in f:
            token = line.strip('\n').split(' ')
            netIp = IPv4Network(str(token[0])+'/'+str(token[1]))            
            ft.append([token[0],token[1],token[2],netIp.prefixlen, token[3]])

        ft = sorted(ft,key = lambda k:k[3], reverse = True) #sort forwarding table by prefixlen
        return ft

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            for target in self.taskQueue:
                task = self.pendingICMP[target]
                if task.retries<5 and time.time() -task.timeStamp >=1:
                    print("packet outgoing (on port:"+str(task.port)+"):")
                    print(str(task.arpToSend) )
                    print("#"*100)
                    task.retries+=1
                    self.net.send_packet(task.port,task.arpToSend)
                    task.timeStamp = time.time()

            gotpkt = True
            try:
                print("start to receive!")
                dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                print("Got no packets signal!")
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break
            if gotpkt==False:
                continue

            print("packet incoming:")
            print(str(pkt))
            print("packet headers:")
            print(str(pkt.headers()))


            arpPkt = pkt.get_header("Arp")          #header extraction here
            Ipv4Header = pkt.get_header("IPv4")          #header extraction here
            if Ipv4Header is not None:
                Ipv4Header.ttl -=1;

                
            if arpPkt is not None:
                if gotpkt:
                    log_debug("Got a packet: {}".format(str(pkt)))
                self.mapCache[arpPkt.senderprotoaddr] = arpPkt.senderhwaddr
                if arpPkt.operation == ArpOperation.Request and arpPkt.targetprotoaddr in self.switchPortIPaddrList:
                    targetIntf = self.net.interface_by_ipaddr(arpPkt.targetprotoaddr)
                    response = create_ip_arp_reply(targetIntf.ethaddr,arpPkt.senderhwaddr,targetIntf.ipaddr,arpPkt.senderprotoaddr)
                    print("packet outgoing (on port:"+dev+"):")
                    print(str(response) )
                    self.net.send_packet(dev, response)
                elif arpPkt.operation == ArpOperation.Reply and arpPkt.targetprotoaddr in self.switchPortIPaddrList and arpPkt.senderprotoaddr in self.pendingICMP:
                    task = self.pendingICMP[arpPkt.senderprotoaddr]

                    for pktToSend in task.pktToSend:
                        EthHeader = pktToSend.get_header("Ethernet")
                        Ipv4Header = pktToSend.get_header("IPv4")
                        EthHeader.src = self.net.interface_by_name(task.port).ethaddr
                        EthHeader.dst = arpPkt.senderhwaddr  #update ethernet header's dst field

                        print("packet outgoing (on port:"+str(task.port)+"):")
                        print(str(pktToSend) )

                        self.net.send_packet(task.port, pktToSend)
                    self.pendingICMP.pop(arpPkt.senderprotoaddr)
                    self.taskQueue.remove(arpPkt.senderprotoaddr)
                else:
                    pass
                    #for intf in self.net.interfaces():
                    #    if dev != intf.name:
                    #        self.net.send_packet(intf.name,pkt)
            elif Ipv4Header is not None and Ipv4Header.dst in self.pendingICMP:
                print("task in queue")
                print("#"*100)
                task = self.pendingICMP[Ipv4Header.dst]
                task.pktToSend.append(pkt)
                continue
            elif Ipv4Header is not None:
                ethPacketToSend = Ethernet()
                for ft_entry in self.ftable:
                    target = IPv4Address(ft_entry[0])
                    mask = IPv4Address(ft_entry[1])
                    dst = Ipv4Header.dst
                    if (int(target) & int(mask)) == (int(dst) & int(mask)):  #longest match found!
                        if dst in self.mapCache:
                            EthHeader = pkt.get_header("Ethernet")
                            EthHeader.src = self.net.interface_by_name(ft_entry[4]).ethaddr
                            EthHeader.dst = self.mapCache[dst]  #update ethernet header's dst field

                            print("packet outgoing (on port:"+str(ft_entry[4])+"):")
                            print(str(pkt) )
                            self.net.send_packet(ft_entry[4], pkt)
                        else: # no IPaddr-HWaddr pair found in cache
                            senderIPaddr = self.net.interface_by_name(ft_entry[4]).ipaddr
                            targetIPaddr = dst
                            senderHWaddr = self.net.interface_by_name(ft_entry[4]).ethaddr
                            arpRequest = create_ip_arp_request(senderHWaddr, senderIPaddr, targetIPaddr)
                            self.taskQueue.append(targetIPaddr)
                            self.pendingICMP[targetIPaddr] = Task(pktToSend=pkt, arpToSend = arpRequest, port = ft_entry[4],timeStamp = time.time())
                            print("packet outgoing (on port:"+str(ft_entry[4])+"):")
                            print(str(arpRequest) )
                            print("entry:")
                            print(ft_entry)
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
