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
    def __init__(self, pktToSend = None, arpToSend = None, port = None,timeStamp=None,sender = None,incomingPort=None):
        self.pktToSend = [pktToSend]
        self.arpToSend = arpToSend
        self.timeStamp = timeStamp
        self.port = port
        self.retries = 0
        self.sender = sender
        self.incomingPort = incomingPort

class Router(object):
    def __init__(self, net):

        self.net = net
        print("name   --    ethernet Address -- IP Network Address -- IP Network mask")
        for intf in net.interfaces():
            print(str(intf.name)+" -- "+str(intf.ethaddr) + " -- " + str(intf.ipaddr) + " -- " + str(intf.netmask))

        print("#"*80)
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


        addrCache = dict()  #map: IP address -> HW address
        taskQueue = []
        unresolved = dict()  #map: IP address -> ICMP packet
        switchPortIPaddrList = [intf.ipaddr for intf in self.net.interfaces() ]
        ftable = self.build_ft()        
        print("forwarding table:")      
        print(ftable)        
        print("router port IP address list:")      
        print(switchPortIPaddrList)
        print("#"*80)

        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            for item in taskQueue:        #send out arp periodically
                task = unresolved[item]
                if task.retries<4 and time.time() -task.timeStamp >=1:
                    task.retries+=1
                    print("outgoing packet(to port:"+str(task.port)+"):")
                    print(task.arpToSend)
                    print("-")
                    self.net.send_packet(task.port,task.arpToSend)
                    task.timeStamp = time.time()
                elif task.retries==4 and time.time() -task.timeStamp >=1:
                    #sendback HostUnreachable to sender after 5 retries 
                    task.retries+=1
                    print(task.arpToSend)
                    print("-")
                    print("task.pktToSend:")
                    print(task.pktToSend)
                    for pktToSend in task.pktToSend:
                        replyPkt = Ethernet() + IPv4() + ICMP()         #generate error ICMP here
                        replyPkt.get_header("IPv4").dst = task.sender
                        replyPkt.get_header("IPv4").src = self.net.interface_by_name(task.incomingPort).ipaddr
                        replyPkt.get_header("IPv4").ttl = 16
                        replyPkt.get_header("ICMP").icmpdata = ICMPDestinationUnreachable()
                        replyPkt.get_header("ICMP").icmpdata.data = b'E\x00\x00\x1c\x00\x00\x00\x00@\x01'
                        replyPkt.get_header("ICMP").icmpcode = ICMPCodeDestinationUnreachable.HostUnreachable
                        pkt = replyPkt
                        dst = task.sender

                        ipToBeResolved = None
                        entry = self.get_first_entry(ftable,dst)
                        if entry is not None:
                            ipToBeResolved = dst if entry[0] == entry[2] else IPv4Address(entry[2])
                        if ipToBeResolved is not None and ipToBeResolved in unresolved:      
                            #if next hop is found unresolved, pkt will be pushed into queue
                            task = unresolved[ipToBeResolved]
                            task.pktToSend.append(pkt)
                            print("#"*80)
                            continue
                        self.process_pkt(pkt,dst,ftable,addrCache,taskQueue,unresolved,None,None)
                    task.timeStamp = time.time()
                    
            gotpkt = True
            try:
                dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break
            if gotpkt==False:
                continue

            print("incoming packet("+str(pkt.headers())+"):")
            print(pkt)
            print("-")

            arpPkt = pkt.get_header("Arp")          #header extraction here
            Ipv4Header = pkt.get_header("IPv4")          #header extraction here
            ICMPHeader = pkt.get_header("ICMP")          #header extraction here
            UDPHeader = pkt.get_header("UDP")          #header extraction here
            EthHeader = pkt.get_header("Ethernet")          #header extraction here
            if Ipv4Header is not None:
                Ipv4Header.ttl -=1;         #decrement ttl
                
            if arpPkt is not None:
                if gotpkt:
                    log_debug("Got a packet: {}".format(str(pkt)))
                addrCache[arpPkt.senderprotoaddr] = arpPkt.senderhwaddr

                if arpPkt.operation == ArpOperation.Request and arpPkt.targetprotoaddr in switchPortIPaddrList:     #answer arp if target is router
                    targetIntf = self.net.interface_by_ipaddr(arpPkt.targetprotoaddr)
                    response = create_ip_arp_reply(targetIntf.ethaddr,arpPkt.senderhwaddr,targetIntf.ipaddr,arpPkt.senderprotoaddr)
                    print("outgoing packet(to port:"+str(dev)+"):")
                    print(response)
                    print("-")
                    self.net.send_packet(dev, response)
                elif arpPkt.operation == ArpOperation.Reply and arpPkt.targetprotoaddr in switchPortIPaddrList and arpPkt.senderprotoaddr in unresolved:
                    task = unresolved[arpPkt.senderprotoaddr]
                    for pktToSend in task.pktToSend:
                        EthHeader = pktToSend.get_header("Ethernet")
                        Ipv4Header = pktToSend.get_header("IPv4")
                        EthHeader.src = self.net.interface_by_name(task.port).ethaddr
                        EthHeader.dst = arpPkt.senderhwaddr  #update ethernet header's dst field
                        print("outgoing packet(to port:"+str(task.port)+"):")
                        print(pktToSend)
                        print("-")
                        self.net.send_packet(task.port, pktToSend)
                    unresolved.pop(arpPkt.senderprotoaddr)
                    taskQueue.remove(arpPkt.senderprotoaddr)
                else:   #drop packet
                    pass
            elif Ipv4Header is not None:
                ipToBeResolved = None
                entry = self.get_first_entry(ftable,Ipv4Header.dst)
                if entry is not None:
                    ipToBeResolved = Ipv4Header.dst if entry[0] == entry[2] else IPv4Address(entry[2])
                if ipToBeResolved is not None and ipToBeResolved in unresolved:      
                    #if next hop is found unresolved, pkt will be pushed into queue
                    task = unresolved[ipToBeResolved]
                    task.pktToSend.append(pkt)
                    print("#"*80)
                    continue
                ethPacketToSend = Ethernet()
                pktSender = Ipv4Header.src
                if UDPHeader is not None:
                    replyPkt = Ethernet() + IPv4() + ICMP()
                    replyPkt.get_header("IPv4").dst = Ipv4Header.src
                    replyPkt.get_header("IPv4").src = self.net.interface_by_name(dev).ipaddr
                    replyPkt.get_header("IPv4").ttl = 16
                    replyPkt.get_header("ICMP").icmpdata = ICMPDestinationUnreachable()
                    replyPkt.get_header("ICMP").icmpdata.data = b'E\x00\x00!\x00\x00\x00\x00%\x11'
                    replyPkt.get_header("ICMP").icmpcode = ICMPCodeDestinationUnreachable.PortUnreachable
                    pkt = replyPkt
                    dst = Ipv4Header.src
                elif ICMPHeader is not None and ICMPHeader.icmptype == ICMPType.EchoRequest and Ipv4Header.ttl<=1:
                    #send back ICMPTimeExceeded if ttl <= 1
                    replyPkt = Ethernet() + IPv4() + ICMP()
                    replyPkt.get_header("IPv4").dst = Ipv4Header.src
                    replyPkt.get_header("IPv4").src = self.net.interface_by_name(dev).ipaddr
                    replyPkt.get_header("IPv4").ttl = 16
                    replyPkt.get_header("ICMP").icmpdata = ICMPTimeExceeded()
                    replyPkt.get_header("ICMP").icmpdata.data = b'E\x00\x00\x1c\x00\x00\x00\x00\x01\x01'
                    replyPkt.get_header("ICMP").icmpdata.origdgramlen=28


                    pkt = replyPkt
                    dst = Ipv4Header.src

                elif ICMPHeader is not None and ICMPHeader.icmptype == ICMPType.EchoRequest and Ipv4Header.dst in switchPortIPaddrList:
                    #send back ICMPEchoReply if dst is router
                    replyPkt = Ethernet() + IPv4() + ICMP()
                    replyPkt.get_header("IPv4").dst = Ipv4Header.src
                    replyPkt.get_header("IPv4").src = Ipv4Header.dst
                    replyPkt.get_header("IPv4").ttl = Ipv4Header.ttl
                    replyPkt.get_header("ICMP").icmpdata = ICMPEchoReply()
                    replyPkt.get_header("ICMP").icmpdata.data = ICMPHeader.icmpdata.data
                    pkt = replyPkt
                    dst = Ipv4Header.src
                else:   #other case that router do a retransmission
                    dst = Ipv4Header.dst

                forwarded = self.get_first_entry(ftable,dst)

                if forwarded is None:      #send back ICMPDestinationUnreachable if dst cannot be found in ft
                    replyPkt = Ethernet() + IPv4() + ICMP()
                    replyPkt.get_header("IPv4").dst = Ipv4Header.src
                    replyPkt.get_header("IPv4").src = self.net.interface_by_name(dev).ipaddr
                    replyPkt.get_header("IPv4").ttl = 16
                    replyPkt.get_header("ICMP").icmpdata = ICMPDestinationUnreachable()
                    replyPkt.get_header("ICMP").icmpdata.data = b'E\x00\x00\x1c\x00\x00\x00\x00\x01\x01'
                    pkt = replyPkt
                    dst = Ipv4Header.src
                self.process_pkt(pkt,dst,ftable,addrCache,taskQueue,unresolved,pktSender,dev)



            print("#"*80)
    def get_first_entry(self,ftable,dst):
        for ft_entry in ftable:
            target = IPv4Address(ft_entry[0])
            mask = IPv4Address(ft_entry[1])
            nextHop = IPv4Address(ft_entry[2])
            portName = ft_entry[4]
            if (int(target) & int(mask)) == (int(dst) & int(mask)):  
                return ft_entry
        return None

    def process_pkt(self,pkt,dst,ftable,addrCache,taskQueue,unresolved,pktSender,dev):
        #process outgoing ICMP packet
        entry = self.get_first_entry(ftable,dst)
        target = IPv4Address(entry[0])
        mask = IPv4Address(entry[1])
        nextHop = IPv4Address(entry[2])
        portName = entry[4]
        if target!=nextHop and nextHop in addrCache:
            EthHeader = pkt.get_header("Ethernet")
            EthHeader.src = self.net.interface_by_name(portName).ethaddr
            EthHeader.dst = addrCache[nextHop]  #update ethernet header's dst field
            print("outgoing packet(to port:"+str(portName)+"):")
            print(pkt)
            print("-")
            self.net.send_packet(portName, pkt)
        elif target==nextHop and dst in addrCache:
            EthHeader = pkt.get_header("Ethernet")
            EthHeader.src = self.net.interface_by_name(portName).ethaddr
            EthHeader.dst = addrCache[dst]  #update ethernet header's dst field
            print("outgoing packet(to port:"+str(portName)+"):")
            print(pkt)
            print("-")
            self.net.send_packet(portName, pkt)
        else: # no IPaddr-HWaddr pair found in cache
            if target!=nextHop and nextHop not in addrCache:
                targetIPaddr = nextHop
            else:     #if target net is current net, send arp looking up dst address
                targetIPaddr = dst
            if targetIPaddr not in unresolved:
                senderIPaddr = self.net.interface_by_name(portName).ipaddr
                senderHWaddr = self.net.interface_by_name(portName).ethaddr
                arpRequest = create_ip_arp_request(senderHWaddr, senderIPaddr, targetIPaddr)
                taskQueue.append(targetIPaddr)
                unresolved[targetIPaddr] = Task(pktToSend=pkt, arpToSend = arpRequest, port = portName,timeStamp = time.time(),sender=pktSender,incomingPort = dev)
                print("outgoing packet(to port:"+str(portName)+"):")
                print(arpRequest)
                print("-")
                self.net.send_packet(portName, arpRequest)



def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
