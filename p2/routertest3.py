#!/usr/bin/env python

import copy
from switchyard.lib.testing import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from switchyard.lib.address import *

def mk_arpresp(arpreqpkt, hwsrc, arphwsrc=None, arphwdst=None):
    # hwdst (hwsrc), ipsrc (ipdst), ipdst (ipsrc) come from arpreq

    if arphwsrc is None:
        arphwsrc = hwsrc
    if arphwdst is None:
        arphwdst = arpreqpkt.get_header(Arp).senderhwaddr
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = arpreqpkt.get_header(Arp).senderhwaddr
    ether.ethertype = EtherType.ARP
    arp_reply = Arp()
    arp_reply.operation = ArpOperation.Reply
    arp_reply.senderprotoaddr = IPAddr(arpreqpkt.get_header(Arp).targetprotoaddr)
    arp_reply.targetprotoaddr = IPAddr(arpreqpkt.get_header(Arp).senderprotoaddr)
    arp_reply.senderhwaddr = EthAddr(arphwsrc)
    arp_reply.targethwaddr = EthAddr(arphwdst)
    return ether + arp_reply


def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64, payload=''):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.srcip = IPAddr(ipsrc)
    ippkt.dstip = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    if reply:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoRequest
    icmppkt.icmpdata.sequence = 42
    icmppkt.icmpdata.data = payload
    return ether + ippkt + icmppkt 

def forwarding_arp_tests():
    s = Scenario("IP forwarding and ARP requester tests")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')
    s.add_file('forwarding_table.txt', '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
10.100.0.0 255.255.0.0 172.16.42.2 router-eth2''')

    #create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
    #create_ip_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr)



    #arpresp = create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
    resppkt = mk_ping("30:00:00:00:00:01", "10:00:00:00:00:03", '172.16.42.2', '192.168.1.100', reply=True, ttl=64)

    resppkt2 = copy.deepcopy(resppkt)
    resppkt2.get_header(Ethernet).src = EthAddr("10:00:00:00:00:01")
    resppkt2.get_header(Ethernet).dst = EthAddr("20:00:00:00:00:01")


    pkt = mk_ping("ab:cd:00:00:00:47", "10:00:00:00:00:01", "172.16.111.222","192.168.1.1", ttl=64)
    s.expect(PacketInputEvent("router-eth0", pkt, display=IPv4), 
             "IP packet to be forwarded to 192.168.1.1 should arrive on router-eth0")

    pkt = create_ip_arp_request("10:00:00:00:00:02","10.10.0.1","10.10.1.254")
    s.expect(PacketOutputEvent("router-eth1", pkt, display=Arp),
             "Router should send ARP request for 10.10.1.254 out router-eth1 interface")

    pkt = create_ip_arp_reply("ab:cd:00:00:00:01","10:00:00:00:00:02","10.10.1.254","10.10.0.1")
    s.expect(PacketInputEvent("router-eth1", pkt, display=Arp),
             "Router should receive ARP reply for 10.10.1.254 on router-eth1 interface")

    pkt = mk_ping("10:00:00:00:00:02","ab:cd:00:00:00:01", "192.168.1.1","172.16.111.222", reply=True, ttl=64)
    s.expect(PacketOutputEvent("router-eth1", pkt, display=IPv4,exact = False),
             "Router should receive ARP reply for 10.10.1.254 on router-eth1 interface")

    pkt = mk_ping("ab:cd:00:00:00:01", "10:00:00:00:00:02", "172.16.111.222","10.10.0.1", ttl=64)
    s.expect(PacketInputEvent("router-eth1", pkt, display=IPv4), 
             "IP packet to be forwarded to 10.10.0.1 should arrive on router-eth1")

    pkt = mk_ping("10:00:00:00:00:02","ab:cd:00:00:00:01", "10.10.0.1","172.16.111.222", reply=True, ttl=64)
    s.expect(PacketOutputEvent("router-eth1", pkt, display=IPv4,exact = False),
             "Router should reply IP packet for 10.10.1.254 on router-eth1 interface")

    #7
    pkt = mk_ping("be:ef:00:00:00:01","10:00:00:00:00:02", "10.10.123.123", "10.100.1.1", ttl=1)
    s.expect(PacketInputEvent("router-eth1", pkt, display=IPv4), 
             "IP packet to be forwarded to 10.100.1.1 should arrive on router-eth1")

    pkt = create_ip_arp_request("10:00:00:00:00:02","10.10.0.1","10.10.123.123")
    s.expect(PacketOutputEvent("router-eth1", pkt, display=Arp),
             "Router should send ARP request for 10.10.123.123 out router-eth1 interface")

    #9
    pkt = create_ip_arp_reply("be:ef:00:00:00:01","10:00:00:00:00:02","10.10.123.123","10.10.0.1")
    s.expect(PacketInputEvent("router-eth1", pkt, display=Arp),
             "Router should receive ARP reply to 10.10.0.1 on router-eth1 interface")

    #10
    pkt = mk_ping("10:00:00:00:00:02","be:ef:00:00:00:01", "10.10.0.1", "10.10.123.123", ttl=64)
    icmpHeader = pkt.get_header("ICMP")
    icmpHeader.icmpdata =  ICMPDestinationUnreachable()
    icmpHeader.icmpdata.data = b'E\x00\x00!\x00\x00\x00\x00%\x11'
    icmpHeader.icmptype = ICMPType.TimeExceeded
    s.expect(PacketOutputEvent("router-eth1", pkt, display=IPv4,exact = False), 
             "IP packet to be forwarded to 10.10.123.123 should arrive on router-eth1")





















    s.expect(PacketInputTimeoutEvent(1.0), "No packet received in 1.0 second")
    return s

scenario = forwarding_arp_tests()

