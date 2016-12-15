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

    ipR0 = '192.168.1.1'
    ethR0 = '10:00:00:00:00:01'

    ipR1 = '10.10.0.1'
    ethR1 = '10:00:00:00:00:02'

    ipR2 = '172.16.42.1'
    ethR2 = '10:00:00:00:00:03'

    ipH1 = '192.168.1.239'
    ethH1 = "ab:cd:ef:ab:cd:ef"

    ipH2 = '192.168.1.126'
    ethH2 = "ab:cc:cc:ab:cd:cc"

    ipH3 = '172.16.42.2'
    ethH3 = "ab:cd:00:ab:cd:00"

    ipH4 = '10.10.50.250'
    ethH4 = "12:34:00:31:cd:00"

    ipH5 = '172.16.4.3'     #next-hop:192.168.1.2  port:'router-eth1'
    ethH5 = "12:34:00:00:12:05"

    reqpkt = mk_ping(ethH1, ethR0, ipH1,ipH4, ttl=64)
    reqpkt2 = mk_ping(ethH3, ethR2, ipH3,ipH5, ttl=64)
    reqpkt3 = mk_ping(ethH2, ethR0, ipH2,ipH4, ttl=64)

    relaypkt = mk_ping(ethR1, ethH4, ipH1,ipH4, ttl=64)
    relaypkt3 = mk_ping(ethR1, ethH4, ipH2,ipH4, ttl=64)
    #create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
    #create_ip_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr)

    arpreq = create_ip_arp_request(ethR1, ipR1, ipH4)
    arpreq2 = create_ip_arp_request(ethR0, ipR0, "192.168.1.2")

    arpreply = create_ip_arp_reply(ethH4,ethR1, ipH4, ipR1)



    #arpresp = create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
    resppkt = mk_ping("30:00:00:00:00:01", "10:00:00:00:00:03", '172.16.42.2', '192.168.1.100', reply=True, ttl=64)

    resppkt2 = copy.deepcopy(resppkt)
    resppkt2.get_header(Ethernet).src = EthAddr("10:00:00:00:00:01")
    resppkt2.get_header(Ethernet).dst = EthAddr("20:00:00:00:00:01")


    ttlmatcher = '''lambda pkt: pkt.get_header(IPv4).ttl == 63'''

    s.expect(PacketInputEvent("router-eth0", reqpkt, display=IPv4), 
             "IP packet to be forwarded to 10.10.50.250 should arrive on router-eth0")
    s.expect(PacketOutputEvent("router-eth1", arpreq, display=Arp),
             "Router should send ARP request for 10.10.50.250 out router-eth2 interface")

    s.expect(PacketInputEvent("router-eth2", reqpkt2, display=IPv4), 
             "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")
    s.expect(PacketOutputEvent("router-eth0", arpreq2, display=Arp),
             "Router should send ARP request for 172.16.42.2 out router-eth2 interface")

    s.expect(PacketInputTimeoutEvent(1.0), "No packet received in 1.0 second")

    s.expect(PacketOutputEvent("router-eth1", arpreq, display=Arp),
             "Router should send ARP request for 10.10.50.250 out router-eth2 interface")
    s.expect(PacketOutputEvent("router-eth0", arpreq2, display=Arp),
             "Router should send ARP request for 192.168.1.2 out router-eth2 interface")

    s.expect(PacketInputEvent("router-eth0", reqpkt3, display=IPv4), 
             "IP packet to be forwarded to 10.10.50.250 should arrive on router-eth0")

    s.expect(PacketInputTimeoutEvent(1.0), "No packet received in 1.0 second")

    s.expect(PacketOutputEvent("router-eth1", arpreq, display=Arp),
             "Router should send ARP request for 10.10.50.250 out router-eth2 interface")
    s.expect(PacketOutputEvent("router-eth0", arpreq2, display=Arp),
             "Router should send ARP request for 192.168.1.2 out router-eth2 interface")

    s.expect(PacketInputTimeoutEvent(0.5), "No packet received in 0.5 second")

    s.expect(PacketInputEvent('router-eth1', arpreply, display=Arp), 
             "ARP reply of  should arrive on router-eth1")

    s.expect(PacketOutputEvent("router-eth1", relaypkt, display=IPv4, exact = False),
             "Router should retransmit ICMP request for 10.10.50.250 out router-eth1 interface")

    s.expect(PacketOutputEvent("router-eth1", relaypkt3, display=IPv4, exact = False),
             "Router should retransmit ICMP request for 10.10.50.250 out router-eth1 interface")
    return s

scenario = forwarding_arp_tests()

