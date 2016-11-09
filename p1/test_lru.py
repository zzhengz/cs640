#!/usr/bin/env python

import sys
import time
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from switchyard.lib.testing import *

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP

    ippkt = IPv4()
    ippkt.srcip = IPAddr(ipsrc)
    ippkt.dstip = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = 32

    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest

    return ether + ippkt + icmppkt

def hub_tests():

    macP0 = '10:00:00:00:00:01'
    macP1 = '10:00:00:00:00:02'
    macP2 = '10:00:00:00:00:03'
    macP3 = '10:00:00:00:00:04'
    macP4 = '10:00:00:00:00:05'
    macP5 = '10:00:00:00:00:06'
    macH2 = '20:00:00:00:00:01'
    macH3 = '30:00:00:00:00:01'
    macH4 = '40:00:00:00:00:01'
    macH5 = '50:00:00:00:00:01'
    macH6 = '60:00:00:00:00:01'
    macH7 = '70:00:00:00:00:01'
    macH8 = '80:00:00:00:00:01'
    macH9 = '90:00:00:00:00:01'
    macAddrBroadcast = 'ff:ff:ff:ff:ff:ff'

    ipH2 = '192.168.100.2'
    ipH3 = '192.168.100.3'
    ipH4 = '192.168.100.4'
    ipH5 = '192.168.100.5'
    ipH6 = '192.168.100.6'
    ipH7 = '192.168.100.7'
    ipH8 = '192.168.100.8'
    ipH9 = '192.168.100.9'

    s = Scenario("LRU switch tests")
    s.add_interface('eth0', macP0)
    s.add_interface('eth1', macP1)
    s.add_interface('eth2', macP2)
    s.add_interface('eth3', macP3)
    s.add_interface('eth4', macP4)
    s.add_interface('eth5', macP5)






    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = mk_pkt(macH3, macAddrBroadcast, ipH3, "255.255.255.255")
    s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), "Basic_switch_test: An Ethernet frame with a broadcast destination address should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt, "eth3", testpkt, "eth4", testpkt, "eth5", testpkt, display=Ethernet), "Basic_switch_test: The Ethernet frame with a broadcast destination address should be forwarded out ports eth0 and eth2, lru=[3 -> eth1]")

    # test case 2: a frame with any unicast address except one assigned to hub
    reqpkt = mk_pkt(macH2, macH3, ipH2,ipH3)
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "Basic_switch_test: An Ethernet frame from macH2 to macH3 should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet), "Basic_switch_test: Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1(not eth2), lru=[2 -> eth0,3 -> eth1])") 

    resppkt = mk_pkt(macH3, macH2, ipH3, '192.168.1.100', reply=True)
    s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet), "Basic_switch_test: An Ethernet frame from 30:00:00:00:00:01 to macH2 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", resppkt, display=Ethernet), "Basic_switch_test: Ethernet frame destined to 20:00:00:00:00:01 should be flooded out eth0, lru=[3 -> eth1, 2 -> eth0]")

    # test case 3: a frame with dest address of one of the interfaces should
    # result in nothing happening
    reqpkt = mk_pkt(macH2, macP2, ipH2,'172.16.42.2')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "Basic_switch_test: An Ethernet frame should arrive on eth0 with destination address the same as eth0's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0), "Basic_switch_test: The switch should not do anything in response to a frame arriving with a destination address referring to the switch itself, lru=[3 -> eth1, 2 -> eth0]")


    # test case 4: host1 reconnected to eth2, switch should know this topology change
    reqpkt = mk_pkt(macH2, macH3, ipH2,ipH3)
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet), "Basic_switch_test: An Ethernet frame from macH2 to macH3 should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet), "Basic_switch_test: Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1(not eth2), lru=[ 2 -> eth2, 3 -> eth1]") 

    resppkt = mk_pkt(macH3, macH2, ipH3, ipH2, reply=True)
    s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet), "Basic_switch_test: An Ethernet frame from 30:00:00:00:00:01 to macH2 should arrive on eth1")
    s.expect(PacketOutputEvent("eth2", resppkt, display=Ethernet), "Basic_switch_test: Ethernet frame destined to 20:00:00:00:00:01 should be flooded out eth2, lru=[ 3 -> eth1,2 -> eth2]")

    # test case 5: host1 reconnected to eth0, switch should know this topology change
    reqpkt = mk_pkt(macH2, macH3, ipH2,ipH3)
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet), "LRU_switch_test: [h2 h3]") 

    reqpkt = mk_pkt(macH4, macH2, ipH4, ipH2)
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: [h3 h4 h2]")

    reqpkt = mk_pkt(macH5, macH2, ipH5, ipH2)
    s.expect(PacketInputEvent("eth3", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: [h3 h4 h5 h2]")

    reqpkt = mk_pkt(macH6, macH2, ipH6, ipH2)
    s.expect(PacketInputEvent("eth4", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: [h3 h4 h5 h6 h2]")

    reqpkt = mk_pkt(macH7, macH3, ipH7, ipH2)
    s.expect(PacketInputEvent("eth5", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketOutputEvent("eth0", reqpkt,"eth1", reqpkt,"eth2", reqpkt,"eth3", reqpkt,"eth4", reqpkt, display=Ethernet), "LRU_switch_test: [h4 h5 h6 h2 h7]")

    reqpkt = mk_pkt(macH2, macH4, ipH2, ipH4)
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketOutputEvent( "eth2", reqpkt, display=Ethernet), "LRU_switch_test: shoud be broadcast [h5 h6 h2 h7 h4]")

    # test case 6: 
    reqpkt = mk_pkt(macH3, macP3, ipH3,'172.16.42.2')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketInputTimeoutEvent(1.0), "LRU_switch_test: sent to switch port 3, should do nothing here, [h6 h2 h7 h4 h3]")

    reqpkt = mk_pkt(macH7, macH5, ipH7, ipH5)
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketOutputEvent( "eth1", reqpkt,"eth2", reqpkt,"eth3", reqpkt,"eth4", reqpkt,"eth5", reqpkt,  display=Ethernet), "LRU_switch_test: shoud be broadcast [h6 h2 h7 h4 h3]")

    reqpkt = mk_pkt(macH8, macP3, ipH8,'172.16.42.2')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketInputTimeoutEvent(1.0), "LRU_switch_test: sent to switch port 3, should do nothing here, [h2 h7 h4 h3 h8]")

    reqpkt = mk_pkt(macH2, macH6, ipH2, ipH6)
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketOutputEvent( "eth1", reqpkt,"eth2", reqpkt,"eth3", reqpkt,"eth4", reqpkt,"eth5", reqpkt,  display=Ethernet), "LRU_switch_test: shoud be broadcast [h2 h7 h4 h3 h8]")

    reqpkt = mk_pkt(macH9, macP3, ipH9,'172.16.42.2')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketInputTimeoutEvent(1.0), "LRU_switch_test: sent to switch port 3, should do nothing here, [h7 h4 h3 h8 h9]")

    reqpkt = mk_pkt(macH7, macH2, ipH7, ipH2)
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketOutputEvent( "eth1", reqpkt,"eth2", reqpkt,"eth3", reqpkt,"eth4", reqpkt,"eth5", reqpkt,  display=Ethernet), "LRU_switch_test: shoud be broadcast [h7 h4 h3 h8 h9]")

    reqpkt = mk_pkt(macH2, macP3, ipH2,'172.16.42.2')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketInputTimeoutEvent(1.0), "LRU_switch_test: sent to switch port 3, should do nothing here, [h4 h3 h8 h9 h2]")

    reqpkt = mk_pkt(macH4, macH7, ipH4, ipH7)
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "LRU_switch_test: receive")
    s.expect(PacketOutputEvent( "eth1", reqpkt,"eth2", reqpkt,"eth3", reqpkt,"eth4", reqpkt,"eth5", reqpkt,  display=Ethernet), "LRU_switch_test: shoud be broadcast [h4 h3 h8 h9 h2]")





    return s

scenario = hub_tests()
