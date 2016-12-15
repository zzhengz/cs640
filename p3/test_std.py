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
    macH1 = '20:00:00:00:00:01'
    macH2 = '30:00:00:00:00:01'
    macH3 = '40:00:00:00:00:01'
    macH4 = '50:00:00:00:00:01'
    macH5 = '60:00:00:00:00:01'
    macH6 = '70:00:00:00:00:01'
    macH7 = '80:00:00:00:00:01'
    macH8 = '90:00:00:00:00:01'
    macAddrBroadcast = 'ff:ff:ff:ff:ff:ff'

    ipH1 = '192.168.100.1'
    ipH2 = '192.168.100.2'
    ipH3 = '192.168.100.3'
    ipH4 = '192.168.100.4'
    ipH5 = '192.168.100.5'
    ipH6 = '192.168.100.6'
    ipH7 = '192.168.100.7'
    ipH8 = '192.168.100.8'

    s = Scenario("LRU switch tests")
    s.add_interface('eth0', macP0)
    s.add_interface('eth1', macP1)
    s.add_interface('eth2', macP2)
    s.add_interface('eth3', macP3)
    s.add_interface('eth4', macP4)
    s.add_interface('eth5', macP5)






    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = mk_pkt(macH2, macAddrBroadcast, ipH2, "255.255.255.255")  #[h2:eth1]
    s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), "Basic_switch_test: An Ethernet frame with a broadcast destination address should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt, "eth3", testpkt, "eth4", testpkt, "eth5", testpkt, display=Ethernet), "Basic_switch_test: The Ethernet frame with a broadcast destination address should be forwarded out ports eth0 and eth2")

    # test case 2: a frame with any unicast address except one assigned to switch
    reqpkt = mk_pkt(macH1, macH2, ipH1,ipH2)    #[h1:eth0 h2:eth1]
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "Basic_switch_test: An Ethernet frame from macH1 to macH2 should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet), "Basic_switch_test: Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1(not eth2)") 

    resppkt = mk_pkt(macH2, macH1, ipH2, ipH1, reply=True)    #[h1:eth0 h2:eth1]
    s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet), "Basic_switch_test: An Ethernet frame from 30:00:00:00:00:01 to macH1 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", resppkt, display=Ethernet), "Basic_switch_test: Ethernet frame destined to 20:00:00:00:00:01 should be flooded out eth0")

    resppkt = mk_pkt(macH8, macH1, ipH8, ipH1, reply=True)    #[h1:eth0 h2:eth1 h8:eth1]
    s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet), "Basic_switch_test: An Ethernet frame from 30:00:00:00:00:01 to macH1 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", resppkt, display=Ethernet), "Basic_switch_test: Ethernet frame destined to 20:00:00:00:00:01 should be flooded out eth0")


    # test case 3: a frame with dest address of one of the interfaces should
    # result in nothing happening
    reqpkt = mk_pkt(macH1, macP2, ipH1,'172.16.42.2')    #[h1:eth0 h2:eth1 h8:eth1]
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "Basic_switch_test: An Ethernet frame should arrive on eth0 with destination address the same as eth0's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0), "Basic_switch_test: The switch should not do anything in response to a frame arriving with a destination address referring to the switch itself.")


    # test case 4: host1 reconnected to eth2, switch should know this topology change
    reqpkt = mk_pkt(macH1, macH2, ipH1,ipH2)    #[h1:eth2 h2:eth1 h8:eth1]
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet), "Basic_switch_test: An Ethernet frame from macH1 to macH2 should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet), "Basic_switch_test: Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1(not eth2)") 

    resppkt = mk_pkt(macH2, macH1, ipH2, ipH1, reply=True)     #[h1:eth2 h2:eth1 h8:eth1]
    s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet), "Basic_switch_test: An Ethernet frame from 30:00:00:00:00:01 to macH1 should arrive on eth1")
    s.expect(PacketOutputEvent("eth2", resppkt, display=Ethernet), "Basic_switch_test: Ethernet frame destined to 20:00:00:00:00:01 should be flooded out eth2")

    # test case 5: host1 reconnected to eth0, switch should know this topology change
    reqpkt = mk_pkt(macH1, macH2, ipH1,ipH2)        #[h1:eth0 h2:eth1 h8:eth1]
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "Standard_switch_test: ")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet), "Standard_switch_test: ") 

    reqpkt = mk_pkt(macH3, macH1, ipH3, ipH1)    #[h1:eth0 h2:eth1 h3:eth2 h8:eth1]
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet), "Standard_switch_test: ")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet), "Standard_switch_test: ")

    reqpkt = mk_pkt(macH4, macH1, ipH4, ipH1)    #[h1:eth0 h2:eth1 h3:eth2 h4:eth3 h8:eth1]
    s.expect(PacketInputEvent("eth3", reqpkt, display=Ethernet), "Standard_switch_test: ")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet), "Standard_switch_test: ")

    reqpkt = mk_pkt(macH4, macH1, ipH4, ipH1)    #[h1:eth0 h2:eth1 h3:eth2 h4:eth3 h8:eth1]
    s.expect(PacketInputEvent("eth3", reqpkt, display=Ethernet), "Standard_switch_test: ")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet), "Standard_switch_test: ")

    reqpkt = mk_pkt(macH5, macH1, ipH5, ipH1)    #[h1:eth0 h2:eth1 h3:eth2 h4:eth3 h5:eth4 h8:eth1]
    s.expect(PacketInputEvent("eth4", reqpkt, display=Ethernet), "Standard_switch_test: ")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet), "Standard_switch_test: ")

    reqpkt = mk_pkt( macH1, macH3, ipH1, ipH3)    #[h1:eth0 h2:eth1 h3:eth2 h4:eth3 h5:eth4 h8:eth1]
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "Standard_switch_test: ")
    s.expect(PacketOutputEvent("eth2", reqpkt, display=Ethernet), "Standard_switch_test: ")

    reqpkt = mk_pkt(macH6, macH2, ipH6, ipH2)    #[h1:eth0 h2:eth1 h3:eth2 h4:eth3 h5:eth4 h6:eth5 h8:eth1]
    s.expect(PacketInputEvent("eth5", reqpkt, display=Ethernet), "Standard_switch_test: ")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet), "Standard_switch_test: ")

    reqpkt = mk_pkt(macH1, macP2, ipH1,'172.16.42.2')    #[h1:eth0 h2:eth1 h3:eth2 h4:eth3 h5:eth4 h6:eth5 h8:eth1]
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "Standard_switch_test: ")
    s.expect(PacketInputTimeoutEvent(12.0), "Standard_switch_test: ")


    reqpkt = mk_pkt(macH1, macH8, ipH1, ipH5)    #[h1:eth0 h2:eth1 h3:eth2 h4:eth3 h5:eth4 h6:eth5 h8:eth1]
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "Standard_switch_test: ")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet), "Standard_switch_test: ")

    reqpkt = mk_pkt(macH3, macH8, ipH1, ipH5)    #[h1:eth0 h2:eth1 h3:eth2 h4:eth3 h5:eth4 h6:eth5 h8:eth1]
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet), "Standard_switch_test: ")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet), "Standard_switch_test: ")


    reqpkt = mk_pkt(macH4, macH8, ipH1, ipH5)    #[h1:eth0 h2:eth1 h3:eth2 h4:eth3 h5:eth4 h6:eth5 h8:eth1]
    s.expect(PacketInputEvent("eth3", reqpkt, display=Ethernet), "Standard_switch_test: ")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet), "Standard_switch_test: ")


    return s

scenario = hub_tests()
