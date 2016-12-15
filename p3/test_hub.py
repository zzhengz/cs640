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

    macAddrSwitchPort0 = '10:00:00:00:00:01'
    macAddrSwitchPort1 = '10:00:00:00:00:02'
    macAddrSwitchPort2 = '10:00:00:00:00:03'
    macAddrHost1 = '20:00:00:00:00:01'
    macAddrHost2 = '30:00:00:00:00:02'
    macAddrHost3 = '40:00:00:00:00:03'
    macAddrBroadcast = 'ff:ff:ff:ff:ff:ff'


    s = Scenario("timeout switch tests")
    s.add_interface('eth0', macAddrSwitchPort0)
    s.add_interface('eth1', macAddrSwitchPort1)
    s.add_interface('eth2', macAddrSwitchPort2)






    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress

    reqpkt = mk_pkt(macAddrHost1, macAddrHost2, '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "Basic_switch_test: An Ethernet frame from macAddrHost1 to macAddrHost2 should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt,"eth2", reqpkt, display=Ethernet), "Basic_switch_test: Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1(not eth2)") 

    resppkt = mk_pkt(macAddrHost2, macAddrHost1, '172.16.42.2', '192.168.1.100', reply=True)
    s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet), "Basic_switch_test: An Ethernet frame from 30:00:00:00:00:01 to macAddrHost1 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", resppkt,"eth2", resppkt, display=Ethernet), "Basic_switch_test: Ethernet frame destined to 20:00:00:00:00:01 should be flooded out eth0")

    # test case 3: a frame with dest address of one of the interfaces should
    # result in nothing happening
    reqpkt = mk_pkt(macAddrHost1, macAddrSwitchPort2, '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "Basic_switch_test: An Ethernet frame should arrive on eth0 with destination address the same as eth0's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0), "Basic_switch_test: The switch should not do anything in response to a frame arriving with a destination address referring to the switch itself.")



    return s

scenario = hub_tests()
