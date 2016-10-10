#!/usr/bin/env python3

'''
Ethernet learning switch in Python: HW3.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

def main(net):
    lru = dict()      #lru table: MAC address => index
    forwardingTable = dict()        #forwarding table: host MAC address => port.name of switch 
    switchPortEthaddrList = [intf.ethaddr for intf in net.interfaces() ]
    while True:
        try:
            inputPortName,packet = net.recv_packet()
        except NoPackets:
            continue
        except:
            return
        ethaddrSrc = packet[0].src
        ethaddrDst = packet[0].dst
        ethaddr_broadcast = EthAddr("ff:ff:ff:ff:ff:ff")
        if ethaddrSrc in lru:     #if source in lru, make it newest
            for eth in lru:
                if lru[eth]<lru[ethaddrSrc]:
                    lru[eth]+=1
            lru[ethaddrSrc] = 0
        else:
            ethaToRemove = None
            for eth in lru:
                lru[eth]+=1
                if lru[eth]>=5:
                    ethaToRemove=eth
            if ethaToRemove is not None:
                lru.pop(ethaToRemove)
                forwardingTable.pop(ethaToRemove)
            lru[ethaddrSrc] = 0
        if ethaddrDst in lru:
            for eth in lru:
                if lru[eth]<lru[ethaddrDst]:
                    lru[eth]+=1
            lru[ethaddrDst] = 0
        forwardingTable[ethaddrSrc] = inputPortName
        if ethaddrDst in switchPortEthaddrList:
            continue    #destination is switch itself
        elif ethaddrDst == ethaddr_broadcast or ethaddrDst not in forwardingTable :
            for intf in net.interfaces():
                if inputPortName != intf.name:
                    net.send_packet(intf.name, packet)
        else:
            net.send_packet(forwardingTable[ethaddrDst], packet)


