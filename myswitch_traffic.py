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
import sys
#switch SDN


def main(net):

    for intf in net.interfaces():
        print (intf.name, intf.ethaddr, intf.ipaddr, intf.netmask)
    #debug use, print out all available ports
    trafficTable = dict()
    forwardingTable = dict()        #forwarding table: host MAC address => port.name of switch 
    switchPortList = net.interfaces() 
    switchPortEthaddrList = [intf.ethaddr for intf in switchPortList]

    while True:
        try:
            inputPortName,packet = net.recv_packet()
        except Shutdown:
            print ("Got shutdown signal; exiting")
            print('*'*100)
            return
        except NoPackets:
            print ("No packets were available.")
            print('*'*100)
            continue
        except BaseException as e:
            print ("uncatched exception happend when receiving packet: " + str(e))
            return
        # if we get here, we must have received a packet

        
        print ("Received {} on {}".format(packet, inputPortName))
        print("packet headers: "+str(packet.headers()))

        ethaddrSrc = packet[0].src
        ethaddrDst = packet[0].dst
        ethaddr_broadcast = EthAddr("ff:ff:ff:ff:ff:ff")

        dstPortName = "broadcast"
        if ethaddrDst in trafficTable:
            trafficTable[ethaddrDst]+=1
            dstPortName = forwardingTable[ethaddrDst]

        
        if ethaddrSrc not in trafficTable and len(trafficTable)>=5:     #evict entry with least traffic
            ethToEvict = min(trafficTable, key = lambda x: trafficTable.get(x))
            print("evict %s from traffic table" % (str(ethToEvict),))
            trafficTable.pop(ethToEvict)
            forwardingTable.pop(ethToEvict)
        if ethaddrSrc not in trafficTable:    #add source into traffic table
            trafficTable[ethaddrSrc] = 0

        forwardingTable[ethaddrSrc] = inputPortName
        #updating forwarding table 

        print("forwarding Table: "+str(forwardingTable))
        print("traffic Table: "+str(trafficTable))

        if ethaddrDst in switchPortEthaddrList:
            print("destination is switch itself")
            print('*'*100)
            continue    #destination is switch itself
        elif dstPortName =="broadcast":
            print("broadcast")
            for intf in net.interfaces():
                #print (intf.name, intf.ethaddr, intf.ipaddr, intf.netmask)
                if inputPortName != intf.name:
                    net.send_packet(intf.name, packet)
        else:
            net.send_packet(dstPortName, packet)
            print("unicast destiny port:" + dstPortName)
        print('*'*100)
        #net.send_packet(inputPortName, packet)














