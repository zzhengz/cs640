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
import time
#switch standard, not able to handle topology changes


def main(net):

    for intf in net.interfaces():
        print (intf.name, intf.ethaddr, intf.ipaddr, intf.netmask)
    #debug use, print out all available ports


    forwardingTable = dict()        #forwardingTable stores mapping from host MAC address to port.name of switch 
    portList = net.interfaces() 
    ethaddrList = [intf.ethaddr for intf in portList]

    while True:
        try:
            inputPortName,packet = net.recv_packet()
        except Shutdown:
            print ("Got shutdown signal; exiting")
            return
        except NoPackets:
            print ("No packets were available.")
            continue
        except BaseException as e:
            print ("uncatched exception happend when receiving packet: " + str(e))
            return
        # if we get here, we must have received a packet
        
        print ("Received {} on {}".format(packet, inputPortName))
        print("packet headers: "+str(packet.headers()))

        port = net.port_by_name(inputPortName)
        if port is None:
            continue
        #print(type(port))

        ethaddrSrc = packet[0].src
        ethaddrDst = packet[0].dst
        ethaddr_broadcast = EthAddr("ff:ff:ff:ff:ff:ff")

        if (ethaddrSrc in forwardingTable and inputPortName!=forwardingTable[ethaddrSrc]) or ethaddrSrc not in forwardingTable:
            forwardingTable[ethaddrSrc] = inputPortName
        #updating forwarding table

        print("forwardingTable: "+str(forwardingTable))
        #print updated forwarding table

        if ethaddrDst in ethaddrList:    #destination is switch itself
            print("destiny is switch itself")
            continue
        elif ethaddrDst == ethaddr_broadcast or ethaddrDst not in forwardingTable :
            print("broadcast")
            for intf in net.interfaces():
                #print (intf.name, intf.ethaddr, intf.ipaddr, intf.netmask)
                if inputPortName != intf.name:
                    net.send_packet(intf.name, packet)
        else:
            print("unicast")
            dstPortName = forwardingTable[ethaddrDst]
            dstPort = net.port_by_name(dstPortName)
            net.send_packet(dstPort.name, packet)
        print('*'*100)
        #net.send_packet(inputPortName, packet)














