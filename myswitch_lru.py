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
#switch SDN


def main(net):

    for intf in net.interfaces():
        print (intf.name, intf.ethaddr, intf.ipaddr, intf.netmask)
    #debug use, print out all available ports
    lruSize = 0
    lruEthNum = dict()      #lru table: MAC address => index
    lruNumEth = dict()      #lru table: index => MAC address
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

        if ethaddrDst in lruEthNum:
            for i in range(lruEthNum[ethaddrDst],lruSize-1):
                lruNumEth[i]=lruNumEth[i+1]
                lruEthNum[lruNumEth[i]] -= 1
            lruEthNum[ethaddrDst] = lruSize-1
            lruNumEth[lruSize-1] = ethaddrDst
        #touch destiny in LRU

        if ethaddrSrc in lruEthNum:     #if source in lru, make it newest
            for i in range(lruEthNum[ethaddrSrc],lruSize-1):
                lruNumEth[i]=lruNumEth[i+1]
                lruEthNum[lruNumEth[i]] -= 1
            lruEthNum[ethaddrSrc] = lruSize-1
            lruNumEth[lruSize-1] = ethaddrSrc
            
        elif lruSize < 5:    #if source not in lru and lru not full, add it in
            lruNumEth[lruSize] = ethaddrSrc
            lruEthNum[ethaddrSrc] = lruSize
            lruSize+=1
        else:
            ethToEvict = lruNumEth[0]
            for i in range(0,4):
                lruNumEth[i]=lruNumEth[i+1]
                lruEthNum[lruNumEth[i+1]] -= 1
            forwardingTable.pop(ethToEvict)
            lruEthNum.pop(ethToEvict)
            lruEthNum[ethaddrSrc] = 4
            lruNumEth[4] = ethaddrSrc
        #touch source in LRU

        forwardingTable[ethaddrSrc] = inputPortName
        #updating forwarding table and LRU

        print("forwardingTable: "+str(forwardingTable))
        print("lruNumEth: "+str(lruNumEth))
        print("lruEthNum: "+str(lruEthNum))



        if ethaddrDst in switchPortEthaddrList:
            print("destination is switch itself")
            print('*'*100)
            continue    #destination is switch itself
        elif ethaddrDst == ethaddr_broadcast or ethaddrDst not in forwardingTable :
            print("broadcast")
            for intf in net.interfaces():
                #print (intf.name, intf.ethaddr, intf.ipaddr, intf.netmask)
                if inputPortName != intf.name:
                    net.send_packet(intf.name, packet)
        else:
            dstPortName = forwardingTable[ethaddrDst]
            dstPort = net.port_by_name(dstPortName)
            net.send_packet(dstPort.name, packet)
            print("unicast destiny port:" + dstPortName)
        print('*'*100)
        #net.send_packet(inputPortName, packet)














