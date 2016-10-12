#!/usr/bin/env python3

'''
Ethernet learning switch in Python: HW3.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    lru = {}   #addr-priority
    forwarding = {} #addr-port
    while True:
        try:
            dev,packet = net.recv_packet()
        except NoPackets:
            print("No packets exception")
            continue
        except Shutdown:
            print("shut down")
            return


        e_src = packet[0].src;
        e_dst = packet[0].dst;
        if len(lru) < 5 and e_src not in lru:                    #if lru cache is not full, add new entry directly using table's length as their priority.
            lru[e_src] = len(lru)
        elif e_src in lru:                  #update priority of old entry
            if not lru[e_src] == dev:
                lru[e_src] = dev
            if e_dst in lru
                for entry in lru:
                    if lru[entry] > lru[e_dst]:
                        lru[entry] = lru[entry] - 1
            lru[e_dst] = len(lru)           #update priority of this recently used entry
        else:                               #if e_src is not recorded, remove the entry with the least priority.
            lowest = min(lru, key = lambda x:lru.get(x))
            del lru[lowest]
            del forwarding[lowest]
            for entry in lru:
                if lru[entry] > lru[e_src]:
                    lru[entry] = lru[entry] - 1
            lru[e_src] = len(lru)

        forwarding[e_src] = dev
        sentFlag = False
        log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            if e_dst in forwarding:
                log_debug ("packet sending to {}, through port {}".format(e_dst,forwarding[e_dst]))
                net.send_packet(forwarding[e_dst],packet)
                sentFlag = True
            if sentFlag == False:
                for intf in my_interfaces:
                    if dev != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
