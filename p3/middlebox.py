#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from threading import *
from random import randint
import time

def dprint(mstr,switch=True):
    if switch is True:
        print(mstr)

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    f = open('middlebox_param.txt','r')
    line = f.readline()
    token = line.strip('\n').split(' ')
    DP = token[1]
    while True:
        gotpkt = True
        try:
            dev,pkt = net.recv_packet()
        except NoPackets:
            dprint("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            dprint("Got shutdown signal")
            break

        if gotpkt:
            dprint("received packet: {}".format(pkt))
            
            

        if dev == "middlebox-eth0":
            dprint("Received from blaster")

            Ipv4Header = pkt.get_header("IPv4")
            EthHeader = pkt.get_header("Ethernet")
            
            if Ipv4Header.src == IPv4Address('192.168.100.1') and Ipv4Header.dst == IPv4Address('192.168.200.1'):
                EthHeader.src = '40:00:00:00:00:02'
                EthHeader.dst = '20:00:00:00:00:01'
                P = random.randint(1,100)
                if(P > DP * 100):
                    net.send_packet("middlebox-eth1", pkt)
                    dprint("sent packet: {}".format(pkt))
                else:
                    dprint('pkt dropped: {}'.format(pkt))
            else:
                dprint('pkt dropped: {}'.format(pkt))


            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
        elif dev == "middlebox-eth1":
            dprint("Received from blastee")

            Ipv4Header = pkt.get_header("IPv4")
            EthHeader = pkt.get_header("Ethernet")

            if Ipv4Header.src == IPv4Address('192.168.200.1') and Ipv4Header.dst == IPv4Address('192.168.100.1'):
                EthHeader.src = '40:00:00:00:00:01'
                EthHeader.dst = '10:00:00:00:00:01'
                net.send_packet("middlebox-eth0", pkt)
                dprint("sent packet: {}".format(pkt))
            else:
                dprint('pkt dropped: {}'.format(pkt))




            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
        else:
            dprint("Oops :))")

    net.shutdown()
