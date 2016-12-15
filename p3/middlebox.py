#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from threading import *
import random
from random import randint
import time

def dprint(mstr,switch=False):
    if switch is True:
        print(mstr)

def read_params():

    f = open('middlebox_params.txt', 'r')
    for line in f:
        params = line.strip('\n').split(' ')
        if '-d' in params:
            idx = params.index('-d')
            if idx+1<len(params):   #make sure index inside boundary
                return params[idx+1]
    return None

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    drop_rate = float(read_params())
    dprint("drop_rate:"+str(drop_rate))
    start = time.time()
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

        if gotpkt is False:
            continue
            

        if dev == "middlebox-eth0":
            dprint("at time:{}, received packet from blaster:{}".format(time.time()-start,pkt))
            if random.uniform(0, 1) <= drop_rate:   #drop packet
                dprint("at time:{}, drop packet: {}".format(time.time()-start,pkt))
                continue

            Ipv4Header = pkt.get_header("IPv4")
            EthHeader = pkt.get_header("Ethernet")
            
            if Ipv4Header.src == IPv4Address('192.168.100.1') and Ipv4Header.dst == IPv4Address('192.168.200.1'):
                EthHeader.src = '40:00:00:00:00:02'
                EthHeader.dst = '20:00:00:00:00:01'
                net.send_packet("middlebox-eth1", pkt)
                dprint("at time:{}, sent packet: {}".format(time.time()-start,pkt))
            else:
                dprint("at time:{}, drop packet: {}".format(time.time()-start,pkt))


            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
        elif dev == "middlebox-eth1":
            dprint("at time:{}, receive packet from blastee: {}".format(time.time()-start,pkt)) 

            Ipv4Header = pkt.get_header("IPv4")
            EthHeader = pkt.get_header("Ethernet")

            if Ipv4Header.src == IPv4Address('192.168.200.1') and Ipv4Header.dst == IPv4Address('192.168.100.1'):
                EthHeader.src = '40:00:00:00:00:01'
                EthHeader.dst = '10:00:00:00:00:01'
                net.send_packet("middlebox-eth0", pkt)
                dprint("at time:{}, sent packet: {}".format(time.time()-start,pkt))
            else:
                dprint("at time:{}, drop packet: {}".format(time.time()-start,pkt))


        else:
            dprint("Oops :))")

    net.shutdown()
