#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from random import randint
import time

def dprint(mstr,switch=True):
    if switch is True:
        print(mstr)

def read_params():

    ret = [None,None,None,None,None,None]
    template = ['-b','-n','-l','-w','-t','-r']
    f = open('blaster_params.txt', 'r')
    for line in f:
        params = line.strip('\n').split(' ')
        for i in range(len(ret)):
            if ret[i] is None:
                try:
                    ret[i] = params[params.index(template[i])+1]
                except BaseException as e:
                    pass
    return ret

def new_pkt(seq_num, payload_len):
    e = Ethernet()
    e.src = '10:00:00:00:00:01'
    e.dst = '40:00:00:00:00:01'
    ip = IPv4()
    ip.srcip = '192.168.100.1'
    ip.dstip = '192.168.200.1'
    ip.protocol = IPProtocol.UDP
    
    return e + ip + UDP()+RawPacketContents(seq_num.to_bytes(4, byteorder='big')+payload_len.to_bytes(2, byteorder='big')+(b'z'*payload_len))
def switchy_main(net):
    blastee_mac = '20:00:00:00:00:01'
    middlebox_er_mac = '40:00:00:00:00:01'
    middlebox_ee_mac = '40:00:00:00:00:02'
    middlebox_er_ip = '192.168.100.2'
    middlebox_ee_ip = '192.168.200.2'

    my_intf = net.interfaces()
    devname = None
    blaster_ip = None
    for intf in my_intf:
        devname = intf.name
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    blaster_ip = myips[0]
    blaster_mac = mymacs[0]
    blastee_IP = None
    blastee_IP, num_pkt,length_payload,sender_window,timeout,recv_timeout = read_params()
    num_pkt = int(num_pkt)
    length_payload = int(length_payload)
    sender_window = int(sender_window)
    timeout = float(timeout)/1000.0
    recv_timeout = int(recv_timeout)
    dprint("blastee_IP = %s, num_pkt = %s,length_payload = %s,sender_window = %s,timeout = %s,recv_timeout = %s"%(blastee_IP, num_pkt,length_payload,sender_window,timeout,recv_timeout))
    if blastee_IP is None:
        blastee_IP = '192.168.200.1'
    unACKed = set()
    pending = []
    LHS=1
    RHS=min(LHS+sender_window-1,num_pkt)
    
    
    for i in range(LHS,RHS+1):
        pending.append(i)

    #timeStamp = time.time()

    #for print stats
    startTime = time.time()
    reTransCount = 0
    toCount = 0
    totalLength = 0
    goodLength = 0
    notRe = set()
    while True:
        if len(pending)>0:
            timeCounter = recv_timeout
            seq_num = pending.pop(0)    #get first seq# to send
            send_pkt = new_pkt(seq_num,length_payload)
            totalLength += length_payload.bit_length()
            if seq_num not in notRe:
                goodLength += length_payload.bit_length()
                seq_num.add(seq_num)
            net.send_packet(devname, send_pkt)
            unACKed.add(seq_num)
            dprint("sent packet: {}".format(send_pkt))
        else:
            timeCounter = timeout   #no packet to send, wait coarse timeout
            
            for i in range(LHS,RHS+1):
                if i in unACKed:
                    pending.append(i)
        gotpkt = True
        try:
            dev,pkt = net.recv_packet(timeCounter)

            #dev,pkt = net.recv_packet(3.0)
        except NoPackets:
            dprint("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            dprint("Got ShutDown signal")
            break

        if gotpkt:
            dprint("received packet: {}".format(pkt))
            dprint("pending packet:"+str(pending) + ", unACKed packets:"+str(unACKed))
            rawData = pkt.get_header('RawPacketContents').to_bytes()
            if len(rawData)!=12:    #if incorrect format for ACK packet
                dprint("incorrect received length")
                continue

            seq_num = int.from_bytes(rawData[0:4],'big')
            if seq_num not in unACKed:
                dprint("seq num not in waiting list")
                continue
            unACKed.remove(seq_num)
            if seq_num != LHS:
                timeCounter= max(timeCounter-(time.time() -timeStamp),0.001)
                timeStamp = time.time()
                continue

            send_pos = RHS+1
            if len(unACKed) ==0:
                LHS=RHS+1
            else:
                LHS = min(unACKed)
            if LHS>num_pkt:
                dprint("all packets sent!")
                dprint("print the stats here.....")
                totalTime = time.time() - startTime
                break
            RHS=min(LHS+sender_window-1,num_pkt)
            for i in range(send_pos,RHS+1):     #send out new added packets in the new window
                unACKed.add(i)
                send_pkt = new_pkt(i,length_payload)
                net.send_packet(devname, send_pkt)
                dprint("sent packet: {}".format(send_pkt))
            timeStamp = time.time()     #reset timer
            timeCounter = timeout
                


        else:
            dprint("Didn't receive anything")

            for i in unACKed:
                send_pkt = new_pkt(i,length_payload)
                net.send_packet(devname, send_pkt)
                dprint("sent packet: {}".format(send_pkt))
            timeStamp = time.time()     #reset timer
            timeCounter = timeout
            '''
            Creating the headers for the packet
            '''
            #pkt = Ethernet() + IPv4() + UDP()
            #pkt[1].protocol = IPProtocol.UDP

            '''
            Do other things here and send packet
            '''

    net.shutdown()
