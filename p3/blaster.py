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
    content = RawPacketContents(seq_num.to_bytes(4, byteorder='big')+payload_len.to_bytes(2, byteorder='big')+(b'z'*payload_len))
    return e + ip + UDP()+ content

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
    recv_timeout = float(recv_timeout)/1000.0
    dprint("blastee_IP = %s, num_pkt = %s,length_payload = %s,sender_window = %s,timeout = %s,recv_timeout = %s"%(blastee_IP, num_pkt,length_payload,sender_window,timeout,recv_timeout))
    if blastee_IP is None:
        blastee_IP = '192.168.200.1'
    ACKed = set() #
    pending = []    # queue keeping all pending packet
    LHS=1
    RHS=min(LHS+sender_window-1,num_pkt)
    for i in range(LHS,RHS+1):
        pending.append(i)

    timeCounter = recv_timeout      #assume recv_timeout < coarse timeout
    timeout_boundary = time.time() + timeout
    start = time.time()
    cnt_sent = 0
    cnt_coarseTO = 0
    while True:
        if time.time() >= timeout_boundary:
            dprint("at time:{}, reset pending queue".format(time.time()-start))
            pending.clear()
            for i in range(LHS,RHS+1):
                if i not in ACKed:
                    pending.append(i)

            seq_num = pending.pop(0)    #get first seq# to send
            send_pkt = new_pkt(seq_num,length_payload)
            net.send_packet(devname, send_pkt)
            dprint("at time:{}, sent packet: {}".format(time.time()-start,seq_num))
            cnt_sent += 1
            
            timeCounter = recv_timeout
            timeout_boundary = time.time() + timeout

            cnt_coarseTO += 1
        elif len(pending)>0:

            seq_num = pending.pop(0)    #get first seq# to send
            send_pkt = new_pkt(seq_num,length_payload)
            net.send_packet(devname, send_pkt)
            #dprint("at time:{}, sent packet: {}".format(time.time()-start,send_pkt))
            dprint("at time:{}, sent packet: {}".format(time.time()-start,seq_num))
            cnt_sent += 1
            if len(pending)==0:     #when just sent last packet
                timeCounter = max(timeout_boundary - time.time(),0.00001)
            else:   #len(pending)>0
                timeCounter = min(timeout_boundary - time.time(),recv_timeout)
        else: # len(pending) == 0

            timeCounter = max(timeout_boundary - time.time(),0.00001)

        gotpkt = True

        try:
            dprint("pending packet:"+str(pending) + ", ACKed packets:"+str(ACKed))
            dev,pkt = net.recv_packet(timeCounter)
        except NoPackets:
            dprint("timeout occurs!")
            gotpkt = False
        except Shutdown:
            dprint("Got ShutDown signal")
            break

        if gotpkt:
            rawData = pkt.get_header('RawPacketContents').to_bytes()
            if len(rawData)!=12:    #incorrect format for ACK packet
                dprint("at time:{}, incorrect received length".format(time.time()-start))
                continue

            seq_num = int.from_bytes(rawData[0:4],'big')
            dprint("at time:{}, received packet:{}".format(time.time()-start,seq_num))
            if seq_num in ACKed:      #seq_num already in ACKed
                dprint("seq num already acked")
                continue
            ACKed.add(seq_num)
            pending = [x for x in pending if x != seq_num]  #also need to remove tasks in pending queue
            if seq_num != LHS:
                continue   

            #case seq_num == LHS: will move sender window and reset timer
            send_pos = RHS+1
                       
            LHS = max(ACKed)+1 if len(ACKed) > 0 else 0 #move LHS
            if LHS>num_pkt:     # when all pkts are sent
                finish_time = time.time()
                if finish_time <= start:
                    finish_time = start + 0.0001    #avoid divide-by-zero
                dprint("at time:{},all packets sent!".format(finish_time-start))

                dprint("print the stats here.....")
                #notice here dprint vs print
                print("Total TX time (in seconds): "+str(finish_time-start))
                print("Number of reTX: "+str(cnt_sent - num_pkt))
                print("Number of coarse TOs: "+str(cnt_coarseTO))
                print("Throughput (Bps): "+str((cnt_sent * length_payload)/(finish_time-start)))
                print("Goodput (Bps): "+str((num_pkt * length_payload)/(finish_time-start)))

                break
            RHS=min(LHS+sender_window-1,num_pkt) #move RHS
            for i in range(send_pos,RHS+1):     #send out new added packets in the new window
                pending.append(i)
            timeCounter = recv_timeout 
            timeout_boundary = time.time() + timeout     #reset coarse timeout


    net.shutdown()
