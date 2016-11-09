#!/usr/bin/python

import sys

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange, custom, quietRun, dumpNetConnections
from mininet.cli import CLI

from time import sleep, time
from subprocess import Popen, PIPE
import subprocess
import argparse
import os

parser = argparse.ArgumentParser(description="Mininet pyswitch topology")
# no arguments needed as yet :-)
args = parser.parse_args()
lg.setLogLevel('info')

class PySwitchTopo(Topo):

    def __init__(self, args):
        # Add default members to class.
        super(PySwitchTopo, self).__init__()


        nodeconfig = {'cpu':-1}
        self.addHost('h1', **nodeconfig)
        self.addHost('h2', **nodeconfig)
        self.addHost('h3', **nodeconfig)
        self.addHost('h4', **nodeconfig)
        self.addHost('h5', **nodeconfig)
        self.addHost('h6', **nodeconfig)
        self.addHost('h7', **nodeconfig)
        self.addHost('h8', **nodeconfig)
        self.addHost('s1', **nodeconfig)
        
        for node in ['h1','h2','h3','h4','h5','h6','h7','h8']:
            # all links are 10Mb/s, 100 millisecond prop delay
            self.addLink(node, 's1', bw=10, delay='100ms')

def set_ip(net, node1, node2, ip):
    node1 = net.get(node1)
    ilist = node1.connectionsTo(net.get(node2)) # returns list of tuples
    intf = ilist[0]
    intf[0].setIP(ip)

def reset_macs(net, node, macbase):
    ifnum = 1
    node_object = net.get(node)
    for intf in node_object.intfList():
        node_object.setMAC(macbase.format(ifnum), intf)
        ifnum += 1

    for intf in node_object.intfList():
        print node,intf,node_object.MAC(intf)

def set_route(net, fromnode, prefix, nextnode):
    node_object = net.get(fromnode)
    ilist = node_object.connectionsTo(net.get(nextnode)) 
    node_object.setDefaultRoute(ilist[0][0])

def setup_addressing(net):
    reset_macs(net, 'h1', '10:00:00:00:00:{:02x}')
    reset_macs(net, 'h2', '20:00:00:00:00:{:02x}')
    reset_macs(net, 'h3', '30:00:00:00:00:{:02x}')
    reset_macs(net, 'h4', '40:00:00:00:00:{:02x}')
    reset_macs(net, 'h5', '50:00:00:00:00:{:02x}')
    reset_macs(net, 'h6', '60:00:00:00:00:{:02x}')
    reset_macs(net, 'h7', '70:00:00:00:00:{:02x}')
    reset_macs(net, 'h8', '80:00:00:00:00:{:02x}')
    reset_macs(net, 's1', '90:00:00:00:00:{:02x}')
    set_ip(net, 'h1','s1','192.168.100.1/24')
    set_ip(net, 'h2','s1','192.168.100.2/24')
    set_ip(net, 'h3','s1','192.168.100.3/24')
    set_ip(net, 'h4','s1','192.168.100.4/24')
    set_ip(net, 'h5','s1','192.168.100.5/24')
    set_ip(net, 'h6','s1','192.168.100.6/24')
    set_ip(net, 'h7','s1','192.168.100.7/24')
    set_ip(net, 'h8','s1','192.168.100.8/24')

def main():
    topo = PySwitchTopo(args)
    net = Mininet(controller=None, topo=topo, link=TCLink, cleanup=True)
    setup_addressing(net)
    net.interact()

if __name__ == '__main__':
    main()
