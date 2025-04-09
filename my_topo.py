#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet(controller=RemoteController,
                    switch=OVSKernelSwitch, 
                    link=TCLink,
                    autoSetMacs=True,)

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                    controller=RemoteController,
                    ip='127.0.0.1',
                    protocol='tcp',
                    port=6653)

    info( '*** Add switches (OpenFlow 1.3)\n')
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch, protocols='OpenFlow13')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch, protocols='OpenFlow13')

    info( '*** Add hosts\n')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2/24', mac='00:00:00:00:00:01')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1/24',  mac='00:00:00:00:00:02')

    # Definiowanie opcji dla łączy
    link_opts_sw = dict(bw=10, delay='1ms')
    link_opts_host = dict(bw=100, delay='1ms')

    info( '*** Add links\n')
    net.addLink(h1, s1, **link_opts_host)
    net.addLink(h2, s4, **link_opts_host)
    
    net.addLink(s1, s2, **link_opts_sw)
    net.addLink(s1, s3, **link_opts_host)
    net.addLink(s1, s5, **link_opts_host)
    
    net.addLink(s2, s4, **link_opts_sw)
    net.addLink(s2, s5, **link_opts_sw)
    
    net.addLink(s3, s4, **link_opts_host)
    net.addLink(s3, s5, **link_opts_sw)
    
    net.addLink(s4, s5, **link_opts_sw)

    info( '*** Starting network\n')
    net.start()

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
