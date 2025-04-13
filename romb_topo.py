#!/usr/bin/env python
# -*- coding: utf-8 -*- # Dodaj kodowanie

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch # Usun nieuzywane importy jak IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    # Ustaw controller na None, dodamy go pozniej
    # Ustaw domyslny switch i link
    net = Mininet(controller=None,
                    switch=OVSKernelSwitch,
                    link=TCLink,
                    autoSetMacs=True)

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                    controller=RemoteController,
                    ip='127.0.0.1',
                    protocol='tcp',
                    port=6653) # Uzyj portu 6653 dla Ryu

    info( '*** Add switches (OpenFlow 1.3)\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13') # Dodaj protocols
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    s4 = net.addSwitch('s4', protocols='OpenFlow13')
    s5 = net.addSwitch('s5', protocols='OpenFlow13')

    info( '*** Add hosts\n')
    # Upewnij sie, ze MAC adresy sa unikalne
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2/24', mac='00:00:00:00:00:02')

    # Definiowanie opcji dla laczy (delay jest opcjonalny)
    link_opts_sw = dict(bw=10) # Niska przepustowosc miedzy switchami
    link_opts_host = dict(bw=100) # Wyzsza dla hostow

    info( '*** Add links\n')
    # Hosty
    net.addLink(h1, s1, **link_opts_host)
    net.addLink(h2, s4, **link_opts_host)

    # Polaczenia miedzy switchami (sprawdz dokladnie topologie!)
    net.addLink(s1, s2, **link_opts_sw)
    net.addLink(s1, s3, **link_opts_sw) # Czy to ma byc host bw? Raczej sw
    net.addLink(s1, s5, **link_opts_sw) # Czy to ma byc host bw? Raczej sw

    net.addLink(s2, s4, **link_opts_sw)
    net.addLink(s2, s5, **link_opts_sw)

    net.addLink(s3, s4, **link_opts_sw) # Czy to ma byc host bw? Raczej sw
    net.addLink(s3, s5, **link_opts_sw)

    net.addLink(s4, s5, **link_opts_sw)

    info( '*** Starting network\n')
    net.start() # Uzyj net.start() zamiast recznego budowania i startowania

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()