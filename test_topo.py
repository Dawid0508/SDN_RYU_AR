# -*- coding: utf-8 -*-
#!/usr/bin/python

"""
Skrypt tworzący topologię sieci do testowania kontrolera Ryu z algorytmem Dijkstry/FAMTAR.

Topologia:
    h1 --- s1 --- s2 --- s4 --- h4  (Ścieżka "szybka", przepustowość 100 Mbps)
            |      |      |
            \----- s3 -----/      (Ścieżka "wolna", przepustowość 10 Mbps)

- h1, h4: Hosty końcowe
- s1, s2, s3, s4: Przełączniki OpenFlow

Aby uruchomić:
1. W jednym terminalu uruchom kontroler Ryu:
    ryu-manager dijkstra_Ryu_controller.py

2. W drugim terminalu uruchom ten skrypt z uprawnieniami roota:
    sudo python test_topo.py
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info

def create_topology():
    """Tworzy i uruchamia niestandardową topologię sieci."""

    net = Mininet(controller=RemoteController, 
                    switch=OVSKernelSwitch, 
                    link=TCLink, 
                    autoSetMacs=True)

    info('*** Adding controller\n')
    c0 = net.addController('c0', 
                            controller=RemoteController, 
                            ip='127.0.0.1', 
                            protocol='tcp',
                            port=6653)

    info('*** Dodawanie hostów\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')

    info('*** Dodawanie przełączników\n')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')

    info('*** Tworzenie połączeń i ustawianie "kosztów" (przepustowości)\n')
    
    # Połączenia hostów z siecią
    net.addLink(h1, s1)
    net.addLink(h4, s4)

    # ŚCIEŻKA SZYBKA (wysoka przepustowość = niski koszt dla algorytmu)
    # Parametr bw (bandwidth) jest podany w Mb/s
    net.addLink(s1, s2, bw=100)
    net.addLink(s2, s4, bw=100)

    # ŚCIEŻKA WOLNA (niska przepustowość = wysoki koszt dla algorytmu)
    net.addLink(s1, s3, bw=10)
    net.addLink(s3, s4, bw=10)

    info('*** Uruchamianie sieci\n')
    net.build()
    c0.start()
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])
    net.get('s5').start([c0])

    info('*** Uruchamianie interfejsu wiersza poleceń (CLI)\n')
    CLI(net)

    info('*** Zatrzymywanie sieci\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()