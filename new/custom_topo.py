#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def create_topology():
    """
    Tworzy i uruchamia niestandardową topologię sieci.
    """
    # Upewnij się, że Mininet jest czysty przed startem
    # Chociaż 'mn -c' jest lepsze, to dodatkowe zabezpieczenie
    
    net = Mininet(
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True,
        cleanup=True # Automatyczne czyszczenie po zamknięciu
    )

    info("*** Tworzenie hostów\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')

    info("*** Tworzenie przełączników\n")
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')

    info("*** Tworzenie połączeń\n")
    # Hosty do przełączników
    net.addLink(h1, s1)
    net.addLink(h2, s2) # h2 podłączony do s2
    net.addLink(h3, s3)
    net.addLink(h4, s4)

    # Przełączniki między sobą
    net.addLink(s1, s2)
    net.addLink(s1, s3)
    net.addLink(s2, s4)
    net.addLink(s3, s4)
    # To połączenie jest kluczowe do testowania Dijkstry
    net.addLink(s1, s4) 

    info("*** Uruchamianie sieci\n")
    net.build()
    net.start()

    info("*** Uruchamianie CLI\n")
    CLI(net)

    info("*** Zatrzymywanie sieci\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()