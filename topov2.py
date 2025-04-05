#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink # Ważne dla ustawienia przepustowości
from mininet.log import setLogLevel, info
from mininet.topo import Topo

class ProstaTopo( Topo ):
    """Prosta topologia trójkątna do testowania FAMTAR."""

    def build( self ):
        "Tworzenie topologii."

        info( '*** Dodawanie przełączników (OpenFlow 1.3)\n')
        s1 = self.addSwitch( 's1', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s2 = self.addSwitch( 's2', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s3 = self.addSwitch( 's3', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        info( '*** Dodawanie hostów\n')
        # Jawne ustawienie MAC adresów, aby pasowały do ewentualnego kodu kontrolera
        h1 = self.addHost( 'h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01' )
        h2 = self.addHost( 'h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02' )

        # Definiowanie opcji dla łączy
        # Niska przepustowość między przełącznikami (np. 10 Mbps) dla łatwiejszego testowania obciążenia
        link_opts_sw = dict(bw=10)
        # Wyższa przepustowość dla hostów (np. 100 Mbps)
        link_opts_host = dict(bw=100)

        info( '*** Dodawanie łączy między przełącznikami\n')
        self.addLink( s1, s2, **link_opts_sw )
        self.addLink( s2, s3, **link_opts_sw )
        self.addLink( s1, s3, **link_opts_sw ) # Zamykamy trójkąt

        info( '*** Dodawanie łączy host-przełącznik\n')
        self.addLink( h1, s1, **link_opts_host )
        self.addLink( h2, s3, **link_opts_host ) # h2 podłączony do s3


def run():
    """Uruchamianie topologii Mininet."""
    # Tworzymy instancję naszej topologii
    topo = ProstaTopo()

    # Tworzymy instancję kontrolera zdalnego
    # Zakładamy, że kontroler Ryu działa na 127.0.0.1:6653 (domyślny port Ryu)
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)

    # Tworzymy sieć Mininet
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch, # Używamy przełączników OVS
                  controller=c0,          # Podłączamy kontroler zdalny
                  link=TCLink,            # Używamy TCLink do kontroli przepustowości
                  autoSetMacs=True        # Można zostawić lub usunąć, bo MACi są ustawione jawnie
                  )

    info( '*** Uruchamianie sieci\n')
    net.start()

    # Możesz dodać komendy do wykonania po starcie, np. konfigurację hostów
    # info( '*** Konfiguracja hostów...\n')
    # h1 = net.get('h1')
    # h1.cmd('jakaś_komenda &')

    info( '*** Uruchamianie CLI Mininet\n')
    CLI(net) # Otwiera interfejs linii komend Mininet

    info( '*** Zatrzymywanie sieci\n')
    net.stop()

if __name__ == '__main__':
    # Ustawienie poziomu logowania na 'info' dla przejrzystości
    setLogLevel( 'info' )
    # Uruchomienie funkcji run
    run()