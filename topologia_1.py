from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink # Ważne dla ustawienia przepustowości
from mininet.log import setLogLevel, info
from mininet.topo import Topo

class Famtartopo( Topo ):
    """Prosta topologia do testowania FAMTAR."""

    def build( self ):
        "Tworzenie topologii."

        # Dodawanie przełączników
        info( '*** Dodawanie przełączników\n')
        s1 = self.addSwitch( 's1', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s2 = self.addSwitch( 's2', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s3 = self.addSwitch( 's3', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s4 = self.addSwitch( 's4', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        # Dodawanie hostów
        info( '*** Dodawanie hostów\n')
        h1 = self.addHost( 'h1', ip='10.0.0.1/24' )
        h2 = self.addHost( 'h2', ip='10.0.0.2/24' )
        h3 = self.addHost( 'h3', ip='10.0.0.3/24' )
        h4 = self.addHost( 'h4', ip='10.0.0.4/24' )

        # Dodawanie łączy między przełącznikami (z niską przepustowością dla łatwiejszego testowania obciążenia)
        info( '*** Dodawanie łączy między przełącznikami\n')
        # Ustaw przepustowość (bw) na niższą wartość (np. 10 Mbps)
        link_opts_sw = dict(bw=10, delay='5ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink( s1, s2, **link_opts_sw )
        self.addLink( s2, s3, **link_opts_sw )
        self.addLink( s3, s4, **link_opts_sw )
        self.addLink( s4, s1, **link_opts_sw )
        self.addLink( s1, s3, **link_opts_sw ) # Łącze diagonalne dla dodatkowych ścieżek

        # Dodawanie łączy między hostami a przełącznikami (z większą przepustowością)
        info( '*** Dodawanie łączy host-przełącznik\n')
        link_opts_host = dict(bw=100) # Możesz dostosować przepustowość
        self.addLink( h1, s1, **link_opts_host )
        self.addLink( h2, s2, **link_opts_host )
        self.addLink( h3, s3, **link_opts_host )
        self.addLink( h4, s4, **link_opts_host )


def run():
    """Uruchamianie topologii Mininet."""
    # Utworzenie kontrolera zdalnego (zakładając, że Ryu działa lokalnie na domyślnym porcie 6653)
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)

    # Utworzenie sieci Mininet z użyciem topologii Famtartopo i TCLink
    net = Mininet(topo=Famtartopo(),
                switch=OVSKernelSwitch,
                controller=c0,
                link=TCLink, # Kluczowe dla ustawienia przepustowości
                autoSetMacs=True)

    info( '*** Uruchamianie sieci\n')
    net.start()

    info( '*** Uruchamianie CLI Mininet\n')
    CLI(net) # Otwiera interfejs linii komend Mininet

    info( '*** Zatrzymywanie sieci')
    net.stop()

if __name__ == '__main__':
    # Ustawienie poziomu logowania
    setLogLevel( 'info' )
    # Uruchomienie funkcji run
    run()