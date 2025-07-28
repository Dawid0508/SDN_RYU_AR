# topo3.py

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info

class MyTopo(Topo):
    def build(self):
        h1 = self.addHost('h1', ip='10.0.0.21', mac='00:00:00:00:00:11')
        h2 = self.addHost('h2', ip='10.0.0.22', mac='00:00:00:00:00:12')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')

        self.addLink(h1, s1)
        self.addLink(h2, s5)
        self.addLink(s1, s2, bw=1.544)
        self.addLink(s3, s5, bw=1.544)
        self.addLink(s3, s4, bw=10)
        self.addLink(s2, s5, bw=10)

def run_topo():
    topo = MyTopo()
    net = Mininet(topo=topo, build=False, ipBase='10.0.0.0/8', link=TCLink, controller=None)
    
    info("Adding the RemoteController\n")
    net.addController('c0', ip='127.0.0.1', protocol='tcp', controller=RemoteController, port=6653)

    net.start()
    info('*** Starting Network\n')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_topo()