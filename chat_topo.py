from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def simple_topo():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)

    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    # Hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')

    # Switches
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')

    # Links
    net.addLink(h1, s1, bw=100, delay='1ms')
    net.addLink(h2, s3, bw=100, delay='1ms')
    net.addLink(s1, s2, bw=10, delay='1ms')
    net.addLink(s2, s3, bw=10, delay='1ms')

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simple_topo()
