# dijkstra_controller.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import networkx as nx

class DijkstraController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DijkstraController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.mac_to_port = {}
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        Obsługuje zmiany stanu przełączników (podłączanie/odłączanie).
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('Rejestracja przełącznika: %s', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Wyrejestrowanie przełącznika: %s', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        """
        Obsługuje zdarzenie dołączenia nowego przełącznika do topologii.
        Buduje graf sieci.
        """
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)

        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        self.logger.info("**** Odkryto %s przełączników i %s połączeń ****", len(switches), len(links_list))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Obsługuje przychodzące pakiety (PacketIn).
        Uczy się adresów MAC i instaluje ścieżki.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignoruj pakiety LLDP, używane do odkrywania topologii
            return
            
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # Zapamiętaj port dla danego adresu MAC
        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port)
            self.net.add_edge(src, dpid)
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src] = in_port

        if dst in self.net:
            # Znajdź najkrótszą ścieżkę używając algorytmu Dijkstry
            path = nx.shortest_path(self.net, src, dst)
            self.logger.info("Najkrótsza ścieżka z %s do %s: %s", src, dst, path)

            # Zainstaluj reguły przepływu na przełącznikach wzdłuż ścieżki
            self.install_path(path, ev, src, dst)
            
            # Wyślij pakiet dalej
            out_port = self.get_out_port(datapath, src, dst, path)
            if out_port is not None:
                self.send_packet_out(datapath, msg.buffer_id, in_port, out_port, msg.data)
        else:
            # Jeśli adres docelowy nie jest znany, zalej sieć (flood)
            self.flood(msg)

    def get_out_port(self, datapath, src, dst, path):
        """
        Pobiera port wyjściowy dla danego przełącznika na ścieżce.
        """
        try:
            next_hop = path[path.index(datapath.id) + 1]
            out_port = self.net[datapath.id][next_hop]['port']
            return out_port
        except IndexError:
            # Ostatni przełącznik na ścieżce
            if dst in self.mac_to_port[datapath.id]:
                return self.mac_to_port[datapath.id][dst]
            return None

    def install_path(self, path, ev, src_mac, dst_mac):
        """
        Instaluje reguły przepływu (flow rules) na przełącznikach wzdłuż ścieżki.
        """
        for i, dpid in enumerate(path[:-1]):
            if not isinstance(dpid, str): # Upewnij się, że to przełącznik
                datapath = self.datapaths[dpid]
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                
                next_dpid = path[i+1]
                out_port = self.net[dpid][next_dpid]['port']
                
                match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
                actions = [parser.OFPActionOutput(out_port)]

                self.add_flow(datapath, 10, match, actions)
                self.logger.info("Instalacja reguły na s%s: %s -> %s port %s", dpid, src_mac, dst_mac, out_port)

    def add_flow(self, datapath, priority, match, actions):
        """
        Dodaje regułę przepływu do przełącznika.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def flood(self, msg):
        """
        Zalewa sieć pakietem (wysyła na wszystkie porty oprócz wejściowego).
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def send_packet_out(self, datapath, buffer_id, in_port, out_port, data):
        """
        Wysyła pakiet (PacketOut) z przełącznika.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)