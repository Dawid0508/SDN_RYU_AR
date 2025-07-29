# dijkstra_controller.py
# -*- coding: utf-8 -*-


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import event
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

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Rejestracja przełącznika: %s', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Wyrejestrowanie przełącznika: %s', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
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
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
            
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        # Uczymy się MAC->port tylko dla pierwszego przełącznika, do którego podłączony jest host
        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port)
            self.net.add_edge(src, dpid)
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src] = in_port

        # Jeśli MAC docelowy jest znany, spróbuj znaleźć i zainstalować ścieżkę
        if dst in self.net:
            try:
                # Oblicz najkrótszą ścieżkę
                path = nx.shortest_path(self.net, src, dst)
                self.logger.info("Znaleziona ścieżka z %s do %s: %s", src, dst, path)
                
                # Zainstaluj reguły przepływu na ścieżce
                self.install_path(path, eth.ethertype, src, dst)

                # Wyślij bieżący pakiet do celu
                out_port = self.get_out_port(datapath, src, dst, path)
                if out_port is not None:
                    self.send_packet_out(datapath, msg.buffer_id, in_port, out_port, msg.data)

            except nx.NetworkXNoPath:
                # Jeśli ścieżki nie znaleziono (np. topologia nie jest jeszcze w pełni znana), zalej sieć
                self.logger.warning("Ścieżka z %s do %s nieznana. Zalewanie sieci (flood)...", src, dst)
                self.flood(msg)
        else:
            # Jeśli MAC docelowy jest nieznany, zawsze zalewaj sieć (kluczowe dla ARP)
            self.flood(msg)

    def get_out_port(self, datapath, src, dst, path):
        try:
            next_hop = path[path.index(datapath.id) + 1]
            out_port = self.net[datapath.id][next_hop]['port']
            return out_port
        except (IndexError, KeyError):
            # Ostatni przełącznik na ścieżce - port wyjściowy prowadzi bezpośrednio do hosta
            return self.mac_to_port.get(datapath.id, {}).get(dst)


    def install_path(self, path, ethertype, src_mac, dst_mac):
        # Instalujemy reguły tylko dla przełączników (pomijamy hosty na końcach ścieżki)
        for i, dpid in enumerate(path[1:-1]):
            datapath = self.datapaths[dpid]
            parser = datapath.ofproto_parser
            
            # Port wejściowy i wyjściowy dla danego przełącznika na ścieżce
            port_in = self.net[path[i]][dpid]['port'] # path[i] to poprzedni węzeł
            port_out = self.net[dpid][path[i+2]]['port'] # path[i+2] to następny węzeł
            
            match = parser.OFPMatch(in_port=port_in, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(port_out)]

            self.add_flow(datapath, 10, match, actions)
            self.logger.info("Instalacja reguły na s%s: %s -> %s (in_port:%s -> out_port:%s)", dpid, src_mac, dst_mac, port_in, port_out)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def send_packet_out(self, datapath, buffer_id, in_port, out_port, data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)