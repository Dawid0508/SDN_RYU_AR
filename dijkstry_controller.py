# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link
from ryu.topology import event
import networkx as nx

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.net = nx.DiGraph()
        self.topology_api_app = self
        self.logger.info("--- Aplikacja Kontrolera FAMTAR (Dijkstra) uruchomiona ---")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"SWITCH: Podłączono przełącznik DPID: {datapath.id:016x}")

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"FLOW: Instaluję regułę na DPID {datapath.id:016x} dla {match} -> {actions}")

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self.logger.info("TOPOLOGY: Wykryto zmianę w topologii, aktualizuję graf...")
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        self.logger.info(f"TOPOLOGY: Znalezione przełączniki: {switches}")

        links_list = get_link(self.topology_api_app, None)
        for link in links_list:
            # Dodajemy wagę '1' do każdego połączenia. To tu będziemy implementować FAMTAR.
            self.net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no, weight=1)
            self.net.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no, weight=1)
        self.logger.info(f"TOPOLOGY: Znalezione połączenia: {self.net.edges()}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src

        # Ignoruj LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.logger.info(f"\n--- Nowy pakiet ---")
        self.logger.info(f"PACKET_IN: Otrzymano pakiet na DPID {dpid:016x} porcie {in_port}")
        self.logger.info(f"           SRC: {src} -> DST: {dst}")

        # Jeśli to ARP, oznacz go
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info("           TYP: To jest pakiet ARP")

        # Uczenie się źródła
        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port, weight=0) # Połączenie host-switch ma koszt 0
            self.net.add_edge(src, dpid, weight=0)
            self.logger.info(f"LEARN: Nowy host {src} dodany do grafu, podłączony do {dpid} port {in_port}")

        # Logika routingu
        if dst in self.net:
            self.logger.info(f"ROUTE: Cel {dst} jest ZNANY. Obliczam ścieżkę Dijkstrą...")
            try:
                path = nx.shortest_path(self.net, src, dst, weight='weight')
                self.logger.info(f"       -> Znaleziona ścieżka: {path}")
                
                next_hop = path[path.index(dpid) + 1]
                out_port = self.net.get_edge_data(dpid, next_hop)['port']
                self.logger.info(f"       -> Następny krok z {dpid} to {next_hop} przez port {out_port}")

                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                match = datapath.ofproto_parser.OFPMatch(eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)

                # Wyślij oryginalny pakiet tą ścieżką
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                    actions=actions, data=msg.data)
                datapath.send_msg(out)
                
            except nx.NetworkXNoPath:
                self.logger.warning(f"WARN: Cel {dst} jest w grafie, ale nie znaleziono ścieżki z {src}!")
        else:
            self.logger.info(f"ROUTE: Cel {dst} jest NIEZNANY. Zalewam sieć (FLOOD)...")
            out_port = datapath.ofproto.OFPP_FLOOD
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
                in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)