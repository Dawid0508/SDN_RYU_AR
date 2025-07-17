# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link
from ryu.topology import event
import networkx as nx

class PathfindingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # Kontekst dpset jest potrzebny do poprawnego działania get_datapath
    _CONTEXTS = {'dpset': dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(PathfindingController, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.net = nx.DiGraph()
        # Globalna tablica MAC: {mac_adres: (dpid, port)}
        self.mac_to_port = {}
        self.logger.info("--- Kontroler z logiką Dijkstry v2.1 (Final) uruchomiony ---")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"FLOW: Instaluję regułę na DPID {datapath.id:016x} dla {match} -> {actions}")

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        link = ev.link
        self.net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no, weight=1)
        self.net.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no, weight=1)
        self.logger.info(f"TOPOLOGY: Dodano połączenie dwukierunkowe {link.src.dpid} <-> {link.dst.dpid}")

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        self.net.add_node(ev.switch.dp.id)
        self.logger.info(f"TOPOLOGY: Dodano przełącznik {ev.switch.dp.id} do grafu.")

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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Naucz się globalnej lokalizacji adresu MAC źródła
        if src not in self.mac_to_port:
            self.mac_to_port[src] = (dpid, in_port)
            self.logger.info(f"LEARN: Nowy host {src} -> podłączony do {dpid} port {in_port}")

        if dst in self.mac_to_port:
            dst_dpid, dst_port = self.mac_to_port[dst]
            
            self.logger.info(f"ROUTE: Cel {dst} jest znany (na {dst_dpid}). Próbuję znaleźć ścieżkę z {dpid} do {dst_dpid}.")
            # Logujemy stan grafu tuż przed próbą znalezienia ścieżki
            self.logger.info(f"       -> Stan grafu: Węzły={list(self.net.nodes())}, Połączenia={list(self.net.edges())}")

            try:
                # Spróbuj znaleźć najkrótszą ścieżkę
                path = nx.shortest_path(self.net, dpid, dst_dpid, weight='weight')
                self.logger.info(f"       -> SUKCES! Znaleziona ścieżka: {path}")

                # Zainstaluj reguły na całej ścieżce
                # (Kod instalacji reguł pozostaje taki sam)
                for i in range(len(path)):
                    current_dpid = path[i]
                    if i < len(path) - 1:
                        next_dpid = path[i+1]
                        out_port = self.net.get_edge_data(current_dpid, next_dpid)['port']
                    else:
                        out_port = dst_port

                    dp = self.dpset.get(current_dpid)
                    if dp:
                        match = dp.ofproto_parser.OFPMatch(eth_dst=dst)
                        actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
                        self.add_flow(dp, 1, match, actions)
                
                # Wyślij oryginalny pakiet
                actions = [datapath.ofproto_parser.OFPActionOutput(self.net.get_edge_data(dpid, path[1])['port'] if len(path) > 1 else dst_port)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                    actions=actions, data=msg.data)
                datapath.send_msg(out)

            except nx.NetworkXNoPath:
                # --- TO JEST KLUCZOWA ZMIANA ---
                # Jeśli nie ma ścieżki, nie powoduj awarii. Zamiast tego zalewamy sieć.
                self.logger.warning(f"WARN: Nie znaleziono ścieżki z {dpid} do {dst_dpid}. Mapa może być niekompletna. Tymczasowo zalewam sieć (FLOOD).")
                actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, 
                    in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)
        else:
            # Cel nieznany, zalewamy sieć
            self.logger.info(f"ROUTE: Cel {dst} jest nieznany. Zalewam sieć (FLOOD).")
            actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER, 
                in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)