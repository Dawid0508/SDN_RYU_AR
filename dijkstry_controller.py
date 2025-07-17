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

class PathfindingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PathfindingController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        # Globalna tablica MAC: {mac_adres: (dpid, port)}
        self.mac_to_port = {}
        self.logger.info("--- Kontroler z logiką Dijkstry v2.0 uruchomiony ---")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"SWITCH: Podłączono przełącznik DPID {datapath.id:016x}")

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
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_port = link.src.port_no
        
        # Waga '1' to domyślny koszt. Tu w przyszłości będzie logika FAMTAR
        self.net.add_edge(src_dpid, dst_dpid, port=src_port, weight=1)
        self.logger.info(f"TOPOLOGY: Dodano połączenie {src_dpid}:{src_port} -> {dst_dpid} do grafu.")

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch
        dpid = switch.dp.id
        self.net.add_node(dpid)
        self.logger.info(f"TOPOLOGY: Dodano przełącznik {dpid} do grafu.")

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

        self.logger.info(f"\n--- Nowy pakiet z {src} do {dst} na przełączniku {dpid} ---")

        # Naucz się globalnej lokalizacji adresu MAC źródła
        self.mac_to_port[src] = (dpid, in_port)

        if dst in self.mac_to_port:
            # Cel jest znany, można wyznaczyć ścieżkę
            dst_dpid, dst_port = self.mac_to_port[dst]
            self.logger.info(f"ROUTE: Cel {dst} jest znany - podłączony do {dst_dpid} port {dst_port}")
            
            # Jeśli źródło i cel są na tym samym przełączniku
            if dpid == dst_dpid:
                self.logger.info("       -> Cel na tym samym przełączniku, wysyłam bezpośrednio.")
                actions = [datapath.ofproto_parser.OFPActionOutput(dst_port)]
                match = datapath.ofproto_parser.OFPMatch(eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)
                self.send_packet_out(datapath, msg, actions, in_port)
                return

            self.logger.info(f"       -> Obliczam ścieżkę z {dpid} do {dst_dpid}...")
            try:
                path = nx.shortest_path(self.net, dpid, dst_dpid, weight='weight')
                self.logger.info(f"       -> Znaleziona ścieżka: {path}")

                # Zainstaluj reguły na całej ścieżce
                for i in range(len(path) - 1):
                    current_dpid = path[i]
                    next_dpid = path[i+1]
                    out_port = self.net.get_edge_data(current_dpid, next_dpid)['port']
                    
                    dp = self.get_datapath(current_dpid)
                    match = dp.ofproto_parser.OFPMatch(eth_dst=dst)
                    actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
                    self.add_flow(dp, 1, match, actions)
                
                # Wyślij oryginalny pakiet
                self.send_packet_out(datapath, msg, actions, in_port)

            except nx.NetworkXNoPath:
                self.logger.warning(f"WARN: Nie znaleziono ścieżki w grafie z {dpid} do {dst_dpid}!")
        else:
            # Cel jest nieznany, zalewamy sieć, żeby go odkryć (głównie dla ARP)
            self.logger.info(f"ROUTE: Cel {dst} jest nieznany. Zalewam sieć (FLOOD).")
            self.send_packet_out(datapath, msg, [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)], in_port)

    def send_packet_out(self, datapath, msg, actions, in_port):
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data)
        datapath.send_msg(out)

    def get_datapath(self, dpid):
        # Pomocnicza funkcja do pobierania obiektu datapath na podstawie DPID
        # Wymaga importu: from ryu.controller import dpset
        # Niestety, prosta metoda nie jest dostępna, więc musimy iterować.
        # W praktyce, dla lepszej wydajności, trzyma się mapowanie w __init__.
        # Tu dla prostoty zostawiamy tak.
        for dp in self.get_datapath.dps.values():
            if dp.id == dpid:
                return dp
    
    # Inicjalizacja pomocniczej zmiennej
    get_datapath.dps = {}
    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def _datapath_handler(self, ev):
        dp = ev.dp
        if ev.enter:
            self.get_datapath.dps[dp.id] = dp
        else:
            del self.get_datapath.dps[dp.id]