# last_dance.py - WERSJA FINALNA

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.topology import event
from collections import defaultdict

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mymac = {}
        self.switches = []
        self.datapaths = {}
        self.adjacency = defaultdict(dict) # Używamy dict zamiast defaultdict dla lepszej kontroli

    # --- NOWE, ODDZIELNE HANDLERY TOPOLOGII ---

    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        switch = ev.switch
        dpid = switch.dp.id
        if dpid not in self.switches:
            self.switches.append(dpid)
            self.datapaths[dpid] = switch.dp
            self.switches.sort()
            self.logger.info(f"Dołączył przełącznik: {dpid}. Aktualna lista: {self.switches}")

    @set_ev_cls(event.EventLinkAdd)
    def _link_add_handler(self, ev):
        link = ev.link
        s1 = link.src.dpid
        s2 = link.dst.dpid
        port1 = link.src.port_no
        port2 = link.dst.port_no
        self.adjacency[s1][s2] = port1
        self.adjacency[s2][s1] = port2
        self.logger.info(f"Odkryto połączenie: {s1}:{port1} <-> {s2}:{port2}")

    @set_ev_cls(event.EventLinkDelete)
    def _link_delete_handler(self, ev):
        link = ev.link
        s1 = link.src.dpid
        s2 = link.dst.dpid
        # Usuń połączenie z mapy
        if s2 in self.adjacency[s1]:
            del self.adjacency[s1][s2]
        if s1 in self.adjacency[s2]:
            del self.adjacency[s2][s1]
        self.logger.info(f"Usunięto połączenie: {s1} <-> {s2}")

    # --- Reszta kodu pozostaje bez zmian ---

    def _get_path(self, src, dst, first_port, final_port):
        self.logger.info(f"Obliczanie ścieżki: src_sw={src}, dst_sw={dst}")
        distance = {dpid: float('inf') for dpid in self.switches}
        previous = {dpid: None for dpid in self.switches}
        distance[src] = 0
        Q = set(self.switches)

        while Q:
            u = min(Q, key=lambda dpid: distance[dpid])
            Q.remove(u)
            if distance[u] == float('inf'):
                break

            # Iterujemy po sąsiadach 'u' używając naszej mapy
            for p in self.adjacency[u].keys():
                weight = 1
                if distance[u] + weight < distance[p]:
                    distance[p] = distance[u] + weight
                    previous[p] = u
        
        path = []
        p = dst
        while p is not None:
            path.append(p)
            p = previous.get(p)
        path.reverse()
        
        if src not in path:
            self.logger.error(f"Ścieżka z {src} do {dst} nie została znaleziona!")
            return None

        path_with_ports = []
        in_port = first_port
        for s1, s2 in zip(path[:-1], path[1:]):
            out_port = self.adjacency[s1][s2]
            path_with_ports.append((s1, in_port, out_port))
            in_port = self.adjacency[s2][s1]
        path_with_ports.append((dst, in_port, final_port))
        
        self.logger.info(f"Znaleziona ścieżka: {path_with_ports}")
        return path_with_ports

    def _install_path(self, p, ev, src_mac, dst_mac):
        msg = ev.msg
        parser = msg.datapath.ofproto_parser
        ofproto = msg.datapath.ofproto
        for sw_dpid, in_port, out_port in p:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapaths.get(sw_dpid)
            if datapath:
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, match=match, priority=1, idle_timeout=10, hard_timeout=30, instructions=inst)
                datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, match=match, priority=0, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Ignorujemy pakiety inne niż IPv4, w tym ARP na początku
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return
            
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        in_port = msg.match['in_port']

        if src not in self.mymac:
            self.mymac[src] = (dpid, in_port)
            self.logger.info(f"Nauczono: host {src} jest na przełączniku {dpid}, porcie {in_port}")

        if dst in self.mymac:
            src_switch, src_port = self.mymac[src]
            dst_switch, dst_port = self.mymac[dst]
            path = self._get_path(src_switch, dst_switch, src_port, dst_port)
            if path:
                self._install_path(path, ev, src, dst)
                out_port = path[0][2]
            else:
                # Nie zalewamy już sieci, jeśli nie ma ścieżki
                return
        else:
            # Nie zalewamy sieci, jeśli cel nieznany
            return

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)