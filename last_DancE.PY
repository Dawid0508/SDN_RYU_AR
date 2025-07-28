# last_dance.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology.api import get_switch, get_link
from ryu.topology import event
from collections import defaultdict

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        
        self.switches = []
        self.datapaths = {}
        self.mymac = {}
        self.adjacency = defaultdict(lambda: defaultdict(lambda: None))

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

            for p in self.switches:
                if self.adjacency[u].get(p) is not None:
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
                mod = parser.OFPFlowMod(
                    datapath=datapath, match=match, priority=1,
                    idle_timeout=10, hard_timeout=30, instructions=inst)
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
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

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
                out_port = ofproto.OFPP_FLOOD
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls([event.EventSwitchEnter, event.EventLinkAdd])
    def get_topology_data(self, ev):
        self.logger.info(f"Aktualizacja topologii - zdarzenie: {ev.__class__.__name__}")

        switch_list = get_switch(self.topology_api_app, None)
        self.switches = [s.dp.id for s in switch_list]
        self.datapaths = {s.dp.id: s.dp for s in switch_list}
        self.logger.info(f"Dostępne przełączniki: {self.switches}")
        
        links_list = get_link(self.topology_api_app, None)
        self.adjacency.clear()
        for link in links_list:
            s1, s2 = link.src.dpid, link.dst.dpid
            port1, port2 = link.src.port_no, link.dst.port_no
            self.adjacency[s1][s2] = port1
            self.adjacency[s2][s1] = port2
        self.logger.info(f"Odkryte połączenia: {[ (l.src.dpid, l.dst.dpid) for l in links_list]}")