# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub
import networkx as nx

class FamtarController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(FamtarController, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.net = nx.DiGraph()
        self.mac_to_port = {}
        
        # --- Logika FAMTAR ---
        self.monitor_thread = hub.spawn(self._monitor)
        self.port_stats = {} # { (dpid, port): (tx_bytes, rx_bytes) }
        self.port_speed = {} # { (dpid, port): speed_in_Bps }
        self.link_to_port = {} # { (dpid1, dpid2): port_on_dpid1 }
        self.congestion_state = {} # { (dpid1, dpid2): True/False }
        self.logger.info("--- Kontroler FAMTAR v1.0 uruchomiony ---")

    # --- Podstawowa obsługa przełączników ---
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    # --- Budowanie topologii ---
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        self.net.add_node(ev.switch.dp.id)
        self.logger.info(f"TOPOLOGY: Dodano przełącznik {ev.switch.dp.id} do grafu.")

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        link = ev.link
        s1, s2 = link.src.dpid, link.dst.dpid
        p1 = link.src.port_no
        self.net.add_edge(s1, s2, port=p1, weight=1)
        self.link_to_port[(s1, s2)] = p1
        self.congestion_state.setdefault((s1, s2), False)
        self.logger.info(f"TOPOLOGY: Dodano połączenie {s1}:{p1} -> {s2}")

    # --- Mechanizm monitorowania FAMTAR ---
    def _monitor(self):
        self.logger.info("MONITOR: Uruchomiono wątek monitorujący...")
        while True:
            for dp in self.dpset.get_all():
                self._request_stats(dp[1])
            hub.sleep(5) # Odpytuj co 5 sekund

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        for stat in sorted(body, key=lambda s: s.port_no):
            port_no = stat.port_no
            key = (dpid, port_no)
            
            if key in self.port_stats:
                prev_tx = self.port_stats[key][0]
                delta_tx = stat.tx_bytes - prev_tx
                speed = delta_tx / 5 # Prędkość w Bajtach/s (interwał 5s)
                self.port_speed[key] = speed * 8 # Prędkość w bitach/s
            
            self.port_stats[key] = (stat.tx_bytes, stat.rx_bytes)
        
        self.update_link_costs()

    def update_link_costs(self):
        for (s1, s2), port in self.link_to_port.items():
            key = (s1, port)
            if key in self.port_speed:
                speed_mbps = self.port_speed[key] / (1024*1024)
                
                # Zgodnie z PDF, pojemność core links to 100 Mbit/s [cite: 180]
                link_capacity_mbps = 100 
                Th_max = 0.9 * link_capacity_mbps # 90% pojemności 
                Th_min = 0.7 * link_capacity_mbps # 70% pojemności 
                
                is_congested = self.congestion_state.get((s1, s2), False)

                if speed_mbps > Th_max and not is_congested:
                    # Przekroczono próg - ustaw wysoką wagę
                    self.net[s1][s2]['weight'] = 1000
                    self.congestion_state[(s1, s2)] = True
                    self.logger.warning(f"FAMTAR: Przeciążenie na linku {s1}->{s2}! Zwiększono koszt do 1000.")
                elif speed_mbps < Th_min and is_congested:
                    # Obciążenie spadło - przywróć normalną wagę
                    self.net[s1][s2]['weight'] = 1
                    self.congestion_state[(s1, s2)] = False
                    self.logger.info(f"FAMTAR: Koniec przeciążenia na {s1}->{s2}. Przywrócono koszt 1.")

    # --- Logika routingu (PacketIn) ---
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return
        
        dst, src = eth.dst, eth.src
        if src not in self.mac_to_port:
            self.mac_to_port[src] = (dpid, in_port)

        if dst in self.mac_to_port:
            dst_dpid, dst_port = self.mac_to_port[dst]
            try:
                path = nx.shortest_path(self.net, dpid, dst_dpid, weight='weight')
                # Logika instalacji reguł... (pozostaje bez zmian)
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
                
                # Wyślij pakiet
                actions = [datapath.ofproto_parser.OFPActionOutput(self.net.get_edge_data(dpid, path[1])['port'] if len(path) > 1 else dst_port)]
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)
            except nx.NetworkXNoPath:
                # Fallback do zalewania, jeśli mapa jest niekompletna
                self.flood(msg)
        else: # Cel nieznany
            self.flood(msg)
            
    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=msg.match['in_port'], actions=actions, data=msg.data)
        datapath.send_msg(out)