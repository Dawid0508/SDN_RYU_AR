# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event
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
        self.port_stats = {}
        self.port_speed = {}
        self.link_to_port = {}
        self.congestion_state = {}
        self.logger.info("--- Kontroler FAMTAR v2.0 (Proaktywny) uruchomiony ---")

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"FLOW: Instaluję regułę na DPID {datapath.id:016x} dla {match} -> {actions}")

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        datapath = ev.switch.dp
        self.net.add_node(datapath.id)
        self.logger.info(f"TOPOLOGY: Dodano przełącznik {datapath.id} do grafu.")
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        s1, s2 = ev.link.src.dpid, ev.link.dst.dpid
        p1, p2 = ev.link.src.port_no, ev.link.dst.port_no
        self.net.add_edge(s1, s2, port=p1, weight=1)
        self.net.add_edge(s2, s1, port=p2, weight=1)
        self.link_to_port[(s1, s2)] = p1
        self.link_to_port[(s2, s1)] = p2
        self.congestion_state.setdefault((s1, s2), False)
        self.congestion_state.setdefault((s2, s1), False)
        self.logger.info(f"TOPOLOGY: Dodano połączenie dwukierunkowe {s1} <-> {s2}")

    def _monitor(self):
        while True:
            for dp in self.dpset.get_all():
                self._request_stats(dp[1])
            hub.sleep(5)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        for stat in sorted(body, key=lambda s: s.port_no):
            key = (dpid, stat.port_no)
            if key in self.port_stats:
                prev_tx = self.port_stats[key]
                speed_bps = ((stat.tx_bytes - prev_tx) * 8) / 5
                self.port_speed[key] = speed_bps
            self.port_stats[key] = stat.tx_bytes
        self.update_link_costs()

    def update_link_costs(self):
        for (s1, s2), port in self.link_to_port.items():
            key = (s1, port)
            speed_mbps = self.port_speed.get(key, 0) / (1000*1000)
            link_capacity_mbps = 10 if 3 in (s1, s2) else 100
            Th_max, Th_min = 0.9 * link_capacity_mbps, 0.7 * link_capacity_mbps
            is_congested = self.congestion_state.get((s1, s2), False)

            if speed_mbps > Th_max and not is_congested:
                self.net[s1][s2]['weight'] = 1000
                self.congestion_state[(s1, s2)] = True
                self.logger.warning(f"FAMTAR: Przeciążenie na linku {s1}->{s2}! Koszt=1000. (Szybkość: {speed_mbps:.2f} Mbps)")
            elif speed_mbps < Th_min and is_congested:
                self.net[s1][s2]['weight'] = 1
                self.congestion_state[(s1, s2)] = False
                self.logger.info(f"FAMTAR: Koniec przeciążenia na {s1}->{s2}. Koszt=1. (Szybkość: {speed_mbps:.2f} Mbps)")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return
            
        dst, src = eth.dst, eth.src
        if src not in self.mac_to_port:
            self.mac_to_port[src] = (dpid, msg.match['in_port'])

        if dst in self.mac_to_port:
            dst_dpid, dst_port = self.mac_to_port[dst]
            try:
                path = nx.shortest_path(self.net, dpid, dst_dpid, weight='weight')
                
                # --- PROAKTYWNA INSTALACJA - PONIŻSZA PĘTLA ROZWIĄZUJE PROBLEM Z PRĘDKOŚCIĄ ---
                for i in range(len(path)):
                    current_dpid = path[i]
                    out_port = dst_port if i == len(path) - 1 else self.net.get_edge_data(current_dpid, path[i+1])['port']
                    dp = self.dpset.get(current_dpid)
                    if dp:
                        match = parser.OFPMatch(eth_dst=dst)
                        actions = [parser.OFPActionOutput(out_port)]
                        self.add_flow(dp, 1, match, actions)
                
                # Wyślij pierwszy pakiet, kolejne polecą już po zainstalowanych regułach
                out_port_first_hop = dst_port if len(path) <= 1 else self.net.get_edge_data(dpid, path[1])['port']
                actions = [parser.OFPActionOutput(out_port_first_hop)]
                self._send_packet_out(datapath, msg, actions)
            except nx.NetworkXNoPath:
                self.flood(msg)
        else:
            self.flood(msg)

    def flood(self, msg):
        actions = [msg.datapath.ofproto_parser.OFPActionOutput(msg.datapath.ofproto.OFPP_FLOOD)]
        self._send_packet_out(msg.datapath, msg, actions)

    def _send_packet_out(self, datapath, msg, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=msg.match['in_port'],
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)