# last_dance.py - WERSJA Z DYNAMICZNYM MONITOROWANIEM

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event
from ryu.lib import hub
from collections import defaultdict
from operator import attrgetter
import time

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mymac = {}
        self.switches = []
        self.datapaths = {}
        self.adjacency = defaultdict(dict)
        
        self.congestion_cooldown = {}

        # --- NOWE STRUKTURY DANYCH DO MONITOROWANIA ---
        
        # Statyczna przepustowość łączy z Mininet (w B/s)
        # 100 Mbps = 12,500,000 B/s; 10 Mbps = 1,250,000 B/s
        self.link_capacity = {
            (1, 2): 12500000, (2, 1): 12500000,
            (2, 4): 12500000, (4, 2): 12500000,
            (1, 3): 1250000,  (3, 1): 1250000,
            (3, 4): 1250000,  (4, 3): 1250000
        }

        # Słownik do przechowywania dynamicznych kosztów łączy
        self.dynamic_costs = defaultdict(lambda: 1)

        # Słownik do przechowywania poprzednich statystyk (dpid, port_no) -> (time, bytes)
        self.link_stats = {}

        # Uruchomienie wątku monitorującego w tle
        self.monitor_thread = hub.spawn(self._monitor)

    # --- Wątek monitorujący ---
    def _monitor(self):
        """Pętla w tle, która co 10 sekund prosi przełączniki o statystyki."""
        while True:
            self.logger.info("--- Rozpoczynam cykl monitorowania sieci ---")
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        """Wysyła zapytanie OFPPortStatsRequest do danego przełącznika."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """Obsługuje odpowiedź ze statystykami i aktualizuje koszty."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            # Ignoruj wewnętrzny port przełącznika
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                
                # Znajdź sąsiada połączonego z tym portem
                dst_dpid = None
                for neighbor, port in self.adjacency[dpid].items():
                    if port == port_no:
                        dst_dpid = neighbor
                        break
                
                if dst_dpid:
                    now = time.time()
                    
                    # Obliczanie obciążenia
                    if key in self.link_stats:
                        last_time, last_bytes = self.link_stats[key]
                        time_diff = time.time() - last_time
                        bytes_diff = stat.tx_bytes - last_bytes
                        
                        if time_diff > 0:
                            bandwidth_usage = (bytes_diff * 8) / time_diff # Prędkość w bitach/s
                            link = (dpid, dst_dpid)
                            capacity_bps = self.link_capacity.get(link, 0) * 8 # Pojemność w bitach/s
                            
                            if capacity_bps > 0:
                                load_percentage = (bandwidth_usage / capacity_bps) * 100
                                
                                # Dynamiczna zmiana kosztu
                                if load_percentage > 80: # Próg 80% obciążenia
                                    self.dynamic_costs[link] = 1000 # Wysoki koszt dla zatłoczonego łącza
                                    self.logger.warning(f"KONGESJA na łączu {link}! Obciążenie: {load_percentage:.2f}%. Zwiększono koszt.")
                                else:
                                    # Oblicz koszt na podstawie przepustowości dla niezatłoczonego łącza
                                    bw_mbps = self.link_capacity.get(link, 1) / 125000 # Przelicz pojemność na Mb/s
                                    if bw_mbps > 0:
                                        self.dynamic_costs[link] = 1000 / bw_mbps # koszt = ref / przepustowość
                                    else:
                                        self.dynamic_costs[link] = 1 # Domyślny koszt, jeśli coś pójdzie nie tak
                            
                    # Zapisz obecne statystyki do następnego porównania
                    self.link_stats[key] = (time.time(), stat.tx_bytes)

    # --- Handlery topologii ---
    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        # ... (bez zmian)
        switch = ev.switch
        dpid = switch.dp.id
        if dpid not in self.switches:
            self.switches.append(dpid)
            self.datapaths[dpid] = switch.dp
            self.switches.sort()

    @set_ev_cls(event.EventLinkAdd)
    def _link_add_handler(self, ev):
        # ... (bez zmian)
        link = ev.link
        s1, s2 = link.src.dpid, link.dst.dpid
        port1, port2 = link.src.port_no, link.dst.port_no
        self.adjacency[s1][s2] = port1
        self.adjacency[s2][s1] = port2
        self.logger.info(f"Odkryto połączenie: {s1}:{port1} <-> {s2}:{port2}")

    # --- Zmodyfikowany algorytm Dijkstry ---
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

            for p in self.adjacency[u].keys():
                # UŻYWAMY DYNAMICZNEGO KOSZTU!
                weight = self.dynamic_costs.get((u, p), 1)
                
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

        # ... (reszta funkcji _get_path, _install_path, switch_features_handler, _packet_in_handler bez zmian)
        path_with_ports = []
        in_port = first_port
        for s1, s2 in zip(path[:-1], path[1:]):
            out_port = self.adjacency[s1][s2]
            path_with_ports.append((s1, in_port, out_port))
            in_port = self.adjacency[s2][s1]
        path_with_ports.append((dst, in_port, final_port))
        
        self.logger.info(f"Znaleziona ścieżka: {path_with_ports} (koszt: {distance[dst]})")
        return path_with_ports

    # ... (skopiuj tutaj resztę swoich funkcji: _install_path, switch_features_handler, _packet_in_handler)
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

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            out_port = ofproto.OFPP_FLOOD
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            if dst in self.mymac:
                src_switch, src_port = self.mymac[src]
                dst_switch, dst_port = self.mymac[dst]
                path = self._get_path(src_switch, dst_switch, src_port, dst_port)
                if path:
                    self._install_path(path, ev, src, dst)
                    out_port = path[0][2]
                else: return
            else: return
        else: return

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)