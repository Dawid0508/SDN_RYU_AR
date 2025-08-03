# last_dance.py - WERSJA FINALNA z implementacją FAMTAR (FFT)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
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

        # --- NOWA TABLICA PRZEKAZYWANIA PRZEPŁYWÓW (FFT) ---
        # Klucz: flow_id, Wartość: {'path': sciezka, 'timestamp': czas}
        self.fft = {}

        # Statyczna przepustowość łączy z Mininet (w B/s)
        self.link_capacity = {
            (1, 2): 12500000, (2, 1): 12500000,
            (2, 4): 12500000, (4, 2): 12500000,
            (1, 3): 1250000,  (3, 1): 1250000,
            (3, 4): 1250000,  (4, 3): 1250000
        }

        self.dynamic_costs = defaultdict(lambda: 1)
        self.link_stats = {}
        self.monitor_thread = hub.spawn(self._monitor)

    def _get_flow_id(self, pkt):
        """Tworzy unikalny identyfikator dla przepływu na podstawie 5-ciu pól."""
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)

        if pkt_ipv4:
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst
            proto = pkt_ipv4.proto

            if pkt_tcp:
                src_port = pkt_tcp.src_port
                dst_port = pkt_tcp.dst_port
                return (src_ip, src_port, dst_ip, dst_port, proto)
            elif pkt_udp:
                src_port = pkt_udp.src_port
                dst_port = pkt_udp.dst_port
                return (src_ip, src_port, dst_ip, dst_port, proto)
        
        # Fallback dla ruchu nie-TCP/UDP (np. ICMP)
        eth = pkt.get_protocol(ethernet.ethernet)
        return (eth.src, eth.dst, eth.ethertype)

    def _monitor(self):
        """Pętla w tle, która co 10 sekund prosi przełączniki o statystyki."""
        while True:
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
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                
                dst_dpid = None
                for neighbor, port in self.adjacency[dpid].items():
                    if port == port_no:
                        dst_dpid = neighbor
                        break
                
                if dst_dpid:
                    link = (dpid, dst_dpid)
                    reverse_link = (dst_dpid, dpid)
                    now = time.time()
                    
                    if link in self.congestion_cooldown and now < self.congestion_cooldown[link]:
                        self.dynamic_costs[link] = 1000
                        self.dynamic_costs[reverse_link] = 1000
                        self.logger.info(f"Łącze {link} jest w okresie schładzania. Koszt pozostaje wysoki.")
                    
                    elif key in self.link_stats:
                        last_time, last_bytes = self.link_stats[key]
                        time_diff = now - last_time
                        bytes_diff = stat.tx_bytes - last_bytes
                        
                        if time_diff > 0:
                            bandwidth_usage = (bytes_diff * 8) / time_diff
                            capacity_bps = self.link_capacity.get(link, 0) * 8
                            
                            if capacity_bps > 0:
                                load_percentage = (bandwidth_usage / capacity_bps) * 100
                                
                                if load_percentage > 80:
                                    self.dynamic_costs[link] = 1000
                                    self.dynamic_costs[reverse_link] = 1000
                                    self.congestion_cooldown[link] = now + 30
                                    self.congestion_cooldown[reverse_link] = now + 30
                                    self.logger.warning(f"KONGESJA na łączu {link}! Obciążenie: {load_percentage:.2f}%. Zwiększono koszt w obu kierunkach.")
                                else:
                                    bw_mbps = self.link_capacity.get(link, 1) / 125000
                                    cost = 1000 / bw_mbps if bw_mbps > 0 else 1
                                    self.dynamic_costs[link] = cost
                                    self.dynamic_costs[reverse_link] = cost

                    self.link_stats[key] = (now, stat.tx_bytes)

    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        switch = ev.switch
        dpid = switch.dp.id
        if dpid not in self.switches:
            self.switches.append(dpid)
            self.datapaths[dpid] = switch.dp
            self.switches.sort()

    @set_ev_cls(event.EventLinkAdd)
    def _link_add_handler(self, ev):
        link = ev.link
        s1, s2 = link.src.dpid, link.dst.dpid
        port1, port2 = link.src.port_no, link.dst.port_no
        self.adjacency[s1][s2] = port1
        self.adjacency[s2][s1] = port2
        self.logger.info(f"Odkryto połączenie: {s1}:{port1} <-> {s2}:{port2}")

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

        path_with_ports = []
        in_port = first_port
        for s1, s2 in zip(path[:-1], path[1:]):
            out_port = self.adjacency[s1][s2]
            path_with_ports.append((s1, in_port, out_port))
            in_port = self.adjacency[s2][s1]
        path_with_ports.append((dst, in_port, final_port))
        
        self.logger.info(f"Znaleziona ścieżka: {path_with_ports} (koszt: {distance[dst]})")
        return path_with_ports

    def _install_path(self, p, ev, src_mac, dst_mac):
        msg = ev.msg
        parser = msg.datapath.ofproto_parser
        ofproto = msg.datapath.ofproto
        
        # Tworzymy unikalny identyfikator przepływu, aby móc instalować reguły dla konkretnych przepływów
        pkt = packet.Packet(msg.data)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)

        # Instalujemy reguły tylko dla ruchu IP
        if not pkt_ipv4:
            return

        for sw_dpid, in_port, out_port in p:
            # Dopasowanie jest teraz bardziej szczegółowe (5-pól)
            match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, 
                                    ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst)
            
            # Dla TCP/UDP możemy dodać porty
            if pkt_tcp:
                    match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, 
                                    ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst,
                                    ip_proto=6, tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
            elif pkt_udp:
                    match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, 
                                    ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst,
                                    ip_proto=17, udp_src=pkt_udp.src_port, udp_dst=pkt_udp.dst_port)

            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapaths.get(sw_dpid)
            if datapath:
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, match=match, priority=2, # Wyższy priorytet
                                        idle_timeout=20, hard_timeout=60, instructions=inst)
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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in self.mymac:
            self.mymac[src] = (dpid, in_port)
            self.logger.info(f"Nauczono: host {src} jest na przełączniku {dpid}, porcie {in_port}")

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            out_port = ofproto.OFPP_FLOOD
        else:
            flow_id = self._get_flow_id(pkt)

            if flow_id in self.fft:
                path = self.fft[flow_id]['path']
                self.fft[flow_id]['timestamp'] = time.time()
                # self.logger.info(f"Przepływ {flow_id} znaleziony w FFT. Używam ścieżki: {path}")
                # Nie instalujemy ponownie ścieżki, bo reguły już powinny być
                out_port = path[0][2]
            else:
                if dst in self.mymac:
                    src_switch, src_port = self.mymac[src]
                    dst_switch, dst_port = self.mymac[dst]
                    
                    path = self._get_path(src_switch, dst_switch, src_port, dst_port)
                    
                    if path:
                        self.logger.info(f"Nowy przepływ {flow_id}. Dodaję do FFT ze ścieżką: {path}")
                        self.fft[flow_id] = {'path': path, 'timestamp': time.time()}
                        self._install_path(path, ev, src, dst)
                        out_port = path[0][2]
                    else:
                        return
                else:
                    return

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
