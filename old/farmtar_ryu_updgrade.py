# -*- coding: utf-8 -*-

import time
import hashlib
import threading
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, ipv6, tcp, udp
from ryu.topology import event

# --- Konfiguracja ---
THRESHOLD_HIGH = 0.9      # Próg obciążenia powyżej którego łącze jest oznaczane jako obciążone
THRESHOLD_LOW = 0.7       # Próg obciążenia poniżej którego łącze wraca do normalnego kosztu
MAX_COST = 1000           # Maksymalny koszt łącza obciążonego
DEFAULT_COST = 1          # Domyślny koszt łącza
IDLE_TIMEOUT = 100        # Czas (sekundy) bezczynności przepływu przed usunięciem z przełącznika
FFT_IDLE_TIMEOUT = 120    # Czas (sekundy) bezczynności wpisu w FFT przed usunięciem przez cleanup
CLEANUP_INTERVAL = 60     # Interwał czyszczenia FFT (sekundy)
STATS_REQUEST_INTERVAL = 10 # Interwał żądania statystyk (sekundy)


class FAMTARController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FAMTARController, self).__init__(*args, **kwargs)
        
        # --- Struktury Danych jako zmienne instancji ---
        self.switches = []                                  # Lista DPID przełączników
        self.datapaths = {}                                 # Słownik DPID -> obiekt datapath
        self.adjacency = defaultdict(lambda: defaultdict(lambda: {"port": None, "cost": DEFAULT_COST})) # Macierz sąsiedztwa
        self.link_load = defaultdict(lambda: {"tx_bytes": 0, "rx_bytes": 0, "timestamp": 0}) # Monitorowanie obciążenia
        self.fft = {}                                       # Flow Forwarding Table: flow_id -> (out_port, timestamp)
        self.mac_to_port = {}                               # Mapowanie: dpid -> {mac -> port}
        self.mac_to_dpid = {}                               # Mapowanie: mac_hosta -> dpid przełącznika

        # --- Blokady dla bezpieczeństwa wątków ---
        self.fft_lock = threading.Lock()
        self.topology_lock = threading.Lock() # Zabezpiecza switches i adjacency
        self.mac_learning_lock = threading.Lock() # Zabezpiecza mac_to_dpid i mac_to_port

        # --- Uruchomienie zadań w tle w sposób zgodny z Ryu ---
        self.monitor_thread = self.hub.spawn(self._request_stats_loop)
        self.cleanup_thread = self.hub.spawn(self._cleanup_fft_loop)
        self.logger.info("Kontroler FAMTAR zainicjowany. Wątki monitoringu i czyszczenia uruchomione.")

    # --- Funkcje Pomocnicze jako metody klasy ---

    def _minimum_distance(self, distance, Q):
        min_dist = float('inf')
        min_node = None
        for node in Q:
            if node in distance and distance[node] < min_dist:
                min_dist = distance[node]
                min_node = node
        return min_node

    def _calculate_path(self, src, dst):
        with self.topology_lock:
            if src not in self.switches or dst not in self.switches:
                self.logger.warning(f"Próba obliczenia ścieżki dla nieznanych przełączników: src={src}, dst={dst}")
                return None

            distance = {node: float('inf') for node in self.switches}
            previous = {node: None for node in self.switches}
            distance[src] = 0
            Q = set(self.switches)

            while Q:
                u = self._minimum_distance(distance, Q)
                if u is None:
                    break
                Q.remove(u)

                for v in self.adjacency[u]:
                    if self.adjacency[u][v]["port"] is not None and v in Q:
                        cost = self.adjacency[u][v]["cost"]
                        alt = distance[u] + cost
                        if alt < distance[v]:
                            distance[v] = alt
                            previous[v] = u
            
            path = []
            current = dst
            visited_for_path = set()
            while current is not None and current not in visited_for_path:
                visited_for_path.add(current)
                path.insert(0, current)
                if current == src:
                    break
                current = previous.get(current)

            if not path or path[0] != src:
                self.logger.warning(f"Nie znaleziono ścieżki z {src} do {dst}")
                return None

            return path

    def _get_ports_for_path(self, path):
        ports = []
        with self.topology_lock:
            for s1, s2 in zip(path[:-1], path[1:]):
                if s2 not in self.adjacency[s1]:
                    self.logger.error(f"Błąd: Brak definicji łącza między {s1} a {s2} w adjacency.")
                    return None
                out_port = self.adjacency[s1][s2]["port"]
                in_port = self.adjacency[s2][s1]["port"]
                ports.append((s1, in_port, out_port))
        
        if len(ports) != len(path) - 1:
            self.logger.error(f"Błąd: Nie udało się uzyskać portów dla całej ścieżki {path}.")
            return None
            
        return ports

    def _calculate_flow_id(self, packet_obj, in_port, eth_src, eth_dst):
        ip_proto, src_port, dst_port = 0, 0, 0
        try:
            ip_header = packet_obj.get_protocol(ipv4.ipv4) or packet_obj.get_protocol(ipv6.ipv6)
            if ip_header:
                ip_proto = ip_header.proto
                tcp_header = packet_obj.get_protocol(tcp.tcp)
                udp_header = packet_obj.get_protocol(udp.udp)
                if tcp_header:
                    src_port, dst_port = tcp_header.src_port, tcp_header.dst_port
                elif udp_header:
                    src_port, dst_port = udp_header.src_port, udp_header.dst_port
        except Exception as e:
            self.logger.error(f"Wyjątek podczas parsowania pakietu dla flow_id: {e}", exc_info=True)

        flow_tuple = (eth_src, eth_dst, ip_proto, src_port, dst_port, in_port)
        return hashlib.md5(str(flow_tuple).encode('utf-8')).hexdigest()

    def _add_flow(self, datapath, match, actions, priority=1, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, match=match, priority=priority,
                                idle_timeout=idle_timeout, instructions=inst)
        datapath.send_msg(mod)

    def _install_path(self, path, flow_id, src_mac, dst_mac, final_out_port, original_in_port):
        self.logger.info(f"--- Instalacja ścieżki dla flow_id: {flow_id} ---")
        self.logger.info(f"    Ścieżka DPID: {path}")

        first_switch_out_port = None
        if len(path) > 1:
            with self.topology_lock:
                first_switch_out_port = self.adjacency[path[0]].get(path[1], {}).get("port")
        elif len(path) == 1: # Hosty na tym samym przełączniku
             first_switch_out_port = final_out_port
        
        for i, dpid in enumerate(path):
            datapath = self.datapaths.get(dpid)
            if not datapath:
                self.logger.error(f"    Błąd: Brak datapath dla przełącznika {dpid}.")
                continue

            parser = datapath.ofproto_parser
            
            # Określanie portu wejściowego i wyjściowego
            with self.topology_lock:
                if i == 0:
                    in_port = original_in_port
                else:
                    in_port = self.adjacency[dpid].get(path[i-1], {}).get("port")

                if i < len(path) - 1:
                    out_port = self.adjacency[dpid].get(path[i+1], {}).get("port")
                else:
                    out_port = final_out_port
            
            if in_port is None or out_port is None:
                self.logger.error(f"    Błąd: Nie można ustalić portu in/out dla switcha {dpid}. In: {in_port}, Out: {out_port}")
                continue

            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(datapath, match, actions, priority=2, idle_timeout=IDLE_TIMEOUT)
            self.logger.info(f"    Instalacja: switch={dpid}, in_port={in_port}, out_port={out_port}")

        # Aktualizacja FFT
        with self.fft_lock:
            if first_switch_out_port is not None:
                self.fft[flow_id] = (first_switch_out_port, time.time())
                self.logger.debug(f"    Dodano/zaktualizowano FFT: flow_id={flow_id}, out_port={first_switch_out_port}")
            else:
                self.logger.warning(f"    Nie udało się ustalić portu dla pierwszego kroku do aktualizacji FFT.")
        self.logger.info(f"--- Zakończono instalację ścieżki dla flow_id: {flow_id} ---")

    # --- Handlery Zdarzeń ---

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath
        
        with self.mac_learning_lock:
            self.mac_to_port.setdefault(dpid, {})

        # Domyślna reguła "table-miss" - pakiety do kontrolera
        match = datapath.ofproto_parser.OFPMatch()
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER,
                                                           datapath.ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, match, actions, priority=0)
        self.logger.info(f"Skonfigurowano domyślną regułę dla przełącznika {dpid}.")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac, src_mac = eth.dst, eth.src
        self.logger.info(f"--- PacketIn: Switch={dpid}, InPort={in_port}, Src={src_mac}, Dst={dst_mac} ---")
        
        # --- Nauka MAC -> Port & MAC -> DPID ---
        with self.mac_learning_lock:
            if self.mac_to_port[dpid].get(src_mac) != in_port:
                self.mac_to_port[dpid][src_mac] = in_port
                self.logger.info(f"    Nauczono: Switch {dpid}, MAC {src_mac} -> Port {in_port}")
            if self.mac_to_dpid.get(src_mac) != dpid:
                self.mac_to_dpid[src_mac] = dpid
                self.logger.info(f"    Nauczono: MAC {src_mac} -> DPID {dpid}")

        flow_id = self._calculate_flow_id(pkt, in_port, src_mac, dst_mac)
        
        # --- Sprawdzanie FFT ---
        with self.fft_lock:
            fft_entry = self.fft.get(flow_id)
            if fft_entry and (time.time() - fft_entry[1] <= FFT_IDLE_TIMEOUT):
                out_port_fft, _ = fft_entry
                self.fft[flow_id] = (out_port_fft, time.time()) # Odśwież timestamp
                self.logger.info(f"    Trafienie w FFT! Wysyłanie na port {out_port_fft}.")
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port_fft)]
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)
                return
            elif fft_entry:
                del self.fft[flow_id]
                self.logger.info(f"    Usunięto przestarzały wpis z FFT: {flow_id}")

        # --- Logika routingu (jeśli nie ma w FFT) ---
        dst_dpid = self.mac_to_dpid.get(dst_mac)
        out_port = None
        
        if dst_dpid == dpid: # Cel na tym samym przełączniku
            out_port = self.mac_to_port[dpid].get(dst_mac)
            if out_port:
                self.logger.info(f"    Cel na tym samym przełączniku {dpid}, port {out_port}")
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
                self._add_flow(datapath, match, actions, priority=2, idle_timeout=IDLE_TIMEOUT)
                with self.fft_lock: # Zapis do FFT
                    self.fft[flow_id] = (out_port, time.time())
            else: # Rzadki przypadek, ale możliwy
                self.logger.warning(f"    Nie znam portu dla {dst_mac} na {dpid}, zalewam.")
                actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]

        elif dst_dpid: # Cel na innym znanym przełączniku
            self.logger.info(f"    Cel na przełączniku {dst_dpid}. Obliczanie ścieżki z {dpid}...")
            path = self._calculate_path(dpid, dst_dpid)
            if path:
                self.logger.info(f"    Znaleziona ścieżka: {path}")
                final_out_port = self.mac_to_port.get(dst_dpid, {}).get(dst_mac)
                if final_out_port:
                    self._install_path(path, flow_id, src_mac, dst_mac, final_out_port, in_port)
                    # Wyślij pierwszy pakiet
                    first_hop_out_port = self._get_ports_for_path(path)[0][2]
                    actions = [datapath.ofproto_parser.OFPActionOutput(first_hop_out_port)]
                else:
                    self.logger.warning(f"    Nie znam portu końcowego dla {dst_mac} na {dst_dpid}. Zalewam.")
                    actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
            else:
                self.logger.warning(f"    Nie znaleziono ścieżki z {dpid} do {dst_dpid}. Zalewam.")
                actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]
        
        else: # Cel nieznany
            self.logger.warning(f"    Nieznany MAC docelowy: {dst_mac}. Zalewam.")
            actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]

        # Wysyłanie pakietu
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch
        dpid = switch.dp.id
        with self.topology_lock:
            if dpid not in self.switches:
                self.switches.append(dpid)
                self.datapaths[dpid] = switch.dp
                self.mac_to_port.setdefault(dpid, {})
                self.logger.info(f"Przełącznik dołączył do topologii: {dpid}")

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        switch = ev.switch
        dpid = switch.dp.id
        with self.topology_lock:
            if dpid in self.switches:
                self.switches.remove(dpid)
            if dpid in self.datapaths:
                del self.datapaths[dpid]
        with self.mac_learning_lock:
            if dpid in self.mac_to_port:
                del self.mac_to_port[dpid]
            # Usuń hosty powiązane z usuniętym przełącznikiem
            keys_to_remove = [mac for mac, dp in self.mac_to_dpid.items() if dp == dpid]
            for key in keys_to_remove:
                del self.mac_to_dpid[key]
        self.logger.info(f"Przełącznik opuścił topologię: {dpid}")

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        link = ev.link
        src_dpid, dst_dpid = link.src.dpid, link.dst.dpid
        src_port, dst_port = link.src.port_no, link.dst.port_no
        with self.topology_lock:
            if src_dpid in self.switches and dst_dpid in self.switches:
                self.adjacency[src_dpid][dst_dpid] = {"port": src_port, "cost": DEFAULT_COST}
                self.adjacency[dst_dpid][src_dpid] = {"port": dst_port, "cost": DEFAULT_COST}
                self.logger.info(f"Łącze dodane: {src_dpid}:{src_port} <-> {dst_dpid}:{dst_port}")
            else:
                self.logger.warning("Ignorowanie łącza - jeden z przełączników nie jest jeszcze znany.")

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        link = ev.link
        src_dpid, dst_dpid = link.src.dpid, link.dst.dpid
        with self.topology_lock:
            if self.adjacency[src_dpid] and self.adjacency[src_dpid][dst_dpid]:
                del self.adjacency[src_dpid][dst_dpid]
            if self.adjacency[dst_dpid] and self.adjacency[dst_dpid][src_dpid]:
                del self.adjacency[dst_dpid][src_dpid]
        self.logger.info(f"Łącze usunięte: {src_dpid} <-> {dst_dpid}")
        
    # --- Pętle monitorujące ---

    def _request_stats_loop(self):
        """Cyklicznie wysyła żądania o statystyki przepływów."""
        while True:
            datapaths_to_request = list(self.datapaths.values())
            for datapath in datapaths_to_request:
                parser = datapath.ofproto_parser
                req = parser.OFPFlowStatsRequest(datapath)
                try:
                    datapath.send_msg(req)
                except Exception as e:
                    self.logger.error(f"Błąd podczas wysyłania żądania statystyk do {datapath.id}: {e}")
            self.hub.sleep(STATS_REQUEST_INTERVAL)
            
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        # TODO: Logika do analizy statystyk i dynamicznej zmiany kosztów łączy
        # self.logger.debug(f"Otrzymano statystyki przepływów z {ev.msg.datapath.id}")
        pass

    def _cleanup_fft_loop(self):
        """Cyklicznie czyści przestarzałe wpisy w tablicy FFT."""
        while True:
            self.hub.sleep(CLEANUP_INTERVAL)
            with self.fft_lock:
                current_time = time.time()
                expired_flows = [flow_id for flow_id, (_, timestamp) in self.fft.items()
                                 if current_time - timestamp > FFT_IDLE_TIMEOUT]
                if expired_flows:
                    self.logger.info(f"Czyszczenie FFT: Usuwanie {len(expired_flows)} przestarzałych wpisów.")
                    for flow_id in expired_flows:
                        del self.fft[flow_id]