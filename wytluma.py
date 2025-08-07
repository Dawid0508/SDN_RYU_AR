# last_dance.py - WERSJA FINALNA Z KOMENTARZAMI

# --- Sekcja 1: Importy ---
# Importujemy niezbędne moduły z biblioteki Ryu oraz moduły standardowe.
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from ryu.topology import event
from ryu.lib import hub # Umożliwia tworzenie wątków działających w tle
from collections import defaultdict
from operator import attrgetter
import time

# --- Sekcja 2: Główna klasa kontrolera ---
class ProjectController(app_manager.RyuApp):
    # Określamy, że nasz kontroler będzie używał protokołu OpenFlow w wersji 1.3.
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # --- Sekcja 3: Inicjalizacja (Konstruktor) ---
    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        
        # --- Struktury danych do przechowywania stanu sieci ---
        # Słownik mapujący adres MAC hosta na (dpid przełącznika, port)
        self.mymac = {}
        # Lista identyfikatorów (DPID) wszystkich znanych przełączników
        self.switches = []
        # Słownik mapujący DPID na obiekt 'datapath' przełącznika (do wysyłania komend)
        self.datapaths = {}
        # Macierz sąsiedztwa: adjacency[s1][s2] przechowuje port na s1 prowadzący do s2
        self.adjacency = defaultdict(dict)
        
        # --- Struktury danych dla logiki FAMTAR ---
        # Tablica Przekazywania Przepływów (FFT): mapuje identyfikator przepływu na jego ścieżkę
        self.fft = {}
        
        # Słownik przechowujący statyczną, maksymalną przepustowość każdego łącza (w B/s)
        # Te wartości muszą odpowiadać tym zdefiniowanym w skrypcie Mininet.
        self.link_capacity = {
            (1, 2): 12500000, (2, 1): 12500000, (2, 4): 12500000, 
            (4, 2): 12500000, (1, 3): 1250000, (3, 1): 1250000,
            (3, 4): 1250000, (4, 3): 1250000
        }
        
        # Słownik przechowujący dynamicznie obliczany "koszt" każdego łącza
        self.dynamic_costs = {}
        # Słownik do przechowywania poprzednich statystyk portów, aby móc obliczyć różnicę
        self.link_stats = {}
        
        # Uruchomienie wątku w tle, który będzie cyklicznie monitorował sieć
        self.monitor_thread = hub.spawn(self._monitor)

    # --- Sekcja 4: Logika FAMTAR i Przetwarzanie Pakietów ---
    
    def _get_flow_id(self, pkt):
        """
        Analizuje pakiet i tworzy dla niego unikalny identyfikator (flow_id).
        Dla ruchu TCP/UDP używa pełnych 5-ciu pól (IP src/dst, porty src/dst, protokół).
        Dla innego ruchu (np. ICMP) używa identyfikatora zapasowego (MAC src/dst, EtherType).
        """
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        if pkt_ipv4:
            src_ip, dst_ip, proto = pkt_ipv4.src, pkt_ipv4.dst, pkt_ipv4.proto
            if pkt_tcp: return (src_ip, pkt_tcp.src_port, dst_ip, pkt_tcp.dst_port, proto)
            if pkt_udp: return (src_ip, pkt_udp.src_port, dst_ip, pkt_udp.dst_port, proto)
        eth = pkt.get_protocol(ethernet.ethernet)
        return (eth.src, eth.dst, eth.ethertype)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Główna funkcja obsługująca pakiety, które trafiają do kontrolera.
        Implementuje logikę ze schematu FAMTAR.
        """
        # Ekstrakcja podstawowych informacji z wiadomości
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignorujemy pakiety LLDP, które służą tylko do odkrywania topologii
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst, src, dpid = eth.dst, eth.src, datapath.id
        in_port = msg.match['in_port']

        # Krok 1: Uczenie się lokalizacji hostów. Zawsze zapisujemy, gdzie pojawił się dany MAC.
        if src not in self.mymac:
            self.mymac[src] = (dpid, in_port)
            self.logger.info(f"Nauczono: host {src} jest na {dpid}:{in_port}")

        # Krok 2: Obsługa pakietów ARP. Są one niezbędne do komunikacji.
        # Zalewamy sieć (flooding), aby umożliwić hostom wzajemne odnalezienie się.
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            out_port = ofproto.OFPP_FLOOD
        else:
            # Krok 3: Obsługa ruchu IP (i innego). Tutaj działa główna logika FAMTAR.
            flow_id = self._get_flow_id(pkt)
            
            # Sprawdzamy, czy przepływ jest już w naszej pamięci FFT.
            if flow_id in self.fft:
                # SCENARIUSZ A: PRZEPŁYW JEST ZNANY
                # Oznacza to, że reguła na przełączniku wygasła.
                # Bierzemy zapisaną ścieżkę z FFT i ponownie ją instalujemy.
                # NIE obliczamy nowej ścieżki, aby zachować stabilność.
                path = self.fft[flow_id]['path']
                self.fft[flow_id]['timestamp'] = time.time() # Odświeżamy znacznik czasu
                self.logger.info(f"Reguła dla znanego przepływu {flow_id} wygasła. Ponownie instaluję ścieżkę z FFT: {path}")
                self._install_path(path, ev)
                out_port = path[0][2]
            else:
                # SCENARIUSZ B: PRZEPŁYW JEST NOWY
                # Dopiero teraz uruchamiamy algorytm Dijkstry, aby znaleźć najlepszą ścieżkę.
                if dst in self.mymac:
                    src_sw, src_port = self.mymac[src]
                    dst_sw, dst_port = self.mymac[dst]
                    path = self._get_path(src_sw, dst_sw, src_port, dst_port)
                    if path:
                        # Zapisujemy nowo obliczoną ścieżkę w FFT.
                        self.logger.info(f"Nowy przepływ {flow_id}. Obliczono i dodano do FFT ścieżkę: {path}")
                        self.fft[flow_id] = {'path': path, 'timestamp': time.time()}
                        self._install_path(path, ev)
                        out_port = path[0][2]
                    else: return # Jeśli nie znaleziono ścieżki, odrzuć pakiet
                else: return # Jeśli cel nieznany, odrzuć pakiet

        # Krok 4: Wysłanie pakietu.
        # Tworzymy wiadomość PacketOut, która instruuje przełącznik, co ma zrobić z bieżącym pakietem.
        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER: data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # --- Sekcja 5: Monitorowanie Sieci i Adaptacja Kosztów ---

    def _monitor(self):
        """Pętla działająca w tle. Co 10 sekund prosi o statystyki i czyści stare wpisy w FFT."""
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            
            now = time.time()
            # Znajdź przepływy, które nie były aktywne przez ponad 60 sekund
            inactive_flows = [fid for fid, data in self.fft.items() if now - data['timestamp'] > 60]
            for fid in inactive_flows:
                del self.fft[fid] # Usuń je z pamięci
                # self.logger.info(f"Usunięto nieaktywny przepływ z FFT: {fid}")

            hub.sleep(10)

    def _request_stats(self, datapath):
        """Wysyła do przełącznika prośbę o statystyki portów."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """Obsługuje odpowiedź ze statystykami i dynamicznie aktualizuje koszty łączy."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                dst_dpid = next((n for n, p in self.adjacency[dpid].items() if p == port_no), None)
                if dst_dpid:
                    link = (dpid, dst_dpid)
                    reverse_link = (dst_dpid, dpid)
                    if key in self.link_stats:
                        last_time, last_bytes = self.link_stats[key]
                        time_diff = time.time() - last_time
                        if time_diff > 0:
                            bw_usage = (stat.tx_bytes - last_bytes) * 8 / time_diff
                            capacity = self.link_capacity.get(link, 0) * 8
                            if capacity > 0:
                                load = bw_usage / capacity * 100
                                th_max, th_min = 80.0, 70.0 # Progi histerezy
                                
                                # Jeśli obciążenie > 80%, a koszt jest niski -> ZWIĘKSZ KOSZT
                                if load > th_max and self.dynamic_costs.get(link, 0) < 1000:
                                    self.dynamic_costs[link] = self.dynamic_costs[reverse_link] = 1000
                                    self.logger.warning(f"KONGESJA na {link}! Obciążenie: {load:.2f}%. Koszt: 1000")
                                # Jeśli obciążenie < 70%, a koszt był wysoki -> ZMNIEJSZ KOSZT
                                elif load < th_min and self.dynamic_costs.get(link, 0) == 1000:
                                    bw_mbps = self.link_capacity.get(link, 1) / 125000
                                    cost = 1000 / bw_mbps if bw_mbps > 0 else 1
                                    self.dynamic_costs[link] = self.dynamic_costs[reverse_link] = cost
                                    self.logger.info(f"Kongestia na {link} ustąpiła. Obciążenie: {load:.2f}%. Koszt: {cost:.2f}")
                    self.link_stats[key] = (time.time(), stat.tx_bytes)

    # --- Sekcja 6: Odkrywanie Topologii i Obliczanie Ścieżek ---

    @set_ev_cls(event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        """Reaguje na dołączenie nowego przełącznika do sieci."""
        switch = ev.switch
        dpid = switch.dp.id
        if dpid not in self.switches:
            self.switches.append(dpid)
            self.datapaths[dpid] = switch.dp
            self.switches.sort()

    @set_ev_cls(event.EventLinkAdd)
    def _link_add_handler(self, ev):
        """Reaguje na odkrycie nowego połączenia między przełącznikami."""
        link = ev.link
        s1, s2 = link.src.dpid, link.dst.dpid
        p1, p2 = link.src.port_no, link.dst.port_no
        self.adjacency[s1][s2], self.adjacency[s2][s1] = p1, p2
        
        # Ustawiamy początkowy koszt łącza na podstawie jego przepustowości
        link_tuple = (s1, s2)
        reverse_link_tuple = (s2, s1)
        bw_mbps = self.link_capacity.get(link_tuple, 1) / 125000
        cost = 1000 / bw_mbps if bw_mbps > 0 else 1
        self.dynamic_costs[link_tuple] = cost
        self.dynamic_costs[reverse_link_tuple] = cost
        self.logger.info(f"Odkryto połączenie: {s1}:{p1} <-> {s2}:{p2}. Ustawiono koszt początkowy: {cost:.2f}")

    def _get_path(self, src, dst, first_port, final_port):
        """Algorytm Dijkstry do znajdowania ścieżki o najniższym koszcie."""
        distance = {dpid: float('inf') for dpid in self.switches}
        previous = {dpid: None for dpid in self.switches}
        distance[src] = 0
        Q = set(self.switches)
        while Q:
            u = min(Q, key=lambda dpid: distance[dpid])
            Q.remove(u)
            if distance[u] == float('inf'): break
            for p in self.adjacency[u].keys():
                # Używamy aktualnych, dynamicznych kosztów!
                weight = self.dynamic_costs.get((u, p), 1)
                if distance[u] + weight < distance[p]:
                    distance[p], previous[p] = distance[u] + weight, u
        
        # Odtworzenie ścieżki
        path, p = [], dst
        while p is not None:
            path.append(p)
            p = previous.get(p)
        path.reverse()
        if src not in path: return None
        
        # Dodanie portów do ścieżki
        path_with_ports = []
        in_port = first_port
        for s1, s2 in zip(path[:-1], path[1:]):
            out_port = self.adjacency[s1][s2]
            path_with_ports.append((s1, in_port, out_port))
            in_port = self.adjacency[s2][s1]
        path_with_ports.append((dst, in_port, final_port))
        
        self.logger.info(f"Znaleziona ścieżka: {path_with_ports} (koszt: {distance[dst]:.2f})")
        return path_with_ports

    # --- Sekcja 7: Funkcje Pomocnicze (Instalacja Reguł) ---

    def _install_path(self, p, ev):
        """Instaluje reguły przepływu (flow rules) na przełącznikach wzdłuż ścieżki."""
        msg = ev.msg
        parser = msg.datapath.ofproto_parser
        ofproto = msg.datapath.ofproto
        pkt = packet.Packet(msg.data)
        pkt_ipv4, pkt_tcp, pkt_udp = pkt.get_protocol(ipv4.ipv4), pkt.get_protocol(tcp.tcp), pkt.get_protocol(udp.udp)
        if not pkt_ipv4: return

        for sw_dpid, in_port, out_port in p:
            # Tworzymy precyzyjną regułę dopasowania (match) na podstawie 5-ciu pól
            match_args = {'in_port': in_port, 'eth_type': ether_types.ETH_TYPE_IP, 'ipv4_src': pkt_ipv4.src, 'ipv4_dst': pkt_ipv4.dst}
            if pkt_tcp:
                match_args.update({'ip_proto': 6, 'tcp_src': pkt_tcp.src_port, 'tcp_dst': pkt_tcp.dst_port})
            elif pkt_udp:
                match_args.update({'ip_proto': 17, 'udp_src': pkt_udp.src_port, 'udp_dst': pkt_udp.dst_port})
            match = parser.OFPMatch(**match_args)
            
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapaths.get(sw_dpid)
            if datapath:
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                # Tworzymy i wysyłamy wiadomość FlowMod, która instaluje regułę
                mod = parser.OFPFlowMod(datapath=datapath, match=match, priority=2,
                                        idle_timeout=20, hard_timeout=60, instructions=inst)
                datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Wywoływana, gdy przełącznik po raz pierwszy łączy się z kontrolerem.
        Instaluje domyślną regułę "table-miss", która każe przesyłać wszystkie
        nieznane pakiety do kontrolera.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, match=match, priority=0, instructions=inst)
        datapath.send_msg(mod)
