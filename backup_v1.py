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
from collections import defaultdict
import time
import hashlib
import threading
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

# Konfiguracja 
TRESHOLD_HIGH = 0.9     # Próg obciążenia powyżej którego łącze jest oznaczane jako obciążone
TRESHOLD_LOW = 0.7      # Próg obciążenia poniżej którego łącze wraca do normalnego kosztu
MAX_COST = 1000         # Maksymalny koszt łącza obciążonego
DEFAULT_COST = 1        # Domyślny koszt łącza
IDLE_TIMEOUT = 100  # Czas (sekundy) po którym wpis w FFT jest uznawany za przestarzały
CLEANUP_INTERVAL = 60 # Interwał czyszczenia FFT (sekundy)

# Struktury Danych 
switches = []
adjacency = defaultdict(lambda: defaultdict(lambda: {"port": None, "cost": DEFAULT_COST}))
link_load = defaultdict(lambda: {"tx_bytes": 0, "rx_bytes": 0, "timestamp": 0}) # Monitorowanie obciążenia łącza
fft = {} # Flow Forwarding Table: flow_id -> out_port

def minimum_distance(distance, Q):
    min_dist = float('inf')
    min_node = None
    
    for node in Q:
        if distance[node] < min_dist:
            min_dist = distance[node]
            min_node = node
    return min_node

def calculate_path(src, dst):
    # Algorytm Dijkstry  z uwzględnieniem dynamicznych kosztów łączy
    # Inicjalizacja odległości do wszystkich węzłów jako nieskończoność
    # oraz poprzedników jako None
    distance = {node: float('inf') for node in switches}
    previous = {node: None for node in switches}
    distance[src] = 0       # Odległość do węzła źródłowego wynosi 0
    Q = set(switches)    # Zbiór węzłów do przetworzenia
    
    while Q:
        u = minimum_distance(distance, Q)
        if u is None:
            break  # Graf niespójny
        Q.remove(u)
        
        for v in switches:
            if adjacency[u][v]["port"] is not None:
                cost = adjacency[u][v]["cost"]
                alt = distance[u] + cost
                if alt < distance[v]:
                    distance[v] = alt
                    previous[v] = u
                    
    # Odtworzenie ścieżki od węzła docelowego do źródłowego
    
    path = []
    current = dst
    while current is not None:
        path.insert(0, current)
        current = previous[current]
        if current == src:       # Jeśli dotarcie do źródła to koniec
            path.insert(0, current)
            break
    
    if path[0] != src:
        return None # Brak ścieżki
    return path

def get_ports(path):
    # Dodawanie in_port i out_port do ścieżki
    
    ports = []
    for s1, s2 in zip(path[:-1], path[1:]):
        out_port = adjacency[s1][s2]["port"]
        in_port = adjacency[s2][s1]["port"]
        ports.append((s1, in_port, out_port))
    return ports

def calculate_flow_id(packet, in_port, eth_src, eth_dst):
    # Obliczanie ID przepływu na podstawie 5-krotki
    ip_proto = 0
    src_port = 0
    dst_port = 0

    try:
        # próba wydobycia informacji IP
        # UŻYWAMY KLAS ipv4.ipv4 i ipv6.ipv6
        ip_header = packet.get_protocol(ipv4.ipv4) or packet.get_protocol(ipv6.ipv6)
        if ip_header:
            ip_proto = ip_header.proto
            # wydobycie informacji TCP/UDP
            # UŻYWAMY KLAS tcp.tcp i udp.udp
            tcp_header = packet.get_protocol(tcp.tcp)
            udp_header = packet.get_protocol(udp.udp)

            if tcp_header:
                src_port = tcp_header.src_port
                dst_port = tcp_header.dst_port
            elif udp_header:
                src_port = udp_header.src_port
                dst_port = udp_header.dst_port
    except Exception as e:
        # Dodajmy bardziej szczegółowy log błędu
        self.logger.error(f"Wyjątek podczas parsowania pakietu dla flow_id: {e}", exc_info=True) # exc_info=True pokaże pełny traceback

    flow_tuple = (eth_src, eth_dst, ip_proto, src_port, dst_port, in_port)
    flow_id = hashlib.md5(str(flow_tuple).encode('utf-8')).hexdigest()
    return flow_id

class FAMTARController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FAMTARController, self).__init__(*args, **kwargs)
        self.datapaths = {}  # Przechowywanie obiektów datapath
        self.fft_lock = threading.Lock() # Zamek do synchronizacji dostępu do FFT        
        self.thread = None


    def add_flow(self, datapath, match, actions, priority=1, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout, priority=priority, instructions=inst)
        datapath.send_msg(mod)

    def install_path(self, path, flow_id, ev, src_mac, dst_mac):
        # Instalacja przepływów na ścieżce
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for sw, in_port, out_port in path:
            datapath = self.datapaths[sw]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, match, actions, idle_timeout=IDLE_TIMEOUT, hard_timeout=0)  # Ustawienie IDLE_TIMEOUT
            self.logger.info(f"Instalacja przepływu: switch={sw}, in_port={in_port}, out_port={out_port}, flow_id={flow_id}, timeout={IDLE_TIMEOUT}")

        with self.fft_lock: # Zabezpieczenie dostępu do FFT
            fft[flow_id] = (path[-1][2], time.time())  # Zapisanie portu i czasu
            self.logger.debug(f"Dodano do FFT: flow_id={flow_id}, out_port={path[-1][2]}, timestamp={fft[flow_id][1]}")


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Konfiguracja przełącznika
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath  # Zapisanie obiektu datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, match, actions, priority=0) #Przechwytywanie wszystkich pakietów do kontrolera

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or dst_mac == 'ff:ff:ff:ff:ff:ff':
            return  # Ignoruj LLDP i pakiety broadcast
        
        # Obsługa przychodzących pakietów
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # Ignorowanie LLDP

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id

        flow_id = calculate_flow_id(pkt, in_port, src_mac, dst_mac)

        with self.fft_lock:
            if flow_id in fft:
                # Przepływ znany - aktualizacja znacznika czasu
                out_port, timestamp = fft[flow_id] # Rozpakowanie tupli
                fft[flow_id] = (out_port, time.time()) # Aktualizacja znacznika czasu
                self.logger.debug(f"Przepływ znaleziony w FFT: flow_id={flow_id}, out_port={out_port}, timestamp={fft[flow_id][1]}")
                actions = [parser.OFPActionOutput(out_port)]
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return

         # Przepływ nieznany - oblicz ścieżkę
        path = calculate_path(dpid, dst_mac)

        if path:
            ports = get_ports(path)
            self.install_path(ports, flow_id, ev, src_mac, dst_mac)

            # Wyślij pakiet
            out_port = ports[0][2]
            actions = [parser.OFPActionOutput(out_port)]
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            self.logger.info(f"Nowy przepływ: flow_id={flow_id}, path={path}, out_port={out_port}")
        else:
            # Brak ścieżki - zalej
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            self.logger.warning("Brak ścieżki, zalewanie")

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        # Dodanie przełącznika do topologii
        switch = ev.switch
        switches.append(switch.dp.id)
        self.logger.info(f"Przełącznik dodany: {switch.dp.id}")

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        # Usunięcie przełącznika z topologii
        switch = ev.switch
        switches.remove(switch.dp.id)
        self.logger.info(f"Przełącznik usunięty: {switch.dp.id}")

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        # Dodanie łącza do topologii
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_port = link.src.port_no
        dst_port = link.dst.port_no

        adjacency[src_dpid][dst_dpid]["port"] = src_port
        adjacency[dst_dpid][src_dpid]["port"] = dst_port
        adjacency[src_dpid][dst_dpid]["cost"] = DEFAULT_COST
        adjacency[dst_dpid][src_dpid]["cost"] = DEFAULT_COST

        self.logger.info(f"Łącze dodane: {src_dpid}:{src_port} <-> {dst_dpid}:{dst_port}")

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        # Usunięcie łącza z topologii
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid

        adjacency[src_dpid][dst_dpid]["port"] = None
        adjacency[dst_dpid][src_dpid]["port"] = None

        self.logger.info(f"Łącze usunięte: {src_dpid} <-> {dst_dpid}")

    #Implementacja monitorowania łącza (wysyłanie zapytań o statystyki)
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath

        for stat in sorted([flow for flow in body if flow.priority == 1],
                        key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])): #Sortowanie statystyk
            src_port = stat.match['in_port']
            dst_mac = stat.match['eth_dst']

            # Znajdź port wyjściowy w topologii (jeśli istnieje)
            dst_port = None
            for sw in switches:
                if adjacency[datapath.id][sw]["port"] is not None:
                    dst_port = adjacency[datapath.id][sw]["port"]

            if dst_port is None:
                continue #Nie znaleziono portu docelowego

            link = (datapath.id, dst_port) # Identyfikacja łącza
            current_time = time.time()
            tx_bytes = stat.byte_count

            #Obliczanie obciążenia łącza
            if link in link_load:
                old_tx_bytes = link_load[link]["tx_bytes"]
                old_timestamp = link_load[link]["timestamp"]
                duration = current_time - old_timestamp
                if duration > 0:
                    load = (tx_bytes - old_tx_bytes) * 8 / duration  # Obciążenie w bitach/s
                    capacity = 1000000000 #Przykladowa przepustowosc 1Gbps.  Zmień na rzeczywistą pojemność łącza

                    #Aktualizacja kosztów łączy
                    if load > TRESHOLD_HIGH * capacity and adjacency[datapath.id][dst_port]["cost"] != MAX_COST:
                        adjacency[datapath.id][dst_port]["cost"] = MAX_COST
                        self.logger.warning(f"Łącze {datapath.id}->{dst_port} obciążone. Zmiana kosztu na {MAX_COST}")
                    elif load < TRESHOLD_LOW * capacity and adjacency[datapath.id][dst_port]["cost"] == MAX_COST:
                        adjacency[datapath.id][dst_port]["cost"] = DEFAULT_COST
                        self.logger.info(f"Łącze {datapath.id}->{dst_port} zwolnione.  Przywrócenie kosztu do {DEFAULT_COST}")
                else:
                    load = 0

            # Aktualizacja informacji o łącze
            link_load[link]["tx_bytes"] = tx_bytes
            link_load[link]["timestamp"] = current_time

        # Wysłanie żądania o statystyki ponownie
        self._request_stats()

    #Żądanie statystyk przepływów
    def _request_stats(self):
        """Pętla wysyłająca cyklicznie żądania statystyk przepływów."""
        for datapath in self.datapaths.values():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)
            
    # Funkcja czyszcząca FFT
    def _cleanup_fft(self):
        """Czyszczenie przestarzałych wpisów w FFT."""
        while True:
            time.sleep(CLEANUP_INTERVAL)
            with self.fft_lock:
                current_time = time.time()
                expired_flows = [flow_id for flow_id, (out_port, timestamp) in fft.items()
                                if current_time - timestamp > IDLE_TIMEOUT] # Lista przestarzałych przepływów
                for flow_id in expired_flows:
                    del fft[flow_id]
                    self.logger.info(f"Usunięto przestarzały wpis z FFT: flow_id={flow_id}")
                self.logger.debug(f"FFT po czyszczeniu: {fft}")

    # Uruchomienie monitoringu po starcie aplikacji
    def start(self):
        super(FAMTARController, self).start()
        self.logger.info("FAMTAR Controller uruchomiony")
        self.monitor_thread = threading.Thread(target = self._request_stats) #Uruchomienie monitoringu
        self.cleanup_thread = threading.Thread(target=self._cleanup_fft) # Uruchomienie czyszczenia FFT
        self.monitor_thread.start()
        self.cleanup_thread.start()