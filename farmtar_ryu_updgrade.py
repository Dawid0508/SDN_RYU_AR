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

# --- Konfiguracja ---
THRESHOLD_HIGH = 0.9     # Próg obciążenia powyżej którego łącze jest oznaczane jako obciążone
THRESHOLD_LOW = 0.7      # Próg obciążenia poniżej którego łącze wraca do normalnego kosztu
MAX_COST = 1000         # Maksymalny koszt łącza obciążonego
DEFAULT_COST = 1        # Domyślny koszt łącza
IDLE_TIMEOUT = 100      # Czas (sekundy) bezczynności przepływu przed usunięciem z przełącznika
FFT_IDLE_TIMEOUT = 120  # Czas (sekundy) bezczynności wpisu w FFT przed usunięciem przez cleanup
CLEANUP_INTERVAL = 60   # Interwał czyszczenia FFT (sekundy)
STATS_REQUEST_INTERVAL = 10 # Interwał żądania statystyk (sekundy)

# --- Struktury Danych ---
switches = []           # Lista DPID przełączników
adjacency = defaultdict(lambda: defaultdict(lambda: {"port": None, "cost": DEFAULT_COST})) # Macierz sąsiedztwa i kosztów
link_load = defaultdict(lambda: {"tx_bytes": 0, "rx_bytes": 0, "timestamp": 0}) # Monitorowanie obciążenia łącza
fft = {}                # Flow Forwarding Table: flow_id -> (out_port, timestamp)
mac_to_dpid = {}        # <<<--- DODANE: Mapowanie MAC hosta -> DPID przełącznika, do którego jest podłączony

# --- Funkcje Pomocnicze ---
def minimum_distance(distance, Q):
    min_dist = float('inf')
    min_node = None
    for node in Q:
        # Upewnij się, że node istnieje w distance przed dostępem
        if node in distance and distance[node] < min_dist:
            min_dist = distance[node]
            min_node = node
    return min_node

def calculate_path(src, dst):
    # Sprawdzenie czy src i dst są w liście znanych przełączników
    if src not in switches or dst not in switches:
        # Logowanie błędu lub zwrócenie None, jeśli przełączniki nie są znane
        # self.logger.warning(f"Próba obliczenia ścieżki dla nieznanych przełączników: src={src}, dst={dst}")
        # Potrzebny dostęp do loggera, jeśli chcemy logować w tej funkcji,
        # lub przekazanie loggera jako argument. Na razie zwracamy None.
        print(f"Ostrzeżenie: Próba obliczenia ścieżki dla nieznanych przełączników: src={src}, dst={dst}")
        return None

    distance = {node: float('inf') for node in switches}
    previous = {node: None for node in switches}
    distance[src] = 0
    Q = set(switches)

    while Q:
        u = minimum_distance(distance, Q)
        if u is None:
            # Sytuacja, gdy graf jest niespójny lub nie ma więcej osiągalnych węzłów
            break
        Q.remove(u)

        # Iterujemy tylko po znanych sąsiadach 'u'
        for v in adjacency[u]:
            if adjacency[u][v]["port"] is not None and v in Q: # Sprawdź czy v jest nadal w Q
                cost = adjacency[u][v]["cost"]
                alt = distance[u] + cost
                if alt < distance[v]:
                    distance[v] = alt
                    previous[v] = u

    # Odtworzenie ścieżki
    path = []
    current = dst
    # Zabezpieczenie przed nieskończoną pętlą, jeśli ścieżka nie istnieje
    visited_for_path = set()
    while current is not None and current not in visited_for_path:
        visited_for_path.add(current)
        path.insert(0, current)
        if current == src:
            break # Znaleziono ścieżkę
        current = previous.get(current) # Użyj .get() dla bezpieczeństwa

    # Sprawdzenie czy ścieżka została poprawnie zbudowana
    if not path or path[0] != src:
        print(f"Nie znaleziono ścieżki z {src} do {dst}")
        return None # Brak ścieżki

    return path


def get_ports(path):
    ports = []
    for s1, s2 in zip(path[:-1], path[1:]):
        # Sprawdzenie czy łącze istnieje
        if s2 not in adjacency[s1] or s1 not in adjacency[s2]:
            print(f"Błąd: Brak definicji łącza między {s1} a {s2} w adjacency.")
            return None # Zwróć None, jeśli brakuje łącza
        out_port = adjacency[s1][s2]["port"]
        in_port = adjacency[s2][s1]["port"]
        if out_port is None or in_port is None:
            print(f"Błąd: Brak informacji o porcie dla łącza między {s1} a {s2}.")
            return None # Zwróć None, jeśli brakuje informacji o porcie
        ports.append((s1, in_port, out_port))

    # Sprawdzenie czy udało się zbudować listę portów
    if len(ports) != len(path) -1:
        print(f"Błąd: Nie udało się uzyskać portów dla całej ścieżki {path}.")
        return None # Błąd w budowaniu portów

    # Dodanie ostatniego segmentu - port wyjściowy na hoście docelowym (nieznany)
    # Zakładamy, że ostatni element path to przełącznik, do którego podłączony jest host
    # i że port wyjściowy zostanie określony przez logikę L2 (mac_to_port)
    # Dla routingu między przełącznikami, możemy zwrócić tylko porty między nimi
    return ports

########### to dodalem 

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

# --- Główna Klasa Kontrolera ---
class FAMTARController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FAMTARController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.fft_lock = threading.Lock()
        self.mac_to_port = {} # <<<--- DODANE: Słownik do nauki MAC -> Port (standard w Ryu)

    def add_flow(self, datapath, match, actions, priority=1, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout, priority=priority, instructions=inst)
        datapath.send_msg(mod)

    # Zmieniona definicja, dodano original_in_port
    def install_path(self, path, flow_id, ev, src_mac, dst_mac, final_out_port, original_in_port):
        # path: lista DPID [dpid_src, dpid_mid1, ..., dpid_dst]
        # final_out_port: port na ostatnim dpid (dpid_dst) do hosta
        # original_in_port: port, na który pakiet wszedł na PIERWSZYM dpid (path[0])
        self.logger.info(f"--- Rozpoczynam instalacje sciezki dla flow_id: {flow_id} ---")
        self.logger.info(f"    Sciezka DPID: {path}")
        self.logger.info(f"    Port koncowy na {path[-1]} do hosta: {final_out_port}")
        self.logger.info(f"    Port wejsciowy na {path[0]}: {original_in_port}")

        if not path:
            self.logger.error("    Blad: Pusta sciezka DPID.")
            return

        first_switch_out_port = None # Do zapisu w FFT

        # Iteracja przez wszystkie przełączniki na ścieżce
        for i in range(len(path)):
            current_dpid = path[i]

            if current_dpid not in self.datapaths:
                self.logger.error(f"    Blad: Brak datapath dla przełącznika {current_dpid}.")
                continue

            datapath = self.datapaths[current_dpid]
            parser = datapath.ofproto_parser

            # Określ port wejściowy (match_in_port)
            if i == 0:
                match_in_port = original_in_port # Użyj przekazanego portu dla pierwszego switcha
            else:
                prev_dpid = path[i-1]
                match_in_port = adjacency[current_dpid].get(prev_dpid, {}).get("port")
                if match_in_port is None:
                    self.logger.error(f"    Blad: Nie znaleziono portu wejsciowego na {current_dpid} z {prev_dpid}.")
                    continue

            # Określ port wyjściowy (out_port)
            if i < len(path) - 1:
                next_dpid = path[i+1]
                out_port = adjacency[current_dpid].get(next_dpid, {}).get("port")
                if out_port is None:
                    self.logger.error(f"    Blad: Nie znaleziono portu wyjsciowego z {current_dpid} do {next_dpid}.")
                    continue
                if i == 0: # Zapamiętaj dla FFT
                    first_switch_out_port = out_port
            else: # Ostatni przełącznik
                out_port = final_out_port
                if out_port is None:
                    self.logger.error(f"    Blad: Brak portu wyjsciowego do hosta na {current_dpid}.")
                    continue

            # Utwórz match i actions
            match = parser.OFPMatch(in_port=match_in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]

            # Dodaj przepływ
            self.add_flow(datapath, match, actions, priority=1, idle_timeout=IDLE_TIMEOUT, hard_timeout=0)
            self.logger.info(f"    Instalacja: switch={current_dpid}, in_port={match_in_port}, out_port={out_port}")

        # Aktualizacja FFT
        with self.fft_lock:
            # Sprawdź, czy udało się ustalić port dla pierwszego kroku
            if first_switch_out_port is not None:
                fft[flow_id] = (first_switch_out_port, time.time())
                self.logger.debug(f"    Dodano/zaktualizowano FFT: flow_id={flow_id}, out_port={first_switch_out_port}")
            elif len(path) == 1 and out_port is not None: # Obsługa przypadku hosta na tym samym switchu (choć nie powinno tu trafić)
                fft[flow_id] = (out_port, time.time())
                self.logger.debug(f"    Dodano/zaktualizowano FFT (ten sam switch): flow_id={flow_id}, out_port={out_port}")
            else:
                # Sprawdźmy, czy path ma tylko jeden element i out_port jest znany (host na tym samym switchu)
                # Ta logika jest już w packet_in_handler, więc tu nie powinna być potrzebna, ale zostawmy ostrzeżenie
                if len(path) != 1:
                    self.logger.warning("    Nie udalo sie ustalic portu dla pierwszego kroku do aktualizacji FFT.")
        self.logger.info(f"--- Zakonczono instalacje sciezki dla flow_id: {flow_id} ---")
    # --- Handlery Eventów ---
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.datapaths[dpid] = datapath
        self.mac_to_port.setdefault(dpid, {}) # Inicjalizuj słownik portów dla nowego przełącznika

        # Dodanie do globalnej listy, jeśli jeszcze go tam nie ma
        if dpid not in switches:
            switches.append(dpid)
            self.logger.info(f"Dodano przełącznik {dpid} do listy znanych przełączników.")

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, match, actions, priority=0) # Default flow: send to controller

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port'] # Oryginalny port wejściowy
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        self.logger.info(f"--- Otrzymano PacketIn ---")
        self.logger.info(f"    Switch: {dpid}, InPort: {in_port}, SrcMAC: {src_mac}, DstMAC: {dst_mac}")

        # --- Nauka MAC -> Port i MAC -> DPID ---
        self.mac_to_port.setdefault(dpid, {})
        if self.mac_to_port[dpid].get(src_mac) != in_port:
            self.logger.info(f"    Nauczono MAC->Port: Switch {dpid}, MAC {src_mac}, Port {in_port}")
            self.mac_to_port[dpid][src_mac] = in_port
        if mac_to_dpid.get(src_mac) != dpid:
            mac_to_dpid[src_mac] = dpid
            self.logger.info(f"    Nauczono MAC->DPID: MAC {src_mac} -> DPID {dpid}")
        self.logger.debug(f"    Aktualny mac_to_dpid: {mac_to_dpid}")
        self.logger.debug(f"    Aktualny mac_to_port[{dpid}]: {self.mac_to_port.get(dpid)}")
        # --- Koniec nauki ---

        flow_id = calculate_flow_id(pkt, in_port, src_mac, dst_mac)
        self.logger.debug(f"    Obliczony flow_id: {flow_id}")

        # Sprawdz FFT
        with self.fft_lock:
            if flow_id in fft:
                out_port_fft, timestamp = fft[flow_id]
                if time.time() - timestamp <= FFT_IDLE_TIMEOUT:
                    fft[flow_id] = (out_port_fft, time.time())
                    self.logger.info(f"    Przeplyw znaleziony w FFT. Wysylanie na port {out_port_fft}.")
                    actions = [parser.OFPActionOutput(out_port_fft)]
                    # ... (kod wysylania PacketOut jak wczesniej) ...
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                            in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
                    self.logger.info(f"--- Zakonczono obsluge PacketIn (FFT hit) ---")
                    return
                else:
                    del fft[flow_id]
                    self.logger.info(f"    Usunieto przestarzaly wpis z FFT (timeout): flow_id={flow_id}")


        # Przeplyw nieznany LUB wpis FFT wygasl - okresl port wyjsciowy
        out_port = None
        actions = None
        path = None # Inicjalizuj path

        if dst_mac in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst_mac]
            self.logger.info(f"    Cel {dst_mac} na tym samym przełączniku {dpid}, port {out_port}")
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            self.add_flow(datapath, match, actions, idle_timeout=IDLE_TIMEOUT, hard_timeout=0)
            self.logger.info(f"    Zainstalowano przeplyw na switchu {dpid} (ten sam switch).")
            # Zapisz w FFT
            with self.fft_lock:
                fft[flow_id] = (out_port, time.time())
                self.logger.debug(f"    Dodano do FFT (ten sam switch): flow_id={flow_id}, out_port={out_port}")

        elif dst_mac in mac_to_dpid:
            dst_dpid = mac_to_dpid[dst_mac]
            self.logger.info(f"    Cel {dst_mac} na znanym przełączniku {dst_dpid}. Obliczanie sciezki z {dpid}...")
            self.logger.debug(f"    Znane przełączniki: {switches}")
            self.logger.debug(f"    Macierz sasiedztwa (fragment dla {dpid}): {adjacency.get(dpid)}")
            path = calculate_path(dpid, dst_dpid) # path to lista DPID

            if path:
                self.logger.info(f"    Znaleziono sciezke DPID: {path}")
                path_ports = get_ports(path)
                final_out_port = self.mac_to_port.get(dst_dpid, {}).get(dst_mac)
                self.logger.debug(f"    Znalezione porty sciezki: {path_ports}")
                self.logger.debug(f"    Znaleziony port koncowy na {dst_dpid}: {final_out_port}")

                if path_ports is not None and final_out_port is not None:
                    # ===>>> WAŻNA ZMIANA: Przekazanie oryginalnego in_port <<<===
                    # Musimy zmodyfikować install_path, aby przyjmował ten port
                    # self.install_path(path, path_ports, flow_id, ev, src_mac, dst_mac, final_out_port, in_port)
                    # Na razie wywołujemy starą wersję, PAMIĘTAJ O POPRAWCE install_path
                    self.install_path(path, flow_id, ev, src_mac, dst_mac, final_out_port, in_port) # Dodano in_port
                    # ===>>> Koniec ważnej zmiany <<<===

                    # Akcja dla pierwszego pakietu - wyslij na pierwszy port sciezki
                    # Sprawdź, czy path_ports nie jest pusta
                    if path_ports:
                        out_port = path_ports[0][2] # Port wyjsciowy PIERWSZEGO przełącznika
                        actions = [parser.OFPActionOutput(out_port)]
                        self.logger.info(f"    Akcja dla pierwszego pakietu: Wyslij na port {out_port} switcha {dpid}")
                    else: # Scieżka ma tylko 1 switch (src == dst), co nie powinno się zdarzyć tutaj
                        self.logger.error("    Blad logiczny: Sciezka znaleziona, ale pusta lista portow miedzy switchami.")
                        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)] # Fallback na flood
                else:
                    self.logger.warning(f"    Nie udalo sie uzyskac portow dla sciezki lub portu do hosta {dst_mac} na {dst_dpid}. Zalewanie.")
                    actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            else:
                self.logger.warning(f"    Nie znaleziono sciezki z {dpid} do {dst_dpid}. Zalewanie.")
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        else:
            self.logger.warning(f"    Nieznany MAC docelowy: {dst_mac}. Zalewanie z przełącznika {dpid}.")
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        # Wyslij pierwszy pakiet (lub zalej)
        if actions: # Upewnij sie, ze jakas akcja zostala ustalona
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            self.logger.info(f"    Wyslano PacketOut.")
        else:
            self.logger.error("    Nie ustalono zadnej akcji dla PacketOut!")
        self.logger.info(f"--- Zakonczono obsluge PacketIn ---")

    # --- Pozostałe Handlery Eventów (bez zmian) ---
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch
        dpid = switch.dp.id
        if dpid not in switches:
            switches.append(dpid)
            self.datapaths[dpid] = switch.dp # Zapisz datapath przy wejściu
            self.mac_to_port.setdefault(dpid, {}) # Inicjalizuj mac_to_port
            self.logger.info(f"Przełącznik dodany: {dpid}")
        else:
            self.logger.warning(f"Przełącznik {dpid} już istnieje na liście.")


    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        switch = ev.switch
        dpid = switch.dp.id
        if dpid in switches:
            switches.remove(dpid)
            self.logger.info(f"Przełącznik usunięty: {dpid}")
        if dpid in self.datapaths:
            del self.datapaths[dpid]
        if dpid in self.mac_to_port:
            del self.mac_to_port[dpid]
        # Opcjonalnie: Usuń wpisy z mac_to_dpid, jeśli hosty były podłączone tylko do tego przełącznika
        keys_to_remove = [mac for mac, dp in mac_to_dpid.items() if dp == dpid]
        for key in keys_to_remove:
            del mac_to_dpid[key]
            self.logger.info(f"Usunięto mapowanie MAC->DPID dla {key} (przełącznik {dpid} odszedł)")


    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_port = link.src.port_no
        dst_port = link.dst.port_no

        # Upewnij się, że oba przełączniki są na liście 'switches'
        if src_dpid in switches and dst_dpid in switches:
            adjacency[src_dpid][dst_dpid]["port"] = src_port
            adjacency[dst_dpid][src_dpid]["port"] = dst_port
            # Resetuj koszt przy dodaniu łącza
            adjacency[src_dpid][dst_dpid]["cost"] = DEFAULT_COST
            adjacency[dst_dpid][src_dpid]["cost"] = DEFAULT_COST
            self.logger.info(f"Łącze dodane: {src_dpid}:{src_port} <-> {dst_dpid}:{dst_port}")
        else:
            self.logger.warning(f"Ignorowanie dodania łącza między {src_dpid} a {dst_dpid} - jeden lub oba przełączniki nie są znane.")


    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        # Usuń wpisy adjacency w obie strony
        if src_dpid in adjacency and dst_dpid in adjacency[src_dpid]:
            del adjacency[src_dpid][dst_dpid]
        if dst_dpid in adjacency and src_dpid in adjacency[dst_dpid]:
            del adjacency[dst_dpid][src_dpid]
        self.logger.info(f"Łącze usunięte między: {src_dpid} <-> {dst_dpid}")

    # --- Monitorowanie i Czyszczenie (z poprawkami) ---
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id

        # Aktualizacja statystyk obciążenia (prostsza wersja, można rozbudować)
        # TODO: Dokładniejsze mapowanie statystyk przepływów na obciążenie konkretnych *łączy*
        #       Obecny kod jest uproszczony i może nie odzwierciedlać dokładnie obciążenia per-link.
        for stat in sorted([flow for flow in body if flow.priority == 1],
                        key=lambda flow: (flow.match.get('in_port', 0), flow.match.get('eth_dst', ''))): # Użyj .get dla bezpieczeństwa
            # Ta część wymagałaby bardziej zaawansowanej logiki, aby powiązać
            # przepływ ze specyficznym łączem wyjściowym i zaktualizować jego koszt.
            # Na razie pomijamy dynamiczną aktualizację kosztów na podstawie statystyk.
            pass

        # self.logger.debug(f"Otrzymano statystyki przepływów z {dpid}")


    def _request_stats_loop(self):
        """Pętla wysyłająca cyklicznie żądania statystyk przepływów."""
        while True:
            # self.logger.debug("Rozpoczynanie cyklu żądań statystyk...")
            # Tworzymy kopię kluczy, aby uniknąć błędów przy modyfikacji słownika w innym wątku
            datapaths_to_request = list(self.datapaths.keys())
            for dpid in datapaths_to_request:
                if dpid in self.datapaths: # Sprawdź, czy datapath nadal istnieje
                    datapath = self.datapaths[dpid]
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    req = parser.OFPFlowStatsRequest(datapath)
                    try:
                        datapath.send_msg(req)
                        # self.logger.debug(f"Wysłano żądanie statystyk do {dpid}")
                    except Exception as e:
                        self.logger.error(f"Błąd podczas wysyłania żądania statystyk do {dpid}: {e}")
                else:
                    self.logger.warning(f"Próba wysłania statystyk do nieistniejącego datapath {dpid}")

            time.sleep(STATS_REQUEST_INTERVAL)

    def _cleanup_fft_loop(self):
        """Pętla czyszcząca przestarzałe wpisy w FFT."""
        while True:
            time.sleep(CLEANUP_INTERVAL)
            with self.fft_lock:
                current_time = time.time()
                expired_flows = [flow_id for flow_id, (out_port, timestamp) in fft.items()
                                if current_time - timestamp > FFT_IDLE_TIMEOUT]
                if expired_flows:
                    self.logger.info(f"Czyszczenie FFT: Usuwanie {len(expired_flows)} przestarzałych wpisów.")
                    for flow_id in expired_flows:
                        del fft[flow_id]
                        # self.logger.debug(f"Usunięto przestarzały wpis z FFT: flow_id={flow_id}")
                # else:
                #      self.logger.debug("Czyszczenie FFT: Brak przestarzałych wpisów.")


# Uruchomienie monitoringu po starcie aplikacji
    def start(self):
        super(FAMTARController, self).start() # Ważne: wywołanie start() z klasy nadrzędnej
        self.logger.info("FAMTAR Controller uruchomiony")
        # Uzywamy self.spawn do uruchamiania watkow w tle zarzadzanych przez Ryu
        self.monitor_thread = threading.Thread(target = self._request_stats_loop) #Uruchomienie monitoringu
        self.cleanup_thread = threading.Thread(target=self._cleanup_fft_loop) # Uruchomienie czyszczenia FFT
        self.monitor_thread.start()
        self.cleanup_thread.start()
        self.logger.info("Watki monitoringu i czyszczenia FFT uruchomione przez spawn.")