from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from collections import defaultdict
from ryu.lib.packet import ipv4, tcp, udp 
from ryu.lib import hub                 
import time 
from operator import attrgetter


def get_path (src, dst, first_port, final_port, weights, switches, adjacency):
    print( "get_path function is called, src=", src," dst=", dst)
    
    distance = {}
    previous = {}

    # Używamy przekazanej listy 'switches'
    for dpid in switches:
        distance[dpid] = float('Inf')
        previous[dpid] = None

    distance[src] = 0
    Q = set(switches) # Używamy przekazanej listy 'switches'

    while Q:
        u = min(Q, key=lambda v: distance[v])
        if distance[u] == float('Inf'):
            break
        Q.remove(u)
        
        # Używamy przekazanej listy 'switches' i mapy 'adjacency'
        for p in switches:
            if adjacency[u][p] is not None:
                w = weights[u][p]
                if distance[u] + w < distance[p]:
                    distance[p] = distance[u] + w
                    previous[p] = u

    # creating a list of switches between src and dst which are in the shortest path obtained by Dijkstra's algorithm reversely
    r = []
    p = dst
    r.append(p)
    # set q to the last node before dst 
    q = previous[p]
    while q is not None:
        if q == src:
            r.append(q)
            break
        p = q
        r.append(p)
        q = previous[p]

    # reversing r as it was from dst to src
    r.reverse()

    # setting path 
    if src == dst:
        path=[src]
    else:
        path=r

    # Now adding in_port and out_port to the path
    r = []
    in_port = first_port
    for s1, s2 in zip(path[:-1], path[1:]):
        out_port = adjacency[s1][s2] 
        r.append((s1, in_port, out_port))
        in_port = adjacency[s2][s1] 
    r.append((dst, in_port, final_port))
    return r


class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.datapath_list = []
        self.switches = []
        self.adjacency = defaultdict(lambda: defaultdict(lambda: None))
        
        # --- NOWE STRUKTURY DANYCH DLA FAMTAR ---
        # Flow Forwarding Table: kluczem jest ID przepływu, wartością jest ścieżka
        self.fft = {}
        # Wagi linków: kluczem jest krotka (dpid1, dpid2), wartością jest koszt
        self.link_weights = defaultdict(lambda: defaultdict(lambda: 1))
        self.datapaths = {}  # Lista przełączników (datapathów)
        
        # Statystyki do obliczania obciążenia
        self.link_stats = {} # Będzie przechowywać (timestamp, bytes) dla każdego linku
        self.mymacs = {}
        
        # Próg kongestii w B/s (np. 50 Mbit/s = 6.25 MB/s)
        self.congestion_threshold = 6250000 
        
        # Wątek do monitorowania sieci
        self.monitor_thread = hub.spawn(self._monitor)

    def install_path(self, p, ev, src_mac, dst_mac):
        print("install_path function is called!")
        #print( "p=", p, " src_mac=", src_mac, " dst_mac=", dst_mac)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        
        # adding path to flow table of each switch inside the shortest path
        for sw, in_port, out_port in p:
            #print( src_mac,"->", dst_mac, "via ", sw, " in_port=", in_port, " out_port=", out_port)
            # setting match part of the flow table
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            # setting actions part of the flow table
            actions = [parser.OFPActionOutput(out_port)]
            # getting the datapath
            datapath = self.datapaths[sw]
            # getting instructions based on the actions
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=0, hard_timeout=0,
                                                    priority=1, instructions=inst)
            # finalizing the change to switch datapath
            datapath.send_msg(mod)

    def _get_flow_id(self, pkt):
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip:
            src_ip = ip.src
            dst_ip = ip.dst
            proto = ip.proto
            
            if proto == 6: # TCP
                t = pkt.get_protocol(tcp.tcp)
                src_port = t.src_port
                dst_port = t.dst_port
                return (src_ip, dst_ip, proto, src_port, dst_port)
            elif proto == 17: # UDP
                u = pkt.get_protocol(udp.udp)
                src_port = u.src_port
                dst_port = u.dst_port
                return (src_ip, dst_ip, proto, src_port, dst_port)
                
        # Jeśli to nie jest TCP/UDP, używamy MAC adresów jako fallback
        eth = pkt.get_protocol(ethernet.ethernet)
        return (eth.src, eth.dst)

    # defining event handler for setup and configuring of switches
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures , CONFIG_DISPATCHER)
    def switch_features_handler(self , ev):
        print("switch_features_handler function is called")
        # getting the datapath, ofproto and parser objects of the event
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath # <-- DODAJ TĘ LINIĘ
        # setting match condition to nothing so that it will match to anything
        match = parser.OFPMatch()
        # setting action to send packets to OpenFlow Controller without buffering
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]
        # setting the priority to 0 so that it will be that last entry to match any packet inside any flow table
        mod = datapath.ofproto_parser.OFPFlowMod(
                            datapath=datapath, match=match, cookie=0,
                            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                            priority=0, instructions=inst)
        # finalizing the mod 
        datapath.send_msg(mod)


    # defining an event handler for packets coming to switches event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # getting msg, datapath, ofproto and parser objects
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # getting the port switch received the packet with
        in_port = msg.match['in_port']
        # creating a packet encoder/decoder class with the raw data obtained by msg
        pkt = packet.Packet(msg.data)
        # getting the protocl that matches the received packet
        eth = pkt.get_protocol(ethernet.ethernet)

        # avoid broadcasts from LLDP 
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == 34525:
            return

        # getting source and destination of the link
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        print("packet in. src=", src, " dst=", dst," dpid=", dpid)

        # add the host to the mymacs of the first switch that gets the packet
        if src not in self.mymacs.keys():
            self.mymacs[src] = (dpid, in_port)
            print("mymacs=", self.mymacs)

        flow_id = self._get_flow_id(pkt)
        
        if flow_id in self.fft:
            # Można by tu odświeżać timestamp, jeśli chcemy usuwać nieaktywne przepływy
            self.fft[flow_id]['timestamp'] = time.time()
            # Ponieważ reguła dla tego przepływu już powinna istnieć, ten pakiet nie powinien
            # w ogóle dotrzeć do kontrolera. Jeśli dotarł, to znaczy że coś jest nie tak,
            # ale na razie ignorujemy ten pakiet, aby uniknąć pętli.
            return
        
            # 2. To jest NOWY przepływ. Musimy znaleźć dla niego ścieżkę.
        if dst in self.mymacs.keys():
            print(f"New flow {flow_id}. Destination is known. Calculating path...")
            
            # Wywołujemy Dijkstrę z aktualnymi wagami!
            p = get_path(self.mymacs[src][0], self.mymacs[dst][0],
            self.mymacs[src][1], self.mymacs[dst][1],
            self.link_weights, self.switches, self.adjacency) # MUSZĄ BYĆ self.switches i self.adjacency
            
            self.install_path(p, ev, src, dst)
            
            # Dodajemy przepływ do naszej tabeli FFT
            self.fft[flow_id] = {'path': p, 'timestamp': time.time()}
            
            print(f"Installed path for new flow: {p}")
            out_port = p[0][2]
        else:
            # Jeśli cel nieznany, zalewamy jak wcześniej
            print("Destination is unknown. Flood has happened.")
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                                    actions=actions, data=data)
        datapath.send_msg(out)
    
    # defining an event handler for adding/deleting of switches, hosts, ports and links event
    events = [event.EventSwitchEnter,
                event.EventSwitchLeave, event.EventPortAdd,
                event.EventPortDelete, event.EventPortModify,
                event.EventLinkAdd, event.EventLinkDelete]
    def _monitor(self):
        while True:
            for dp in self.datapath_list:
                self._request_stats(dp)
            hub.sleep(5) # Czekaj 5 sekund

    # Metoda do wysyłania zapytań o statystyki
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    # Handler odpowiedzi na zapytania o statystyki
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                tx_bytes = stat.tx_bytes

                if key in self.link_stats:
                    # Oblicz przepustowość
                    last_time, last_bytes = self.link_stats[key]
                    time_diff = time.time() - last_time
                    bytes_diff = tx_bytes - last_bytes
                    
                    if time_diff > 0:
                        bandwidth = bytes_diff / time_diff # w B/s
                        
                        # Znajdź do którego przełącznika prowadzi ten link
                        dst_dpid = None
                        for neighbor in self.adjacency[dpid]:
                            # Sprawdź czy port prowadzący do tego sąsiada to ten, dla którego mamy statystyki
                            if self.adjacency[dpid][neighbor] == port_no:
                                dst_dpid = neighbor
                                break
                        
                        if dst_dpid:
                            link = (dpid, dst_dpid)
                            # Aktualizuj wagi na podstawie kongestii
                            if bandwidth > self.congestion_threshold:
                                if self.link_weights[link[0]][link[1]] == 1:
                                    print(f"CONGESTION DETECTED on link {link}! Bw: {bandwidth/125000:.2f} Mbps. Increasing cost.")
                                    self.link_weights[link[0]][link[1]] = 9999 # Duży koszt
                            else:
                                if self.link_weights[link[0]][link[1]] > 1:
                                    print(f"Congestion on link {link} has ended. Restoring cost.")
                                    self.link_weights[link[0]][link[1]] = 1 # Wracamy do normalnego kosztu
                
            # Zapisz aktualny stan do późniejszego porównania
            self.link_stats[key] = (time.time(), tx_bytes)
        
    @set_ev_cls(events)
    def get_topology_data(self, ev):
        
        print("get_topology_data is called.")
        switch_list = get_switch(self.topology_api_app, None)  
        
        self.switches = [switch.dp.id for switch in switch_list]
        
        self.datapath_list = [switch.dp for switch in switch_list]
        self.datapath_list.sort(key=lambda dp: dp.id)

        links_list = get_link(self.topology_api_app, None)
        mylinks = [(link.src.dpid,link.dst.dpid,link.src.port_no,link.dst.port_no) for link in links_list]

        # <<< ZMIANA TUTAJ >>>
        self.adjacency.clear()
        # Inicjalizuj wagi za każdym razem, gdy zmienia się topologia
        self.link_weights = defaultdict(lambda: defaultdict(lambda: 1))
        
        for s1, s2, port1, port2 in mylinks:
            self.adjacency[s1][s2] = port1
            self.adjacency[s2][s1] = port2
            
            # Ustawiamy domyślną wagę 1 dla każdego nowo odkrytego linku
            self.link_weights[s1][s2] = 1
            self.link_weights[s2][s1] = 1