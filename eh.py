# eh.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from ryu.topology.api import get_switch, get_link
from ryu.topology import event
from collections import defaultdict
from ryu.lib import hub
import time
from operator import attrgetter

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        
        # --- All state is now part of the class instance ---
        self.switches = []
        self.datapaths = {}  # Using a dictionary for robust lookup
        self.adjacency = defaultdict(lambda: defaultdict(lambda: None))
        self.mymacs = {}
        
        # --- FAMTAR data structures ---
        self.fft = {}
        self.link_weights = defaultdict(lambda: defaultdict(lambda: 1))
        self.link_stats = {}
        self.congestion_threshold = 6250000  # 50 Mbit/s in B/s
        
        # Monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("ProjectController application running...")

    def _get_path(self, src, dst, first_port, final_port):
        """
        Dijkstra's algorithm to find the shortest path.
        This is now a method of the class and uses self.switches and self.adjacency.
        """
        self.logger.info(f"get_path function is called, src={src} dst={dst} first_port={first_port} final_port={final_port}")
        
        distance = {}
        previous = {}
        weights = self.link_weights # Use class attribute for weights

        for dpid in self.switches:
            distance[dpid] = float('Inf')
            previous[dpid] = None

        distance[src] = 0
        Q = set(self.switches)

        while Q:
            u = min(Q, key=lambda v: distance[v])
            if distance[u] == float('Inf'):
                break # All remaining vertices are inaccessible from source
            Q.remove(u)
            
            for p in self.switches:
                if self.adjacency[u][p] is not None:
                    w = weights[u][p]
                    if distance[u] + w < distance[p]:
                        distance[p] = distance[u] + w
                        previous[p] = u

        path = []
        p = dst
        while p is not None:
            path.append(p)
            p = previous[p]
        
        path.reverse()

        if src not in path:
            self.logger.error(f"Path not found from {src} to {dst}")
            return []

        r = []
        in_port = first_port
        for s1, s2 in zip(path[:-1], path[1:]):
            out_port = self.adjacency[s1][s2]
            r.append((s1, in_port, out_port))
            in_port = self.adjacency[s2][s1]
        
        r.append((dst, in_port, final_port))
        return r

    def _install_path(self, p, ev, src_mac, dst_mac):
        self.logger.info(f"install_path function is called for path: {p}")
        msg = ev.msg
        ofproto = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser
        
        for sw_dpid, in_port, out_port in p:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            
            # Use the robust dictionary lookup for the datapath object
            datapath = self.datapaths.get(sw_dpid)
            if datapath:
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(
                    datapath=datapath, match=match, priority=1,
                    idle_timeout=10, hard_timeout=30, instructions=inst)
                datapath.send_msg(mod)
            else:
                self.logger.error(f"Could not find datapath for dpid: {sw_dpid}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD,
            idle_timeout=0, hard_timeout=0, priority=0, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"Switch {datapath.id} connected and configured.")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == 34525:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in self.mymacs:
            self.mymacs[src] = (dpid, in_port)
            self.logger.info(f"Learned host {src} on switch {dpid} port {in_port}")

        if dst in self.mymacs:
            # Destination is known, calculate and install path
            self.logger.info(f"New flow: {src} -> {dst}. Destination is known. Calculating path...")
            
            # Get path arguments
            src_dpid = self.mymacs[src][0]
            dst_dpid = self.mymacs[dst][0]
            first_port = self.mymacs[src][1]
            final_port = self.mymacs[dst][1]
            
            # Call the class method to get the path
            path = self._get_path(src_dpid, dst_dpid, first_port, final_port)
            
            if path:
                self.logger.info(f"Path found: {path}. Installing flow...")
                self._install_path(path, ev, src, dst)
                
                # Send the current packet out the correct port on the first switch
                out_port = path[0][2]
            else:
                self.logger.warning("Path not found, resorting to flooding.")
                out_port = ofproto.OFPP_FLOOD
        else:
            # Destination is unknown, flood the packet
            self.logger.info(f"Destination {dst} is unknown. Flooding packet from {src} on dpid {dpid}.")
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        """
        This event handler is called when switches and links are added.
        It updates the class's internal state.
        """
        self.logger.info("Topology changed. Refreshing data...")
        
        # Update switch and datapath information
        switch_list = get_switch(self.topology_api_app, None)
        self.switches = [s.dp.id for s in switch_list]
        self.datapaths = {s.dp.id: s.dp for s in switch_list}
        self.logger.info(f"Switches discovered: {self.switches}")
        
        # Update link information and adjacency matrix
        links_list = get_link(self.topology_api_app, None)
        self.adjacency = defaultdict(lambda: defaultdict(lambda: None)) # Reset adjacency
        for link in links_list:
            s1 = link.src.dpid
            s2 = link.dst.dpid
            port1 = link.src.port_no
            port2 = link.dst.port_no
            self.adjacency[s1][s2] = port1
            self.adjacency[s2][s1] = port2
            
            # Initialize weights for new links
            self.link_weights[s1][s2] = 1
            self.link_weights[s2][s1] = 1
        self.logger.info(f"Links discovered: {self.adjacency}")


    # --- Monitoring and Congestion Control Methods (unchanged, but added logging) ---
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
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
                tx_bytes = stat.tx_bytes

                if key in self.link_stats:
                    last_time, last_bytes = self.link_stats[key]
                    time_diff = time.time() - last_time
                    bytes_diff = tx_bytes - last_bytes
                    
                    if time_diff > 0:
                        bandwidth = bytes_diff / time_diff  # B/s
                        dst_dpid = None
                        for neighbor, port in self.adjacency[dpid].items():
                            if port == port_no:
                                dst_dpid = neighbor
                                break
                        
                        if dst_dpid:
                            link = (dpid, dst_dpid)
                            if bandwidth > self.congestion_threshold:
                                if self.link_weights[link[0]][link[1]] == 1:
                                    self.logger.warning(f"CONGESTION DETECTED on link {link}! Bw: {bandwidth/125000:.2f} Mbps. Increasing cost.")
                                    self.link_weights[link[0]][link[1]] = 9999
                            else:
                                if self.link_weights[link[0]][link[1]] > 1:
                                    self.logger.info(f"Congestion on link {link} has ended. Restoring cost.")
                                    self.link_weights[link[0]][link[1]] = 1
                
                self.link_stats[key] = (time.time(), tx_bytes)