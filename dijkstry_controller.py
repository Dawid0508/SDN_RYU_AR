# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

class SimpleLearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleLearningSwitch, self).__init__(*args, **kwargs)
        # Tablica MAC: {dpid: {mac_adres: port}}
        self.mac_to_port = {}
        self.logger.info("--- Aplikacja Testowa (Simple Learning Switch) uruchomiona ---")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Zainstaluj domyślną regułę "table-miss" - wysyłaj nieznane pakiety do kontrolera
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"SWITCH: Podłączono przełącznik DPID: {datapath.id:016x}. Instaluję regułę table-miss.")

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"FLOW: Instaluję regułę na DPID {datapath.id:016x}")

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
            # ignoruj pakiety lldp
            return
            
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.logger.info(f"\n--- Nowy pakiet ---")
        self.logger.info(f"PACKET_IN: Otrzymano pakiet na DPID {dpid:016x} porcie {in_port} (SRC: {src}, DST: {dst})")
        
        # Inicjalizuj tablicę MAC dla tego przełącznika, jeśli jeszcze nie istnieje
        self.mac_to_port.setdefault(dpid, {})

        # Naucz się adresu MAC, aby uniknąć zalewania następnym razem
        if src not in self.mac_to_port[dpid]:
            self.mac_to_port[dpid][src] = in_port
            self.logger.info(f"LEARN: Nauczono się, że {src} jest na porcie {in_port} przełącznika {dpid}")

        # Sprawdź, czy znamy port dla docelowego adresu MAC
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            self.logger.info(f"ROUTE: Cel {dst} jest znany na porcie {out_port}. Instaluję regułę i wysyłam.")
        else:
            # Jeśli nie znamy celu, zalewamy sieć
            out_port = ofproto.OFPP_FLOOD
            self.logger.info(f"ROUTE: Cel {dst} jest nieznany. Zalewam sieć (FLOOD).")

        actions = [parser.OFPActionOutput(out_port)]

        # Zainstaluj regułę przepływu, aby uniknąć packet_in następnym razem
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        # Wyślij pakiet
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)