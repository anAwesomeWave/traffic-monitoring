from logging.config import fileConfig

import requests

from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import Ether

ROOT_PATH = os.path.join(os.path.dirname(__file__), '..')
LOGGER_CONF = ROOT_PATH + '/logger_config.conf'
fileConfig(
    LOGGER_CONF,
    disable_existing_loggers=False,
    defaults={'logfilename': ROOT_PATH + '/logs/pcap-scanner.log'}
)
logger = logging.getLogger(__name__)


class PcapFilters:

    def __init__(self, packets):
        self.packets = packets

    def filter_packets_by_protocol(self, protocol):
        filtered = self.packets.filter(lambda p: protocol in p)
        return filtered

    def filter_packets_by_source_ip(self, source_ip):
        filtered_packets = self.packets.filter(
            lambda p: IP in p and p[IP].src == source_ip)
        return filtered_packets

    def filter_packets_by_destination_ip(self, destination_ip):
        filtered_packets = self.packets.filter(lambda p: IP in p and p[IP].dst == destination_ip)
        return filtered_packets

    def filter_packets_by_source_port(self, source_port):
        filtered_packets = self.packets.filter(lambda p: TCP in p and p[TCP].sport == source_port)
        return filtered_packets

    def filter_packets_by_destination_port(self, destination_port):
        filtered_packets = self.packets.filter(lambda p: TCP in p and p[TCP].dport == destination_port)
        return filtered_packets

    def filter_packets_by_mac_address(self, mac_address):
        filtered_packets = self.packets.filter(lambda p: Ether in p and (
                    p.src == mac_address or p.dst == mac_address))
        return filtered_packets

    def filter_packets_by_ip_range(self, start_ip, end_ip):
        filtered_packets = self.packets.filter(
            lambda p: IP in p and start_ip <= p[IP].src <= end_ip)
        return filtered_packets

    def filter_packets_by_http(self):
        filtered_packets = self.packets.filter(lambda p: p.haslayer(TCP))
        return filtered_packets

    def parse_dns_packets(self):
        dns_packets = self.packets.filter(lambda p: DNS in p)
        domain_info = []
        for packet in dns_packets:
            domain_name = packet[DNS].qd.qname.decode('utf-8')
            domain_info.append(domain_name)
        return domain_info

    def filter_suspicious_packets(self, max_payload_size):
        suspicious_packets = self.packets.filter(
            lambda p: TCP in p and len(p[TCP].payload) > max_payload_size)
        return suspicious_packets

    def filter_packets_by_tcp_flags(self, flags):
        filtered_packets = self.packets.filter(
            lambda p: TCP in p and p[TCP].flags & flags)
        return filtered_packets

    def parse_beacon_frames(self):
        beacon_frames = self.packets.filter(lambda p: p.haslayer(Dot11Beacon))
        channel_info = {}
        for beacon in beacon_frames:
            ssid = beacon.info.decode('utf-8', 'ignore')
            bssid = beacon.addr3
            channel = ord(beacon[Dot11Elt:3].info)
            power_constraint = self.get_power_constraint(beacon)
            if channel not in channel_info:
                channel_info[channel] = []
            channel_info[channel].append((ssid, bssid, power_constraint))
        return channel_info

    @staticmethod
    def get_power_constraint(beacon):
        power_constraint_elem = beacon.getlayer(Dot11Elt, ID=32)
        if power_constraint_elem:
            power_constraint = ord(power_constraint_elem.info)
            return power_constraint
        return None

    def parse_management_frames(self):
        management_frames = self.packets.filter(
            lambda p: p.haslayer(Dot11) and p.type == 0)
        frame_info = []
        for frame in management_frames:
            frame_type = frame.subtype
            source_mac = frame.addr2
            destination_mac = frame.addr1
            frame_info.append((frame_type, source_mac, destination_mac))
        return frame_info

    @staticmethod
    def get_frame_type_explanation(frame_type):
        frame_types = {
            0: "Association Request",
            1: "Association Response",
            2: "Reassociation Request",
            3: "Reassociation Response",
            4: "Probe Request",
            5: "Probe Response",
            8: "Beacon",
            9: "ATIM",
            10: "Disassociation",
            11: "Authentication",
            12: "Deauthentication",
            13: "Action"
        }
        return frame_types.get(frame_type, "Unknown")


def analyze_pcap(pcap_file, max_payload_size=1024, ports=[], IPs=[]):
    """
    Analyzes a pcap file and performs various packet filtering and parsing operations.

    Args:
        pcap_file: The path to the pcap file to analyze.
        @type pcap_file: file.pcap.
        @type max_payload_size: bytes.
        @param IPs: list of ip addresses to track.
        @param ports: list of ports addresses to track.
    """

    logger.info('Start scanning network')

    Metrics = {
        "Total packets": 0,
        "TCP packets": 0,
        "UDP packets": 0,
        "ICMP packets": 0,
        "HTTP packets": 0,
        "Domain names": set(),
        "Ports": dict(),
        "IPs": dict(),
        "Suspicious packets": dict(),
        "Management Frames Info": []
    }
    packets = rdpcap(pcap_file)
    pcap_filters = PcapFilters(packets)

    Metrics["Total packets"] = len(packets)
    Metrics["TCP packets"] = len(pcap_filters.filter_packets_by_protocol(TCP))
    Metrics["UDP packets"] = len(pcap_filters.filter_packets_by_protocol(UDP))
    Metrics["ICMP packets"] = len(pcap_filters.filter_packets_by_protocol(ICMP))
    Metrics["HTTP packets"] = len(pcap_filters.filter_packets_by_http())
    domain_info = pcap_filters.parse_dns_packets()
    for domain_name in domain_info:
        Metrics["Domain names"].add(domain_name)

    max_payload_packets = len(pcap_filters.filter_suspicious_packets(max_payload_size))
    syn_packets = len(pcap_filters.filter_packets_by_tcp_flags(0x02))
    Metrics["Suspicious packets"] = {f"By payload {max_payload_size}": max_payload_packets,
                                     "SYN packets": syn_packets}

    for IP in IPs:
        source_ip_packets = len(pcap_filters.filter_packets_by_source_ip(IP))
        destination_ip_packets = len(pcap_filters.filter_packets_by_destination_ip(IP))
        Metrics["IPs"][IP] = {"Transmitted packets": source_ip_packets,
                              "Received packets": destination_ip_packets}

    for port in ports:
        source_port_packets = len(pcap_filters.filter_packets_by_source_port(port))
        destination_port_packets = len(pcap_filters.filter_packets_by_destination_port(port))
        Metrics["Ports"][port] = {"To": source_port_packets,
                                  "From": destination_port_packets}

    management_frame_info = pcap_filters.parse_management_frames()
    for frame_type, source_mac, destination_mac in management_frame_info:
        frame_type_explanation = pcap_filters.get_frame_type_explanation(frame_type)
        Metrics["Management Frames Info"].append({str(frame_type_explanation): f"From {source_mac} and {destination_mac}"})

    print("\n--------------Metrics----------\n")
    for key, value in Metrics.items():
        print("{0}: {1}".format(key, value))
    print("\n--------------------------------\n")

    return Metrics


def send_metrics_to_server(max_payload, ports=[], IPs=[]):
        """
            Try to create metrics on Flask server and send them.
        """
        data = [
            {
                "name": "total_packets",
                "value": 0,
                "class": "Gauge",
                "method": "set",
                "description": "number of packets transmitted in 30 seconds"
            },
            {
                "name": "icmp_packets",
                "value": 0,
                "class": "Gauge",
                "method": "set",
                "description": "number of ICMP packets transmitted in 30 seconds"
            },
            {
                "name": "tcp_packets",
                "value": 0,
                "class": "Gauge",
                "method": "set",
                "description": "number of TCP packets transmitted in 30 seconds"
            },
            {
                "name": "udp_packets",
                "value": 0,
                "class": "Gauge",
                "method": "set",
                "description": "number of UDP packets transmitted in 30 seconds"
            },
            {
                "name": "http_packets",
                "value": 0,
                "class": "Gauge",
                "method": "set",
                "description": "number of HTTP packets transmitted in 30 seconds"
            },
            {
                "name": "max_payload_packets",
                "value": 0,
                "class": "Gauge",
                "method": "set",
                "description": f"number of HTTP packets that contains more than {max_payload} bytes"
            },
            {
                "name": "syn_packets",
                "value": 0,
                "class": "Gauge",
                "method": "set",
                "description": "number of SYN packets transmitted in 30 seconds"
            },
        ]

        for IP in IPs:
            data.append({
                "name": f"packets_received_{IP.replace('.', '_')}",
                "value": 0,
                "class": "Gauge",
                "method": "set",
                "description": f"number of packets transmitted to {IP}"
            })
            data.append({
                "name": f"packets_transmitted_{IP.replace('.', '_')}",
                "value": 0,
                "class": "Gauge",
                "method": "set",
                "description": f"number of packets received from {IP}"
            })

        for port in ports:
            data.append({
                "name": f"packets_from_port_{port}",
                "value": 0,
                "class": "Gauge",
                "method": "set",
                "description": f"number of packets received from port {port}"
            })
            data.append({
                "name": f"packets_to_port_{port}",
                "value": 0,
                "class": "Gauge",
                "method": "set",
                "description": f"number of packets transmitted to port {port}"
            })

        server = "http://localhost:5000/create_metrics"
        logger.info(f"Sending request to {server} with data: {data}")
        r = requests.post(server, json=data)
        if r.status_code != 200:
            logger.error(r, r.status_code)
