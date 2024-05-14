from scapy.all import *
from prettytable import PrettyTable
from scapy.layers.dns import DNS
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import Ether


class PcapFilters:

    def __init__(self, packets):
        self.packets = packets

    def filter_packets(self):
        tcp_packets = self.packets.filter(lambda p: TCP in p)
        udp_packets = self.packets.filter(lambda p: UDP in p)
        icmp_packets = self.packets.filter(lambda p: ICMP in p)
        other_packets = self.packets.filter(lambda p: not (TCP in p or UDP in p or ICMP in p))
        return tcp_packets, udp_packets, icmp_packets, other_packets

    def filter_packets_by_source_ip(self, source_ip):
        filtered_packets = self.packets.filter(lambda p: IP in p and p[IP].src == source_ip)
        return filtered_packets

    def filter_packets_by_destination_port(self, dest_port):
        filtered_packets = self.packets.filter(lambda p: TCP in p and p[TCP].dport == dest_port)
        return filtered_packets

    def filter_packets_by_mac_address(self, mac_address):
        filtered_packets = self.packets.filter(lambda p: Ether in p and (p.src == mac_address or p.dst == mac_address))
        return filtered_packets

    def filter_packets_by_ip_range(self, start_ip, end_ip):
        filtered_packets = self.packets.filter(lambda p: IP in p and start_ip <= p[IP].src <= end_ip)
        return filtered_packets

    def filter_packets_by_protocol(self, protocol):
        filtered_packets = self.packets.filter(lambda p: p.haslayer(protocol))
        return filtered_packets

    def parse_dns_packets(self):
        dns_packets = self.packets.filter(lambda p: DNS in p)
        domain_info = []
        for packet in dns_packets:
            domain_name = packet[DNS].qd.qname.decode('utf-8')
            domain_info.append(domain_name)
        return domain_info

    def filter_suspicious_packets(self, max_payload_size):
        suspicious_packets = self.packets.filter(lambda p: TCP in p and len(p[TCP].payload) > max_payload_size)
        return suspicious_packets

    def filter_packets_by_tcp_flags(self, flags):
        filtered_packets = self.packets.filter(lambda p: TCP in p and p[TCP].flags & flags)
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
        management_frames = self.packets.filter(lambda p: p.haslayer(Dot11) and p.type == 0)
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

    @staticmethod
    def summarize_findings(tcp_packets, udp_packets, icmp_packets, other_packets, source_ip_packets, dest_port_packets,
                           mac_address_packets, ip_range_packets, http_packets, suspicious_packets, syn_packets,
                           channel_info, management_frame_info, domain_info):

        table = PrettyTable()
        table.field_names = ["Finding", "Count/Value"]
        table.align["Finding"] = "l"
        table.align["Count/Value"] = "c"

        table.add_row(["TCP Packets", len(tcp_packets)])
        table.add_row(["UDP Packets", len(udp_packets)])
        table.add_row(["ICMP Packets", len(icmp_packets)])
        table.add_row(["Other Packets", len(other_packets)])
        table.add_row(["Packets from Source IP 192.168.0.1", len(source_ip_packets)])
        table.add_row(["Packets to Destination Port 80", len(dest_port_packets)])
        table.add_row(["Packets from/to MAC 00:11:22:33:44:55", len(mac_address_packets)])
        table.add_row(["Packets in IP Range 192.168.0.1 - 192.168.0.100", len(ip_range_packets)])
        table.add_row(["HTTP Packets", len(http_packets)])
        table.add_row(["Suspicious Packets (Payload > 1024)", len(suspicious_packets)])
        table.add_row(["SYN Packets", len(syn_packets)])

        beacon_channels = ", ".join(str(channel) for channel in channel_info.keys())
        table.add_row(["Beacon Frame Channels", beacon_channels])

        for frame_type, source_mac, destination_mac in management_frame_info:
            frame_type_explanation = PcapFilters.get_frame_type_explanation(frame_type)
            table.add_row([f"Management Frame: {frame_type_explanation}", ""])

        dns_domains = "\n".join(domain_info)
        table.add_row(["DNS Domains", dns_domains])

        return table


def analyze_pcap(pcap_file):
    """
    Analyzes a pcap file and performs various packet filtering and parsing operations.

    Args:
        pcap_file: The path to the pcap file to analyze.
    """
    packets = rdpcap(pcap_file)
    pcap_filters = PcapFilters(packets)
    tcp_packets, udp_packets, icmp_packets, other_packets = pcap_filters.filter_packets()
    source_ip_packets = pcap_filters.filter_packets_by_source_ip("192.168.0.1")
    dest_port_packets = pcap_filters.filter_packets_by_destination_port(80)
    mac_address_packets = pcap_filters.filter_packets_by_mac_address("00:11:22:33:44:55")
    ip_range_packets = pcap_filters.filter_packets_by_ip_range("192.168.0.1", "192.168.0.100")
    http_packets = pcap_filters.filter_packets_by_protocol(TCP)
    domain_info = pcap_filters.parse_dns_packets()
    suspicious_packets = pcap_filters.filter_suspicious_packets(1024)
    syn_packets = pcap_filters.filter_packets_by_tcp_flags(0x02)  # SYN flag
    channel_info = pcap_filters.parse_beacon_frames()
    management_frame_info = pcap_filters.parse_management_frames()

    print("Detailed Output:")
    print(f"Number of TCP packets: {len(tcp_packets)}")
    print(f"Number of UDP packets: {len(udp_packets)}")
    print(f"Number of ICMP packets: {len(icmp_packets)}")
    print(f"Number of other packets: {len(other_packets)}")
    print(f"Packets from source IP 192.168.0.1: {len(source_ip_packets)}")
    print(f"Packets to destination port 80: {len(dest_port_packets)}")
    print(f"Packets from/to MAC address 00:11:22:33:44:55: {len(mac_address_packets)}")
    print(f"Packets in IP range 192.168.0.1 - 192.168.0.100: {len(ip_range_packets)}")
    print(f"HTTP packets: {len(http_packets)}")
    print(f"Suspicious packets (payload size > 1024): {len(suspicious_packets)}")
    print(f"SYN packets: {len(syn_packets)}")

    print("\nBeacon frame information by channel:")
    for channel, beacons in channel_info.items():
        print(f"Channel {channel}:")
        for ssid, bssid, power_constraint in beacons:
            print(f"  SSID: {ssid}, BSSID: {bssid}, Power Constraint: {power_constraint} dBm")

    print("\nManagement frame information:")
    for frame_type, source_mac, destination_mac in management_frame_info:
        frame_type_explanation = pcap_filters.get_frame_type_explanation(frame_type)
        print(f"  Frame Type: {frame_type} ({frame_type_explanation}), Source MAC: {source_mac}, Destination MAC: {destination_mac}")

    print("\nDomain information from DNS packets:")
    for domain_name in domain_info:
        print(f"  {domain_name}")

    summary_table = pcap_filters.summarize_findings(
        tcp_packets, udp_packets, icmp_packets, other_packets,
        source_ip_packets, dest_port_packets, mac_address_packets,
        ip_range_packets, http_packets, suspicious_packets, syn_packets,
        channel_info, management_frame_info, domain_info
    )

    print("\nSummary of Findings:")
    print(summary_table)


def main():
    pcap_file = "scan-pcap/capture.pcap"
    analyze_pcap(pcap_file)

#main()