from scan_network import scanner
from scan_pcap import get_pcap

if __name__ == '__main__':
    network = input('input network addr.')
    scan = scanner.Scanner()
    scan.scan_network(network)
    scan.full_scan()
    scan.create_readable_msg_dict_based()
    scan.send_metrics_to_server()

    get_pcap.write_pcap(
        2048,
        list(set([80, 443] + scan.open_ports)),
        scan.discovered_hosts
    )
