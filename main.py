from shutil import which

from scan_network import scanner
from scan_pcap import get_pcap


def is_tool(name):
    """ Check if the program exists within the system. """
    return which(name) is not None


print(is_tool('tsharkw'))

if __name__ == '__main__':
    for tool in {'docker', 'tshark'}:
        if is_tool(tool) is False:
            print(f'ERROR: you don\'t have {tool} installed.')
            exit(1)
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
