import logging
from logging.config import fileConfig
import argparse

import yaml

from scan_network import scanner
from scan_pcap import pcap_scanner

NMAP_HELP = """
SCAN NETWORK THAT YOUR ENTERED
Usage:
 network_scan 192.168.1.71/24

Options:
 -fs --full_scan 

"""
fileConfig(
    'logger_config.conf',
    disable_existing_loggers=False,
    defaults={'logfilename': 'logs/main.log'}
)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    # # logging.basicConfig(
    # #     level=logging.INFO,
    # #     format="%(asctime)s [%(levelname)s] %(message)s",
    # #     handlers=[
    # #         logging.FileHandler("../logs/log_file.log"),
    # #         logging.StreamHandler()
    # #     ]
    # # )
    # logger.info(123213213)
    #
    # my_scanner = scanner.Scanner()
    # my_scanner.scan_network()
    #
    # with open("config.yml") as f:
    #     cfg = yaml.load(f, Loader=yaml.FullLoader)
    #     print(cfg)
    #
    parser = argparse.ArgumentParser(
        prog='Network monitoring',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    subparsers = parser.add_subparsers(
        title='subcommands',
        help='sub-command help',
    )

    parser_nmap = subparsers.add_parser(
        'network_scan',
        help='scan give network. Usage: main.py network_scan 192.168.1.0/24',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser_nmap.add_argument('network', type=str, help='bar help')
    parser_nmap.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        default=True,
        help='Provide info about collected data to the terminal. Works better with -fs'
    )
    parser_nmap.add_argument(
        '-fs',
        '--fullscan',
        action='store_true',
        default=False,
        help='fullscan all found hosts in network.'
    )
    parser_nmap.add_argument(
        '-m',
        '--send_metrics_to_server',
        action='store_true',
        default=True,
        help='Send metrics `total_hosts_discovered`,`total_ports_discovered`.'
    )

    args = parser.parse_args()