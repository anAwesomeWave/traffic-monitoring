import os
import logging
from logging.config import fileConfig
import pprint
import json

import nmap
import animation

ROOT_PATH = os.path.join(os.path.dirname(__file__), '..')
LOGGER_CONF = ROOT_PATH + '/logger_config.conf'
fileConfig(
    LOGGER_CONF,
    disable_existing_loggers=False,
    defaults={'logfilename': ROOT_PATH + '/logs/nmap-scanner.log'}
)
logger = logging.getLogger(__name__)

clock = ['-', '\\', '|', '/']


class Scanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.discovered_hosts = []
        self.all_gathered_data = {}

        self.total_hosts_discovered = 0
        self.total_open_posts_discovered = 0

    @animation.wait(clock)
    def scan_network(
            self,
            hosts: str = '192.168.1.0/24',
            arguments: str = '-n -v -sP -PE -PA21,23,3389'
    ) -> list:
        logger.info(f'Scanning hosts: {hosts}')
        logger.debug(f'Hosts: {hosts}\nArguments: {arguments}')
        up_hosts = []
        # nm = nmap.PortScanner()
        answer = self.nm.scan(hosts=hosts, arguments=arguments)
        logger.debug(answer)
        if 'warning' in answer['nmap']['scaninfo']:
            logger.info(
                f"NMAP-Warning: {answer['nmap']['scaninfo']['warning']}")

        if 'error' in answer['nmap']['scaninfo']:
            logger.critical(
                f"NMAP-ERROR: {answer['nmap']['scaninfo']['error']}")

        hosts_list = [
            (x, self.nm[x]['status']['state']) for x in self.nm.all_hosts()
        ]
        for host, status in hosts_list:
            if status == 'up':
                up_hosts.append(host)
        self.discovered_hosts = up_hosts
        self.total_hosts_discovered = len(up_hosts)
        logger.info(f'Discovered hosts: {up_hosts}')
        return up_hosts

    def full_scan(self, hosts=[], args='-p 1-5432 -A') -> dict:
        """
            returns a dictionary with a key corresponding to each host.
            The value for each key is a dictionary with exactly three keys:
            tcp, udp, vendor.
            Ex. {'host1': {'tcp': {21: ...}, 'udp': {...}, 'vendor': {}}, ... }

            If any error occurs. Return dictionary with one key "error".
            Ex. {"error": "some_nmap_error"}
        """

        all_data = {}
        if len(hosts) == 0:
            hosts = self.discovered_hosts

        # nm = nmap.PortScanner()
        for host in hosts:
            logger.info(f'Starting full scan on host: {host}')
            answer = self.nm.scan(host, arguments=args)
            logger.info(answer)

            if 'warning' in answer['nmap']['scaninfo']:
                logger.warning(
                    f"NMAP-Warning: {answer['nmap']['scaninfo']['warning']}"
                )
            if 'error' in answer['nmap']['scaninfo']:
                logger.critical(
                    f"NMAP-ERROR: {answer['nmap']['scaninfo']['error']}"
                )
                return {'error': answer['nmap']['scaninfo']['error']}

            if host == 'localhost':
                host = '127.0.0.1'
            data = {}
            for i in {'vendor', 'tcp', 'udp'}:
                if i in answer['scan'][host]:
                    data[i] = answer['scan'][host][i]
            all_data[host] = data
        self.all_gathered_data = all_data
        return all_data

    def create_readable_msg_dict_based(self):
        """
            Create message BASED ON self.all_gathered_data field.
            YOU MUST call full_scan at first.
        """
        total_open_hosts = len(self.all_gathered_data.keys())
        total_open_ports = 0
        msg = [f"TOTAL OPEN HOSTS IN NETWORK: {total_open_hosts}"]
        hosts_info = []
        for host, data in self.all_gathered_data.items():
            msg_for_host = [f"HOST {host}:"]
            for protocol in data.keys():
                if protocol == 'vendor':
                    continue
                msg_for_host.append(f' - {protocol}:')
                for port, port_data in data[protocol].items():
                    if port_data['state'] == 'open':
                        total_open_ports += 1
                    msg_for_host.append(
                        f'\t- {port}({port_data["state"]})-----{port_data["name"]}, {port_data["product"]}, {port_data["version"]}'
                    )
            msg_for_host = '\n'.join(msg_for_host)
            hosts_info.append(msg_for_host)
        hosts_info = '\n------------------------------\n'.join(hosts_info)
        msg.append(f'TOTAL OPEN PORTS IN NETWORK: {total_open_ports}')
        msg.append(hosts_info)

        self.total_hosts_discovered = total_open_hosts
        self.total_open_posts_discovered = total_open_ports

        return '\n'.join(msg)

    def send_metrics_to_server(self):
        """
            Try to create metrics on Flask server and send them.
        """
        pass


if __name__ == '__main__':
    scanner = Scanner()
    print(scanner.scan_network('192.168.1.0/24'))
    # pprint.pprint(scanner.full_scan(['localhost']), indent=4)
    scanner.full_scan()
    print(scanner.create_readable_msg_dict_based())
