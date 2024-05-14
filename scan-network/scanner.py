import logging
import pprint

import nmap
import animation


logger = logging.getLogger(__name__)
# print(nm.scan('127.0.0.1', '21-23,5432'))
# print(nm.scan('192.168.1.1-254', '1-500'))

# print(nm.command_line())
#
# print(nm.scaninfo())
# print(nm.all_hosts())
# print(nm['127.0.0.1'].tcp(22))


# print(n)

# def full_scan(hosts: str='127.0.0.1', ports: str='1-1024', arguments:str = '-v -A -T4') -> dict:
#     nm = nmap.PortScanner()
#     answer = nm.scan(hosts, ports, arguments)
#     # print(answer, type(answer))
#     pprint.pprint(answer, indent=4)
#
# scan_network('127.0.0.1', '1-1024', '-v -A -T4')
clock = ['-', '\\', '|', '/']


class Scanner:
    def __init__(self):
        self.discovered_hosts = []

    @animation.wait(clock)
    def scan_network(self, hosts: str='192.168.1.0/24', arguments: str = '-n -v -sP -PE -PA21,23,3389') -> list:
        logger.info(f'Scanning hosts: {hosts}')
        logger.debug(f'Hosts: {hosts}\nArguments: {arguments}')
        up_hosts = []
        nm = nmap.PortScanner()
        answer = nm.scan(hosts=hosts, arguments=arguments)
        logger.debug(answer)
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        for host, status in hosts_list:
            if status == 'up':
                up_hosts.append(host)
        self.discovered_hosts = up_hosts
        logger.info(f'Discovered hosts: {up_hosts}')
        return up_hosts

    def full_scan(self, hosts):
        for host in self.discovered_hosts:
            pass


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("../logs/log_file.log"),
            logging.StreamHandler()
        ]
    )
    scanner = Scanner()
    print(scanner.scan_network('192.168.1.0/24'))

# nm = nmap.PortScanner()
# nm.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
# hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
# for host, status in hosts_list:
#     print(host, status)
