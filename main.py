import yaml
import logging
from logging.config import fileConfig


from scan_network import scanner
from scan_pcap import pcap_scanner

fileConfig(
    'logger_config.conf',
    disable_existing_loggers=False,
    defaults={'logfilename': 'logs/main.log'}
)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    # logging.basicConfig(
    #     level=logging.INFO,
    #     format="%(asctime)s [%(levelname)s] %(message)s",
    #     handlers=[
    #         logging.FileHandler("../logs/log_file.log"),
    #         logging.StreamHandler()
    #     ]
    # )
    logger.info(123213213)

    my_scanner = scanner.Scanner()
    my_scanner.scan_network()

    with open("config.yml") as f:
        cfg = yaml.load(f, Loader=yaml.FullLoader)
        print(cfg)

