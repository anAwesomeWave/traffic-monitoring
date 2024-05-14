import yaml
import logging

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("../logs/log_file.log"),
            logging.StreamHandler()
        ]
    )
    with open("config.yml") as f:
        cfg = yaml.load(f, Loader=yaml.FullLoader)
        print(cfg)

