import yaml

with open("config.yml") as f:
    cfg = yaml.load(f, Loader=yaml.FullLoader)
    print(cfg)
