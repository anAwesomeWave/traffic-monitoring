# Traffic Monitoring


## 📖 About:
Tools for network monitoring

## 📦 Installation:
1. Clone this repository from GitHub:

```
git clone git@github.com:anAwesomeWave/traffic-monitoring.git
```

2. Go to project directory:

```
cd traffic-monitoring
```
3. Install all dependencies:

```
pip3 install -r requirements.txt
```
# TODO

## 💡 Quickstart:
To run prometheus&grafana network monitoring 
```
sudo docker compose up
```
-------
If you only want to scan network for open ports, try:
```
python3 scan_network/scanner.py -h  # docs
python3 scan_network/scanner.py -v -fs -m  # full usage

```

Go to http://localhost:9090 to enter grafana.

# TODO



## Metrics:
### Список метрик, которые собирает программа.
### - scan_network/scanner.py
- total_hosts_discovered (Количество известных хостов в сети)
- total_ports_discovered (Количество открытых портов в сети)
