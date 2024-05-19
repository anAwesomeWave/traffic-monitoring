# Traffic Monitoring



## 📖 About:
Tools for network monitoring

## Prerequisites
List with the necessary programs.
Check that you have them
 - TSHARK 

```sudo apt install tshark -y```

 - DOCKER [Link](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository)

``` sudo apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - && sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && sudo apt-get update && sudo apt-get install -y docker-ce ```

## 📦 Installation:
1. Clone this repository from GitHub:

```
git clone git@github.com:anAwesomeWave/traffic-monitoring.git
```

2. Go to project directory:

```
cd traffic-monitoring
```
3. Create virtual environment:
```
python3 -m venv venv

source venv/bin/activate
```
4. Install all dependencies:

```
pip3 install -r requirements.txt
```

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


## Ports:

#### - http://localhost:9090  -- Prometheus
#### - http://localhost:13000 -- Grafana
#### - https://localhost:7777 -- OpenVAS


## Metrics:
### Список метрик, которые собирает программа.
### - scan_network/scanner.py
- total_hosts_discovered (Количество известных хостов в сети)
- total_ports_discovered (Количество открытых портов в сети)
