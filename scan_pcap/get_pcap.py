import shlex
import subprocess
import time
import requests

from scan_pcap.pcap_scanner import analyze_pcap, send_metrics_to_server

server = "http://localhost:5000/get_data"


def write_pcap(max_payload, ports=[], IPs=[]):
    send_metrics_to_server(max_payload, ports, IPs)
    while True:
        data = dict()
        cmd = "tshark -F pcap -w ./data.pcap"
        p = subprocess.Popen(shlex.split(cmd))
        time.sleep(10)
        p.kill()
        Metrics = analyze_pcap("data.pcap", max_payload, ports, IPs)
        print("\n--------------Sending Metrics----------\n")
        for key in Metrics.keys():
            if type(Metrics[key]) == int:
                data[(key.lower()).replace(' ', '_')] = Metrics[key]
            elif key == "Suspicious packets":
                data["max_payload_packets"] = Metrics["Suspicious packets"][f"By payload {max_payload}"]
                data["syn_packets"] = Metrics["Suspicious packets"]["SYN packets"]
            elif key == "IPs":
                for IP in IPs:
                    data[f"packets_received_{IP.replace('.', '_')}"] = Metrics["IPs"][IP]["Received packets"]
                    data[f"packets_transmitted_{IP.replace('.', '_')}"] = Metrics["IPs"][IP]["Transmitted packets"]
            elif key == "Ports":
                for port in ports:
                    data[f"packets_to_port_{port}"] = Metrics["Ports"][port]["To"]
                    data[f"packets_from_port_{port}"] = Metrics["Ports"][port]["From"]
        r = requests.post(server, json=data)
        print("\n-------------------------------------------------\n")

