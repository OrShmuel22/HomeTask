from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPRequest
import json
import requests
import time
from pathlib import Path


class PcapDataReader:
    def __init__(self, file_path: str, http_file_name: str, dns_file_name: str):
        self.file_path = file_path
        self.http_file_name = http_file_name
        self.dns_file_name = dns_file_name

    def CreateJsonFileFromPcapFile(self) -> bool:
        if not Path(self.file_path).is_file():
            print("the pcap file Doesn't exists or wrong directory")
            return False
        packets_list = rdpcap(self.file_path)
        dns_list = []
        http_list = []
        # data structure "set" to non-repit duplicate value
        ip_set = set()
        for p in packets_list:
            if p.haslayer(HTTPRequest):
                ip_source = p.getlayer("IP").src
                source_port = p.getlayer("TCP").sport
                ip_destination = p.getlayer("IP").dst
                destination_port = p.getlayer("TCP").dport
                request_data = p.getlayer("HTTP Request").Path.decode("UTF-8")
                http_host = p.getlayer("HTTP Request").Host.decode("UTF-8")
                http_method = p.getlayer("HTTP Request").Method.decode("UTF-8")
                ip_set.update([ip_source, ip_destination])
                dict_http_data = {"ip_source": ip_source,
                                  "source_port": source_port,
                                  "source_geo_ip": "",
                                  "ip_destination": ip_destination,
                                  "destination_port": destination_port,
                                  "destination_geo_ip": "",
                                  "request_data": request_data,
                                  "http_host": http_host,
                                  "http_method": http_method}
                http_list.append(dict_http_data)
            if p.haslayer(DNSQR):
                domain_name = p.qd.qname.decode("UTF-8")
                # remove the last chapter(".") from the domain name
                dict_dns_data = {"domain_name": domain_name[:-1]}
                dns_list.append(dict_dns_data)
        self.GetGeoLocation(ip_set, http_list)
        self.ListToJsonFile(self.http_file_name, http_list)
        self.ListToJsonFile(self.dns_file_name, dns_list)

    def ListToJsonFile(self, filename: str, list_of_data: list) -> None:
        with open(filename + '.json', 'w', encoding='utf-8') as f:
            json.dump(list_of_data, f, indent=2)
        print("the file " + filename + " created successfully")

    def GetGeoLocation(self, ip_set: set, http_list: list):
        geo_ip = {}
        # fields in the url return only status and country
        api_url = "http://ip-api.com/batch?fields=57345"
        ip_list = list(ip_set)
        ip_api = requests.post(api_url, data=f"{json.dumps(ip_list)}")
        data_from_api = ip_api.json()
        for data in data_from_api:
            status = data["status"]
            ip = data["query"]
            if status == "success":
                country = data["country"]
                geo_ip[ip] = country
            else:
                geo_ip[ip] = "unknown"
        for data in http_list:
            if data['ip_source'] in geo_ip:
                data['source_geo_ip'] = geo_ip[data['ip_source']]
            if data['ip_destination'] in geo_ip:
                data['destination_geo_ip'] = geo_ip[data['ip_destination']]
        return http_list


pcap_file = PcapDataReader('2019-08-13-MedusaHTTP-malware-traffic.pcap', "HttpFile", "DnsFile")
pcap_file.CreateJsonFileFromPcapFile()
