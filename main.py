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

    def create_json_file_from_pcap_file(self):
        try:
            packets_list = rdpcap(self.file_path)
            try:
                dns_list = []
                http_list = []
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
                self.get_geo_location(ip_set, http_list)
                self.list_to_json_file(self.http_file_name, http_list)
                self.list_to_json_file(self.dns_file_name, dns_list)
            except Exception as error:
                print("Something went wrong")
                print("Error:" + str(error))
        except FileNotFoundError as error:
            print("the pcap file Doesn't exists or wrong directory")
            print("Error:" + str(error))

    def list_to_json_file(self, filename: str, list_of_data: list) -> None:
        with open(filename + '.json', 'w', encoding='utf-8') as f:
            json.dump(list_of_data, f, indent=2)
        print("the file " + filename + " created successfully")

    def get_geo_location(self, ip_set: set, http_list: list):
        geo_ip = {}
        # fields return only status and country
        api_url = "http://ip-api.com/batch?fields=57345"
        ip_list = list(ip_set)
        # maximum batch process of ip per batch is 100
        max_batch_ip = 100
        chunk_list = []
        if len(ip_list) > max_batch_ip:
            # slice list to chunk of 100
            chunk_list = list(self.divide_chunks(ip_list, max_batch_ip))
            for chunk in range(0, len(chunk_list)):
                ip_api = requests.post(api_url, data=f"{json.dumps(chunk_list[chunk])}")
                data_from_api = ip_api.json()
                for data in data_from_api:
                    status = data["status"]
                    ip = data["query"]
                    if status == "success":
                        country = data["country"]
                        geo_ip[ip] = country
                    else:
                        geo_ip[ip] = "unknown"
        else:
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
        # return the list with update geo ip values
        for data in http_list:
            ip_source = data['ip_source']
            ip_destination = data['ip_destination']
            if data['ip_source'] in geo_ip:
                data['source_geo_ip'] = geo_ip[ip_source]
            if data['ip_destination'] in geo_ip:
                data['destination_geo_ip'] = geo_ip[ip_destination]
        return http_list

    def divide_chunks(self, list_ip, max_ip_for_batch):
        # looping till length l
        for i in range(0, len(list_ip), max_ip_for_batch):
            yield list_ip[i:i + max_ip_for_batch]


pcap_file = PcapDataReader('2019-08-13-MedusaHTTP-malware-traffic.pcap', "HttpFile", "DnsFile")
pcap_file.create_json_file_from_pcap_file()
