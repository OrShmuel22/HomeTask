from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPRequest
import json
from geoip import geolite2
from pathlib import Path


class GetDataFromPcap:
    def __init__(self, file_patch: str, http_file_name: str, dns_file_name: str):
        self.file_patch = file_patch
        self.http_file_name = http_file_name
        self.dns_file_name = dns_file_name

    def CreateJsonFileFromPcapFile(self) -> bool:
        if Path(self.file_patch).is_file() is False:
            print("the pcap file Doesn't exists or wrong directory")
            return False
        packets_list = rdpcap(self.file_patch)
        dns_list = []
        http_list = []
        for p in packets_list:
            if p.haslayer(HTTPRequest):
                ip_source = p.getlayer("IP").src
                source_port = p.getlayer("TCP").sport
                ip_destination = p.getlayer("IP").dst
                destination_port = p.getlayer("TCP").dport
                request_data = p.getlayer("HTTP Request").Path.decode("UTF-8")
                http_host = p.getlayer("HTTP Request").Host.decode("UTF-8")
                http_method = p.getlayer("HTTP Request").Method.decode("UTF-8")
                source_geo_ip = self.GetGeoLocation(ip_source)
                destination_geo_ip = self.GetGeoLocation(ip_destination)
                dict_http_data = {"ip_source": ip_source,
                                  "source_port": source_port,
                                  "source_geo_ip": source_geo_ip,
                                  "ip_destination": ip_destination,
                                  "destination_port": destination_port,
                                  "destination_geo_ip": destination_geo_ip,
                                  "request_data": request_data,
                                  "http_host": http_host,
                                  "http_method": http_method}
                http_list.append(dict_http_data)
            if p.haslayer(DNSQR):
                domain_name = p.qd.qname.decode("UTF-8")
                # remove the last chapter(".") from the domain name
                dict_dns_data = {"domain_name": domain_name[:-1]}
                dns_list.append(dict_dns_data)
        self.ListToJsonFile(self.http_file_name, http_list)
        self.ListToJsonFile(self.dns_file_name, dns_list)

    def ListToJsonFile(self, filename: str, list_of_data: list) -> None:
        with open(filename + '.json', 'w', encoding='utf-8') as f:
            json.dump(list_of_data, f, indent=2)
        print("the file " + filename + " created successfully")

    def GetGeoLocation(self, ip: str) -> str:
        match = geolite2.lookup(ip)
        if match is not None:
            return match.country
        return "unknown"


pcap_file = GetDataFromPcap('2019-08-13-MedusaHTTP-malware-traffic.pcap', "HttpFile", "DnsFile")
pcap_file.CreateJsonFileFromPcapFile()
