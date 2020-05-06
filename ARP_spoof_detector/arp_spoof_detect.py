#!/usr/bin/python
import scapy.all as scapy
import argparse

def getmac(ip):
    arp_request_header = scapy.ARP(pdst = ip)
    ether_header = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = ether_header/arp_request_header
    answered_list = scapy.srp(arp_request_packet,timeout=1,verbose=False)[0]
    return  answered_list[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    # check if packet has ARP layer and also if its a response
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op==2:
        try:
            # get mac using io
            real_mac = getmac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                print ("[+] You are under attack!!")
        except IndexError:
            pass

parser=argparse.ArgumentParser()    
parser.add_argument("-i","--interface",dest="interface",help="Specify Victim IP addres", required=True)
options = parser.parse_args()
            
sniff(options.interface)
