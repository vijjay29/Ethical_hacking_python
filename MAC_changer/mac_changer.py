import argparse
import subprocess
import re 

def macchanger(interface,macaddr):

	subprocess.call(["ifconfig",interface,"down"])
	subprocess.call(["ifconfig",interface,"hw","ether",macaddr])
	subprocess.call(["ifconfig",interface,"up"])

	print(f"[+] Changing Mac Address of Interface {interface} to {macaddr}")

def getmac(interface):

	ifconfig_result = subprocess.check_output(["ifconfig",interface])
	current_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",ifconfig_result.decode())

	if current_mac:
		return current_mac.group(0)
	else:
		return None


parser = argparse.ArgumentParser(description='Tool to change MAC address of the machine, supports only on linux')
parser.add_argument('-i', '--interface', dest="interface", help="Interface to change the mac address")
parser.add_argument('-m', '--mac', dest="mac", help="MAC address")

args = parser.parse_args()

if not args.interface or not args.mac:
	args.interface = input("> Interface to change the mac address : ")
	args.mac = input("> MAC address : ")

# function to change the mac address
macchanger(args.interface, args.mac)
new_mac = getmac(args.interface)

#verify whether the mac is changed or Not
if new_mac == args.mac :
	print (f"[+] Mac Address Successfully Chaged with new one {new_mac}")
else:
	print ("[-] Error Occured")
