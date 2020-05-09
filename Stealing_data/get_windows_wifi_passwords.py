#!/usr/bin/python

import subprocess
import re

out = subprocess.check_output("netsh wlan show profile",shell=True)
print (out)
wifi_nw_list = re.findall(b"(?:Profile\s*:\s)(.*)", out)

for name in wifi_nw_list:
    command = 'netsh wlan show profile "{}" key=clear'.format(name.decode(encoding='UTF-8'))
    current_result = subprocess.check_output(command ,shell=True)
    print (current_result.decode(encoding='UTF-8'))
    print ("--x--"*30)