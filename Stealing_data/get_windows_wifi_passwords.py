#!/usr/bin/python
# -*- coding: utf-8 -*-

import subprocess
import re

out = subprocess.check_output("netsh wlan show profile",shell=True)
wifi_nw_list = re.findall(b"(?:Profile\s*:\s)(.*)", out)

for name in wifi_nw_list:
    command = 'netsh wlan show profile "{}" key=clear'.format(name.decode(encoding='UTF-8'))
    current_result = subprocess.check_output(command ,shell=True)
    # print (current_result.decode(encoding='UTF-8'))
    wifi_passd = re.search(b"(?:Key\sContent\s*:\s)(.*)", current_result)
    if wifi_passd:
        print ('WiFi : {},  Password : {}'.format(name.strip(), wifi_passd.group(1).strip()))
    print ("--x--"*10)