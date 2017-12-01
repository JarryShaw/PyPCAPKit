#!/usr/bin/python3
# -*- coding: utf-8 -*-


import pprint
import webbrowser


# UI for PCAP Viewer
# PCAP Viewer Implementation on Console


from analyser import Analyser
from jspcap.exceptions import FileError


EMSP = '                   '

CMDS = '''
 1. open pcap file
 2. want more info
 3. need some help
 4. show init page
 5. view on GitHub
 6. abort and quit
'''

CALL = {
    '1' : lambda self_: self_.open_cmd(),
    '2' : lambda self_: self_.info_cmd(),
    '3' : lambda self_: self_.help_cmd(),
    '4' : lambda self_: self_.init_cmd(),
    '5' : lambda self_: self_.repo_cmd(),
    '6' : lambda self_: self_.quit_cmd(),
}


class Display(Analyser):

    def __init__(self):
        self.init_cmd()
        self.show_cmd()

    def show_cmd(self):
        print(CMDS)

        cmd = input('Your command: ')
        while True:
            func = CALL.get(cmd)
            if func is None:
                cmd = input('Invalid command. Please Retry: ')
            else:
                break

        func(self)
        self.show_cmd()

    def read_cmd(self, name):
        with open(name, 'r') as file_:
            for line in file_:
                content = line.strip('\n').replace(EMSP, '')
                print(content)

    def open_cmd(self):
        pass

    def info_cmd(self):
        self.read_cmd('src/about')

    def help_cmd(self):
        self.read_cmd('src/manual')

    def init_cmd(self):
        self.read_cmd('src/init')

    def repo_cmd(self):
        webbrowser.open('https://github.com/JarryShaw/jspcap/')

    def quit_cmd(self):
        exit()
