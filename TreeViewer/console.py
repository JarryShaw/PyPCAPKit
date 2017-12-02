#!/usr/bin/python3
# -*- coding: utf-8 -*-


import math
import os
import pprint
import platform
import re
import shutil
import subprocess
import webbrowser


# UI for PCAP Viewer
# PCAP Viewer Implementation on Console


from analyser import Analyser
from jspcap.exceptions import FileError
from jspcap.extractor import Extractor


# platform specific settings
windows = (platform.system() == 'Windows')
shcoding = 'gbk' if windows else 'utf-8'

# global header pattern
GH = re.compile(r'(global).*?(header)', re.I)

# window size (columns)
SIZE = shutil.get_terminal_size()[0] - 15
LONG = SIZE if SIZE > 10 else 0

# embeded spaces
EMSP = '                   '

# extracting label
NUMB = lambda number, protocol: ' - Frame {:>3d}: {}'.format(number, protocol)

# exporting label
EXPT = lambda percent: '{sharp}{space}    {:>2.2f}%'.format(percent,
    sharp = '#' * math.ceil(LONG * percent / 100),
    space = ' ' * (LONG - math.ceil(LONG * percent / 100))
)

# root commands
INIT = '''
Please select a command:

  1. open pcap file
  2. want more info
  3. need some help
  4. show init page
  5. view on GitHub
  6. abort and quit
'''

# dict of root commands
INIT_CMD = {
    '1' : lambda self_, *, root: self_.open_cmd(root=root),
    '2' : lambda self_, *, root: self_.read_cmd('src/about', root=root),
    '3' : lambda self_, *, root: self_.read_cmd('src/manual', root=root),
    '4' : lambda self_, *, root: self_.read_cmd('src/init', root=root),
    '5' : lambda self_, *, root: self_.repo_cmd(root=root),
    '6' : lambda self_, *, root: None,
}

# commands after `open_cmd`
OPEN = '''
What would you like to do next:

  1. view report in the terminal
  2. export report as treeview
  3. export report as plist
  4. export report as json
  5. export report as PDF
  6. go back
  7. quit
'''

# dict of commands after `open_cmd`
OPEN_CMD = {
    '1' : lambda self_, *, root: 'view',
    '2' : lambda self_, *, root: self_.move_cmd(root=root),
    '3' : lambda self_, *, root: self_.save_cmd('plist', root=root),
    '4' : lambda self_, *, root: self_.save_cmd('json', root=root),
    '5' : lambda self_, *, root: self_.expt_cmd(root=root),
    '6' : lambda self_, *, root: root,
    '7' : lambda self_, *, root: None,
}

# commands after `view_cmd`
VIEW = '''
How would you like to view the report?

  1. show all
  2. go to frame
  3. search in frames
  4. go back
  5. quit
'''

# dict of commands after `view_cmd`
VIEW_CMD = {
    '1' : lambda self_, *, root: self_.read_cmd('src/out', root=root),
    '2' : lambda self_, *, root: self_.goto_cmd(root=root),
    '3' : lambda self_, *, root: self_.view_cmd(root=root),
    '4' : lambda self_, *, root: root,
    '5' : lambda self_, *, root: None,
}

# dict of all commands
DICT = dict(
    init = (INIT, INIT_CMD),
    open = (OPEN, OPEN_CMD),
    view = (VIEW, VIEW_CMD),
)

# tuple of quit commands
QUIT = ('q', 'quit', 'exit')


class Display(Analyser):

    def __init__(self):
        self.read_cmd('src/init')

        kind = 'init'
        while kind:
            kind = self.show_cmd(kind)

        os.remove('src/out')
        exit()

    def show_cmd(self, kind, *, root='init'):
        cmds = DICT.get(kind)

        print(cmds[0])
        cmd = input('Your command: ')
        func = cmds[1].get(cmd)
        while func is None:
            if cmd in QUIT:
                return None
            cmd = input('⚠️Invalid command.\nPlease retry: ')
            func = cmds[1].get(cmd)
        return func(self, root=root)

    def repo_cmd(self, *, root='init'):
        webbrowser.open('https://github.com/JarryShaw/jspcap/')
        return root

    def read_cmd(self, name, *, root='init'):
        with open(name, 'r') as file_:
            for line in file_:
                content = line.strip('\n').replace(EMSP, '')
                print(content)
        return root

    def open_cmd(self, *, root='init'):
        # remove cache
        self._frnum = 1
        open('src/out', 'w').close()

        fin = input('\nWhich file would you like to open: ')
        if '.pcap' not in fin:
            fin = '{}.pcap'.format(fin)

        while not os.path.isfile(fin):
            if fin in QUIT:
                return None
            fin = input('Invalid file.\nPlease retry: ')
            if '.pcap' not in fin:
                fin = '{}.pcap'.format(fin)

        self.__file = fin
        self.__frames = []
        with open(fin, 'rb') as file_:
            try:
                print('🚨Loading file {}...'.format(fin))
                self.record_header(file_)
                print('🍺Extracting...')

                while True:
                    try:
                        self.record_frames(file_)
                        content = NUMB((self.length - 1), self.protocol)
                        print(content)
                    except EOFError:
                        break

                print(end='\r', flush=True)
                print('🍻Extraction done.')
                return 'open'
            except FileError:
                print('Unsupported file format.')
                return root

    def move_cmd(self, *, root='open'):
        path = input('Where would you like to export: ')
        while True:
            if path in QUIT:
                return None
            try:
                shutil.copyfile('src/out', path)
                print('The report has been stored in {}'.format(path))
                return root
            except:
                path = input('Invalid file name!\nPlease retry: ')

    def expt_cmd(self, *, root='open'):
        path = input('The exported file name: ')
        if path in QUIT:
            return None

        process = subprocess.Popen(
                        ['pandoc', 'src/out', '-o', file_],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )

        output, error = process.communicate()
        if process.returncode:
            print('Unable to export PDF: {}'.format(error.decode(shcoding)))
        else:
            print('Export done.')
            print('The report has been stored in {}'.format(path))
        return root

    def save_cmd(self, fmt, *, root='open'):
        path = input('The exported file name: ')
        while True:
            if path in QUIT:
                return None
            try:
                ext = Extractor(fmt=fmt, fin=self.__file, fout=path, auto=False)
                print('🍺Exporting...')

                # extracting pcap file
                for frame in ext:
                    percent = 100.0 * ext.length / self.length
                    content = EXPT(percent)
                    print(content, end='\r', flush=True)

                print()
                print('🍻Export done.')
                print('The report has been stored in {}'.format(ext.output))
                return root
            except:
                path = input('Invalid file name!\nPlease retry: ')

    def goto_cmd(self, *, root='view'):
        with open('src/out', 'r') as file_:
            for _ctr, line in enumerate(file_):
                if 'Frame' in line:
                    frames.append(_ctr)

        num = input('Which frame in range would you like to view: ')
        while True:
            if num in QUIT:
                return None
            try:
                ctr = int(num)
            except ValueError:
                if re.findall(GH, num):
                    ctr = 0;    break
            else:
                if ctr < self.length:
                    break
            num = input('Invalid frame number!\nPlease retry: ')

        this = self.__frames[ctr-1] if isinstance(ctr, int) else 0
        that = self.__frames[ctr] if isinstance(ctr, int) else self.__frames[0]

        with open('src/out', 'r') as file_:
            for _ctr, line in enumerate(file_):
                if _ctr >= this:
                    print(line)
                if _ctr >= that:
                    break

        return root

    def view_cmd(self, mode, *, root='view'):
        topic = input('What keyword would you to search in frames: ')
