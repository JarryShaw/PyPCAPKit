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
    '1' : lambda self_: self_.open_cmd(),
    '2' : lambda self_: self_.read_cmd('assets/about'),
    '3' : lambda self_: self_.read_cmd('assets/manual'),
    '4' : lambda self_: self_.read_cmd('assets/init'),
    '5' : lambda self_: self_.repo_cmd(),
    '6' : lambda self_: None,
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
    '1' : lambda self_: self_.view_cmd(),
    '2' : lambda self_: self_.move_cmd(),
    '3' : lambda self_: self_.save_cmd('plist'),
    '4' : lambda self_: self_.save_cmd('json'),
    '5' : lambda self_: self_.expt_cmd(),
    '6' : lambda self_: 'init',
    '7' : lambda self_: None,
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
    '1' : lambda self_: self_.read_cmd('assets/out', root='view'),
    '2' : lambda self_: self_.goto_cmd(),
    '3' : lambda self_: self_.srch_cmd(),
    '4' : lambda self_: 'open',
    '5' : lambda self_: None,
}

# commands after `goto_cmd`
GOTO = '''
What would you like to do next?

  1. go to next frame
  2. go to previous frame
  3. go back
  4. quit
'''

# dict of commands after `goto_cmd`
GOTO_CMD = {
    '1' : lambda self_: self_.next_cmd(),
    '2' : lambda self_: self_.back_cmd(),
    '3' : lambda self_: 'view',
    '4' : lambda self_: None,
}

# dict of all commands
DICT = dict(
    init = (INIT, INIT_CMD),
    open = (OPEN, OPEN_CMD),
    view = (VIEW, VIEW_CMD),
    goto = (GOTO, GOTO_CMD),
)

# tuple of quit commands
QUIT = ('q', 'quit', 'exit')

# dict of file names
NAME = {
    'assets/about'  : 'ABOUT',
    'assets/init'   : 'README',
    'assets/manual' : 'MANUAL',
    'assets/out'    : 'REPORT',
    'assets/recent' : 'LOG',
}


class Display:
    """Console UI for PCAP Tree Viewer

    This class implemented a UI class for the application. It is a pure
    console/terminal ASCII flavour program. Whilst it has already implemented
    most functions supported in the graphic UI, we are still trying to make
    a cross-platform console graphic UI using `curses` from the Python
    standard library.

    Properties:
        * length -- <int> current frame number of the extracting process
        * protocol -- <str> current frame protocol chain of the extracting process

        * __ext -- <jspcap.Extractor> pcap extractor
        * __now -- <int> pointer of the current frame number
        * __frames -- <list> list of line number where frames start in the report

    Utilities:
        * show_cmd -- print instruction and call corresponding command
        * read_cmd -- print certain file then go back to root
        * save_cmd -- export report to certain format and path

    Methods:
        * root -> init
            * open_cmd -- open then extract requested pcap file
            * read_cmd -> about
            * read_cmd -> manual
            * read_cmd -> init
            * repo_cmd -- open web browser and go to GitHub page
            * exit
        * root -> open (after open_cmd)
            * view_cmd -- pretreat report
            * move_cmd -- move report to requested path
            * save_cmd -> plist
            * save_cmd -> json
            * expt_cmd -- export report as PDF
            * root -> init
            * exit
        * root -> view (after view_cmd)
            * read_cmd -> out
            * goto_cmd -- go to certain frame
            * srch_cmd -- search and go to corresponding frame
            * root -> open
            * exit
        * root -> goto (after goto_cmd)
            * next_cmd -- go to next frame
            * back_cmd -- go to previous frame
            * root -> view
            * exit

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def length(self):
        return self.__ext.length

    @property
    def protocol(self):
        return self.__ext.protocol

    ##########################################################################
    # Data modules.
    ##########################################################################

    def __init__(self):
        try:
            self.read_cmd('assets/init')
        except FileNotFoundError:
            print('\n❌Unable to find README.')
            exit()

        kind = 'init'
        while kind:
            kind = self.show_cmd(kind)

        try:
            os.remove('assets/out')
        except FileNotFoundError:
            pass
        exit()

    ##########################################################################
    # Utilities.
    ##########################################################################

    def show_cmd(self, kind, *, root='init'):
        cmds = DICT.get(kind)

        print(cmds[0])
        cmd = input('Your command: ')
        func = cmds[1].get(cmd)
        while func is None:
            if cmd in QUIT:
                return None
            cmd = input('Invalid command.\nPlease retry: ')
            func = cmds[1].get(cmd)
        return func(self)

    def read_cmd(self, name, *, root='init'):
        try:
            with open(name, 'r') as file_:
                for line in file_:
                    content = line
                    print(content, end='')
        except FileNotFoundError:
            print('\n❌Unable to find {}.'.format(NAME.get(name)))
        finally:
            return root

    def save_cmd(self, fmt, *, root='open'):
        path = input('\nWhere would you like to export: ')
        while True:
            if path in QUIT:
                return None
            try:
                ext = Extractor(fmt=fmt, fin=self.__ext.input, fout=path, auto=False)
                print('\n🍺Exporting...')

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

    ##########################################################################
    # Methods.
    ##########################################################################

    def repo_cmd(self, *, root='init'):
        webbrowser.open('https://github.com/JarryShaw/jspcap/')
        return root

    def open_cmd(self, *, root='init'):
        # remove cache
        open('assets/out', 'w').close()

        fin = input('\nWhich file would you like to open: ')
        if '.pcap' not in fin:
            fin = '{}.pcap'.format(fin)

        while not os.path.isfile(fin):
            if fin in QUIT:
                return None
            fin = input('Invalid file.\nPlease retry: ')
            if '.pcap' not in fin:
                fin = '{}.pcap'.format(fin)

        self.__frames = []
        try:
            print('\n🚨Loading file {}...'.format(fin))
            self.__ext = Extractor(fin=fin, fout='assets/out', fmt='tree', auto=False, extension=False)

            # extracting pcap file
            print('🍺Extracting...')
            for frame in self.__ext:
                content = NUMB(self.length, self.protocol)
                print(content)

            print(end='\r', flush=True)
            print('🍻Extraction done.')
            return 'open'
        except FileError:
            print('Unsupported file format.')
            return root
        except FileNotFoundError:
            print("❌Invalid input file '{}'.".format(fin))
            return root

    def expt_cmd(self, *, root='open'):
        path = input('\nWhere would you like to export: ')
        if path in QUIT:
            return None

        print('\n🍺Exporting...')
        process = subprocess.Popen(
                        ['pandoc', 'assets/out', '-o', path],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
        output, error = process.communicate()
        if process.returncode:
            print('Unable to export PDF: {}'.format(error.decode(shcoding)))
        else:
            print('🍻Export done.')
            print("The report has been stored in '{}'".format(path))
        return root

    def move_cmd(self, *, root='open'):
        path = input('\nWhere would you like to export: ')
        while True:
            if path in QUIT:
                return None
            try:
                print('🍺Exporting...')
                shutil.copyfile('assets/out', path)
                print('🍻Export done.')
                print('The report has been stored in {}'.format(path))
                return root
            except FileNotFoundError:
                print('\n❌Unable to find REPORT.')
                return root
            except:
                path = input('Invalid file name!\nPlease retry: ')

    def view_cmd(self, *, root='open'):
        try:
            open('assets/out', 'r').close()
        except FileNotFoundError:
            print('\n❌Unable to find REPORT.')
            return root

        if not self.__frames:
            with open('assets/out', 'r') as file_:
                for _ctr, line in enumerate(file_):
                    if 'Frame' in line:
                        self.__frames.append(_ctr)
                self.__frames.append(_ctr+1)
        return 'view'

    def srch_cmd(self, *, root='view'):
        try:
            open('assets/out', 'r').close()
        except FileNotFoundError:
            print('\n❌Unable to find REPORT.')
            return root

        topic = input('\nWhat keyword would you to search in frames: ')
        pattern = re.escape(topic)
        result = []

        print('\n🍺Searching...')
        with open('assets/out', 'r') as file_:
            for _ctr, line in enumerate(file_):
                if re.findall(pattern, line, re.I):
                    result.append(_ctr)

        if not result:
            print("🍻No keyword '{}' found.".format(topic))
            return root

        now = 1
        frame = []
        this = 0
        that = self.__frames[0]

        for ctr in result:
            try:
                while not (this <= ctr < that):
                    now += 1
                    this = self.__frames[now-1]
                    that = self.__frames[now]
                frame.append(now)
            except IndexError:
                continue


        this = self.__frames[frame[0]-1] if frame[0] > 0 else 0
        that = self.__frames[frame[0]] if frame[0] > 0 else self.__frames[0]

        with open('assets/out', 'r') as file_:
            print()
            for _ctr, line in enumerate(file_):
                if _ctr >= this:
                    print(line.strip('\n'))
                if _ctr >= that - 2:
                    if len(frame) - 1:
                        frame.pop(0)
                        this = self.__frames[frame[0]-1] if frame[0] > 0 else 0
                        that = self.__frames[frame[0]]
                    else:
                        break

        return root

    def goto_cmd(self, *, root='view'):
        try:
            open('assets/out', 'r').close()
        except FileNotFoundError:
            print('\n❌Unable to find REPORT.')
            return root

        num = input('\nWhich frame in range would you like to view: ')
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

        this = self.__frames[ctr-1] if ctr > 0 else 0
        that = self.__frames[ctr] if ctr > 0 else self.__frames[0]

        with open('assets/out', 'r') as file_:
            print()
            for _ctr, line in enumerate(file_):
                if _ctr >= this:
                    print(line.strip('\n'))
                if _ctr >= that - 2:
                    break

        self.__now = ctr
        return 'goto'

    def back_cmd(self, *, root='goto'):
        try:
            open('assets/out', 'r').close()
        except FileNotFoundError:
            print('\n❌Unable to find REPORT.')
            return root

        if self.__now == 0:
            self.__now = self.length - 1
        else:
            self.__now -= 1

        ctr = self.__now
        this = self.__frames[ctr-1] if ctr > 0 else 1
        that = self.__frames[ctr] if ctr > 0 else self.__frames[0]

        with open('assets/out', 'r') as file_:
            print()
            for _ctr, line in enumerate(file_):
                if _ctr >= this:
                    print(line.strip('\n'))
                if _ctr >= that - 2:
                    break

        self.__now = ctr
        return root

    def next_cmd(self, *, root='goto'):
        try:
            open('assets/out', 'r').close()
        except FileNotFoundError:
            print('\n❌Unable to find REPORT.')
            return root

        if self.__now == self.length - 1:
            self.__now = 0
        else:
            self.__now += 1

        ctr = self.__now
        this = self.__frames[ctr-1] if ctr > 0 else 0
        that = self.__frames[ctr] if ctr > 0 else self.__frames[0]

        with open('assets/out', 'r') as file_:
            print()
            for _ctr, line in enumerate(file_):
                if _ctr >= this:
                    print(line.strip('\n'))
                if _ctr >= that - 2:
                    break

        self.__now = ctr
        return root


if __name__ == '__main__':
    Display()
