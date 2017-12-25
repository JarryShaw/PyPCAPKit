#!/usr/bin/python3
# -*- coding: utf-8 -*-


import functools
import math
import os
import pathlib
import re
import shutil
import subprocess
import time
import platform
import webbrowser


# UI for PCAP Viewer
# PCAP Viewer Implementation on Tkinter


from tkinter import *
from tkinter.filedialog import askopenfilename, asksaveasfilename
from tkinter.messagebox import askokcancel, showerror, showinfo, showwarning
from tkinter.scrolledtext import ScrolledText

from jspcap.exceptions import FileError
from jspcap.extractor import Extractor

# macOS only:
#   from Foundation import NSBundle


# Platform specific settings
macOS = (platform.system() == 'Darwin')
windows = (platform.system() == 'Windows')
shcoding = 'gbk' if windows else 'utf-8'

# Keyboard accelerator words
cmdkw = 'Command' if macOS else 'Ctrl'
delkw = 'Delete'
optkw = 'Opt' if macOS else 'Alt'
sftkw = 'Shift'
upakw = '↑'
dwnkw = '↓'
brlkw = '['
brrkw = ']'

# Keyboard event bindings
cmdbd = 'Command' if macOS else 'Control'
cmabd = 'comma'
delbd = 'Delete'
optbd = 'Alt'
sftbd = 'Shift'
upabd = 'uparrow'
dwnbd = 'downarrow'
brlbd = 'bracketleft'
brrbd = 'bracketright'

# accelerator & event
short = lambda *args: '-'.join(args) if macOS else '+'.join(args)
event = lambda *args: '<' + '-'.join(args) + '>'

# geometry (window size)
SIZE = '674x476' if macOS else '850x620'

# background colour
BGCOLOUR = '#e2c08d'

# embeded spaces
EMSP = '                   '

# file names
NAME = {
    'assets/about'  : 'ABOUT',
    'assets/init'   : 'README',
    'assets/manual' : 'MANUAL',
    'assets/out'    : 'REPORT',
    'assets/recent' : 'LOG',
}

# File name regex
# r'''\A(.*?)(\ copy)?(\ [0-9]+)?[.](.*)\Z'''
FILE = re.compile(r'''
    \A                      # begin of string
    (?P<name>.*?)           # file name
    (?P<copy>\ copy)?       # copy
    (?P<fctr>\ [0-9]+)?     # number of duplication
    [.]                     # dot
    (?P<exts>.*)            # extension
    \Z                      # end of string
''', re.VERBOSE)

# Extracting Label
NUMB = lambda number: '''

       Extracting... Frame {:>2d}

'''.format(number)

# Loading Label
TEXT = lambda percent: '''

          Loading... {:>2.2f}%

   +------------------------------+
   |{sharp}{space}|
   +------------------------------+

'''.format(percent,
    sharp = '#' * math.ceil(30 * percent / 100),
    space = ' ' * (30 - math.ceil(30 * percent / 100))
)

# Exporting Label
EXPT = lambda percent: '''

         Exporting... {:>2.2f}%

   +------------------------------+
   |{sharp}{space}|
   +------------------------------+

'''.format(percent,
    sharp = '#' * math.ceil(30 * percent / 100),
    space = ' ' * (30 - math.ceil(30 * percent / 100))
)


class Display:
    """Graphic UI for PCAP Tree Viewer

    This class implemented a UI class for the application. It is based on
    tkinter, jspcap and jsformat. Its design imitates macOS applications,
    specificly the menu bar. However, due to the lack of system APIs, some
    features are not implemented yet. We are trying to migrate to `PyObjc`,
    which supports macOS native application with py2app library.

    Properties:
        * length -- <int> current frame number of the extracting process

        * _ext -- <jspcap.Extractor> pcap extractor
        * _cpflg -- <bool> copy flag, if the current pcap file is duplicated before
        * _cpstr -- <str> copy string, the string number of next duplication

        * master -- <tkinter.Tk> root window
        * frame -- <tkinter.Frame> frame on root
        * menu -- <tkinter.Menu> menu bar
        * text -- <tkinter.Text> text for initial display
        * label -- <tkinter.Label> label for 'Extracting', 'Loading' and 'Exporting'
        * scrollbar -- <tkinter.Scrollbar> scrollbar for listbox
        * listbox -- <tkinter.Listbox> listbox for output viewer

    Methods:
        * menu_setup -- set up menu bar
            * Home Cascade
                * intr_cmd -- set up command About PCAP Tree Viewer
                * pref_cmd -- set up command Preferences
                * Service Cascade
                    * sysp_cmd -- set up command System Preferences...
                * hide_cmd -- set up command Hide PCAP Tree Viewer
                * wipe_cmd -- set up command Hide Others
                * show_cmd -- set up command Show All
                * quit_cmd -- set up command Quit PCAP Tree Viewer
            * File Cascade
                * open_cmd -- set up command Open...
                * Open Recent Cascade
                    * rmrf_cmd -- set up command Clear Menu
                * shut_cmd -- set up command Close Window
                * save_cmd -- set up command Save
                * copy_cmd -- set up command Duplicate
                * mvrn_cmd -- set up command Rename...
                * move_cmd -- set up command Move To...
                * expt_cmd -- set up command Export...
            * Edit Cascade
                * cmdc_cmd -- set up command Copy
                * cmda_cmd -- set up command Select All
                * invt_cmd -- set up command Invert Selection
                * mvsh_cmd -- set up command Move to Trash
                * Find Cascade
                    * find_cmd -- set up command Find
                    * find_prev -- set up command Find Previous
                    * find_self -- set up command Use Selection for Find
                    * find_jump -- set up command Jump to Selection
            * Go Cascade
                * goto_cmd -- set up command Go
                * goto_up -- set up command Up
                * goto_down -- set up command Down
                * goto_prev -- set up command Previous Frame
                * goto_next -- set up command Next Frame
                * goto_go -- set up command Go to Frame...
                * goto_frame -- set up command
                * goto_back -- set up command Back
                * goto_fwd -- set up command Forward
            * Window Cascade
                * mini_cmd -- set up command Minimize
                * zoom_cmd -- set up command Zoom
            * Help Cascade
                * srch_cmd -- set up command Search
                * help_cmd -- set up command PCAP Tree Viewer Help
                * repo_cmd -- set up command View on GitHub

    Utilities:
        * init_display -- initial page setup
        * open_file -- ask and open pcap file
        * load_file -- extract pcap file then load report
        * keep_file -- update recent files
        * save_file -- save or export report in certain format
            * expt_file -- export report to json or plist file
        * show_error -- show error when not-implemented functions called

    Usage:
        >>> Display()

    """
    _cpflg = False
    _cpstr = 1

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def length(self):
        return self._ext.length

    ##########################################################################
    # Data modules.
    ##########################################################################

    def __init__(self):
        try:
            os.remove('assets/out')
        except FileNotFoundError:
            pass

        # root window setup
        self.master = Tk()
        self.master.title('PCAP Tree Viewer')
        self.master.geometry(SIZE)
        self.master.resizable(False, False)

        # frame setup
        self.frame = Frame(bd=8)
        self.frame.pack()

        # menu setup
        self.menu = Menu(self.master)
        self.master.config(menu=self.menu)
        self.menu_setup()

        self.init_display()
        self.master.mainloop()

    ##########################################################################
    # Methods.
    ##########################################################################

    def menu_setup(self):
        """Menu Strcuture:

        PCAP Tree Viewer | Home (macOS)
            * About PCAP Tree Viewer
            * Preferences...                          ⌘,
            * Service
                - No Services Apply (disabled)
                - System Preferences...
            -----------------------------------------------
            * Hide PCAP Tree Viewer                   ⌘H
            * Hide Others                            ⌥⌘H
            * Show All
            -----------------------------------------------
            * Quit PCAP Tree Viewer                   ⌘Q

        File
            * Open...                                 ⌘O
            * Open Recent
                * Recent File 0
                * Recent File 1
                * ......
                -------------------------------------------
                * Clear Menu
            * Close Window                            ⌘W
            * Save                                    ⌘S
            * Duplicate                              ⇧⌘S
            * Rename...
            * Move To...
            * Export...
            * Export as PDF...
            -----------------------------------------------
            * Print                                   ⌘P

        Edit
            * Copy                                    ⌘C
            * Select All                              ⌘A
            * Invert Selection                       ⇧⌘I
            -----------------------------------------------
            * Move to Trash                           ⌘⌫
            -----------------------------------------------
            * Find
                * Find...                             ⌘F
                * Find Next                           ⌘G
                * Find Previous                      ⇧⌘G
                * Use Selection for Find              ⌘E
                * Jump to Selection                   ⌘J

        Go
            * Up                                       ↑
            * Down                                     ↓
            * Previous Frame                          ⌥↑
            * Next Frame                              ⌥↓
            * Go to Frame...                         ⌥⌘G
            -----------------------------------------------
            * Back                                    ⌘[
            * Forward                                 ⌘]

        Window
            * Minimize                                ⌘M
            * Zoom

        Help
            * Search
            -----------------------------------------------
            * PCAP Tree Viewer Help
            * View on GitHub

        """
        if macOS:
            from Foundation import NSBundle
            bundle = NSBundle.mainBundle()
            if bundle:
                info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
                if info and info['CFBundleName'] == 'Python':
                    info['CFBundleName'] = 'PCAP Tree Viewer'

        # home menu
        home_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='Home', menu=home_menu)
        home_menu.add_cascade(label='About PCAP Tree Viewer', command=self.intr_cmd)
        home_menu.add_separator()
        home_menu.add_command(label='Preferences...', command=self.pref_cmd, accelerator=short(cmdkw, '，'))
        self.master.bind(event(cmdbd, cmabd), self.pref_cmd)
        home_menu.add_separator()
        serv_menu = Menu(home_menu, tearoff=0)
        home_menu.add_cascade(label='Service', menu=serv_menu)
        serv_menu.add_command(label='No Services Apply', state='disabled')
        serv_menu.add_command(label='System Preferences...', command=self.sysp_cmd)
        home_menu.add_separator()
        home_menu.add_command(label='Hide PCAP Tree Viewer', command=self.hide_cmd, accelerator=short(cmdkw, 'Ｈ'))
        self.master.bind(event(cmdbd, 'h'), self.hide_cmd)
        home_menu.add_command(label='Hide Others', command=self.wipe_cmd, accelerator=short(optkw, cmdkw, 'Ｈ'))
        self.master.bind(event(optbd, cmdbd, 'h'), self.wipe_cmd)
        home_menu.add_command(label='Show All', command=self.show_cmd)
        home_menu.add_separator()
        home_menu.add_command(label='Quit PCAP Tree Viewer', command=self.quit_cmd, accelerator=short(cmdkw, 'Ｑ'))
        self.master.bind(event(cmdbd, 'q'), self.quit_cmd)

        # file menu
        file_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='File', menu=file_menu)
        file_menu.add_command(label='Open...', command=self.open_cmd, accelerator=short(cmdkw, 'Ｏ'))
        self.master.bind(event(cmdbd, 'o'), self.open_cmd)
        frct_menu = Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label='Open Recent', menu=frct_menu)
        try:
            with open('assets/recent', 'r') as file_:
                file_real = False
                for (fctr, file_name) in enumerate(file_):
                    file_real = True if file_name else False
                    frct_menu.add_command(label=file_name, command=functools.partial(self.open_cmd, name=file_name))
        except Exception:
            file_real = False
        if file_real:
            frct_menu.add_separator()
            frct_menu.add_command(label='Clear Menu',
                command=functools.partial(self.rmrf_cmd, menu=frct_menu, fctr=fctr)
            )
        else:
            frct_menu.add_command(label='Clear Menu', state='disabled')
        file_menu.add_separator()
        file_menu.add_command(label='Close Window', command=self.shut_cmd, accelerator=short(cmdkw, 'Ｗ'))
        self.master.bind(event(cmdbd, 'w'), self.shut_cmd)
        file_menu.add_command(label='Save', command=self.save_cmd, accelerator=short(cmdkw, 'Ｓ'))
        self.master.bind(event(cmdbd, 's'), self.save_cmd)
        file_menu.add_command(label='Duplicate', command=self.copy_cmd, accelerator=short(sftkw, cmdkw, 'Ｓ'))
        self.master.bind(event(sftbd, cmdbd, 's'), self.copy_cmd)
        file_menu.add_command(label='Rename...', command=self.mvrn_cmd)
        file_menu.add_command(label='Move To...', command=self.move_cmd)
        file_menu.add_command(label='Export...', command=self.expt_cmd)
        file_menu.add_command(label='Export as PDF...', command=functools.partial(self.expt_cmd, fmt='pdf'))
        file_menu.add_separator()
        file_menu.add_command(label='Print', accelerator=short(cmdkw, 'Ｐ'),
            command=functools.partial(self.expt_cmd, fmt='print')
        )
        self.master.bind(event(cmdbd, 'p'), functools.partial(self.expt_cmd, 'print'))

        # edit menu
        edit_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='Edit', menu=edit_menu)
        edit_menu.add_command(label='Copy', command=self.cmdc_cmd, accelerator=short(cmdkw, 'Ｃ'))
        self.master.bind(event(cmdbd, 'c'), self.cmdc_cmd)
        edit_menu.add_command(label='Select All', command=self.cmda_cmd, accelerator=short(cmdkw, 'Ａ'))
        self.master.bind(event(cmdbd, 'a'), self.cmda_cmd)
        edit_menu.add_command(label='Invert Selection', command=self.invt_cmd, accelerator=short(sftkw, cmdkw, 'Ｉ'))
        self.master.bind(event(sftbd, cmdbd, 'i'), self.invt_cmd)
        edit_menu.add_separator()
        edit_menu.add_command(label='Move to Trash', command=self.mvsh_cmd, accelerator=short(cmdkw, delkw))
        self.master.bind(event(cmdbd, delbd), self.mvsh_cmd)
        edit_menu.add_separator()
        find_menu = Menu(edit_menu, tearoff=0)
        edit_menu.add_cascade(label='Find', menu=find_menu)
        find_menu.add_command(label='Find...', command=self.find_cmd, accelerator=short(cmdkw, 'Ｆ'))
        self.master.bind(event(cmdbd, 'f'), self.find_cmd)
        find_menu.add_command(label='Find Next', accelerator=short(cmdkw, 'Ｇ'),
            command=functools.partial(self.find_cmd, cmd='next')
        )
        self.master.bind(event(cmdbd, 'g'), functools.partial(self.find_cmd, cmd='next'))
        find_menu.add_command(label='Find Previous', accelerator=short(sftkw, cmdkw, 'Ｇ'),
            command=functools.partial(self.find_cmd, cmd='prev')
        )
        self.master.bind(event(sftbd, cmdbd, 'g'), functools.partial(self.find_cmd, cmd='prev'))
        find_menu.add_command(label='Use Selection for Find', accelerator=short(cmdkw, 'Ｅ'),
            command=functools.partial(self.find_cmd, cmd='self')
        )
        self.master.bind(event(cmdbd, 'e'), functools.partial(self.find_cmd, cmd='self'))
        find_menu.add_command(label='Jump to Selection', accelerator=short(cmdkw, 'Ｊ'),
            command=functools.partial(self.find_cmd, cmd='jump')
        )
        self.master.bind(event(cmdbd, 'j'), functools.partial(self.find_cmd, cmd='jump'))

        # go menu
        goto_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='Go', menu=goto_menu)
        goto_menu.add_command(label='Up', command=functools.partial(self.goto_cmd, cmd='up'), accelerator=short(upakw))
        self.master.bind(event(upabd), functools.partial(self.goto_cmd, cmd='up'))
        goto_menu.add_command(label='Down', command=functools.partial(self.goto_cmd, cmd='down'), accelerator=short(dwnkw))
        self.master.bind(event(dwnbd), functools.partial(self.goto_cmd, cmd='down'))
        goto_menu.add_command(label='Previous Frame', accelerator=short(optkw, upakw),
            command=functools.partial(self.goto_cmd, cmd='prev')
        )
        self.master.bind(event(optbd, upabd), functools.partial(self.goto_cmd, cmd='prev'))
        goto_menu.add_command(label='Next Frame', accelerator=short(optkw, dwnkw),
            command=functools.partial(self.goto_cmd, cmd='next')
        )
        self.master.bind(event(optbd, dwnbd), functools.partial(self.goto_cmd, cmd='next'))
        goto_menu.add_command(label='Go to Frame...', accelerator=short(optkw, cmdkw, 'Ｇ'),
            command=functools.partial(self.goto_cmd, cmd='go')
        )
        self.master.bind(event(optbd, cmdbd, 'g'), functools.partial(self.goto_cmd, cmd='go'))
        goto_menu.add_separator()
        goto_menu.add_command(label='Back', accelerator=short(cmdkw, brlkw),
            command=functools.partial(self.goto_cmd, cmd='back')
        )
        self.master.bind(event(cmdbd, brlbd), functools.partial(self.goto_cmd, cmd='back'))
        goto_menu.add_command(label='Forward', accelerator=short(cmdkw, brrkw),
            command=functools.partial(self.goto_cmd, cmd='fwd')
        )
        self.master.bind(event(cmdbd, brrbd), functools.partial(self.goto_cmd, cmd='fwd'))

        # window menu
        wind_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='Window', menu=wind_menu)
        wind_menu.add_command(label='Minimize', command=self.mini_cmd, accelerator=short(cmdkw, 'Ｍ'))
        self.master.bind(event(cmdbd, 'm'), self.mini_cmd)
        wind_menu.add_command(label='Zoom', command=self.zoom_cmd)

        # help menu
        help_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='Help', menu=help_menu)
        if not macOS:
            help_menu.add_command(label='Search', command=self.srch_cmd)
            help_menu.add_separator()
        help_menu.add_command(label='PCAP Tree Viewer Help', command=self.help_cmd)
        help_menu.add_command(label='View on GitHub', command=self.repo_cmd)

    # About PCAP Tree Viewer
    def intr_cmd(self):
        toplevel = Toplevel(self.master)
        toplevel.title('About PCAP Tree Viewer')
        scrolledtext = ScrolledText(
                toplevel, font=('Courier New', 12),
                width=50, height=20
        )
        scrolledtext.pack()
        try:
            with open('assets/about', 'r') as file_:
                for line in file_:
                    scrolledtext.insert(END, line)
                    scrolledtext.update()
            scrolledtext.config(state=DISABLED)
            toplevel.resizable(width=False, height=False)
        except FileNotFoundError:
            showerror("Something's missing.", 'Unable to fine ABOUT.')

    # Preferences
    def pref_cmd(self, *args):
        self.show_error('set preferences')

    # System Preferences...
    def sysp_cmd(self):
        self.show_error('open System Preferences')

    # Hide PCAP Tree Viewer
    def hide_cmd(self, *args):
        self.master.withdraw()

    # Hide Others
    def wipe_cmd(self, *args):
        self.show_error('hide others')

    # Show All
    def show_cmd(self):
        self.zoom_cmd()

    # Quit PCAP Tree Viewer
    def quit_cmd(self, *args):
        try:
            os.remove('assets/out')
        except FileNotFoundError:
            pass
        self.master.destroy()

    # Open...
    def open_cmd(self, event=None, *, name=None):
        self.open_file(name)

    # Clear Menu
    def rmrf_cmd(self, *, menu, fctr):
        open('assets/recent', 'w').close()
        menu.delete(0, fctr+2)
        menu.add_command(label='Clear Menu', state=DISABLED)

    # Close Window
    def shut_cmd(self, *args):
        if askokcancel(
                'Close Window',
                'Do you really want to close?'
            ):
            try:
                os.remove('assets/out')
            except FileNotFoundError:
                pass
            self.master.destroy()

    # Save
    def save_cmd(self, *args):
        try:
            self.save_file()
        except FileNotFoundError:
            self.show_warning('Save')

    # Duplicate
    def copy_cmd(self, *args):
        try:
            ifnm = self._ext.input
        except AttributeError:
            self.show_warning('Duplicate')
            return
        fnmt = FILE.match(ifnm)
        if fnmt is None:
            return

        name = fnmt.group('name') or ''
        copy = fnmt.group('copy') or ''
        fctr = fnmt.group('fctr')
        exts = fnmt.group('exts') or ''

        if fctr:
            self._cpctr = 1 + (self._cpctr if self._cpflg else int(fctr))
            fctr = ' ' + str(self._cpctr)
        else:
            self._cpctr = 2 if copy else 1
            fctr = (' ' + str(self._cpctr)) if copy else ' copy'
        self._cpflg = True

        cpnm = name + copy + fctr + '.' + exts
        shutil.copyfile(ifnm, cpnm)

    # Rename...
    def mvrn_cmd(self):
        self.move_cmd(rename=True)

    # Move To...
    def move_cmd(self, *, rename=False):
        try:
            tmp = self._ext
        except AttributeError:
            cmd = 'rename' if rename else 'move'
            self.show_warning(cmd)
            return

        file_ = asksaveasfilename(
            parent=self.master, title='Please select a directory ...',
            initialdir='./', defaultextension='.pcap'
        )
        if file_ == '':
            return
        try:
            os.rename(self._ext.input, file_)
        except FileNotFoundError:
            showerror(
                'Unable to {cmd} {fin} to {fout}'.format(
                    cmd='rename' if rename else 'move',
                    fin=self._ext.input, fout=file_
                ),
                'The original file is missing.'
            )
        except:
            showerror(
                'Unable to {cmd} {fin} to {fout}'.format(
                    cmd='rename' if rename else 'move',
                    fin=self._ext.input, fout=file_
                ),
                'Invalid destination file name.'
            )

    # Export...
    def expt_cmd(self, event=None, *, fmt=None):
        try:
            tmp = self._ext
        except AttributeError:
            self.show_warning('Export')
            return

        if fmt is None:
            toplevel = Toplevel(self.master)
            toplevel.title('Export ...')
            toplevel.resizable(width=False, height=False)

            frame = Frame(toplevel, bd=4)
            frame.pack()

            fmttext = ['JSON', 'macOS Property List', 'Text Tree View', 'PDF']
            fmtlist = ['json', 'plist', 'tree', 'pdf']

            var = StringVar()
            for m in range(4):
                radiobutton = Radiobutton(frame,
                    text=fmttext[m], value=fmtlist[m], state=NORMAL,
                    variable=var, command=functools.partial(self.save_file, var)
                )
                radiobutton.pack(anchor=W)
                radiobutton.deselect()
        else:
            self.save_file(fmt)

    # Copy
    def cmdc_cmd(self, *args):
        try:
            data = []
            for index in range(self.listbox.size()):
                if self.listbox.selection_includes(index):
                    data.append(self.listbox.get(index))

            data = '\n'.join(data)
            self.master.clipboard_clear()
            self.master.clipboard_append(data)
        except AttributeError:
            self.master.clipboard_clear()

    # Select All
    def cmda_cmd(self, *args):
        try:
            for index in range(self.listbox.size()):
                self.listbox.selection_set(index)
                self.listbox.yview(index)
                self.listbox.update()
        except AttributeError:
            self.show_warning('Select All')

    # Invert Selection
    def invt_cmd(self, *args):
        try:
            for index in range(self.listbox.size()):
                if self.listbox.selection_includes(index):
                    self.listbox.selection_clear(index)
                else:
                    self.listbox.selection_set(index)
                self.listbox.yview(index)
                self.listbox.update()
        except AttributeError:
            self.show_warning('Invert Selection')

    # Move to Trash
    def mvsh_cmd(self, *args):
        try:
            os.remove(self._ext.input)
        except FileNotFoundError:
            pass
        except AttributeError:
            self.show_warning('Move to Trash')

    # Find
    def find_cmd(self, event=None, *, cmd=None):
        try:
            if cmd == 'next':
                pass
            elif cmd == 'prev':
                pass
            elif cmd == 'self':
                self.find_self()
            elif cmd == 'jump':
                self.find_jump()
            else:
                self._nindex = -1
                self._pindex = self.listbox.size()
                toplevel = Toplevel(self.master)

                frame = Frame(toplevel, bd=4)
                frame.pack()

                var = StringVar()
                var.trace_add('write', lambda name, index, mode, var=var: var.get())

                entry = Entry(frame, textvariable=var, font=('Courier New', 12))
                entry.pack(side=LEFT)

                button_next = Button(frame,
                        text='Next',
                        font=('Courier New', 12),
                        command=functools.partial(self.find_next, var)
                )
                button_next.pack(side=RIGHT)

                button_prev = Button(frame,
                        text='Previous',
                        font=('Courier New', 12),
                        command=functools.partial(self.find_prev, var)
                )
                button_prev.pack(side=RIGHT)
        except AttributeError:
            self.show_warning('Find')

    # Find Next
    def find_next(self, text):
        if text.__class__.__name__ == 'StringVar':
            text = text.get()

        if self._nindex >= 0:
            self.listbox.selection_clear(self._nindex)
            self.listbox.update()

        if self._nindex >= self.listbox.size():
            self._nindex = -1

        for index in range(self._nindex+1, self.listbox.size()):
            if text in self.listbox.get(index):
                self.listbox.selection_set(index)
                self.listbox.yview(index)
                self.listbox.update()
                self._nindex = index
                break
        else:
            if self._nindex == -1:
                showerror(
                    'Find nothing...',
                    "No result on '{text}'.".format(text=text)
                )
            else:
                self._nindex = -1
                self.find_next(text)

    # Find Previous
    def find_prev(self, text):
        if text.__class__.__name__ == 'StringVar':
            text = text.get()

        if self._pindex < self.listbox.size():
            self.listbox.selection_clear(self._pindex)
            self.listbox.update()

        if self._pindex <= 0:
            self._pindex = -1

        for index in range(self._pindex-1, -1, -1):
            if text in self.listbox.get(index):
                self.listbox.selection_set(index)
                self.listbox.yview(index)
                self.listbox.update()
                self._index = index
                break
        else:
            if self._pindex == 0:
                showinfo(
                    'Find nothing...',
                    "No result on '{text}'.".format(text=text)
                )
            else:
                self._pindex = self.listbox.size()
                self.find_prev(text)

    # Use Selection for Find
    def find_self(self):
        flag = False
        for index in range(self.listbox.size()):
            if self.listbox.selection_includes(index):
                if flag:
                    showerror(
                        'Unsupported Operation',
                        "'Use Selection for Find' must be one line."
                    )
                    return
                text = self.listbox.get(index)
                flag = True

        toplevel = Toplevel(self.master)

        frame = Frame(toplevel, bd=4)
        frame.pack()

        label = Label(frame, text=text, font=('Courier New', 12))
        label.pack(side=LEFT)

        button_next = Button(frame,
                text='Next',
                font=('Courier New', 12),
                command=functools.partial(self.find_next, text)
        )
        button_next.pack(side=RIGHT)

        button_prev = Button(frame,
                text='Previous',
                font=('Courier New', 12),
                command=functools.partial(self.find_prev, text)
        )
        button_prev.pack(side=RIGHT)

    # Jump to Selection
    def find_jump(self):
        for index in range(self.listbox.size()):
            if self.listbox.selection_includes(index):
                break
        self.listbox.yview(index)
        self.listbox.update()

    # Go
    def goto_cmd(self, event=None, *, cmd=None):
        try:
            for index in range(self.listbox.size()):
                if self.listbox.selection_includes(index):
                    self.listbox.selection_clear(index)
                    break
            else:
                index = 0
        except AttributeError:
            self.show_warning('Go')
            return

        if cmd == 'up':
            self.goto_up(index)
        elif cmd == 'down':
            self.goto_down(index)
        elif cmd == 'pre':
            self.goto_prev(index)
        elif cmd == 'next':
            self.goto_next(index)
        elif cmd == 'go':
            self.goto_go()
        elif cmd == 'back':
            self.goto_back(index)
        elif cmd == 'fwd':
            self.goto_fwd(index)
        else:
            pass

    # Up
    def goto_up(self, index):
        if index <= 0:
            index = self.listbox.size() + 1
        self.listbox.selection_set(index - 1)
        self.listbox.yview(index - 1)
        self.listbox.update()

    # Down
    def goto_down(self, index):
        if index + 1 >= self.listbox.size():
            index = -1
        self.listbox.selection_set(index + 1)
        self.listbox.yview(index + 1)
        self.listbox.update()

    # Previous Frame
    def goto_prev(self, index):
        tmp = self.goto_back(index)
        if tmp is None:
            return

        for tmp in range(tmp+1, self.listbox.size()):
            if 'Frame' not in self.listbox.get(index):
                self.listbox.selection_set(tmp)
                self.listbox.update()
                break

    # Next Frame
    def goto_next(self, index):
        tmp = self.goto_fwd(index)
        if tmp is None:
            return

        for tmp in range(tmp+1, self.listbox.size()):
            if 'Frame' not in self.listbox.get(index):
                self.listbox.selection_set(tmp)
                self.listbox.update()
                break

    # Go to Frame...
    def goto_go(self):
        toplevel = Toplevel(self.master)

        frame = Frame(toplevel, bd=4)
        frame.pack()

        label = Label(frame, text='Frame ', font=('Courier New', 12))
        label.pack(side=LEFT)

        var = StringVar()
        var.trace_add('write', lambda name, index, mode, var=var: var.get())

        entry = Entry(frame, textvariable=var, font=('Courier New', 12))
        entry.pack(side=LEFT)

        button = Button(frame,
            text='Go',
            font=('Courier New', 12),
            command=functools.partial(self.goto_frame, var, window=toplevel)
        )
        button.pack(side=RIGHT)

    def goto_frame(self, var, *, window):
        index = int(var.get())
        if (not isinstance(index, int)) or index < 1:
            showerror(
                'Unsupported Input',
                'Frame number must be a positive integer.'
            )
            window.destroy()
            self.goto_go()

        frame = 'Frame {index}'.format(index=index)
        for tmp in range(self.listbox.size()):
            if frame in self.listbox.get(tmp):
                self.listbox.yview(tmp)
                self.listbox.update()
                break
        else:
            showerror(
                'Not Found',
                "No frame ranged '{index}'.".format(index=index)
            )
        window.destroy()

    # Back
    def goto_back(self, index):
        if index <= 0:
            index = self.listbox.size() - 1
        for tmp in range(index-1, 0, -1):
            if 'Frame' in self.listbox.get(index) \
                or 'Global Header' in self.listbox.get(index):
                self.listbox.selection_set(tmp)
                self.listbox.yview(tmp)
                self.listbox.update()
                break
        else:
            showwarning(
                'Hit the math.ceil!',
                'No frame in the front.'
            )
            return
        return tmp

    # Forward
    def goto_fwd(self, index):
        if index >= self.listbox.size() - 1:
            index = -1
        for tmp in range(index+1, self.listbox.size()):
            if 'Frame' in self.listbox.get(index) \
                or 'Global Header' in self.listbox.get(index):
                self.listbox.selection_set(tmp)
                self.listbox.yview(tmp)
                self.listbox.update()
                break
        else:
            showwarning(
                'Hit the floor!',
                'No frame down below.'
            )
            return
        return tmp

    # Minimize
    def mini_cmd(self, *args):
        self.master.iconify()

    # Zoom
    def zoom_cmd(self):
        self.master.update()
        self.master.deiconify()

    # Search
    def srch_cmd(self):
        self.show_error('search')

    # PCAP Tree Viewer Help
    def help_cmd(self):
        toplevel = Toplevel(self.master)
        toplevel.title('PCAP Tree Viewer Help')
        scrolledtext = ScrolledText(
                toplevel, font=('Courier New', 12),
                width=57, height=20
        )
        scrolledtext.pack()
        try:
            with open('assets/manual', 'r') as file_:
                for line in file_:
                    scrolledtext.insert(END, line)
                    scrolledtext.update()
        except FileNotFoundError:
            showerror("Something's missing!", 'Unable to find MANUAL.')
            return
        scrolledtext.config(state=DISABLED)
        toplevel.resizable(width=False, height=False)

    # View on GitHub
    def repo_cmd(self):
        webbrowser.open('https://github.com/JarryShaw/jspcap/')

    ##########################################################################
    # Utilities.
    ##########################################################################

    def init_display(self):
        # scrollpad setup
        self.text = Text(
            self.frame, bd=0, font=('Courier New', 13),
            width=500, height=500
        )
        self.text.pack(side=LEFT, fill=BOTH)

        # start button setup
        self.button = Button(
            self.frame, text='Open ...',
            command=self.open_file, font=('Courier New', 13)
        )
        self.button.place(relx=0.5, rely=0.93, anchor=CENTER)
        try:
            with open('assets/init', 'r') as file_:
                for line in file_:
                    content = EMSP + line
                    self.text.insert(END, content)
                    self.text.update()
        except FileNotFoundError:
            showerror("Something's missing!", 'Unable to find README.')
            self.quit_cmd()
        self.text.config(state=DISABLED)

    def open_file(self, name=None):
        # remove cache
        open('assets/out', 'w').close()

        ifnm = name or askopenfilename(
            parent=self.master, title='Please select a file ...',
            filetypes=[('PCAP Files', '*.pcap'), ('All Files', '*.*')],
            initialdir='./', initialfile='in.pcap'
        )
        ifnm = ifnm.strip()

        if pathlib.Path(ifnm).is_file():
            try:
                self._ext = Extractor(fin=ifnm, fout='assets/out', fmt='tree', auto=False, extension=False)
            except FileError:
                showerror('Unsupported file format!', 'Please retry.')
                self.button.place()
                self.text.pack()
                return

            self.button.place_forget()
            self.text.pack_forget()

            try:
                self.listbox.pack_forget()
                self.scrollbar.pack_forget()
            except:
                pass
            self._frnum = 1

            self.keep_file(ifnm)
            self.load_file()
        else:
            if askokcancel('Unsupported file!', 'Please retry.'):
                self.open_file()
            else:
                self.button.place()
                self.text.pack()

    def load_file(self):
        # scrollpad setup
        self.scrollbar = Scrollbar(self.frame)
        self.scrollbar.pack(side=RIGHT, fill=Y)
        self.listbox = Listbox(self.frame, bd=0, font=('Courier New', 12),
                        width=500, height=500, yscrollcommand=self.scrollbar.set,
                        selectmode=EXTENDED, activestyle='none', takefocus=0
                    )
        self.listbox.pack(side=LEFT, fill=BOTH)
        self.scrollbar.config(command=self.listbox.yview)

        # loading label setup
        self.label = Label(self.frame, width=40, height=10, bd=4, anchor='w',
                        justify=LEFT, bg=BGCOLOUR, font=('Courier New', 22)
                    )
        self.label.place(relx=0.5, rely=0.5, anchor=CENTER)

        # extracting pcap file
        for frame in self._ext:
            content = NUMB(self._ext.length)
            self.label.config(text=content)
            self.label.update()

        time.sleep(0.3)

        # loading treeview
        percent = 0
        content = TEXT(percent)
        self.label.config(text=content)

        try:
            with open('assets/out', 'r') as fout:
                _ctr = 0
                for (_lctr, line) in enumerate(fout):
                    self.listbox.insert(END, line)
                    self.listbox.update()
                    self.listbox.yview(END)
                    self.listbox.selection_clear(0, _lctr)
                    if 'Frame' in line:
                        percent = 100.0 * _ctr / self.length
                        content = TEXT(percent)
                        self.label.config(text=content)
                        self.label.update()
                        _ctr += 1

            content = TEXT(100)
            self.label.config(text=content)
            self.label.update()

            # loading over
            time.sleep(0.7)
            self.listbox.yview(0)
            self.label.place_forget()
        except FileNotFoundError:
            showerror("Something's missing!", 'Unable to find REPORT.')
            self.open_file(self._ext.input)

    def keep_file(self, name):
        records = []
        try:
            with open('assets/recent', 'r') as file_:
                for line in file_:
                    records.append(line.strip())
        except FileNotFoundError:
            open('assets/recent', 'w').close()

        try:
            index = records.index(name)
        except ValueError:
            index = 0
            if len(records) >= 10:
                records.pop()
        else:
            records.pop(index)
        finally:
            records.insert(0, name)

        with open('assets/recent', 'w') as file_:
            record = '\n'.join(records)
            file_.write(record)

    def save_file(self, fmt=None):
        if fmt.__class__.__name__ == 'StringVar':
            fmt = fmt.get()

        try:
            tmp = self._ext
        except AttributeError:
            self.show_warning('Export')
            return

        if fmt is None or fmt == 'pdf' or fmt == 'tree':
            dfext = '.pdf' if fmt == 'pdf' else '.txt'
            file_ = asksaveasfilename(
                parent=self.master, title='Please select a directory ...',
                initialdir='./', defaultextension=dfext
            )
            if file_:
                if fmt == 'pdf':
                    process = subprocess.Popen(
                                    ['pandoc', 'assets/out', '-o', file_],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                                )
                    output, error = process.communicate()
                    if process.returncode:
                        showerror('Unable to export PDF', error.decode(shcoding))
                    else:
                        showinfo('Export done.', "File stored in '{dir}'.".format(dir=file_))
                else:
                    try:
                        shutil.copyfile('assets/out', file_)
                    except FileNotFoundError:
                        showerror('Unable to export.', 'Report file is missing.')
                    else:
                        showinfo('Export done.', "File stored in '{dir}'.".format(dir=file_))
        elif fmt == 'json':
            self.expt_file(fmt)
        elif fmt == 'plist':
            self.expt_file(fmt)
        else: # fmt == 'print'
            self.show_error('print')

    def expt_file(self, fmt):
        file_ = asksaveasfilename(
            parent=self.master, title='Please select a directory ...',
            initialdir='./', defaultextension='.{fmt}'.format(fmt=fmt)
        )
        if file_:
            try:
                ext = Extractor(fmt=fmt, fin=self._ext.input, fout=file_, auto=False)
            except FileNotFoundError:
                showerror('Unable to export.', "Original file '{}' is missing.".format(self._ext.input))
            else:
                # loading label setup
                self.label = Label(self.frame, width=40, height=10, bd=4, anchor='w',
                                justify=LEFT, bg=BGCOLOUR, font=('Courier New', 22)
                            )
                self.label.place(relx=0.5, rely=0.5, anchor=CENTER)

                # extracting pcap file
                for frame in ext:
                    percent = 100.0 * ext.length / self.length
                    content = EXPT(percent)
                    self.label.config(text=content)
                    self.label.update()

                time.sleep(0.5)
                self.label.place_forget()
                showinfo('Export done.', "File stored in '{dir}'.".format(dir=file_))

    def show_error(self, error):
        showerror(
            'Unable to {error}...'.format(error=error),
            'Heilige, Scheiße! Not implemented yet.'
        )

    def show_warning(self, warning):
        showwarning(
            "Disabled command '{warning}'...".format(warning=warning),
            'Níam olc! Wrong time to call me.'
        )


if __name__ == '__main__':
    Display()
