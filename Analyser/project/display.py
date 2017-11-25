#!/usr/bin/python3
# -*- coding: utf-8 -*-


from analyser import Analyser
from functools import partial
from math import ceil
from os import remove
from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import askokcancel
from time import sleep
from sys import platform


# Platform specific settings
macOS = (platform == 'darwin')
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

NUMB = lambda number: '''

       Extracting... Frame {:>2d}

'''.format(number)

TEXT = lambda percent: '''

          Loading... {:>2.2f}%

   +------------------------------+
   |{sharp}{space}|
   +------------------------------+

'''.format(percent,
    sharp = '#' * ceil(30 * percent / 100),
    space = ' ' * (30 - ceil(30 * percent / 100))
)


class Display(Analyser):

    ##########################################################################
    # Data modules.
    ##########################################################################

    def __init__(self):
        # root window setup
        self.master = Tk()
        self.master.title('PCAP Tree Viewer')
        self.master.geometry('674x476')
        self.master.resizable(width=False, height=False)

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
        self.master.bind(event(cmdbd, 'H'), self.hide_cmd)
        home_menu.add_command(label='Hide Others', command=self.wipe_cmd, accelerator=short(optkw, cmdkw, 'Ｈ'))
        self.master.bind(event(optbd, cmdbd, 'H'), self.wipe_cmd)
        home_menu.add_command(label='Show All', command=self.show_cmd)
        home_menu.add_separator()
        home_menu.add_command(label='Quit PCAP Tree Viewer', command=self.quit_cmd, accelerator=short(cmdkw, 'Ｑ'))
        self.master.bind(event(cmdbd, 'Q'), self.quit_cmd)

        # file menu
        file_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='File', menu=file_menu)
        file_menu.add_command(label='Open...', command=self.open_cmd, accelerator=short(cmdkw, 'Ｏ'))
        self.master.bind(event(cmdbd, 'O'), self.open_cmd)
        frct_menu = Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label='Open Recent', menu=frct_menu)
        try:
            with open('recent') as file_:
                file_real = False
                for file_name in file_.readlines():
                    file_real = True if file_name else False
                    frct_menu.add_command(label=file_name, command=partial(self.open_cmd, file_name))
        except Exception:
            file_real = False
        if file_real:
            frct_menu.add_separator()
            frct_menu.add_command(label='Clear Menu', command=self.rmrf_cmd)
        else:
            frct_menu.add_command(label='Clear Menu', state='disabled')
        file_menu.add_separator()
        file_menu.add_command(label='Close Window', command=self.shut_cmd, accelerator=short(cmdkw, 'Ｗ'))
        self.master.bind(event(cmdbd, 'W'), self.shut_cmd)
        file_menu.add_command(label='Save', command=self.save_cmd, accelerator=short(cmdkw, 'Ｓ'))
        self.master.bind(event(cmdbd, 'S'), self.save_cmd)
        file_menu.add_command(label='Duplicate', command=self.copy_cmd, accelerator=short(sftkw, cmdkw, 'Ｓ'))
        self.master.bind(event(sftbd, cmdbd, 'S'), self.copy_cmd)
        file_menu.add_command(label='Rename...', command=self.mvrn_cmd)
        file_menu.add_command(label='Move To...', command=self.move_cmd)
        file_menu.add_command(label='Export...', command=self.expt_cmd)
        file_menu.add_command(label='Export as PDF...', command=partial(self.expt_cmd, 'pdf'))
        file_menu.add_separator()
        file_menu.add_command(label='Print', command=self.expt_cmd, accelerator=short(cmdkw, 'Ｐ'))
        self.master.bind(event(cmdbd, 'P'), self.expt_cmd)

        # edit menu
        edit_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='Edit', menu=edit_menu)
        edit_menu.add_command(label='Copy', command=self.cmdc_cmd, accelerator=short(cmdkw, 'Ｃ'))
        self.master.bind(event(cmdbd, 'C'), self.cmdc_cmd)
        edit_menu.add_command(label='Select All', command=self.cmda_cmd, accelerator=short(cmdkw, 'Ａ'))
        self.master.bind(event(cmdbd, 'A'), self.cmda_cmd)
        edit_menu.add_command(label='Invert Selection', command=self.invt_cmd, accelerator=short(sftkw, cmdkw, 'Ｉ'))
        self.master.bind(event(sftbd, cmdbd, 'I'), self.invt_cmd)
        edit_menu.add_separator()
        edit_menu.add_command(label='Move to Trash', command=self.mvsh_cmd, accelerator=short(cmdkw, delkw))
        self.master.bind(event(cmdbd, delbd), self.mvsh_cmd)
        edit_menu.add_separator()
        find_menu = Menu(edit_menu, tearoff=0)
        edit_menu.add_cascade(label='Find', menu=find_menu)
        find_menu.add_command(label='Find...', command=self.find_cmd, accelerator=short(cmdkw, 'Ｆ'))
        self.master.bind(event(cmdbd, 'F'), self.find_cmd)
        find_menu.add_command(label='Find Next', command=partial(self.find_cmd, 'next'), accelerator=short(cmdkw, 'Ｇ'))
        self.master.bind(event(cmdbd, 'G'), partial(self.find_cmd, 'next'))
        find_menu.add_command(label='Find Previous', command=partial(self.find_cmd, 'pre'), accelerator=short(sftkw, cmdkw, 'Ｇ'))
        self.master.bind(event(sftbd, cmdbd, 'G'), partial(self.find_cmd, 'pre'))
        find_menu.add_command(label='Use Selection for Find', command=partial(self.find_cmd, 'self'), accelerator=short(cmdkw, 'Ｅ'))
        self.master.bind(event(cmdbd, 'E'), partial(self.find_cmd, 'self'))
        find_menu.add_command(label='Jump to Selection', command=partial(self.find_cmd, 'jump'), accelerator=short(cmdkw, 'Ｊ'))
        self.master.bind(event(cmdbd, 'J'), partial(self.find_cmd, 'jump'))

        # go menu
        goto_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='Go', menu=goto_menu)
        goto_menu.add_command(label='Up', command=partial(self.goto_cmd, 'up'), accelerator=short(upakw))
        self.master.bind(event(upabd), partial(self.goto_cmd, 'up'))
        goto_menu.add_command(label='Down', command=partial(self.goto_cmd, 'down'), accelerator=short(dwnkw))
        self.master.bind(event(dwnbd), partial(self.goto_cmd, 'down'))
        goto_menu.add_command(label='Previous Frame', command=partial(self.goto_cmd, 'pre'), accelerator=short(optkw, upakw))
        self.master.bind(event(optbd, upabd), partial(self.goto_cmd, 'pre'))
        goto_menu.add_command(label='Next Frame', command=partial(self.goto_cmd, 'next'), accelerator=short(optkw, dwnkw))
        self.master.bind(event(optbd, dwnbd), partial(self.goto_cmd, 'next'))
        goto_menu.add_command(label='Go to Frame...', command=partial(self.goto_cmd, 'go'), accelerator=short(optkw, cmdkw, 'Ｇ'))
        self.master.bind(event(optbd, cmdbd, 'G'), partial(self.goto_cmd, 'go'))
        goto_menu.add_separator()
        goto_menu.add_command(label='Back', command=partial(self.goto_cmd, 'back'), accelerator=short(cmdkw, brlkw))
        self.master.bind(event(cmdbd, brlbd), partial(self.goto_cmd, 'back'))
        goto_menu.add_command(label='Forward', command=partial(self.goto_cmd, 'fwd'), accelerator=short(cmdkw, brrkw))
        self.master.bind(event(cmdbd, brrbd), partial(self.goto_cmd, 'fwd'))

        # window menu
        wind_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='Window', menu=wind_menu)
        wind_menu.add_command(label='Minimize', command=self.mini_cmd, accelerator=short(cmdkw, 'Ｍ'))
        self.master.bind(event(cmdbd, 'M'), self.mini_cmd)
        wind_menu.add_command(label='Zoom', command=self.zoom_cmd)

        # help menu
        help_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label='Help', menu=help_menu)
        if not macOS:
            help_menu.add_command(label='Search', command=self.srch_cmd)
            help_menu.add_separator()
        help_menu.add_command(label='PCAP Tree Viewer Help', command=self.help_cmd)

    # About PCAP Tree Viewer
    def intr_cmd(self):
        pass

    # Preferences
    def pref_cmd(self, *args):
        print('called')

    # System Preferences...
    def sysp_cmd(self):
        pass

    # Hide PCAP Tree Viewer
    def hide_cmd(self):
        pass

    # Hide Others
    def wipe_cmd(self):
        pass

    # Show All
    def show_cmd(self):
        pass

    # Quit PCAP Tree Viewer
    def quit_cmd(self):
        pass

    # Open...
    def open_cmd(self, name=None):
        print('called')

    # Clear Menu
    def rmrf_cmd(self):
        pass

    # Close Window
    def shut_cmd(self):
        pass

    # Save
    def save_cmd(self):
        pass

    # Duplicate
    def copy_cmd(self):
        pass

    # Rename...
    def mvrn_cmd(self):
        pass

    # Move To...
    def move_cmd(self):
        pass

    # Export...
    def expt_cmd(self, fmt=None):
        pass

    # Copy
    def cmdc_cmd(self):
        pass

    # Select All
    def cmda_cmd(self):
        pass

    # Invert Selection
    def invt_cmd(self):
        pass

    # Move to Trash
    def mvsh_cmd(self):
        pass

    # Find
    def find_cmd(self, cmd=None):
        pass

    # Go
    def goto_cmd(self, cmd=None):
        pass

    # Minimize
    def mini_cmd(self):
        pass

    # Zoom
    def zoom_cmd(self):
        pass

    # Search
    def srch_cmd(self):
        pass

    # PCAP Tree Viewer Help
    def help_cmd(self):
        pass

    def init_display(self):
        # scrollpad setup
        self.listbox = Listbox(
            self.frame, bd=0, font=('Courier New', 12),
            width=500, height=500, selectmode=EXTENDED,
            activestyle='none', takefocus=0
        )
        self.listbox.pack(side=LEFT, fill=BOTH)

        # start button setup
        self.button = Button(
            self.frame, text='Open ...',
            command=self.open_file, font=('Courier New', 13)
        )
        self.button.place(relx=0.5, rely=0.93, anchor=CENTER)

        with open('init') as file_:
            for line in file_.readlines():
                self.listbox.insert(END, line)
                self.listbox.update()

    def open_file(self):
        self.button.place_forget()
        ifnm = askopenfilename(
            parent=self.master, title='Please select a file ...',
            filetypes=[('PCAP Files', '*.pcap'), ('All Files', '*.*')],
            initialdir='./', initialfile='in.pcap'
        )

        try:
            print(ifnm)
            self._ifile = open(ifnm, 'rb')
            self.record_header(self._ifile)      # read PCAP global header
            self.listbox.pack_forget()
            self.load_file()
        except Exception:
            if askokcancel('Unsupported file!', 'Please retry.'):
                self.open_file()
            else:
                self.master.destroy()

    def save_file(self):
        pass

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
                        justify=LEFT, bg='green', font=('Courier New', 22)
                    )
        self.label.place(relx=0.5, rely=0.5, anchor=CENTER)

        # extracting pcap file
        while True:
            try:
                self.record_frames(self._ifile)      # read frames
                content = NUMB(self.length - 1)
                self.label.config(text=content)
                self.label.update()
            except EOFError:
                break

        sleep(1)

        # loading treeview
        percent = 0
        content = TEXT(percent)
        self.label.config(text=content)

        with open('out') as fout:
            _ctr = 0
            for (_lctr, line) in enumerate(fout.readlines()):
                self.listbox.insert(END, line)
                self.listbox.update()
                self.listbox.yview(END)
                self.listbox.selection_clear(0, _lctr)
                if 'Frame' in line:
                    _ctr += 1
                    percent = 100.0 * _ctr / self.length
                    content = TEXT(percent)
                    self.label.config(text=content)
                    self.label.update()

        content = TEXT(100)
        self.label.config(text=content)
        self.label.update()
        remove('out')

        # loading over
        sleep(2)
        self.listbox.yview(0)
        self.label.place_forget()


if __name__ == '__main__':
    Display()
