#!/usr/bin/python3
# -*- coding: utf-8 -*-


from analyser import Analyser
from math import ceil
from os import remove
from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import askokcancel
from time import sleep


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
        self.master.title('PCAP Tree View')
        self.master.geometry("674x444")
        self.master.resizable(width=False,height=False)

        # frame setup
        self.frame = Frame(bd=8)
        self.frame.pack()

        # menu setup
        self.menu = Menu(self.master)

        self.init()
        self.master.mainloop()

    ##########################################################################
    # Methods.
    ##########################################################################

    def init(self):
        # scrollpad setup
        self.listbox = Listbox(self.frame, bd=0, font=('Courier New', 12),
                        width=500, height=500, selectmode=EXTENDED,
                        activestyle='none', takefocus=0
                    )
        self.listbox.pack(side=LEFT, fill=BOTH)

        # start button setup
        self.button = Button(self.frame, text='Open ...', command=self.open, font=('Courier New', 16))
        self.button.place(relx=0.8, rely=0.8, anchor=CENTER)

        with open('init') as file_:
            for line in file_.readlines():
                self.listbox.insert(END, line)
                self.listbox.update()

    def load(self):
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

    def open(self):
        self.button.place_forget()
        ifnm = askopenfilename(
                parent=self.master, title='Please select a file ...',
                filetypes=[('PCAP Files', '*.pcap'), ('All Files', '*.*')],
                initialdir='./', initialfile='in.pcap')

        try:
            self._ifile = open(ifnm, 'rb')
            self.record_header(self._ifile)      # read PCAP global header
            self.listbox.pack_forget()
            self.load()
        except IOError:
            if askokcancel('Unsupported file!', 'Please retry.'):
                self.open()
            else:
                self.root.destroy()

    def save(self):
        pass


if __name__ == '__main__':
    Display()
