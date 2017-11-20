#!/usr/bin/python3
# -*- coding: utf-8 -*-


from analyser import Analyser
from os import remove
from tkinter import mainloop, BOTH, END, LEFT, RIGHT, Y, \
                    Frame, Listbox, Scrollbar, Tk


def display(fin=None):

    extractor = Analyser(fin=fin)

    master = Tk()
    master.title('PCAP Tree View')
    master.geometry("670x443")

    frame = Frame(bd=8)
    frame.pack()

    scrollbar = Scrollbar(frame)
    scrollbar.pack(side=RIGHT, fill=Y)

    listbox = Listbox(frame, bd=0, font=('Courier New', 12),
                    width=500, height=500, yscrollcommand=scrollbar.set
                )

    with open('out') as fout:
        for line in fout.readlines():
            listbox.insert(END, line)
    remove('out')

    listbox.pack(side=LEFT, fill=BOTH)

    scrollbar.config(command=listbox.yview)

    mainloop()


if __name__ == '__main__':
    fin = input('Please input the name of pcap file: ')
    display(fin)
