#!/usr/bin/python3
# -*- coding: utf-8 -*-


from analyser import Analyser
from math import ceil, floor
from os import remove
from tkinter import *
from time import sleep

'          Loading ... {:>2.2f}%\n\n{sharp}{space}\n'

TEXT = lambda percent: '''

          Loading... {:>2.2f}%

     {sharp}{space}

'''.format(
    percent, sharp = '#' * ceil(28 * percent / 100), space = ' ' * floor(28 * percent / 100)
)


def display(fin=None):

    extractor = Analyser(fin=fin)

    master = Tk()
    master.title('PCAP Tree View')
    master.geometry("674x444")
    master.resizable(width=False,height=False)

    frame = Frame(bd=8)
    frame.pack()

    scrollbar = Scrollbar(frame)
    scrollbar.pack(side=RIGHT, fill=Y)

    listbox = Listbox(frame, bd=0, font=('Courier New', 12),
                    width=500, height=500, yscrollcommand=scrollbar.set,
                    selectmode=EXTENDED, activestyle='none', takefocus=0
                )
    listbox.pack(side=LEFT, fill=BOTH)

    scrollbar.config(command=listbox.yview)

    label = Label(frame, width=40, height=10, font=('Courier New', 22), bd=4, anchor='w', justify=LEFT, bg='green')
    # label.place(x=60, y=150)
    label.place(relx=0.5, rely=0.5, anchor=CENTER)
    percent = 0
    content = TEXT(percent)
    label.config(text=content)
    # text = canvas.create_text(content, 0.5, 0.5, justify=CENTER)

    with open('out') as fout:
        # master.title('PCAP Tree View ... |')
        _ctr = 0
        for (_lctr, line) in enumerate(fout.readlines()):
            listbox.insert(END, line)
            listbox.update()
            listbox.yview(END)
            listbox.selection_clear(0, _lctr)
            if 'Frame' in line:
                _ctr += 1
                percent = 100.0 * _ctr / extractor.length
                content = TEXT(percent)
                # print(content)
                label.config(text=content)
            # if _lctr % 10 == 0:
                # _text = ''[_lctr // 10 % 4]
                # master.title('PCAP Tree View ... {text}'.format(text=_text))
    content = TEXT(100)
    # print(content)
    label.config(text=content)
    label.update()
    remove('out')

    sleep(2)
    listbox.yview(0)
    label.place_forget()

    mainloop()


if __name__ == '__main__':
    fin = input('Please input the name of pcap file: ')
    display(fin)
