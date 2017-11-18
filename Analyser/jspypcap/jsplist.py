#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import textwrap

# Writer for PLIST files
# Dump a macOS Property List file

FMT_XML = None
HEADERS = '''\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
'''
HEADERE = '''\
</dict>
</plist>
'''

# list     = ['<array>', '</array>']
# dict     = ['<dict>', '</dict>']
# str      = ['<string>', '</string>']
# bytes    = ['<data>', '</data>']
# datetime = ['<date>', '</date>']
# int      = ['<integer>', '</integer>']
# float    = ['<real>', '</real>']
# bool     = ['<true/>', '<false/>']


class Writer:

    def __init__(self, fname):
        self._tctr = 1              # counter for tab level
        self._file = fname          # .plist file name
        self._sptr = os.SEEK_SET    # seek pointer

        self._magic_types = dict(
            list     = lambda text, file_: self._append_array(text, file_),
            dict     = lambda text, file_: self._append_dict(text, file_),
            str      = lambda text, file_: self._append_string(text, file_),
            bytes    = lambda text, file_: self._append_data(text, file_),
            datetime = lambda text, file_: self._append_date(text, file_),
            int      = lambda text, file_: self._append_integer(text, file_),
            float    = lambda text, file_: self._append_real(text, file_),
            bool     = lambda text, file_: self._append_bool(text, file_),
        )

        self.plist_header()

    def __call__(self, value, *, _name=None):
        with open(self._file, 'r+') as _file:
            self.append_value(value, _file, _name)
            self._sptr = _file.tell()
            _file.write(HEADERE)

    def plist_header(self):
        with open(self._file, 'w') as _file:
            _file.write(HEADERS)
            self._sptr = _file.tell()
            _file.write(HEADERE)

    def append_value(self, value, _file, _name):
        _tabs = '\t' * self._tctr
        _keys = '{tabs}<key>{name}</key>\n'.format(tabs=_tabs, name=_name)
        _file.seek(self._sptr, os.SEEK_SET)
        _file.write(_keys)

        self._append_dict(value, _file)

    def _append_array(self, value, _file):
        _tabs = '\t' * self._tctr
        _labs = '{tabs}<array>\n'.format(tabs=_tabs)
        _file.write(_labs)
        self._tctr += 1

        for _item in value:
            if _item is None:   continue
            _type = type(_item).__name__
            self._magic_types[_type](_item, _file)

        self._tctr -= 1
        _tabs = '\t' * self._tctr
        _labs = '{tabs}</array>\n'.format(tabs=_tabs)
        _file.write(_labs)

    def _append_dict(self, value, _file):
        _tabs = '\t' * self._tctr
        _labs = '{tabs}<dict>\n'.format(tabs=_tabs)
        _file.write(_labs)
        self._tctr += 1

        for _item in value:
            _text = value[_item]
            if _text is None:   continue

            _tabs = '\t' * self._tctr
            _keys = '{tabs}<key>{item}</key>\n'.format(tabs=_tabs, item=_item)
            _file.write(_keys)

            _type = type(_text).__name__
            self._magic_types[_type](_text, _file)

        self._tctr -= 1
        _tabs = '\t' * self._tctr
        _labs = '{tabs}</dict>\n'.format(tabs=_tabs)
        _file.write(_labs)

    def _append_string(self, value, _file):
        _tabs = '\t' * self._tctr
        _text = value
        _labs = '{tabs}<string>{text}</string>\n'.format(tabs=_tabs, text=_text)
        _file.write(_labs)

    def _append_data(self, value, _file):
        # binascii.b2a_base64(value) -> plistlib.Data
        # binascii.a2b_base64(Data) -> value(bytes)

        _tabs = '\t' * self._tctr
        _text = ' '.join(textwrap.wrap(value.hex(), 2))
        # _data = [H for H in iter(
        #         functools.partial(io.StringIO(value.hex()).read, 2), '')
        #         ]  # to split bytes string into length-2 hex string list
        _labs = '{tabs}<data>\n{tabs}{text}\n{tabs}</data>\n'.format(tabs=_tabs, text=_text)
        _file.write(_labs)

    def _append_date(self, value, _file):
        _tabs = '\t' * self._tctr
        _text = value.strftime('%Y-%m-%dT%H:%M:%SZ')
        _labs = '{tabs}<date>{text}</date>\n'.format(tabs=_tabs, text=_text)
        _file.write(_labs)

    def _append_integer(self, value, _file):
        _tabs = '\t' * self._tctr
        _text = value
        _labs = '{tabs}<integer>{text}</integer>\n'.format(tabs=_tabs, text=_text)
        _file.write(_labs)

    def _append_real(self, value, _file):
        _tabs = '\t' * self._tctr
        _text = value
        _labs = '{tabs}<real>{text}</real>\n'.format(tabs=_tabs, text=_text)
        _file.write(_labs)

    def _append_bool(self, value, _file):
        _tabs = '\t' * self._tctr
        _text = '<true/>' if value else '<false/>'
        _labs = '{tabs}{text}\n'.format(tabs=_tabs, text=_text)
        _file.write(_labs)
