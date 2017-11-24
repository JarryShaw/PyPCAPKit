#!/usr/bin/python3
# -*- coding: utf-8 -*-


import collections
import os
import textwrap


# Writer for treeview text files
# Dump a TEXT file for PCAP analyser


from .dumper import Dumper


HEADER_START = 'PCAP File Tree-View Format\n'
HEADER_END = ''

TEMP_BRANCH = '  |   '
TEMP_SPACES = '      '

MAGIC_TYPES = dict(
    dict = lambda self_, text, file_: self_._append_branch(text, file_),    # branch
    list = lambda self_, text, file_: self_._append_list(text, file_),      # array
    tuple = lambda self_, text, file_: self_._append_tuple(text, file_),    # array
    str = lambda self_, text, file_: self_._append_string(text, file_),     # string
    bytes = lambda self_, text, file_: self_._append_bytes(text, file_),    # string
    datetime = lambda self_, text, file_: self_._append_date(text, file_),  # string
    int = lambda self_, text, file_: self_._append_number(text, file_),     # number
    float = lambda self_, text, file_: self_._append_number(text, file_),   # number
    bool = lambda self_, text, file_: self_._append_bool(text, file_),      # True | False
    NoneType = lambda self_, text, file_: self_._append_none(text, file_),  # N/A
)


class Tree(Dumper):
    """Tree-view Format

    value   ::=  branch | array | string | number | bool | N/A

    string
      |-- string
      |     |-- string -> value
      |     |-- string
      |     |     |-- string -> value
      |     |     |-- string -> value
      |     |-- string -> value
      |     |-- string -> value
      |           |-- string -> value
      |           |-- string -> value
      |-- string -> value, value, value
      |-- string -> True
      |-- string -> False
      |-- string -> N/A
      |-- string -> value
      |-- string -> value

    """
    _tctr = -1
    _hsrt = HEADER_START
    _hend = HEADER_END

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def kind(self):
        return 'txt'

    ##########################################################################
    # Utilities.
    ##########################################################################

    def append_value(self, value, _file, _name):
        _keys = '\n' + _name + '\n'
        _file.seek(self._sptr, os.SEEK_SET)
        _file.write(_keys)

        self._bctr = collections.defaultdict(int)    # blank branch counter dict
        self._append_branch(value, _file)

    def _append_list(self, value, _file):
        for (_nctr, _item) in enumerate(value):
            _cmma = ',' if _nctr else ''
            _file.write(_cmma)

            _type = type(_item).__name__
            MAGIC_TYPES[_type](self, _item, _file)

    def _append_tuple(self, value, _file):
        _tabs = ''
        for _ in range(self._tctr + 1):
            _tabs += TEMP_SPACES if self._bctr[_] else TEMP_BRANCH

        _tlen = len(value) - 1
        for (_nctr, _item) in enumerate(value):
            _bptr = '  |-->'
            _text = '{tabs}{bptr}'.format(tabs=_tabs, bptr=_bptr)
            _file.write(_text)

            _type = type(_item).__name__
            MAGIC_TYPES[_type](self, _item, _file)

            _suff = '\n' if _nctr < _tlen else ''
            _file.write(_suff)

    def _append_branch(self, value, _file):
        self._tctr += 1

        _vlen = len(value)
        for (_vctr, (_item, _text)) in enumerate(value.items()):
            _type = type(_text).__name__
            if _type == 'dict' or _type == 'tuple' or \
                    (_type == 'bytes' and len(_text) > 16):
                _pref = '\n'
            else:
                _pref = ' ->'

            _labs = ''
            for _ in range(self._tctr):
                _labs += TEMP_SPACES if self._bctr[_] else TEMP_BRANCH
            if _vctr == _vlen - 1:
                self._bctr[self._tctr] = 1

            _keys = '{labs}  |-- {item}{pref}'.format(labs=_labs, item=_item, pref=_pref)
            _file.write(_keys)

            MAGIC_TYPES[_type](self, _text, _file)

            _suff = '' if _type == 'dict' else '\n'
            _file.write(_suff)

        self._bctr[self._tctr] = 0
        self._tctr -= 1

    def _append_string(self, value, _file):
        _text = value
        _labs = ' {text}'.format(text=_text)
        _file.write(_labs)

    def _append_bytes(self, value, _file):
        # binascii.b2a_base64(value) -> plistlib.Data
        # binascii.a2b_base64(Data) -> value(bytes)

        if len(value) > 16:
            _tabs = ''
            for _ in range(self._tctr + 1):
                _tabs += TEMP_SPACES if self._bctr[_] else TEMP_BRANCH

            _list = []
            for (_ictr, _item) in enumerate(textwrap.wrap(value.hex(), 32)):
                _bptr = '       ' if _ictr else '  |--> '
                _text = ' '.join(textwrap.wrap(_item, 2))
                _item = '{tabs}{bptr}{text}'.format(tabs=_tabs, bptr=_bptr, text=_text)
                _list.append(_item)
            _labs = '\n'.join(_list)
        else:
            _text = ' '.join(textwrap.wrap(value.hex(), 2))
            _labs = ' {text}'.format(text=_text)
        _file.write(_labs)

    def _append_date(self, value, _file):
        _text = value.strftime('%Y-%m-%d %H:%M:%S')
        _labs = ' {text}'.format(text=_text)
        _file.write(_labs)

    def _append_number(self, value, _file):
        _text = value
        _labs = ' {text}'.format(text=_text)
        _file.write(_labs)

    def _append_bool(self, value, _file):
        _text = 'True' if value else 'False'
        _labs = ' {text}'.format(text=_text)
        _file.write(_labs)

    def _append_none(self, value, _file):
        _text = 'N/A'
        _labs = ' {text}'.format(text=_text)
        _file.write(_labs)
