#!/usr/bin/python3
# -*- coding: utf-8 -*-


import collections
import os
import textwrap


# Writer for treeview text files
# Dump a TEXT file for PCAP analyser


from .dumper import Dumper


HEADER_START = 'PCAP File Tree-View Format\n'
HEADER_END = ' '

TEMP_BRANCH = '  |   '
TEMP_SPACES = '      '

MAGIC_TYPES = dict(
    dict = lambda self, text, file: self._append_branch(text, file),    # branch
    Info = lambda self, text, file: self._append_branch(text, file),    # branch
    list = lambda self, text, file: self._append_array(text, file),     # array
    tuple = lambda self, text, file: self._append_array(text, file),    # array
    str = lambda self, text, file: self._append_string(text, file),     # string
    bytes = lambda self, text, file: self._append_bytes(text, file),    # string
    datetime = lambda self, text, file: self._append_date(text, file),  # string
    int = lambda self, text, file: self._append_number(text, file),     # number
    float = lambda self, text, file: self._append_number(text, file),   # number
    bool = lambda self, text, file: self._append_bool(text, file),      # True | False
    NoneType = lambda self, text, file: self._append_none(text, file),  # N/A
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

    def _append_array(self, value, _file):
        if not value:
            self._append_none(None, _file)

        _bptr = ''
        _tabs = ''
        _tlen = len(value) - 1
        if _tlen:
            _bptr = '  |-->'
            for _ in range(self._tctr + 1):
                _tabs += TEMP_SPACES if self._bctr[_] else TEMP_BRANCH

        for (_nctr, _item) in enumerate(value):
            _text = '{tabs}{bptr}'.format(tabs=_tabs, bptr=_bptr)
            _file.write(_text)

            _type = type(_item).__name__
            MAGIC_TYPES[_type](self, _item, _file)

            _suff = '\n' if _nctr < _tlen else ''
            _file.write(_suff)

    def _append_branch(self, value, _file):
        if not value:
            self._append_none(None, _file)

        self._tctr += 1
        _vlen = len(value)
        for (_vctr, (_item, _text)) in enumerate(value.items()):
            _type = type(_text).__name__

            flag_dict = (_type == 'dict')
            flag_tuple = (_type == 'tuple' and len(_text) > 1)
            flag_bytes = (_type == 'bytes' and len(_text) > 16)
            if any((flag_dict, flag_tuple, flag_bytes)):
                _pref = '\n'
            else:
                _pref = ' ->'

            _labs = ''
            for _ in range(self._tctr):
                _labs += TEMP_SPACES if self._bctr[_] else TEMP_BRANCH

            _keys = '{labs}  |-- {item}{pref}'.format(labs=_labs, item=_item, pref=_pref)
            _file.write(_keys)

            if _vctr == _vlen - 1:
                self._bctr[self._tctr] = 1

            MAGIC_TYPES[_type](self, _text, _file)

            _suff = '' if _type == 'dict' else '\n'
            _file.write(_suff)

        self._bctr[self._tctr] = 0
        self._tctr -= 1

    def _append_string(self, value, _file):
        if not value:
            self._append_none(None, _file)

        _text = value
        _labs = ' {text}'.format(text=_text)
        _file.write(_labs)

    def _append_bytes(self, value, _file):
        # binascii.b2a_base64(value) -> plistlib.Data
        # binascii.a2b_base64(Data) -> value(bytes)
        if not value:
            self._append_none(None, _file)

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
