#!/usr/bin/python3
# -*- coding: utf-8 -*-


import collections
import os
import textwrap


# Writer for JSON files
# Dump a JSON file for PCAP analyser


from .dumper import Dumper


HEADER_START = '{\n'

HEADER_END = '\n}'

MAGIC_TYPES = dict(
    str = lambda self, text, file: self._append_string(text, file),     # string
    bytes = lambda self, text, file: self._append_bytes(text, file),    # string
    datetime = lambda self, text, file: self._append_date(text, file),  # string
    int = lambda self, text, file: self._append_number(text, file),     # number
    float = lambda self, text, file: self._append_number(text, file),   # number
    dict = lambda self, text, file: self._append_object(text, file),    # object
    Info = lambda self, text, file: self._append_object(text, file),    # object
    list = lambda self, text, file: self._append_array(text, file),     # array
    tuple = lambda self, text, file: self._append_array(text, file),    # array
    bool = lambda self, text, file: self._append_bool(text, file),      # true | false
    NoneType = lambda self, text, file: self._append_none(text, file),  # null
)


class JSON(Dumper):
    """JavaScript Object Notation (JSON) Format

    object    ::=  "{}" | ("{" members "}")
    members   ::=  pair | (pair "," members)
    pair      ::=  string ":" value
    array     ::=  "[]" | ("[" elements "]")
    elements  ::=  value | (value "," elements)
    value     ::=  string | number | object
                     | array | true | false | null

    """
    _hsrt = HEADER_START
    _hend = HEADER_END
    _vctr = collections.defaultdict(int)    # value counter dict

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def kind(self):
        return 'json'

    ##########################################################################
    # Utilities.
    ##########################################################################

    def append_value(self, value, _file, _name):
        _tabs = '\t' * self._tctr
        _cmma = ',\n' if self._vctr[self._tctr] else ''
        _keys = '{cmma}{tabs}"{name}" :'.format(cmma=_cmma, tabs=_tabs, name=_name)

        _file.seek(self._sptr, os.SEEK_SET)
        _file.write(_keys)

        self._vctr[self._tctr] += 1
        self._append_object(value, _file)

    def _append_array(self, value, _file):
        _labs = ' ['
        _file.write(_labs)

        self._tctr += 1

        for _item in value:
            _cmma = ',' if self._vctr[self._tctr] else ''
            _file.write(_cmma)

            self._vctr[self._tctr] += 1

            _type = type(_item).__name__
            MAGIC_TYPES[_type](self, _item, _file)

        self._vctr[self._tctr] = 0
        self._tctr -= 1

        _labs = ' ]'
        _file.write(_labs)

    def _append_object(self, value, _file):
        _labs = ' {'
        _file.write(_labs)
        self._tctr += 1

        for (_item, _text) in value.items():
            _tabs = '\t' * self._tctr
            _cmma = ',' if self._vctr[self._tctr] else ''
            _keys = '{cmma}\n{tabs}"{item}" :'.format(cmma=_cmma, tabs=_tabs, item=_item)
            _file.write(_keys)

            self._vctr[self._tctr] += 1

            _type = type(_text).__name__
            MAGIC_TYPES[_type](self, _text, _file)

        self._vctr[self._tctr] = 0
        self._tctr -= 1
        _tabs = '\t' * self._tctr
        _labs = '\n{tabs}{}'.format('}', tabs=_tabs)
        _file.write(_labs)

    def _append_string(self, value, _file):
        _text = value
        _labs = ' "{text}"'.format(text=_text)
        _file.write(_labs)

    def _append_bytes(self, value, _file):
        # binascii.b2a_base64(value) -> plistlib.Data
        # binascii.a2b_base64(Data) -> value(bytes)

        _text = ' '.join(textwrap.wrap(value.hex(), 2))
        # _data = [H for H in iter(
        #         functools.partial(io.StringIO(value.hex()).read, 2), '')
        #         ]  # to split bytes string into length-2 hex string list
        _labs = ' "{text}"'.format(text=_text)
        _file.write(_labs)

    def _append_date(self, value, _file):
        _text = value.strftime('%Y-%m-%dT%H:%M:%SZ')
        _labs = ' "{text}"'.format(text=_text)
        _file.write(_labs)

    def _append_number(self, value, _file):
        _text = value
        _labs = ' {text}'.format(text=_text)
        _file.write(_labs)

    def _append_bool(self, value, _file):
        _text = 'true' if value else 'false'
        _labs = ' {text}'.format(text=_text)
        _file.write(_labs)

    def _append_none(self, value, _file):
        _text = 'null'
        _labs = ' {text}'.format(text=_text)
        _file.write(_labs)
