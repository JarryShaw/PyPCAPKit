#!/usr/bin/python3
# -*- coding: utf-8 -*-


# TODO: Supports more `dtd`s of XML.


import os
import textwrap


# Dumper for XML files
# Write a XML file for PCAP analyser


from .dumper import Dumper


HEADER_START = '''\
<?xml version="1.0" encoding="UTF-8"?>
<packet>
'''

HEADER_END = '''\
</packet>
'''

MAGIC_TYPES = dict(
    list = lambda self, text, file: self._append_array(text, file),     # array
    tuple = lambda self, text, file: self._append_array(text, file),    # array
    dict = lambda self, text, file: self._append_dict(text, file),      # dict
    Info = lambda self, text, file: self._append_dict(text, file),      # dict
    str = lambda self, text, file: self._append_string(text, file),     # string
    bytes = lambda self, text, file: self._append_data(text, file),     # data
    datetime = lambda self, text, file: self._append_date(text, file),  # date
    int = lambda self, text, file: self._append_integer(text, file),    # integer
    float = lambda self, text, file: self._append_real(text, file),     # real
    bool = lambda self, text, file: self._append_bool(text, file),      # true | false
)


class XML(Dumper):
    """Extensible Markup Language Format

    value    ::=  array | dict | string | data
                    | date | integer | real | bool
    array    ::=  "<array>" value* "</array>"
    dict     ::=  "<dict>" ("<key>" str "</key>" value)* "</dict>"
    string   ::=  "<string>" str "</string>"
    data     ::=  "<data>" bytes "</data>"
    date     ::=  "<date>" datetime "</date>"
    integer  ::=  "<integer>" int "</integer>"
    real     ::=  "<real>" float "</real>"
    bool     ::=  "<true/>" | "<false/>"

    """
    _hsrt = HEADER_START
    _hend = HEADER_END

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def kind(self):
        return 'xml'

    ##########################################################################
    # Utilities.
    ##########################################################################

    def append_value(self, value, _file, _name):
        _tabs = '\t' * self._tctr
        _keys = '{tabs}<name>{name}</name>\n'.format(tabs=_tabs, name=_name)
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
            MAGIC_TYPES[_type](self, _item, _file)

        self._tctr -= 1
        _tabs = '\t' * self._tctr
        _labs = '{tabs}</array>\n'.format(tabs=_tabs)
        _file.write(_labs)

    def _append_dict(self, value, _file):
        _tabs = '\t' * self._tctr
        _dict = '<dict>' if self._tctr > 1 else '<frame>'
        _labs = '{tabs}{dict}\n'.format(tabs=_tabs, dict=_dict)
        _file.write(_labs)
        self._tctr += 1

        for (_item, _text) in value.items():
            if _text is None:   continue

            _tabs = '\t' * self._tctr
            _keys = '{tabs}<key>{item}</key>\n'.format(tabs=_tabs, item=_item)
            _file.write(_keys)

            _type = type(_text).__name__
            MAGIC_TYPES[_type](self, _text, _file)

        self._tctr -= 1
        _tabs = '\t' * self._tctr
        _dict = '</dict>' if self._tctr > 1 else '</frame>'
        _labs = '{tabs}{dict}\n'.format(tabs=_tabs, dict=_dict)
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
        _labs = '{tabs}<data>\n'.format(tabs=_tabs)

        _list = []
        for _item in textwrap.wrap(value.hex(), 32):
            _text = ' '.join(textwrap.wrap(_item, 2))
            _item = '{tabs}\t{text}'.format(tabs=_tabs, text=_text)
            _list.append(_item)
        _labs += '\n'.join(_list)
        # _data = [H for H in iter(
        #         functools.partial(io.StringIO(value.hex()).read, 2), '')
        #         ]  # to split bytes string into length-2 hex string list
        _labs += '\n{tabs}</data>\n'.format(tabs=_tabs)
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
