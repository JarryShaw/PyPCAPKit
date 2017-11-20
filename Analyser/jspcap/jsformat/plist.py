#!/usr/bin/python3
# -*- coding: utf-8 -*-


import os
import textwrap


# Dumper for PLIST files
# Write a macOS Property List file


from .xml import MAGIC_TYPES, XML


HEADER_START = '''\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
'''

HEADER_END = '''\
</dict>
</plist>
'''


class PLIST(XML):

    _hsrt = HEADER_START
    _hend = HEADER_END

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def kind(self):
        return 'plist'

    ##########################################################################
    # Utilities.
    ##########################################################################

    def append_value(self, value, _file, _name):
        _tabs = '\t' * self._tctr
        _keys = '{tabs}<key>{name}</key>\n'.format(tabs=_tabs, name=_name)
        _file.seek(self._sptr, os.SEEK_SET)
        _file.write(_keys)

        self._append_dict(value, _file)

    def _append_dict(self, value, _file):
        _tabs = '\t' * self._tctr
        _labs = '{tabs}<dict>\n'.format(tabs=_tabs)
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
        _labs = '{tabs}</dict>\n'.format(tabs=_tabs)
        _file.write(_labs)
