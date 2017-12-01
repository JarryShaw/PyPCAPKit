#!/usr/bin/python3
# -*- coding: utf-8 -*-


import sys
import traceback


class BaseError(Exception):
    """Cautions:

    * Turn off system-default traceback function by set `sys.tracebacklimit` to 0.
    * But bugs appear in Python 3.6, so we have to set `sys.tracebacklimit` to None.
    * In Python 2.7, `trace.print_stack(limit=None)` dose not support negative limit.

    """
    def __new__(cls, message):
        self = super(Exception, cls).__new__(cls)
        (self.traceback_3 if sys.version_info[0] > 2 else self.traceback_2)()
        return self

    def tb_preparation(self):
        tb = traceback.extract_stack()

        for ptr in range(len(tb)):
            if 'jspcap' in tb[ptr][0]:
                index = ptr;    break

        return index

    def traceback_2(self):
        index = self.tb_preparation()

        print('Traceback (most recent call last):')
        print(''.join(traceback.format_stack()[:index])[:-1])
        sys.tracebacklimit = 0

    def traceback_3(self):
        index = self.tb_preparation()

        print('Traceback (most recent call last):')
        traceback.print_stack(limit=-index)
        sys.tracebacklimit = None


class StringError(BaseError):
    def __init__(self, message):
        raise TypeError(message)


class BytesError(BaseError):
    def __init__(self, message):
        raise TypeError(message)


class FileError(BaseError):
    def __init__(self, message):
        raise TypeError(message)


class FormatError(BaseError):
    def __init__(self, message):
        raise KeyError(message)
