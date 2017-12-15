#!/usr/bin/python3
# -*- coding: utf-8 -*-


import abc
import os


# Abstract Base Class of Dumpers
# Pre-define useful arguments and methods of dumpers


ABCMeta = abc.ABCMeta
abstractmethod = abc.abstractmethod
abstractproperty = abc.abstractproperty


class Dumper(object):

    __all__ = ['kind']
    __metaclass__ = ABCMeta

    ##########################################################################
    # Properties.
    ##########################################################################

    # file format of current dumper
    @abstractproperty
    def kind(self):
        pass

    ##########################################################################
    # Methods.
    ##########################################################################

    def dump_header(self):
        with open(self._file, 'w') as _file:
            _file.write(self._hsrt)
            self._sptr = _file.tell()
            _file.write(self._hend)

    @abstractmethod
    def append_value(self, value, _file, _name):
        pass

    ##########################################################################
    # Data models.
    ##########################################################################

    _sptr = os.SEEK_SET    # seek pointer
    _tctr = 1              # counter for tab level

    # Not hashable
    __hash__ = None

    def __new__(cls, fname):
        self = super().__new__(cls)
        return self

    def __init__(self, fname):
        if not os.path.isfile(fname):
            open(fname, 'w+').close()
        self._file = fname          # dump file name
        self.dump_header()          # initialise output file

    def __call__(self, value, *, name=None):
        with open(self._file, 'r+') as _file:
            self.append_value(value, _file, name)
            self._sptr = _file.tell()
            _file.write(self._hend)
