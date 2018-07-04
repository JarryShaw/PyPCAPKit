# -*- coding: utf-8 -*-
"""decorator functions

`pcapkit.utilities.decorators` contains several useful
decorators, including `seekset` and `beholder`.

"""
import functools
import io
import os

###############################################################################
# from pcapkit.protocols.raw import Raw
# from pcapkit.foundation.analysis import Analysis
###############################################################################


__all__ = ['seekset', 'beholder', 'beholder_ng']


def seekset(func):
    """[ClassMethod] Read file from start then set back to original."""
    @functools.wraps(func)
    def seekcur(self, *args, **kw):
        seek_cur = self._file.tell()
        self._file.seek(self._foffset, os.SEEK_SET)
        return_ = func(self, *args, **kw)
        self._file.seek(seek_cur, os.SEEK_SET)
        return return_
    return seekcur


def beholder(func):
    """[ClassMethod] Behold extraction procedure."""
    @functools.wraps(func)
    def behold(self, proto, length, *args, **kwargs):
        seek_cur = self._file.tell()
        try:
            return func(proto, length, *args, **kwargs)
        except Exception as error:
            from pcapkit.protocols.raw import Raw

            self._file.seek(seek_cur, os.SEEK_SET)
            next_ = Raw(io.BytesIO(self._read_fileng(length)), length, error=str(error))
            return False, next_.info, next_.protochain, next_.alias
    return behold


def beholder_ng(func):
    """Behold analysis procedure."""
    @functools.wraps(func)
    def behold(file, length, *args, **kwargs):
        seek_cur = file.tell()
        try:
            return func(file, length, *args, **kwargs)
        except Exception as error:
            from pcapkit.foundation.analysis import Analysis
            from pcapkit.protocols.raw import Raw

            file.seek(seek_cur, os.SEEK_SET)

            raw = Raw(file, length, error=str(error))
            return Analysis(raw.info, raw.protochain, raw.alias)
    return behold
