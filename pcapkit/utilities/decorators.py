# -*- coding: utf-8 -*-
# pylint: disable=protected-access
"""decorator functions

:mod:`pcapkit.utilities.decorators` contains several useful
decorators, including :func:`~pcapkit.utilities.decorators.seekset`
and :func:`~pcapkit.utilities.decorators.beholder`.

"""
import functools
import io
import os
import traceback

from pcapkit.utilities.logging import logger

###############################################################################
# from pcapkit.foundation.analysis import analyse
# from pcapkit.protocols.raw import Raw
###############################################################################

__all__ = ['seekset', 'seekset_ng', 'beholder', 'beholder_ng']


def seekset(func):
    """Read file from start then set back to original.

    Important:
        This decorator function is designed for decorating *class methods*.

    The decorator will keep the current offset of :attr:`self._file`, then
    call the decorated function. Afterwards, it will rewind the  offset of
    :attr:`self._file` to the original and returns the return value from
    the decorated function.

    Note:
        The decorated function should have following signature::

            func(self, *args, **kw)

    See Also:
        :meth:`pcapkit.protocols.protocol.Protocol._read_packet`

    :meta decorator:
    """
    @functools.wraps(func)
    def seekcur(self, *args, **kw):
        seek_cur = self._file.tell()
        self._file.seek(self._seekset, os.SEEK_SET)
        return_ = func(self, *args, **kw)
        self._file.seek(seek_cur, os.SEEK_SET)
        return return_
    return seekcur


def seekset_ng(func):
    """Read file from start then set back to original.

    Important:
        This decorator function is designed for decorating *plain functions*.

    The decorator will rewind the offset of ``file``  to ``seekset``, then
    call the decorated function and returns its return value.

    Note:
        The decorated function should have following signature::

            func(protocol, file, *args, seekset=os.SEEK_SET, **kw)

        c.f. :func:`pcapkit.foundation.analysis._analyse`.

    See Also:
        :mod:`pcapkit.foundation.analysis`

    :meta decorator:
    """
    @functools.wraps(func)
    def seekcur(protocol, file, *args, seekset=os.SEEK_SET, **kw):  # pylint: disable=redefined-outer-name
        # seek_cur = file.tell()
        file.seek(seekset, os.SEEK_SET)
        return_ = func(protocol, file, *args, seekset=seekset, **kw)
        # file.seek(seek_cur, os.SEEK_SET)
        return return_
    return seekcur


def beholder(func):
    """Behold extraction procedure.

    Important:
        This decorator function is designed for decorating *class methods*.

    This decorate first keep the current offset of
    :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`, then
    try to call the decorated function. Should any exception raised, it will
    re-parse the :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`
    as :class:`~pcapkit.protocols.raw.Raw` protocol.

    Note:
        The decorated function should have following signature::

            func(self, proto, length, *args, **kwargs)

    See Also:
        :meth:`pcapkit.protocols.protocol.Protocol._decode_next_layer`

    :meta decorator:
    """
    @functools.wraps(func)
    def behold(self, proto, length, *args, **kwargs):
        seek_cur = self._file.tell()
        try:
            return func(proto, length, *args, **kwargs)
        except Exception as exc:
            from pcapkit.protocols.raw import Raw  # pylint: disable=import-outside-toplevel
            error = traceback.format_exc(limit=1).strip().split(os.linesep)[-1]
            # error = traceback.format_exc()

            # log error
            logger.error(error, exc_info=exc)

            self._file.seek(seek_cur, os.SEEK_SET)
            next_ = Raw(io.BytesIO(self._read_fileng(length)), length, error=error)
            return next_
    return behold


def beholder_ng(func):
    """Behold analysis procedure.

    Important:
        This decorator function is designed for decorating *plain functions*.

    This decorate first keep the current offset of ``file``, then try to call
    the decorated function. Should any exception raised, it will re-parse the
    ``file`` as :class:`~pcapkit.protocols.raw.Raw` protocol.

    Note:
        The decorated function should have following signature::

            func(file, length, *args, **kwargs)

    See Also:
        :meth:`pcapkit.protocols.transport.transport.Transport._import_next_layer`

    :meta decorator:
    """
    @functools.wraps(func)
    def behold(file, length, *args, **kwargs):
        seek_cur = file.tell()
        try:
            return func(file, length, *args, **kwargs)
        except Exception as exc:
            # from pcapkit.foundation.analysis import analyse
            from pcapkit.protocols.raw import Raw  # pylint: disable=import-outside-toplevel
            error = traceback.format_exc(limit=1).strip().split(os.linesep)[-1]
            # error = traceback.format_exc()

            # log error
            logger.error(error, exc_info=exc)

            file.seek(seek_cur, os.SEEK_SET)

            # raw = Raw(file, length, error=str(error))
            # return analyse(raw.info, raw.protochain, raw.alias)
            next_ = Raw(file, length, error=error)
            return next_
    return behold
