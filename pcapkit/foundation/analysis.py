# -*- coding: utf-8 -*-
# pylint: disable=import-outside-toplevel
"""analyser for application layer

:mod:`pcapkit.foundation.analysis` works as a header quarter to
analyse and match application layer protocol. Then, call
corresponding modules and functions to extract the attributes.

"""
import os

from pcapkit.protocols.raw import Raw
from pcapkit.utilities.decorators import seekset_ng
from pcapkit.utilities.exceptions import ProtocolError

###############################################################################
# from pcapkit.protocols.application.ftp import FTP
# from pcapkit.protocols.application.httpv1 import HTTPv1
# from pcapkit.protocols.application.httpv2 import HTTPv2
###############################################################################

__all__ = ['analyse']


def analyse(file, length=None, *, termination=False):
    """Analyse application layer packets.

    Args:
        file (io.BytesIO): source data stream
        length (Optional[int]): packet length

    Keyword Args:
        termination (bool): If terminate parsing application layer protocol.

    Returns:
        Protocol: Parsed application layer protocol.

    Notes:
        Currently, the analysis processes in following order:

        1. :class:`~pcapkit.protocols.application.ftp.FTP`
        2. :class:`HTTP/1.* <pcapkit.protocols.application.httpv1.HTTPv1>`
        3. :class:`HTTP/2 <pcapkit.protocols.application.httpv2.HTTPv2>`

        and :class:`~pcapkit.protocols.raw.Raw` as the fallback result.

    """
    seekset = file.tell()
    if not termination:
        # FTP analysis
        flag, ftp = _analyse_ftp(file, length, seekset=seekset)
        if flag:
            return ftp

        # HTTP/1.* analysis
        flag, http = _analyse_httpv1(file, length, seekset=seekset)
        if flag:
            return http

        # HTTP/2 analysis
        flag, http = _analyse_httpv2(file, length, seekset=seekset)
        if flag:
            return http

        # backup file offset
        file.seek(seekset, os.SEEK_SET)

    # raw packet analysis
    return Raw(file, length)


@seekset_ng
def _analyse_httpv1(file, length=None, *, seekset=os.SEEK_SET):  # pylint: disable=unused-argument
    """Analyse HTTP/1.* packet.

    Args:
        file (io.BytesIO): source data stream
        length (Optional[int]): packet length

    Keyword Args:
        seekset (int): original file offset

    Returns:
        Tuple[bool, Optional[HTTPv1]]: If the packet is HTTP/1.*,
        returns :data:`True` and parsed HTTP/1.* packet; otherwise
        returns :data:`False` and :data:`None`.

    """
    try:
        from pcapkit.protocols.application.httpv1 import HTTPv1
        http = HTTPv1(file, length)
    except ProtocolError:
        return False, None
    return True, http


@seekset_ng
def _analyse_httpv2(file, length, *, seekset=os.SEEK_SET):  # pylint: disable=unused-argument
    """Analyse HTTP/2 packet.

    Args:
        file (io.BytesIO): source data stream
        length (Optional[int]): packet length

    Keyword Args:
        seekset (int): original file offset

    Returns:
        Tuple[bool, Optional[HTTPv1]]: If the packet is HTTP/2,
        returns :data:`True` and parsed HTTP/2 packet; otherwise
        returns :data:`False` and :data:`None`.

    """
    try:
        from pcapkit.protocols.application.httpv2 import HTTPv2
        http = HTTPv2(file, length)
    except ProtocolError:
        return False, None
    return True, http


@seekset_ng
def _analyse_ftp(file, length, *, seekset=os.SEEK_SET):  # pylint: disable=unused-argument
    """Analyse FTP packet.

    Args:
        file (io.BytesIO): source data stream
        length (Optional[int]): packet length

    Keyword Args:
        seekset (int): original file offset

    Returns:
        Tuple[bool, Optional[HTTPv1]]: If the packet is FTP,
        returns :data:`True` and parsed FTP packet; otherwise
        returns :data:`False` and :data:`None`.

    """
    try:
        from pcapkit.protocols.application.ftp import FTP
        ftp = FTP(file, length)
    except ProtocolError:
        return False, None
    return True, ftp
