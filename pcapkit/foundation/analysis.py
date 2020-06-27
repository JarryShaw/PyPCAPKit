# -*- coding: utf-8 -*-
# pylint: disable=import-outside-toplevel
"""analyser for application layer

:mod:`pcapkit.foundation.analysis` works as a header quarter to
analyse and match application layer protocol. Then, call
corresponding modules and functions to extract the attributes.

"""
import importlib
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

#: List of protocols supported by the analyser.
ANALYSE_PROTO = [
    ('pcapkit.protocols.application.ftp', 'FTP'),
    ('pcapkit.protocols.application.httpv1', 'HTTPv1'),
    ('pcapkit.protocols.application.httpv2', 'HTTPv2'),
]


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

    See Also:
        The analysis processes order is defined by :data:`~pcapkit.foundation.analysis.ANALYSE_PROTO`.

    """
    seekset = file.tell()
    if not termination:
        for (module, name) in ANALYSE_PROTO:
            try:
                protocol = getattr(importlib.import_module(module), name)
            except (ImportError, AttributeError):
                continue

            packet = _analyse(protocol, file, length, seekset=seekset)
            if packet is None:
                continue
            return packet

        # backup file offset
        file.seek(seekset, os.SEEK_SET)

    # raw packet analysis
    return Raw(file, length)


@seekset_ng
def _analyse(protocol, file, length=None, *, seekset=os.SEEK_SET):  # pylint: disable=unused-argument
    """Analyse packet.

    Args:
        protocol (Protocol): target protocol class
        file (io.BytesIO): source data stream
        length (Optional[int]): packet length

    Keyword Args:
        seekset (int): original file offset

    Returns:
        Optional[Protocol]: If the packet is parsed successfully,
        returns the parsed  packet; otherwise returns :data:`None`.

    """
    try:
        packet = protocol(file, length)
    except ProtocolError:
        packet = None
    return packet


def register(module, class_, *, index=None):
    """Register a new protocol class.

    Arguments:
        module (str): module name
        class_ (str): class name

    Keyword Arguments:
        index (Optional[int]): Index of the protocol class
            when inserted to :data:`~pcapkit.foundation.analysis.ANALYSE_PROTO`.

    Notes:
        The full qualified class name of the new protocol class
        should be as ``{module}.{class_}``.

    """
    if index is None:
        ANALYSE_PROTO.append((module, class_))
    else:
        ANALYSE_PROTO.insert(index, (module, class_))
