# -*- coding: utf-8 -*-
"""data models for L2TP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.const.l2tp.type import Type

__all__ = ['L2TP']


@info_final
class Flags(Data):
    """Data model for L2TP flags and version info."""

    #: Type.
    type: 'Type'
    #: Length.
    len: 'bool'
    #: Sequence.
    seq: 'bool'
    #: Offset.
    offset: 'bool'
    #: Priority.
    prio: 'bool'

    if TYPE_CHECKING:
        def __init__(self, type: 'Type', len: 'bool', seq: 'bool', offset: 'bool', prio: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,redefined-builtin,multiple-statements


@info_final
class L2TP(Protocol):
    """Data model for L2TP packet."""

    #: Flags and version info.
    flags: 'Flags'
    #: Version.
    version: 'int'
    #: Length.
    length: 'Optional[int]'
    #: Tunnel ID.
    tunnelid: 'int'
    #: Session ID.
    sessionid: 'int'
    #: Sequence Number.
    ns: 'Optional[int]'
    #: Next Sequence Number.
    nr: 'Optional[int]'
    #: Offset Size.
    offset: 'Optional[int]'

    if TYPE_CHECKING:
        #: Header length.
        hdr_len: 'int'

        def __init__(self, flags: 'Flags', version: 'int', length: 'Optional[int]', tunnelid: 'int', sessionid: 'int',
                     ns: 'Optional[int]', nr: 'Optional[int]', offset: 'Optional[int]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,redefined-builtin,multiple-statements,line-too-long
