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
    #: Reserved bits 2, 3, 5 and 8-11 of the flags word, in their on-wire
    #: positions (i.e. masked by ``0x34F0``). :rfc:`2661` §3.1 has them "set
    #: to 0 on outgoing messages and ignored on incoming messages"; they are
    #: carried verbatim so that a rebuild reproduces the word as it arrived.
    reserved: 'int'

    if TYPE_CHECKING:
        def __init__(self, type: 'Type', len: 'bool', seq: 'bool', offset: 'bool', prio: 'bool', reserved: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,redefined-builtin,multiple-statements,line-too-long


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
        #: Offset pad (:data:`None` unless ``flags.offset`` is set).
        padding: 'Optional[bytes]'

        def __init__(self, flags: 'Flags', version: 'int', length: 'Optional[int]', tunnelid: 'int', sessionid: 'int',
                     ns: 'Optional[int]', nr: 'Optional[int]', offset: 'Optional[int]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,redefined-builtin,multiple-statements,line-too-long
