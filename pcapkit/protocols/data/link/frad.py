# -*- coding: utf-8 -*-
"""data models for Frame Relay Access Device (FRAD) frames"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Optional

__all__ = ['FRAD']


@info_final
class FRAD(Protocol):
    """Data model for a Frame Relay Access Device (FRAD) frame."""

    #: Data Link Connection Identifier, from the Q.922 address field.
    dlci: 'int'
    #: Command/response indication bit.
    cr: 'int'
    #: Forward explicit congestion notification.
    fecn: 'int'
    #: Backward explicit congestion notification.
    becn: 'int'
    #: Discard eligibility.
    de: 'int'
    #: Control field; ``0x03`` (UI) for ordinary data traffic.
    control: 'int'
    #: NLPID selecting the encapsulated protocol, with any ``0x00`` pad
    #: already resolved to the real value that followed it.
    nlpid: 'int'
    #: SNAP OUI, present only when :attr:`nlpid` is ``0x80``.
    snap_oui: 'Optional[bytes]'
    #: SNAP PID, present only when :attr:`nlpid` is ``0x80``.
    snap_pid: 'Optional[int]'
    #: Header length, in octets -- 4 for a direct NLPID, 5 with the pad byte,
    #: or 10 with the SNAP header besides.
    len: 'int'

    if TYPE_CHECKING:
        def __init__(self, dlci: 'int', cr: 'int', fecn: 'int', becn: 'int', de: 'int',  # pylint: disable=unused-argument,super-init-not-called
                     control: 'int', nlpid: 'int', snap_oui: 'Optional[bytes]',  # pylint: disable=unused-argument
                     snap_pid: 'Optional[int]', len: 'int') -> 'None': ...  # pylint: disable=unused-argument,redefined-builtin
