# -*- coding: utf-8 -*-
"""data model for UDP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from pcapkit.const.reg.apptype import AppType
    from pcapkit.protocols.misc.checksum.checksum import ChecksumStatus

__all__ = ['UDP']


@info_final
class UDP(Protocol):
    """Data model for UDP protocol."""

    #: Source port.
    srcport: 'AppType'
    #: Destination port.
    dstport: 'AppType'
    #: Length, header included.
    len: 'int'
    #: Checksum.
    checksum: 'bytes'

    if TYPE_CHECKING:
        #: Octets captured past the Length field, present only when there are
        #: any.
        trailer: 'bytes'
        #: Outcome of verifying :attr:`checksum`, present only when the
        #: enclosing IP layer verified it under
        #: :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`.
        checksum_status: 'ChecksumStatus'

        def __init__(self, srcport: 'AppType', dstport: 'AppType', len: 'int', checksum: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
