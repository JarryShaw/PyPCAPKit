# -*- coding: utf-8 -*-
"""data model for UDP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data

if TYPE_CHECKING:
    from pcapkit.const.reg.apptype import AppType

__all__ = ['UDP']


@info_final
class UDP(Data):
    """Data model for UDP protocol."""

    #: Source port.
    srcport: 'AppType'
    #: Destination port.
    dstport: 'AppType'
    #: Length (header includes).
    len: 'int'
    #: Checksum.
    checksum: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, srcport: 'AppType', dstport: 'AppType', len: 'int', checksum: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
