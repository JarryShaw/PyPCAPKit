# -*- coding: utf-8 -*-
"""data model for UDP protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

__all__ = ['UDP']


class UDP(Info):
    """Data model for UDP protocol."""

    #: Source port.
    srcport: 'int'
    #: Destination port.
    dstport: 'int'
    #: Length (header includes).
    len: 'int'
    #: Checksum.
    checksum: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, srcport: 'int', dstport: 'int', len: 'int', checksum: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
