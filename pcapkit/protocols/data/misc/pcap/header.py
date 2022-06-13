# -*- coding: utf-8 -*-
"""data modules for global header of PCAP file"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from typing_extensions import Literal

    from pcapkit.const.reg.linktype import LinkType
    from pcapkit.corekit.version import VersionInfo

__all__ = ['Header', 'MagicNumber']


class MagicNumber(Info):
    """Magic number of PCAP file."""

    #: Magic number sequence.
    data: 'bytes'
    #: Byte order.
    byteorder: 'Literal["big", "little"]'
    #: Nanosecond-timestamp resolution flag.
    nanosecond: 'bool'

    if TYPE_CHECKING:
        def __init__(self, data: 'bytes', byteorder: 'Literal["big", "little"]', nanosecond: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


class Header(Info):
    """Global header of PCAP file."""

    #: Magic number.
    magic_number: 'MagicNumber'
    #: Version number.
    version: 'VersionInfo'
    #: GMT to local correction.
    thiszone: 'int'
    #: Accuracy of timestamps.
    sigfigs: 'int'
    #: Max length of captured packets, in octets.
    snaplen: 'int'
    #: Data link type.
    network: 'LinkType'

    if TYPE_CHECKING:
        def __init__(self, magic_number: 'MagicNumber', version: 'VersionInfo',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     thiszone: 'int', sigfigs: 'int', snaplen: 'int', network: 'LinkType') -> 'None': ...  # pylint: disable=unused-argument
