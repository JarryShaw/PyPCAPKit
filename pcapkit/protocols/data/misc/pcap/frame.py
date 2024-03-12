# -*- coding: utf-8 -*-
"""data models for frame header of PCAP file"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from datetime import datetime
    from decimal import Decimal

__all__ = ['Frame', 'FrameInfo']


@info_final
class FrameInfo(Data):
    """Frame metadata information."""

    #: Timestamp seconds.
    ts_sec: 'int'
    #: Timestamp microseconds.
    ts_usec: 'int'
    #: Number of octets of packet saved in file.
    incl_len: 'int'
    #: Actual length of packet.
    orig_len: 'int'

    if TYPE_CHECKING:
        def __init__(self, ts_sec: 'int', ts_usec: 'int', incl_len: 'int', orig_len: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called


@info_final
class Frame(Protocol):
    """Frame header of PCAP file."""

    #: Metadata information.
    frame_info: 'FrameInfo'
    #: Timestamp instance.
    time: 'datetime'
    #: Frame index.
    number: 'int'
    #: UNIX timestamp.
    time_epoch: 'Decimal'
    #: Number of octets of packet saved in file.
    len: 'int'
    #: Actual length of packet.
    cap_len: 'int'

    if TYPE_CHECKING:
        #: Protocol chain.
        protocols: 'str'

        def __init__(self, frame_info: 'FrameInfo', time: 'datetime', number: 'int', time_epoch: 'Decimal',
                     len: 'int', cap_len: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,line-too-long,redefined-builtin
