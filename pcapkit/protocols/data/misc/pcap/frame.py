# -*- coding: utf-8 -*-
"""data modules for frame header of PCAP file"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from datetime import datetime
    from decimal import Decimal

__all__ = ['Frame', 'FrameInfo']


class FrameInfo(Info):
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


class Frame(Info):
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

        def __init__(self, frame_info: 'FrameInfo', time: 'datetime', number: 'int', time_epoch: 'Decimal', len: 'int', cap_len: 'int') -> 'None': ...  # pylint: disable=unused-argument,multiple-statements,super-init-not-called,line-too-long,redefined-builtin
