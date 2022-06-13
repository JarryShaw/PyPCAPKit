# -*- coding: utf-8 -*-
"""PCAP Dumper
=================

:mod:`pcapkit.dumpkit.pcap` is the dumper for :mod:`pcapkit` implementation,
specifically for PCAP format, which is alike those described in
:mod:`dictdumper`.

"""
import sys
from typing import TYPE_CHECKING

import dictdumper

from pcapkit.protocols.misc.pcap.frame import Frame
from pcapkit.protocols.misc.pcap.header import Header

if TYPE_CHECKING:
    from enum import IntEnum as StdlibIntEnum
    from typing import Any, BinaryIO, Optional

    from aenum import IntEnum as AenumIntEnum
    from typing_extensions import Literal

    from pcapkit.const.reg.linktype import LinkType as RegType_LinkType

__all__ = [
    'PCAPIO',
]


class PCAPIO(dictdumper.Dumper):
    """PCAP file dumper."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def kind(self) -> 'Literal["pcap"]':
        """File format of current dumper."""
        return 'pcap'

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, fname: 'str', *, protocol: 'RegType_LinkType | StdlibIntEnum | AenumIntEnum | str | int',
                 byteorder: 'Literal["big", "little"]' = sys.byteorder,
                 nanosecond: 'bool' = False, **kwargs: 'Any') -> 'None':  # pylint: disable=arguments-differ
        """Initialise dumper.

        Args:
            fname: output file name
            protocol: data link type
            byteorder: header byte order
            nanosecond: nanosecond-resolution file flag
            **kwargs: arbitrary keyword arguments

        """
        #: int: Frame counter.
        self._fnum = 1
        #: bool: Nanosecond-resolution file flag.
        self._nsec = nanosecond
        #: RegType_LinkType | StdlibIntEnum | AenumIntEnum | str | int: Data link type.
        self._link = protocol

        super().__init__(fname, protocol=protocol, byteorder=byteorder, nanosecond=nanosecond, **kwargs)

    def __call__(self, value: 'Frame', name: 'Optional[str]' = None) -> 'PCAPIO':
        """Dump a new frame.

        Args:
            value: content to be dumped
            name: name of current content block

        Returns:
            The dumper class itself (to support chain calling).

        """
        with open(self._file, 'ab') as file:
            self._append_value(value, file, name or '')
        return self

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _dump_header(self, *, protocol: 'RegType_LinkType | StdlibIntEnum | AenumIntEnum | str | int',  # pylint: disable=arguments-differ
                     byteorder: 'Literal["big", "little"]' = sys.byteorder, nanosecond: 'bool' = False,
                     **kwargs: 'Any') -> 'None':  # pylint: disable=unused-argument
        """Initially dump file heads and tails.

        Args:
            protocol: data link type
            byteorder: header byte order
            nanosecond: nanosecond-resolution file flag
            **kwargs: arbitrary keyword arguments

        """
        packet = Header(
            network=protocol,
            byteorder=byteorder,
            nanosecond=nanosecond,
        ).data
        with open(self._file, 'wb') as file:
            file.write(packet)

    def _append_value(self, value: 'Frame', file: 'BinaryIO', name: 'str') -> 'None':  # pylint: disable=unused-argument
        """Call this function to write contents.

        Args:
            value: content to be dumped
            file: output file
            name: name of current content block

        """
        packet = Frame(
            nanosecond=self._nsec,
            num=self._fnum,
            proto=self._link,
            packet=value.packet,
            **value.info.frame_info,
        ).data
        file.write(packet)
        self._fnum += 1
