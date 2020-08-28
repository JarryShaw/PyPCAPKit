# -*- coding: utf-8 -*-
"""dump utilities

:mod:`pcapkit.dumpkit` is the collection of dumpers for
:mod:`pcapkit` implementation, which is alike those described
in :mod:`dictdumper`.

"""
import sys

import dictdumper

from pcapkit.protocols.pcap.frame import Frame
from pcapkit.protocols.pcap.header import Header

__all__ = ['PCAPIO', 'NotImplementedIO']


class NotImplementedIO(dictdumper.Dumper):
    """Unspecified output format."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def kind(self):
        """File format of current dumper.

        :rtype: Literal[NotImplemented]
        """
        return NotImplemented

    ##########################################################################
    # Data models.
    ##########################################################################

    def __call__(self, value, name=None):  # pylint: disable=unused-argument
        """Dump a new frame.

        Args:
            value (:obj:`Dict[str, Any]`): content to be dumped
            name (:obj:`Optional[str]`): name of current content block

        Returns:
            :class:`PCAP`: the dumper class itself (to support chain calling)

        """

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _dump_header(self, **kwargs):  # pylint: disable=unused-argument
        """Initially dump file heads and tails.

        Keyword Args:
            **kwargs: arbitrary keyword arguments

        """

    def _append_value(self, value, file, name):  # pylint: disable=unused-argument
        """Call this function to write contents.

        Args:
            value (Dict[str, Any]): content to be dumped
            file (io.TextIOWrapper): output file
            name (str): name of current content block

        """


class PCAPIO(dictdumper.Dumper):
    """PCAP file dumper."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def kind(self):
        """File format of current dumper.

        :rtype: Literal['pcap']
        """
        return 'pcap'

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, fname, *, protocol, byteorder=sys.byteorder, nanosecond=False, **kwargs):  # pylint: disable=arguments-differ
        """Initialise dumper.

        Args:
            fname (str): output file name

        Keyword Args:
            protocol (Union[pcapkit.const.reg.linktype.LinkType, enum.IntEnum, str, int]): data link type
            byteorder (Literal['little', 'big']): header byte order
            nanosecond (bool): nanosecond-resolution file flag
            **kwargs: arbitrary keyword arguments

        """
        #: int: Frame counter.
        self._fnum = 1
        #: bool: Nanosecond-resolution file flag.
        self._nsec = nanosecond
        #: Union[pcapkit.const.reg.linktype.LinkType, enum.IntEnum, str, int]: Data link type.
        self._link = protocol

        super().__init__(fname, protocol=protocol, byteorder=byteorder,
                         nanosecond=nanosecond, **kwargs)

    def __call__(self, value, name=None):
        """Dump a new frame.

        Args:
            value (Info[DataType_Frame]): content to be dumped
            name (:obj:`Optional[str]`): name of current content block

        Returns:
            :class:`PCAP`: the dumper class itself (to support chain calling)

        """
        with open(self._file, 'ab') as file:
            self._append_value(value, file, name)
        return self

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _dump_header(self, *, protocol, byteorder=sys.byteorder, nanosecond=False, **kwargs):  # pylint: disable=arguments-differ,unused-argument
        """Initially dump file heads and tails.

        Keyword Args:
            protocol (Union[pcapkit.const.reg.linktype.LinkType, enum.IntEnum, str, int]): data link type
            byteorder (Literal['little', 'big']): header byte order
            nanosecond (bool): nanosecond-resolution file flag
            **kwargs: arbitrary keyword arguments

        """
        packet = Header(
            network=protocol,
            byteorder=byteorder,
            nanosecond=nanosecond,
        ).data
        with open(self._file, 'wb') as file:
            file.write(packet)

    def _append_value(self, value, file, name):  # pylint: disable=unused-argument
        """Call this function to write contents.

        Args:
            value (Info[DataType_Frame]): content to be dumped
            file (io.BufferedReader): output file
            name (str): name of current content block

        """
        packet = Frame(
            packet=value.packet,
            nanosecond=self._nsec,
            num=self._fnum,
            proto=self._link,
            **value.get('frame_info', value),
        ).data
        file.write(packet)
        self._fnum += 1
