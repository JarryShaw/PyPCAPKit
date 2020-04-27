# -*- coding: utf-8 -*-
# pylint: disable=bad-whitespace
"""root link layer protocol

:mod:`pcapkit.protocols.link.link` contains both
:data:`~pcapkit.protocols.link.link.LINKTYPE` and
:class:`~pcapkit.protocols.link.link.Link`. The former is
a dictionary of link layer header  type values, registered
in IANA. And the latter is a base class for link layer
protocols, eg. ARP/InARP, Ethernet, L2TP, OSPF, RARP/DRARP
and etc.

"""
import collections
import importlib

from pcapkit.const.reg.ethertype import EtherType as ETHERTYPE
from pcapkit.const.reg.linktype import LinkType as LINKTYPE
from pcapkit.protocols.protocol import Protocol

__all__ = ['Link', 'LINKTYPE']


class Link(Protocol):  # pylint: disable=abstract-method
    """Abstract base class for link layer protocol family.

    Attributes:
        name (str): name of corresponding protocol
        info (Info): info dict of current instance
        alias (str): acronym of corresponding protocol
        layer (str): ``'Link'``
        length (int): header length of corresponding protocol
        protocol (EtherType): enumeration of next layer protocol
        protochain (ProtoChain): protocol chain of current instance

        _file (io.BytesIO): source data stream
        _info (Info): info dict of current instance
        _protos (ProtoChain): protocol chain of current instance

    Methods:
        decode_bytes: try to decode bytes into str
        decode_url: decode URLs into Unicode

        _read_protos: read next layer protocol type
        _read_fileng: read file buffer
        _read_unpack: read bytes and unpack to integers
        _read_binary: read bytes and convert into binaries
        _read_packet: read raw packet data
        _decode_next_layer: decode next layer protocol type
        _import_next_layer: import next layer protocol extractor

    """
    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Link'

    #: DefaultDict[int, Tuple[str, str]]: Protocol index mapping for decoding next layer,
    #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.link.link.Link._import_next_layer>`.
    __proto__ = collections.defaultdict(lambda: ('pcapkit.protocols.raw', 'Raw'), {
        0x0806: ('pcapkit.protocols.link.arp',      'ARP'),
        0x8035: ('pcapkit.protocols.link.rarp',     'RARP'),
        0x8100: ('pcapkit.protocols.link.vlan',     'VLAN'),
        0x0800: ('pcapkit.protocols.internet.ipv4', 'IPv4'),
        0x86DD: ('pcapkit.protocols.internet.ipv6', 'IPv6'),
        0x8137: ('pcapkit.protocols.internet.ipx',  'IPX'),
    })

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self):
        """Protocol layer."""
        return self.__layer__

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size):
        """Read next layer protocol type.

        Arguments:
            size (int): buffer size

        Returns:
            EtherType: next layer's protocol enumeration

        """
        _byte = self._read_unpack(size)
        _prot = ETHERTYPE.get(_byte)
        return _prot

    def _import_next_layer(self, proto, length):  # pylint: disable=signature-differs
        """Import next layer extractor.

        This method currently supports following protocols as registered in
        :data:`~pcapkit.const.reg.linktype.LinkType`:

        * :class:`~pcapkit.protocols.link.arp.ARP`
        * :class:`~pcapkit.protocols.link.rarp.RARP`
        * :class:`~pcapkit.protocols.link.vlan.VLAN`
        * :class:`~pcapkit.protocols.internet.ipv4.IPv4`
        * :class:`~pcapkit.protocols.internet.ipv6.IPv6`
        * :class:`~pcapkit.protocols.internet.ipx.IPX`

        Arguments:
            proto (int): next layer protocol index
            length (int): valid (*non-padding*) length

        Returns:
            Protocol: instance of next layer

        """
        if length == 0:
            from pcapkit.protocols.null import NoPayload as protocol  # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.raw import Raw as protocol  # pylint: disable=import-outside-toplevel
        else:
            module, name = self.__proto__[proto]
            protocol = getattr(importlib.import_module(module), name)

        next_ = protocol(self._file, length, error=self._onerror,
                         layer=self._exlayer, protocol=self._exproto)

        return next_
