# -*- coding: utf-8 -*-
"""root link layer protocol

`pcapkit.protocols.link.link` contains both `LINKTYPE`
and `Link`. The former is a dictionary of link layer header
type values, registered in IANA. And the latter is a base
class for link layer protocols, eg. ARP/InARP, Ethernet,
L2TP, OSPF, RARP/DRARP and etc.

"""
from pcapkit._common.linktype import LinkType as LINKTYPE
from pcapkit.protocols.internet.internet import ETHERTYPE
from pcapkit.protocols.protocol import Protocol

__all__ = ['Link', 'LINKTYPE']


class Link(Protocol):
    """Abstract base class for link layer protocol family.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Link`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * decode_bytes -- try to decode bytes into str
        * decode_url -- decode URLs into Unicode

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor

    """
    __layer__ = 'Link'

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

        Positional arguments:
            * size  -- int, buffer size

        Returns:
            * str -- next layer's protocol name

        """
        _byte = self._read_unpack(size)
        _prot = ETHERTYPE.get(_byte)
        return _prot

    def _import_next_layer(self, proto, length):
        """Import next layer extractor.

        Positional arguments:
            * proto -- str, next layer protocol name
            * length -- int, valid (not padding) length

        Returns:
            * bool -- flag if extraction of next layer succeeded
            * Info -- info of next layer
            * ProtoChain -- protocol chain of next layer
            * str -- alias of next layer

        Protocols:
            * ARP -- data link layer
            * RARP -- data link layer
            * VLAN -- data link layer
            * IPv4 -- internet layer
            * IPv6 -- internet layer
            * IPX -- internet layer

        """
        if length == 0:
            from pcapkit.protocols.null import NoPayload as Protocol
        elif self._sigterm:
            from pcapkit.protocols.raw import Raw as Protocol
        elif proto == 0x0806:
            from pcapkit.protocols.link.arp import ARP as Protocol
        elif proto == 0x8035:
            from pcapkit.protocols.link.rarp import RARP as Protocol
        elif proto == 0x8100:
            from pcapkit.protocols.link.vlan import VLAN as Protocol
        elif proto == 0x0800:
            from pcapkit.protocols.internet.ipv4 import IPv4 as Protocol
        elif proto == 0x86DD:
            from pcapkit.protocols.internet.ipv6 import IPv6 as Protocol
        elif proto == 0x8137:
            from pcapkit.protocols.internet.ipx import IPX as Protocol
        else:
            from pcapkit.protocols.raw import Raw as Protocol
        next_ = Protocol(self._file, length, error=self._onerror,
                         layer=self._exlayer, protocol=self._exproto)
        return next_
