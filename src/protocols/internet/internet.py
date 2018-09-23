# -*- coding: utf-8 -*-
"""root internet layer protocol

`pcapkit.protocols.internet.internet` contains both
`ETHERTYPE` and `Internet`. The former is a dictionary
of ethertype IEEE 802 numbers, registered in IANA. And the
latter is a base class for internet layer protocols, eg.
AH, IP, IPsec, IPv4, IPv6, IPX, and etc.

"""
from pcapkit._common.ethertype import EtherType as ETHERTYPE
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.protocol import Protocol
from pcapkit.protocols.transport.transport import TP_PROTO
from pcapkit.utilities.decorators import beholder

__all__ = ['Internet', 'ETHERTYPE']


class Internet(Protocol):
    """Abstract base class for internet layer protocol family.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

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
    __layer__ = 'Internet'

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
        _prot = TP_PROTO.get(_byte)
        return _prot

    def _decode_next_layer(self, dict_, proto=None, length=None, *, version=4, ipv6_exthdr=None):
        """Decode next layer extractor.

        Positional arguments:
            * dict_ -- dict, info buffer
            * proto -- str, next layer protocol name
            * length -- int, valid (not padding) length

        Keyword Arguments:
            * version -- int, IP version (4 in default)
                            <keyword> 4 / 6
            * ext_proto -- ProtoChain, ProtoChain of IPv6 extension headers

        Returns:
            * dict -- current protocol with next layer extracted

        """
        if self._onerror:
            next_ = beholder(self._import_next_layer)(self, proto, length, version=version)
        else:
            next_ = self._import_next_layer(proto, length, version=version)
        info, chain = next_.info, next_.protochain

        # make next layer protocol name
        layer = next_.alias.lower()
        # proto = next_.__class__.__name__

        # write info and protocol chain into dict
        dict_[layer] = info
        self._next = next_
        if ipv6_exthdr is not None:
            for proto in reversed(ipv6_exthdr):
                chain = ProtoChain(proto.__class__, proto.alias, basis=chain)
        self._protos = ProtoChain(self.__class__, self.alias, basis=chain)
        return dict_

    def _import_next_layer(self, proto, length=None, *, version=4, extension=False):
        """Import next layer extractor.

        Positional arguments:
            * proto -- str, next layer protocol name
            * length -- int, valid (not padding) length

        Keyword Arguments:
            * version -- int, IP version (4 in default)
                            <keyword> 4 / 6
            * extension -- bool, if is extension header (False in default)
                            <keyword> True / False

        Returns:
            * bool -- flag if extraction of next layer succeeded
            * Info -- info of next layer
            * ProtoChain -- protocol chain of next layer
            * str -- alias of next layer

        Protocols:
            * IPv4 -- internet layer
            * IPv6 -- internet layer
            * AH -- internet layer
            * TCP -- transport layer
            * UDP -- transport layer

        """
        if length == 0:
            from pcapkit.protocols.null import NoPayload as Protocol
        elif self._sigterm or proto == 59:
            from pcapkit.protocols.raw import Raw as Protocol
        elif proto == 51:
            from pcapkit.protocols.internet.ah import AH as Protocol
        elif proto == 139:
            from pcapkit.protocols.internet.hip import HIP as Protocol
        elif proto == 0:
            from pcapkit.protocols.internet.hopopt import HOPOPT as Protocol
        elif proto == 44:
            from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag as Protocol
        elif proto == 60:
            from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts as Protocol
        elif proto == 43:
            from pcapkit.protocols.internet.ipv6_route import IPv6_Route as Protocol
        elif proto == 135:
            from pcapkit.protocols.internet.mh import MH as Protocol
        elif proto == 4:
            from pcapkit.protocols.internet.ipv4 import IPv4 as Protocol
        elif proto == 41:
            from pcapkit.protocols.internet.ipv6 import IPv6 as Protocol
        elif proto == 6:
            from pcapkit.protocols.transport.tcp import TCP as Protocol
        elif proto == 17:
            from pcapkit.protocols.transport.udp import UDP as Protocol
        else:
            from pcapkit.protocols.raw import Raw as Protocol
        next_ = Protocol(self._file, length, version=version, extension=extension,
                         error=self._onerror, layer=self._exlayer, protocol=self._exproto)
        return next_
