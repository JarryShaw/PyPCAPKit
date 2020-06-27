# -*- coding: utf-8 -*-
# pylint: disable=bad-whitespace
"""root internet layer protocol

:mod:`pcapkit.protocols.internet.internet` contains :class:`~pcapkit.protocols.internet.internet.Internet`,
which is a base class for internet layer protocols, eg. :class:`~pcapkit.protocols.internet.ah.AH`,
:class:`~pcapkit.protocols.internet.ipsec.IPsec`, :class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.IPv6`, :class:`~pcapkit.protocols.internet.ipx.IPX`, and etc.

"""
import collections
import importlib

from pcapkit.const.reg.ethertype import EtherType as ETHERTYPE
from pcapkit.const.reg.transtype import TransType as TP_PROTO
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.decorators import beholder

__all__ = ['Internet', 'ETHERTYPE']


class Internet(Protocol):  # pylint: disable=abstract-method
    """Abstract base class for internet layer protocol family."""

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Internet'

    #: DefaultDict[int, Tuple[str, str]]: Protocol index mapping for decoding next layer,
    #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.internet.link.Link._import_next_layer>`.
    __proto__ = collections.defaultdict(lambda: ('pcapkit.protocols.raw', 'Raw'), {
        0:   ('pcapkit.protocols.internet.hopopt',     'HOPOPT'),
        4:   ('pcapkit.protocols.internet.ipv4',       'IPv4'),
        6:   ('pcapkit.protocols.transport.tcp',       'TCP'),
        17:  ('pcapkit.protocols.transport.udp',       'UDP'),
        41:  ('pcapkit.protocols.internet.ipv6',       'IPv6'),
        43:  ('pcapkit.protocols.internet.ipv6_route', 'IPv6_Route'),
        44:  ('pcapkit.protocols.internet.ipv6_frag',  'IPv6_Frag'),
        51:  ('pcapkit.protocols.internet.ah',         'AH'),
        60:  ('pcapkit.protocols.internet.ipv6_opts',  'IPv6_Opts'),
        111: ('pcapkit.protocols.internet.ipx',        'IPX'),
        135: ('pcapkit.protocols.internet.mh',         'MH'),
        139: ('pcapkit.protocols.internet.hip',        'HIP'),
    })

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self):
        """Protocol layer.

        :rtype: Literal['Internet']
        """
        return self.__layer__

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register(cls, code, module, class_):
        """Register a new protocol class.

        Arguments:
            code (int): protocol code as in :class:`~pcapkit.const.reg.transtype.TransType`
            module (str): module name
            class_ (str): class name

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{module}.{class_}``.

        """
        cls.__proto__[code] = (module, class_)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size):
        """Read next layer protocol type.

        Arguments:
            size (int): buffer size

        Returns:
            pcapkit.const.reg.transtype.TransType: next layer's protocol enumeration

        """
        _byte = self._read_unpack(size)
        _prot = TP_PROTO.get(_byte)
        return _prot

    def _decode_next_layer(self, dict_, proto=None, length=None, *, version=4, ipv6_exthdr=None):  # pylint: disable=arguments-differ
        """Decode next layer extractor.

        Arguments:
            dict_ (dict): info buffer
            proto (int): next layer protocol index
            length (int): valid (*non-padding*) length

        Keyword Arguments:
            version (Literal[4, 6]): IP version
            ipv6_exthdr (pcapkit.corekit.protochain.ProtoChain): protocol chain of IPv6 extension headers

        Returns:
            dict: current protocol with next layer extracted

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
        self._next = next_  # pylint: disable=attribute-defined-outside-init
        if ipv6_exthdr is not None:
            for proto_cls in reversed(ipv6_exthdr):
                chain = ProtoChain(proto_cls.__class__, proto_cls.alias, basis=chain)
        self._protos = ProtoChain(self.__class__, self.alias, basis=chain)  # pylint: disable=attribute-defined-outside-init
        return dict_

    def _import_next_layer(self, proto, length=None, *, version=4, extension=False):  # pylint: disable=arguments-differ
        """Import next layer extractor.

        This method currently supports following protocols as registered in
        :data:`~pcapkit.const.reg.transtype.TransType`:

        .. list-table::
           :header-rows: 1

           * - ``proto``
             - Class
           * - 0
             - :class:`~pcapkit.protocols.internet.hopopt.HOPOPT`
           * - 4
             - :class:`~pcapkit.protocols.internet.ipv4.IPv4`
           * - 6
             - :class:`~pcapkit.protocols.transport.tcp.TCP`
           * - 17
             - :class:`~pcapkit.protocols.transport.udp.UDP`
           * - 41
             - :class:`~pcapkit.protocols.internet.ipv6.IPv6`
           * - 43
             - :class:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route`
           * - 44
             - :class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`
           * - 51
             - :class:`~pcapkit.protocols.internet.ah.AH`
           * - 60
             - :class:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`
           * - 111
             - :class:`~pcapkit.protocols.internet.ipx.IPX`
           * - 135
             - :class:`~pcapkit.protocols.internet.mh.MH`
           * - 139
             - :class:`~pcapkit.protocols.internet.hip.HIP`

        Arguments:
            proto (int): next layer protocol index
            length (int): valid (*non-padding*) length

        Keyword Arguments:
            version (Literal[4, 6]): IP protocol version
            extension (bool): if is extension header

        Returns:
            pcapkit.protocols.protocol.Protocol: instance of next layer

        """
        if length == 0:
            from pcapkit.protocols.null import NoPayload as protocol  # pylint: disable=import-outside-toplevel
        elif self._sigterm or proto == 59:  # No Next Header for IPv6
            from pcapkit.protocols.raw import Raw as protocol  # pylint: disable=import-outside-toplevel
        else:
            module, name = self.__proto__[proto]
            try:
                protocol = getattr(importlib.import_module(module), name)
            except (ImportError, AttributeError):
                from pcapkit.protocols.raw import Raw as protocol  # pylint: disable=import-outside-toplevel

        next_ = protocol(self._file, length, version=version, extension=extension,
                         error=self._onerror, layer=self._exlayer, protocol=self._exproto)
        return next_
