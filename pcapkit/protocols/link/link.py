# -*- coding: utf-8 -*-
# pylint: disable=bad-whitespace
"""root link layer protocol

:mod:`pcapkit.protocols.link.link` contains :class:`~pcapkit.protocols.link.link.Link`,
which is a base class for link layer protocols, e.g. :class:`~pcapkit.protocols.link.link.arp.ARP`/InARP,
:class:`~pcapkit.protocols.link.link.ethernet.Ethernet`, :class:`~pcapkit.protocols.link.link.l2tp.L2TP`,
:class:`~pcapkit.protocols.link.link.ospf.OSPF`, :class:`~pcapkit.protocols.link.link.rarp.RARP`/DRARP and etc.

"""
import collections
import importlib

from pcapkit.const.reg.ethertype import EtherType as ETHERTYPE
from pcapkit.const.reg.linktype import LinkType as LINKTYPE
from pcapkit.protocols.protocol import Protocol

__all__ = ['Link', 'LINKTYPE']


class Link(Protocol):  # pylint: disable=abstract-method
    """Abstract base class for link layer protocol family."""

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
        """Protocol layer.

        :rtype: Literal['Link']
        """
        return self.__layer__

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register(cls, code, module, class_):
        """Register a new protocol class.

        Arguments:
            code (int): protocol code as in :class:`~pcapkit.const.reg.ethertype.EtherType`
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
            pcapkit.const.reg.ethertype.EtherType: next layer's protocol enumeration

        """
        _byte = self._read_unpack(size)
        _prot = ETHERTYPE.get(_byte)
        return _prot

    def _import_next_layer(self, proto, length=None):
        """Import next layer extractor.

        This method currently supports following protocols as registered in
        :data:`~pcapkit.const.reg.ethertype.EtherType`:

        .. list-table::
           :header-rows: 1

           * - ``proto``
             - Protocol
           * - 0x0806
             - :class:`~pcapkit.protocols.link.arp.ARP`
           * - 0x8035
             - :class:`~pcapkit.protocols.link.rarp.RARP`
           * - 0x8100
             - :class:`~pcapkit.protocols.link.vlan.VLAN`
           * - 0x0800
             - :class:`~pcapkit.protocols.internet.ipv4.IPv4`
           * - 0x86DD
             - :class:`~pcapkit.protocols.internet.ipv6.IPv6`
           * - 0x8137
             - :class:`~pcapkit.protocols.internet.ipx.IPX`


        Arguments:
            proto (int): next layer protocol index
            length (int): valid (*non-padding*) length

        Returns:
            pcapkit.protocols.protocol.Protocol: instance of next layer

        """
        if length == 0:
            from pcapkit.protocols.null import NoPayload as protocol  # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.raw import Raw as protocol  # pylint: disable=import-outside-toplevel
        else:
            module, name = self.__proto__[proto]
            try:
                protocol = getattr(importlib.import_module(module), name)
            except (ImportError, AttributeError):
                from pcapkit.protocols.raw import Raw as protocol  # pylint: disable=import-outside-toplevel

        next_ = protocol(self._file, length, error=self._onerror,
                         layer=self._exlayer, protocol=self._exproto)

        return next_
