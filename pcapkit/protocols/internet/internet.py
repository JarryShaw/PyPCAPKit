# -*- coding: utf-8 -*-
"""Base Protocol
===================

:mod:`pcapkit.protocols.internet.internet` contains :class:`~pcapkit.protocols.internet.internet.Internet`,
which is a base class for internet layer protocols, eg. :class:`~pcapkit.protocols.internet.ah.AH`,
:class:`~pcapkit.protocols.internet.ipsec.IPsec`, :class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.IPv6`, :class:`~pcapkit.protocols.internet.ipx.IPX`, and etc.

"""
import collections
import importlib
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.const.reg.transtype import TransType as RegType_TransType
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.protocol import PT, Protocol
from pcapkit.utilities.decorators import beholder

if TYPE_CHECKING:
    from typing import Optional, Type

    from typing_extensions import Literal

__all__ = ['Internet']


class Internet(Protocol[PT], Generic[PT]):  # pylint: disable=abstract-method
    """Abstract base class for internet layer protocol family.

    This class currently supports parsing of the following protocols, which are
    registered in the :attr:`self.__proto__ <pcapkit.protocols.internet.internet.Internet.__proto__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
       * - :attr:`~pcapkit.const.reg.transtype.TransType.HOPOPT`
         - :class:`pcapkit.protocols.internet.hopopt.HOPOPT`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.IPv4`
         - :class:`pcapkit.protocols.internet.ipv4.IPv4`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.TCP`
         - :class:`pcapkit.protocols.transport.tcp.TCP`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.UDP`
         - :class:`pcapkit.protocols.transport.udp.UDP`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.IPv6`
         - :class:`pcapkit.protocols.internet.ipv6.IPv6`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.IPv6_Route`
         - :class:`pcapkit.protocols.internet.ipv6_route.IPv6_Route`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.IPv6_Frag`
         - :class:`pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.AH`
         - :class:`pcapkit.protocols.internet.ah.AH`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.IPv6_NoNxt`
         - :class:`pcapkit.protocols.misc.raw.Raw`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.IPv6_Opts`
         - :class:`pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.IPX_in_IP`
         - :class:`pcapkit.protocols.internet.ipx.IPX`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.Mobility_Header`
         - :class:`pcapkit.protocols.internet.mh.MH`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.HIP`
         - :class:`pcapkit.protocols.internet.hip.HIP`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Internet'  # type: Literal['Internet']

    #: DefaultDict[int, Tuple[str, str]]: Protocol index mapping for decoding next layer,
    #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.internet.internet.Internet._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.internet.internet.Internet._import_next_layer>`.
    __proto__ = collections.defaultdict(
        lambda: ('pcapkit.protocols.misc.raw', 'Raw'),
        {
            RegType_TransType.HOPOPT:          ('pcapkit.protocols.internet.hopopt',     'HOPOPT'),
            RegType_TransType.IPv4:            ('pcapkit.protocols.internet.ipv4',       'IPv4'),
            RegType_TransType.TCP:             ('pcapkit.protocols.transport.tcp',       'TCP'),
            RegType_TransType.UDP:             ('pcapkit.protocols.transport.udp',       'UDP'),
            RegType_TransType.IPv6:            ('pcapkit.protocols.internet.ipv6',       'IPv6'),
            RegType_TransType.IPv6_Route:      ('pcapkit.protocols.internet.ipv6_route', 'IPv6_Route'),
            RegType_TransType.IPv6_Frag:       ('pcapkit.protocols.internet.ipv6_frag',  'IPv6_Frag'),
            RegType_TransType.AH:              ('pcapkit.protocols.internet.ah',         'AH'),
            RegType_TransType.IPv6_NoNxt:      ('pcapkit.protocols.misc.raw',            'Raw'),
            RegType_TransType.IPv6_Opts:       ('pcapkit.protocols.internet.ipv6_opts',  'IPv6_Opts'),
            RegType_TransType.IPX_in_IP:       ('pcapkit.protocols.internet.ipx',        'IPX'),
            RegType_TransType.Mobility_Header: ('pcapkit.protocols.internet.mh',         'MH'),
            RegType_TransType.HIP:             ('pcapkit.protocols.internet.hip',        'HIP'),
        },
    )

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self) -> 'Literal["Internet"]':
        """Protocol layer."""
        return self.__layer__

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register(cls, code: 'RegType_TransType', module: str, class_: str) -> 'None':
        r"""Register a new protocol class.

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{module}.{class_}``.

        Arguments:
            code: protocol code as in :class:`~pcapkit.const.reg.transtype.TransType`
            module: module name
            class\_: class name

        """
        cls.__proto__[code] = (module, class_)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size: 'int') -> 'RegType_TransType':
        """Read next layer protocol type.

        Arguments:
            size: buffer size

        Returns:
            Next layer's protocol enumeration.

        """
        _byte = self._read_unpack(size)
        _prot = RegType_TransType.get(_byte)
        return _prot

    def _decode_next_layer(self, dict_: 'PT', proto: 'Optional[int]' = None,  # pylint: disable=arguments-differ
                           length: 'Optional[int]' = None, *, version: 'Literal[4, 6]' = 4,
                           ipv6_exthdr: 'Optional[ProtoChain]' = None) -> 'PT':
        r"""Decode next layer extractor.

        Arguments:
            dict\_: info buffer
            proto: next layer protocol index
            length: valid (*non-padding*) length
            version: IP version
            ipv6_exthdr: protocol chain of IPv6 extension headers

        Returns:
            Current protocol with next layer extracted.

        """
        next_ = self._import_next_layer(proto, length, version=version)  # type: ignore[misc,call-arg,arg-type]
        info, chain = next_.info, next_.protochain

        # make next layer protocol name
        layer = next_.info_name
        # proto = next_.__class__.__name__

        # write info and protocol chain into dict
        dict_.__update__([(layer, info)])
        self._next = next_  # pylint: disable=attribute-defined-outside-init
        if ipv6_exthdr is not None:
            if chain is not None:
                chain = ipv6_exthdr + chain
            else:
                chain = ipv6_exthdr  # type: ignore[unreachable]
        self._protos = ProtoChain(self.__class__, self.alias, basis=chain)  # pylint: disable=attribute-defined-outside-init
        return dict_

    @beholder  # type: ignore[arg-type]
    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                           version: 'Literal[4, 6]' = 4, extension: 'bool' = False) -> 'Protocol':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index
            length: valid (*non-padding*) length
            version: IP protocol version
            extension: if is extension header

        Returns:
            Instance of next layer.

        """
        if TYPE_CHECKING:
            protocol: 'Type[Protocol]'

        if length is not None and length == 0:
            from pcapkit.protocols.misc.null import NoPayload as protocol  # type: ignore[no-redef] # isort: skip # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.misc.raw import Raw as protocol  # type: ignore[no-redef] # isort: skip # pylint: disable=import-outside-toplevel
        else:
            module, name = self.__proto__[proto]
            protocol = cast('Type[Protocol]', getattr(importlib.import_module(module), name))

        next_ = protocol(self._file, length, version=version, extension=extension,  # type: ignore[abstract]
                         alias=proto, layer=self._exlayer, protocol=self._exproto)
        return next_
