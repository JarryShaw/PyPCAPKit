# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""Base Protocol
===================

.. module:: pcapkit.protocols.internet.internet

:mod:`pcapkit.protocols.internet.internet` contains :class:`~pcapkit.protocols.internet.internet.Internet`,
which is a base class for internet layer protocols, eg. :class:`~pcapkit.protocols.internet.ah.AH`,
:class:`~pcapkit.protocols.internet.ipsec.IPsec`, :class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.IPv6`, :class:`~pcapkit.protocols.internet.ipx.IPX`, and etc.

"""
import collections
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.protocols.protocol import ProtocolBase as Protocol
from pcapkit.utilities.decorators import beholder
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import Any, Optional, Type

    from typing_extensions import Literal

__all__ = ['Internet']


class Internet(Protocol[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
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

    #: DefaultDict[int, ModuleDescriptor[Protocol] | Type[Protocol]]: Protocol index mapping for decoding next layer,
    #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.internet.internet.Internet._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.internet.internet.Internet._import_next_layer>`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            Enum_TransType.HOPOPT:          ModuleDescriptor('pcapkit.protocols.internet.hopopt',     'HOPOPT'),
            Enum_TransType.IPv4:            ModuleDescriptor('pcapkit.protocols.internet.ipv4',       'IPv4'),
            Enum_TransType.TCP:             ModuleDescriptor('pcapkit.protocols.transport.tcp',       'TCP'),
            Enum_TransType.UDP:             ModuleDescriptor('pcapkit.protocols.transport.udp',       'UDP'),
            Enum_TransType.IPv6:            ModuleDescriptor('pcapkit.protocols.internet.ipv6',       'IPv6'),
            Enum_TransType.IPv6_Route:      ModuleDescriptor('pcapkit.protocols.internet.ipv6_route', 'IPv6_Route'),
            Enum_TransType.IPv6_Frag:       ModuleDescriptor('pcapkit.protocols.internet.ipv6_frag',  'IPv6_Frag'),
            Enum_TransType.AH:              ModuleDescriptor('pcapkit.protocols.internet.ah',         'AH'),
            Enum_TransType.IPv6_NoNxt:      ModuleDescriptor('pcapkit.protocols.misc.raw',            'Raw'),
            Enum_TransType.IPv6_Opts:       ModuleDescriptor('pcapkit.protocols.internet.ipv6_opts',  'IPv6_Opts'),
            Enum_TransType.IPX_in_IP:       ModuleDescriptor('pcapkit.protocols.internet.ipx',        'IPX'),
            Enum_TransType.Mobility_Header: ModuleDescriptor('pcapkit.protocols.internet.mh',         'MH'),
            Enum_TransType.HIP:             ModuleDescriptor('pcapkit.protocols.internet.hip',        'HIP'),
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
    def register(cls, code: 'Enum_TransType', protocol: 'ModuleDescriptor[Protocol] | Type[Protocol]') -> 'None':  # type: ignore[override]
        r"""Register a new protocol class.

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: protocol code as in :class:`~pcapkit.const.reg.transtype.TransType`
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.Protocol` subclass

        """
        if isinstance(protocol, ModuleDescriptor):
            protocol = protocol.klass
        if not issubclass(protocol, Protocol):
            raise RegistryError(f'protocol must be a Protocol subclass, not {protocol!r}')
        if code in cls.__proto__:
            warn(f'protocol {code} already registered, overwriting', RegistryWarning)
        cls.__proto__[code] = protocol

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size: 'int') -> 'Enum_TransType':
        """Read next layer protocol type.

        Arguments:
            size: buffer size

        Returns:
            Next layer's protocol enumeration.

        """
        _byte = self._read_unpack(size)
        _prot = Enum_TransType.get(_byte)
        return _prot

    def _decode_next_layer(self, dict_: '_PT', proto: 'Optional[int]' = None,  # pylint: disable=arguments-differ
                           length: 'Optional[int]' = None, *, packet: 'Optional[dict[str, Any]]' = None,
                           version: 'Literal[4, 6]' = 4, ipv6_exthdr: 'Optional[ProtoChain]' = None) -> '_PT':
        r"""Decode next layer extractor.

        Arguments:
            dict\_: info buffer
            proto: next layer protocol index
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)
            version: IP version
            ipv6_exthdr: protocol chain of IPv6 extension headers

        Returns:
            Current protocol with next layer extracted.

        Notes:
            We added a new key ``__next_type__`` to ``dict_`` to store the
            next layer protocol type, and a new key ``__next_name__`` to
            store the next layer protocol name. These two keys will **NOT**
            be included when :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` is called.

        """
        next_ = cast('Protocol',  # type: ignore[redundant-cast]
                     self._import_next_layer(proto, length, packet=packet, version=version))  # type: ignore[arg-type,misc,call-arg]
        info, chain = next_.info, next_.protochain

        # make next layer protocol name
        layer = next_.info_name
        # proto = next_.__class__.__name__

        # write info and protocol chain into dict
        dict_.__update__({
            layer: info,
            '__next_type__': type(next_),
            '__next_name__': layer,
        })
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
                           packet: 'Optional[dict[str, Any]]' = None,
                           version: 'Literal[4, 6]' = 4, extension: 'bool' = False) -> 'Protocol':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)
            version: IP protocol version
            extension: if is extension header

        Returns:
            Instance of next layer.

        """
        if TYPE_CHECKING:
            protocol: 'Type[Protocol]'

        file_ = self.__header__.get_payload()
        if length is None:
            length = len(file_)

        if length == 0:
            from pcapkit.protocols.misc.null import NoPayload as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.misc.raw import Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        else:
            protocol = self.__proto__[proto]  # type: ignore[assignment]
            if isinstance(protocol, ModuleDescriptor):
                protocol = protocol.klass  # type: ignore[unreachable]
                self.__proto__[proto] = protocol  # update mapping upon import

        next_ = protocol(file_, length, version=version, extension=extension,  # type: ignore[abstract]
                         alias=proto, packet=packet, layer=self._exlayer, protocol=self._exproto)
        return next_
