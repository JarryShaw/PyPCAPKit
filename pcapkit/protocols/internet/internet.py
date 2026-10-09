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
import io
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.protocol import _PT, _ST, ProtocolBase
from pcapkit.protocols.schema.schema import keep_short_read, replay_short_read
from pcapkit.utilities.decorators import beholder
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import IO, Any, Optional, Type

    from typing_extensions import Literal, Self

__all__ = ['Internet']


class Internet(ProtocolBase[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Abstract base class for internet layer protocol family.

    This class parses the following protocols, which are registered in the
    :attr:`self.__proto__ <pcapkit.protocols.internet.internet.Internet.__proto__>`
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
       * - :attr:`~pcapkit.const.reg.transtype.TransType.ESP`
         - :class:`pcapkit.protocols.internet.esp.ESP`
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
       * - :attr:`~pcapkit.const.reg.transtype.TransType.SCTP`
         - :class:`pcapkit.protocols.transport.sctp.SCTP`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.OSPFIGP`
         - :class:`pcapkit.protocols.application.ospf.OSPF`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Internet'  # type: Literal['Internet']

    #: DefaultDict[int, ModuleDescriptor[ProtocolBase] | ~typing.Type[ProtocolBase]]: Protocol index mapping for decoding next layer,
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
            Enum_TransType.ESP:             ModuleDescriptor('pcapkit.protocols.internet.esp',        'ESP'),
            Enum_TransType.AH:              ModuleDescriptor('pcapkit.protocols.internet.ah',         'AH'),
            Enum_TransType.IPv6_NoNxt:      ModuleDescriptor('pcapkit.protocols.misc.raw',            'Raw'),
            Enum_TransType.IPv6_Opts:       ModuleDescriptor('pcapkit.protocols.internet.ipv6_opts',  'IPv6_Opts'),
            Enum_TransType.IPX_in_IP:       ModuleDescriptor('pcapkit.protocols.internet.ipx',        'IPX'),
            Enum_TransType.Mobility_Header: ModuleDescriptor('pcapkit.protocols.internet.mh',         'MH'),
            Enum_TransType.HIP:             ModuleDescriptor('pcapkit.protocols.internet.hip',        'HIP'),
            Enum_TransType.SCTP:            ModuleDescriptor('pcapkit.protocols.transport.sctp',      'SCTP'),

            # OSPF rides directly on IP, so IANA protocol number 89 is its only
            # dispatch point. The dissector nonetheless lives under
            # ``protocols.application`` and reports ``__layer__ = 'Application'``,
            # because a routing protocol computes the forwarding table rather
            # than forwarding packets -- the dispatch tier and the subpackage are
            # deliberately decoupled, c.f.
            # :doc:`/contributing/conventions/protocol-layer-placement`.
            Enum_TransType.OSPFIGP:         ModuleDescriptor('pcapkit.protocols.application.ospf', 'OSPF'),
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
    def register(cls, code: 'Enum_TransType', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':  # type: ignore[override]
        r"""Register a new protocol class.

        Notes:
            The fully qualified class name should be
            ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: protocol code as in :class:`~pcapkit.const.reg.transtype.TransType`
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.Protocol` subclass

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.Protocol` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this protocol number
                is already registered, naming the displaced entry and its
                replacement so a caller can tell *what* was lost. Fires only
                when the incumbent differs from the replacement; see :meth:`ProtocolBase.register
                <pcapkit.protocols.protocol.ProtocolBase.register>` for the
                guard this shares with ``register_protocol``.

        """
        incumbent = cls.__proto__.get(code)
        if incumbent is not None and (incumbent is protocol or (
                isinstance(incumbent, ModuleDescriptor) and isinstance(protocol, ModuleDescriptor)
                and incumbent == protocol)):
            return
        if isinstance(protocol, ModuleDescriptor):
            protocol = protocol.klass
        if not isinstance(protocol, type):
            raise RegistryError(f'protocol must be a class, not {protocol!r}')
        if not issubclass(protocol, ProtocolBase):
            raise RegistryError(f'protocol must be a Protocol subclass, not {protocol!r}')
        if incumbent is not None and incumbent is not protocol:
            warn(f'protocol {code} already registered, overwriting '
                 f'{incumbent!r} with {protocol!r}', RegistryWarning)
        cls.__proto__[code] = protocol

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: Construction keywords, as for :meth:`ProtocolBase.from_data
                <pcapkit.protocols.protocol.ProtocolBase.from_data>`.

        Returns:
            Protocol instance, cut back to what was captured when the header
            it was parsed from was cut short (:issue:`1458`).

        """
        return replay_short_read(super().from_data(data, **kwargs), data)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None,
                      length: 'Optional[int]' = None, *,
                      extension: 'bool' = False, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Notes:
            An IPv6 extension header is handed the rest of the datagram, but
            parses only itself: its :attr:`info` holds no payload, and
            :class:`~pcapkit.protocols.internet.ipv6.IPv6` decodes what follows.
            So :attr:`data` is cut down to the header's own :attr:`length`, and
            ``from_data(info).data`` rebuilds it exactly (:issue:`1446`).

            A header the data ends inside keeps that in its :attr:`info`, so
            that :meth:`from_data` rebuilds only what was captured
            (:issue:`1458`).

        """
        super().__post_init__(file, length, extension=extension, **kwargs)  # type: ignore[arg-type]
        keep_short_read(self)

        if extension and file is not None and len(self._data) > self.length:
            self._data = self._data[:self.length]
            self._file = io.BytesIO(self._data)
            self.__cached__.pop('__len__', None)

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
                           version: 'Literal[4, 6]' = 4, ipv6_exthdr: 'Optional[ProtoChain]' = None,
                           payload: 'Optional[bytes]' = None) -> '_PT':
        r"""Decode next layer extractor.

        Arguments:
            dict\_: info buffer
            proto: next layer protocol index
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)
            version: IP version
            ipv6_exthdr: protocol chain of IPv6 extension headers
            payload: payload from packet. If not provided, will extract from
                :meth:`self.__header__.get_payload <pcapkit.protocols.schema.schema.Schema.get_payload>`

        Returns:
            Current protocol with next layer extracted.

        Notes:
            ``dict_`` gains the key ``__next_type__`` (next layer protocol
            type) and ``__next_name__`` (next layer protocol name). Neither
            is included when :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` is called.

        """
        next_ = cast('ProtocolBase',  # type: ignore[redundant-cast]
                     self._import_next_layer(proto, length, packet=packet, version=version,
                                             payload=payload))  # type: ignore[arg-type,misc,call-arg]
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
                           packet: 'Optional[dict[str, Any]]' = None, version: 'Literal[4, 6]' = 4,
                           extension: 'bool' = False, payload: 'Optional[bytes]' = None) -> 'ProtocolBase':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)
            version: IP protocol version
            extension: if is extension header
            payload: payload from packet. If not provided, will extract from
                :meth:`self.__header__.get_payload <pcapkit.protocols.schema.schema.Schema.get_payload>`

        Returns:
            Instance of next layer.

        """
        if TYPE_CHECKING:
            protocol: 'Type[ProtocolBase]'

        if payload is None:
            file_ = self.__header__.get_payload()
        else:
            file_ = payload
        if length is None:
            length = len(file_)

        if min(length, len(file_)) == 0:
            from pcapkit.protocols.misc.null import NoPayload as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.misc.raw import Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        else:
            protocol = self._lookup_next_layer(self.__proto__, proto)

        return self._parse_next_layer(protocol, file_, length, version=version, extension=extension,
                                      alias=proto, packet=packet, layer=self._exlayer,
                                      protocol=self._exproto, __context__=self._exctx)
