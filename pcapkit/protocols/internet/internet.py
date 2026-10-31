# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""Base Protocol
===================

.. module:: pcapkit.protocols.internet.internet

:mod:`pcapkit.protocols.internet.internet` contains :class:`~pcapkit.protocols.internet.internet.Internet`,
which is a base class for internet layer protocols, e.g. :class:`~pcapkit.protocols.internet.ah.AH`,
:class:`~pcapkit.protocols.internet.ipsec.IPsec`, :class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.IPv6` and :class:`~pcapkit.protocols.internet.ipx.IPX`.

"""
import collections
import contextvars
import io
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.decorators import beholder
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.protocol import _PT, _ST, ProtocolBase, _rebuilding
from pcapkit.protocols.schema.schema import keep_short_read, replay_short_read
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import stacklevel
from pcapkit.utilities.warnings import ProtocolWarning, RegistryWarning, warn

if TYPE_CHECKING:
    from typing import IO, Any, ClassVar, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.corekit.enum import EnumRegistry
    from pcapkit.protocols.data.data import Data

__all__ = ['Internet']

#: contextvars.ContextVar[int]: Where the payload :meth:`Internet._make_payload`
#: rebuilds sits in a chain of IPv6 extension headers, should it be one: one past
#: the layer it is the payload of, as :meth:`Internet._next_exthdr_depth` places
#: it while parsing, see :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT`.
_exthdr_rebuilt = contextvars.ContextVar('_exthdr_rebuilt', default=0)


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
       * - :attr:`~pcapkit.const.reg.transtype.TransType.IGMP`
         - :class:`pcapkit.protocols.internet.igmp.IGMP`, which dispatches to
           :class:`pcapkit.protocols.internet.igmpv1.IGMP`,
           :class:`pcapkit.protocols.internet.igmpv2.IGMP` or
           :class:`pcapkit.protocols.internet.igmpv3.IGMP`
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
       * - :attr:`~pcapkit.const.reg.transtype.TransType.Shim6`
         - :class:`pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.SCTP`
         - :class:`pcapkit.protocols.transport.sctp.SCTP`
       * - :attr:`~pcapkit.const.reg.transtype.TransType.OSPFIGP`
         - :class:`pcapkit.protocols.application.ospf.OSPF`

    .. versionchanged:: 1.5.0

       A layer parsed as an IPv6 extension header keeps only its own octets in
       ``data``, so that ``from_data(info).data`` rebuilds it exactly
       (:issue:`1446`).

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Internet'  # type: Literal['Internet']

    #: Protocol index mapping for decoding next layer,
    #: see :meth:`self._decode_next_layer <pcapkit.protocols.internet.internet.Internet._decode_next_layer>`
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
            Enum_TransType.IGMP:            ModuleDescriptor('pcapkit.protocols.internet.igmp',       'IGMP'),
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
            # deliberately decoupled, see
            # :doc:`/contributing/conventions/protocol-layer-placement`.
            Enum_TransType.OSPFIGP:         ModuleDescriptor('pcapkit.protocols.application.ospf', 'OSPF'),
        },
    )

    #: What :attr:`__proto__` is keyed by: the enum a key must be a member of,
    #: and whether a bare :class:`int` is a valid key there too. Declared by the
    #: class *owning* the registry, and read from it by
    #: :func:`~pcapkit.foundation.registry.protocols.register_protocol_code` so a
    #: ``code=`` key is checked exactly as
    #: :func:`~pcapkit.foundation.registry.protocols.register_transtype` checks
    #: its own -- a subclass sharing this registry is therefore checked as
    #: :class:`Internet` is, while :class:`~pcapkit.protocols.internet.ipx.IPX`,
    #: which keeps one of its own, declares its own pairing or none at all
    #: (:issue:`2268`).
    __proto_key__: 'ClassVar[tuple[Type[EnumRegistry], bool]]' = (Enum_TransType, False)

    #: int: How many IPv6 extension headers in a row the next layer follows:
    #: this layer's place in such a chain, or how many headers
    #: :class:`~pcapkit.protocols.internet.ipv6.IPv6` walked, else ``0``, see
    #: :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` and :meth:`_next_exthdr_depth`.
    _exthdr_depth = 0

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
                :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this protocol number
                is already registered, naming the displaced entry and its
                replacement so a caller can tell *what* was lost. Fires only
                when the incumbent differs from the replacement; see :meth:`Protocol.register
                <pcapkit.protocols.protocol.Protocol.register>` for the
                guard this shares with ``register_protocol``, and for the
                shipped descriptor a restore puts back (:issue:`1504`).

        .. versionchanged:: 1.3.0

           Takes the class, or a
           :class:`~pcapkit.corekit.module.ModuleDescriptor` naming it, as
           ``protocol``, in place of the ``module`` and ``class_`` name
           strings.

        """
        incumbent = cls.__proto__.get(code)
        entry = cls._next_layer_entry(code, protocol)
        if entry is None:
            return
        if incumbent is not None and incumbent is not entry:
            warn(f'protocol {code} already registered, overwriting '
                 f'{incumbent!r} with {entry!r}', RegistryWarning)
        cls.__proto__[code] = entry

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: Construction keywords, as for :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

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
            _exthdr_depth (int): Where this layer is in a chain of IPv6
                extension headers, counting from ``1``, or ``0`` if it is not
                in one. Handed over by :meth:`_import_next_layer` while
                parsing, see :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT`; a layer
                constructed instead, as :meth:`from_data` rebuilds one, takes it
                from :meth:`_rebuilt_exthdr_depth` (:issue:`1619`).
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
        # NOTE: Set before parsing, since parsing is what dissects the next layer.
        depth = cast('int', kwargs.pop('_exthdr_depth', 0))
        self._exthdr_depth = depth if file is not None else self._rebuilt_exthdr_depth()

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

    def _next_exthdr_depth(self, proto: 'Optional[int]', extension: 'bool' = False) -> 'int':
        """Place the next layer in its chain of IPv6 extension headers.

        Arguments:
            proto: next layer protocol index
            extension: if the next layer is parsed as an extension header by
                :class:`~pcapkit.protocols.internet.ipv6.IPv6`'s walk, which
                counts the chain itself, see :meth:`IPv6._decode_next_layer
                <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>`

        Returns:
            One more than :attr:`_exthdr_depth` if ``proto`` names an IPv6
            extension header, or ``0`` if it names none, so that another layer
            between two headers starts a new chain. Past
            :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT`, the next layer is left raw.

        """
        if extension:
            return 0
        try:
            Enum_ExtensionHeader(proto)
        except ValueError:
            return 0
        return self._exthdr_depth + 1

    @classmethod
    def _rebuilt_exthdr_depth(cls) -> 'int':
        """Place a layer :meth:`from_data` rebuilds in its chain of IPv6 extension headers.

        Returns:
            Where :meth:`_make_payload` of the layer it is the payload of puts
            it, if it is an IPv6 extension header, or ``0`` if it is not, as
            :meth:`_next_exthdr_depth` places a layer being parsed. A layer
            rebuilt on its own is at ``0``, as one parsed from its own octets is.

        Note:
            The parse tells an extension header by the protocol number naming
            it, which a rebuild does not have, so this tells one by its class:
            :class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext` is the base
            of every :class:`Internet` layer :attr:`__proto__` registers under
            such a number.

        """
        from pcapkit.protocols.internet.ipv6_ext import IPv6_Ext  # isort: skip # pylint: disable=import-outside-toplevel
        return _exthdr_rebuilt.get() if issubclass(cls, IPv6_Ext) else 0

    @classmethod
    def _make_payload(cls, data: 'Data') -> 'ProtocolBase':
        """Create payload from ``data`` for protocol construction.

        As :meth:`Protocol._make_payload
        <pcapkit.protocols.protocol.Protocol._make_payload>`, but the payload
        is built at its place in its chain of IPv6 extension headers, one past
        this layer's, since it parses its own octets again. So rebuilding a frame
        stops at :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` where parsing it did, rather
        than that many headers past each header of the chain, and warns of the
        limit once, as :meth:`_next_layer_class` describes (:issue:`1619`).

        Args:
            data: protocol data

        Returns:
            Payload for protocol construction.

        """
        # NOTE: IPv6 parses its upper layer after the headers it walked, not one
        # past itself, but its walk stops short of an extension header only
        # where that header is kept raw (at a limit, in a later fragment, or
        # where it does not parse), so no rebuilt upper layer reads this place.
        token = _exthdr_rebuilt.set(cls._rebuilt_exthdr_depth() + 1)
        try:
            return super()._make_payload(data)
        finally:
            _exthdr_rebuilt.reset(token)

    def _next_layer_class(self, proto: 'Optional[int]', file_: 'bytes', length: 'int',
                          extension: 'bool' = False) -> 'tuple[Type[ProtocolBase], dict[str, Any]]':
        r"""Pick the class the next layer is parsed with.

        Arguments:
            proto: next layer protocol index
            file\_: payload of the current layer
            length: valid (*non-padding*) length
            extension: if is extension header, see :meth:`_next_exthdr_depth`

        Returns:
            :class:`~pcapkit.protocols.misc.null.NoPayload` if there is
            nothing to parse; :class:`~pcapkit.protocols.misc.raw.Raw` if the
            parse stops at this layer, or the next layer is an IPv6 extension
            header past :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` in a row; otherwise the
            class registered for ``proto``. Paired with it, the keywords that
            only that next layer is constructed with: the warning given, as
            ``error``, or the next layer's place in its chain, as
            ``_exthdr_depth``.

        Warns:
            ProtocolWarning: If the next layer is past
                :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` (:issue:`1604`), unless this
                layer is inside a payload being rebuilt (:issue:`1619`).

        """
        if min(length, len(file_)) == 0:
            from pcapkit.protocols.misc.null import NoPayload  # isort: skip # pylint: disable=import-outside-toplevel
            return NoPayload, {}
        if self._sigterm:
            from pcapkit.protocols.misc.raw import Raw  # isort: skip # pylint: disable=import-outside-toplevel
            return Raw, {}

        depth = self._next_exthdr_depth(proto, extension)
        limit = config.EXTENSION_HEADER_LIMIT
        if limit != -1 and depth > limit:
            from pcapkit.protocols.misc.raw import Raw  # isort: skip # pylint: disable=import-outside-toplevel

            message = (f'{self.alias}: a chain of IPv6 extension headers reached the limit of '
                       f'{limit} headers; the rest of the packet, from Next '
                       f'Header {int(cast("int", proto))}, is left undissected')
            # NOTE: Inside a payload being rebuilt, the layer it is rebuilt for
            # warns of the same octets once its own parse gets here, as for
            # :data:`~pcapkit.utilities.config.FRAME_LAYER_LIMIT`.
            if not _rebuilding.get():
                warn(message, ProtocolWarning, stacklevel=stacklevel())
            return Raw, {'error': message}

        from pcapkit.protocols.internet.igmp import IGMP as IGMPBase  # isort: skip # pylint: disable=import-outside-toplevel

        protocol = self._lookup_next_layer(self.__proto__, cast('int', proto))
        if protocol is IGMPBase:
            protocol = IGMPBase._dispatch(file_, length)
        if depth and issubclass(protocol, Internet):
            return protocol, {'_exthdr_depth': depth}
        return protocol, {}

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
            ``dict_`` gains the keys ``__next_type__`` (next layer protocol
            type) and ``__next_name__`` (next layer protocol name), which
            :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>`
            carries and the dumpers leave out.

        """
        next_ = cast('ProtocolBase',  # type: ignore[redundant-cast]
                     self._import_next_layer(proto, length, packet=packet, version=version,
                                             payload=payload))  # type: ignore[misc,call-arg]
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

        Notes:
            An IPv6 extension header past :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` in a
            row is not dissected: it and the rest of the packet are kept as
            :class:`~pcapkit.protocols.misc.raw.Raw`, with one
            :exc:`~pcapkit.utilities.warnings.ProtocolWarning` (:issue:`1604`).
            Each header dissects the next one from here, so the chain's depth
            is handed to the next layer, see :meth:`_next_layer_class`.

        """
        if payload is None:
            file_ = self.__header__.get_payload()
        else:
            file_ = payload
        if length is None:
            length = len(file_)

        protocol, extra = self._next_layer_class(proto, file_, length, extension)
        return self._parse_next_layer(protocol, file_, length, version=version, extension=extension,
                                      alias=proto, packet=packet, layer=self._exlayer,
                                      protocol=self._exproto, __context__=self._exctx, **extra)
