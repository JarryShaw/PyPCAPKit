# -*- coding: utf-8 -*-
"""Base Protocol
===================

.. module:: pcapkit.protocols.transport.transport

:mod:`pcapkit.protocols.transport.transport` holds
:class:`~pcapkit.protocols.transport.transport.Transport`, the base class of the
transport layer protocols.

.. versionremoved:: 1.7.0

   ``pcapkit.protocols.transport.transport.logger``, which nothing logged to once
   :meth:`Transport.analyze <pcapkit.protocols.transport.transport.Transport.analyze>`
   stopped (:issue:`2862`).

"""
from typing import TYPE_CHECKING, Generic

from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.schema.shortread import keep_short_read, replay_short_read
from pcapkit.protocols.protocol import _PT, _ST, ProtocolBase
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import IO, Any, DefaultDict, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol
    from pcapkit.corekit.context import ContextRegistry

__all__ = ['Transport']


class Transport(ProtocolBase[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Abstract base class for transport layer protocol family."""

    if TYPE_CHECKING:
        #: Protocol index mapping for decoding next layer,
        #: see :meth:`self._decode_next_layer <pcapkit.protocols.transport.transport.Transport._decode_next_layer>`
        #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
        __proto__: 'DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Transport'  # type: Literal['Transport']

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self) -> 'Literal["Transport"]':
        """Protocol layer."""
        return self.__layer__

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register(cls, code: 'int', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':
        """Register a new protocol class.

        Notes:
            The fully qualified class name of the new protocol class
            should be ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: port number
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

        Important:
            Call it on a concrete transport protocol, whose own ``__proto__``
            it updates.

        Raises:
            pcapkit.utilities.exceptions.UnsupportedCall: If called on
                :class:`Transport` itself.
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this port is already
                registered and the incumbent differs from the replacement; the
                message names both. An unresolved
                :class:`~pcapkit.corekit.module.ModuleDescriptor` counts as
                different from the class it names. The guard is the one
                :meth:`Protocol.register
                <pcapkit.protocols.protocol.Protocol.register>` describes
                (:issue:`1504`).

        Note:
            Each transport protocol defines its own ``__proto__``, so
            ``register_apptype``, which calls this once per transport protocol,
            never warns spuriously.

        .. versionchanged:: 1.3.0

           Takes the protocol as one ``protocol`` argument, a
           :class:`~pcapkit.corekit.module.ModuleDescriptor` or a
           :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass, in place of
           the ``module`` and ``class_`` names.

        """
        if cls is Transport:
            raise UnsupportedCall(f'{cls.__name__} is an abstract class')

        incumbent = cls.__proto__.get(code)
        entry = cls._next_layer_entry(code, protocol)
        if entry is None:
            return
        if incumbent is not None and incumbent is not entry:
            warn(f'port {code} already registered, overwriting '
                 f'{incumbent!r} with {entry!r}', RegistryWarning)
        cls.__proto__[code] = entry

    @classmethod
    def analyze(cls, ports: 'tuple[Enum_AppType, Enum_AppType]', payload: 'bytes', **kwargs: 'Any') -> 'ProtocolBase':  # type: ignore[override] # pylint: disable=arguments-renamed
        """Analyse packet payload.

        Args:
            ports: Source & destination ports, as the application types
                :meth:`_make_port` resolves them to -- what
                :attr:`TCP.src <pcapkit.protocols.transport.tcp.protocol.TCP.src>` and
                :attr:`TCP.dst <pcapkit.protocols.transport.tcp.protocol.TCP.dst>` read
                off a parsed header, resolved the same way.
            payload: Packet payload.
            **kwargs: Keyword arguments for the payload's constructor, such as
                the stops and context a frame's next layer is parsed with.

        Returns:
            Parsed payload as a :class:`~pcapkit.protocols.protocol.ProtocolBase`
            instance. A payload that fails to parse is kept as
            :meth:`Protocol.analyze <pcapkit.protocols.protocol.Protocol.analyze>`
            keeps one, its ``protocol`` the port looked up, as an :obj:`int`, as
            a frame's fallback records the port :meth:`_decode_next_layer`
            looked up. An empty payload is
            :class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload`, as in a
            frame, and one past a stop this class meets is ``Raw``.

        Important:
            The annotation names the **base** registry because every transport
            protocol shares this method while resolving its ports in a registry
            of its own, such as :class:`~pcapkit.const.reg.apptype.tcp.TCP`. A
            caller that knows its transport gets the narrower type from
            whatever handed it the pair, e.g. :meth:`TCP._make_ports
            <pcapkit.foundation.reassembly.tcp.reassembly.TCP._make_ports>`.

            A bare :obj:`int` port still resolves: a member hashes as its port
            (:meth:`AppType.__hash__
            <pcapkit.const.reg.apptype.apptype.AppType.__hash__>`) and compares
            equal to it (:meth:`AppType.__eq__
            <pcapkit.const.reg.apptype.apptype.AppType.__eq__>`). So each port
            is tested against :attr:`__proto__` as it arrived, and the chosen
            one is unwrapped through :meth:`AppType.__int__
            <pcapkit.const.reg.apptype.apptype.AppType.__int__>` only when it
            is a member; unwrapping anything else would make :obj:`None` raise
            rather than fall back to
            :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, and ``'80'``
            dispatch as a port.

            A miss writes nothing back, so an unregistered port does not grow
            the process-wide registry -- see :meth:`Protocol._lookup_registry
            <pcapkit.protocols.protocol.Protocol._lookup_registry>`.

        .. versionchanged:: 1.5.0

           ``ports`` is a pair of
           :class:`~pcapkit.const.reg.apptype.apptype.AppType` members rather
           than of bare :obj:`int` port numbers, so :meth:`TCP.submit
           <pcapkit.foundation.reassembly.tcp.reassembly.TCP.submit>`, through
           :class:`~pcapkit.foundation.reassembly.data.Deferred`, hands
           over the same named ports a parsed header carries (:issue:`2417`).

        .. versionchanged:: 1.7.0

           The fallback holds the whole payload and the failure's message,
           rather than the octets the failed parse left unread (:issue:`2842`).
           Its ``protocol`` is the port looked up, a refusal it absorbs is
           quiet, any other error is logged at :data:`logging.WARNING` rather
           than ``ERROR``, and the failed parse's warnings are dropped
           (:issue:`2862`). An empty payload is ``NoPayload`` (:issue:`2880`).
           A payload past a stop is ``Raw``, and the parse gets the port as
           ``alias``, as a frame's next layer does (:issue:`2933`).

        """
        if TYPE_CHECKING:
            protocol: 'Type[ProtocolBase]'

        port = ports[0] if ports[0] in cls.__proto__ else ports[1]
        code = int(port) if isinstance(port, Enum_AppType) else port
        if cls._stops_next_layer(kwargs):
            from pcapkit.protocols.misc.raw.protocol import Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        else:
            protocol = cls._dispatch_family(cls._lookup_next_layer(cls.__proto__, code), payload, len(payload))
        return cls._analyze_next_layer(protocol, payload, code, **kwargs)

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', /, **kwargs: 'Any') -> 'Self':
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
                      length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Notes:
            A header the data ends inside keeps that in its
            :attr:`~pcapkit.protocols.protocol.Protocol.info`, so that
            :meth:`from_data` rebuilds only what was captured (:issue:`1458`).

        """
        super().__post_init__(file, length, **kwargs)  # type: ignore[arg-type]
        keep_short_read(self, length)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @staticmethod
    def _dispatch_family(klass: 'Type[ProtocolBase]', file_: 'bytes',
                         length: 'int') -> 'Type[ProtocolBase]':
        r"""Resolve a family base the registry binds to the member that parses ``file_``.

        The HTTP ports bind the family base
        :class:`~pcapkit.protocols.application.http.protocol.HTTP`, whose
        :meth:`~pcapkit.protocols.application.http.protocol.HTTP._dispatch_version` picks
        :class:`~pcapkit.protocols.application.httpv1.protocol.HTTPv1` or
        :class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2` from the payload,
        as :meth:`Internet._import_next_layer
        <pcapkit.protocols.internet.internet.Internet._import_next_layer>` does
        for :class:`~pcapkit.protocols.internet.igmp.protocol.IGMP` (:issue:`2524`).

        Arguments:
            klass: next layer protocol class, as the registry binds it
            file\_: payload of the current layer
            length: valid (*non-padding*) length

        Returns:
            The member for a family base, otherwise ``klass`` itself.

        """
        from pcapkit.protocols.application.http.protocol import HTTP as HTTPBase  # isort: skip # pylint: disable=import-outside-toplevel

        if klass is HTTPBase:
            return HTTPBase._dispatch_version(file_, length)
        return klass

    @staticmethod
    def _parse_next_layer(klass: 'Type[ProtocolBase]', file_: 'bytes', length: 'int', /, *,
                          layer: 'Optional[str]' = None,
                          protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                          context: 'Optional[ContextRegistry]' = None,
                          **state: 'Any') -> 'ProtocolBase':
        r"""Parse the next layer, resolving a family base to its member first.

        Arguments:
            klass: next layer protocol class
            file\_: payload of the current layer
            length: valid (*non-padding*) length
            layer: parse the next layer until such layer
            protocol: parse the next layer until such protocol
            context: caller supplied parsing context
            **state: next-layer state, as for :meth:`Protocol._parse_next_layer
                <pcapkit.protocols.protocol.Protocol._parse_next_layer>`

        Returns:
            As :meth:`Protocol._parse_next_layer
            <pcapkit.protocols.protocol.Protocol._parse_next_layer>`, for the
            class :meth:`_dispatch_family` resolves ``klass`` to.

        """
        return ProtocolBase._parse_next_layer(Transport._dispatch_family(klass, file_, length),
                                              file_, length, layer=layer, protocol=protocol,
                                              context=context, **state)

    @classmethod
    def _make_port(cls, port: 'Enum_AppType | int',
                   proto: 'Enum_TransportProtocol') -> 'Enum_AppType':
        """Resolve a port number to its application type.

        Arguments:
            port: port number, or the application type itself
            proto: transport protocol the port belongs to, which is what
                distinguishes e.g. TCP/80 from UDP/80

        Returns:
            The :class:`~pcapkit.const.reg.apptype.apptype.AppType` for ``port``.

        Raises:
            ProtocolError: If ``port`` is a :obj:`bool` (:issue:`2287`), or is
                neither an :class:`int` that fits in 16 bits nor an
                :class:`~pcapkit.const.reg.apptype.apptype.AppType`.

        Important:
            The schema field converts a bare :obj:`int` port only on the way
            *out* (:meth:`PortEnumField.pre_process
            <pcapkit.corekit.fields.numbers.PortEnumField.pre_process>`), so
            normalising here gives a constructed packet the same
            :class:`~pcapkit.const.reg.apptype.apptype.AppType` as a parsed one.

        .. versionchanged:: 1.6.0

           A port past 16 bits, a negative one, or one that is not an
           :class:`int` raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`,
           rather than a bare :exc:`~pcapkit.utilities.exceptions.EnumValueError`
           (:issue:`2594`).

        """
        if isinstance(port, Enum_AppType):
            return port
        # NOTE: ``bool`` is an ``int`` subclass, so ``AppType.get`` would look
        # ``True``/``False`` up as port 1/0 rather than refuse them (#2287).
        if isinstance(port, bool) or not isinstance(port, int):
            raise ProtocolError(f'{cls.__name__}: invalid port: {port!r}')
        try:
            return Enum_AppType.get(port, proto=proto)
        except ValueError as error:  # the registry's own range, quiet as get raises it
            raise ProtocolError(f'{cls.__name__}: invalid port: {port!r}') from error

    def _decode_next_layer(self, dict_: '_PT', ports: 'tuple[int, int]', length: 'Optional[int]' = None, *,  # type: ignore[override]
                           packet: 'Optional[dict[str, Any]]' = None) -> '_PT':  # pylint: disable=arguments-renamed
        """Decode next layer protocol.

        The next layer is looked up by port number. The lower of the two ports
        is the primary key; the higher one is used only when it alone is
        registered.

        Arguments:
            dict_: info buffer
            ports: source & destination port numbers
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Current protocol with next layer extracted.

        Important:
            The port is forwarded **whether or not it is registered**:
            :meth:`Protocol._import_next_layer
            <pcapkit.protocols.protocol.Protocol._import_next_layer>` passes
            it on as ``alias`` and :class:`~pcapkit.protocols.misc.raw.protocol.Raw`
            records it as :attr:`Data_Raw.protocol
            <pcapkit.protocols.misc.raw.data.Raw.protocol>`, which tells
            payloads on different undecoded ports apart. The port carried is the
            one looked up.
            :meth:`SCTP._decode_next_layer
            <pcapkit.protocols.transport.sctp.protocol.SCTP._decode_next_layer>` and
            :meth:`Internet._import_next_layer
            <pcapkit.protocols.internet.internet.Internet._import_next_layer>`
            behave the same way for an unregistered PPID and transport type.

        """
        sort_port = sorted(ports)
        if sort_port[0] not in self.__proto__ and sort_port[1] in self.__proto__:
            proto = sort_port[1]
        else:
            proto = sort_port[0]
        return super()._decode_next_layer(dict_, proto, length, packet=packet)
