# -*- coding: utf-8 -*-
"""Base Protocol
===================

.. module:: pcapkit.protocols.transport.transport

:mod:`pcapkit.protocols.transport.transport` contains
:class:`~pcapkit.protocols.transport.transport.Transport`,
which is a base class for transport layer protocols, eg.
:class:`~pcapkit.protocols.transport.tcp.TCP`,
:class:`~pcapkit.protocols.transport.udp.UDP` and
:class:`~pcapkit.protocols.transport.sctp.SCTP`.

"""
import io
from typing import TYPE_CHECKING, Generic

from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.protocol import _PT, _ST, ProtocolBase
from pcapkit.protocols.schema.schema import keep_short_read, replay_short_read
from pcapkit.utilities.exceptions import RegistryError, StructError, UnsupportedCall, stacklevel
from pcapkit.utilities.logging import DEVMODE, get_logger
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import IO, Any, DefaultDict, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol

__all__ = ['Transport']


#: logging.Logger: Module-level logger, a child of the package-wide
#: :data:`pcapkit.utilities.logging.logger`.
logger = get_logger(__name__)


class Transport(ProtocolBase[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Abstract base class for transport layer protocol family."""

    if TYPE_CHECKING:
        #: Protocol index mapping for decoding next layer,
        #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.transport.transport.Transport._decode_next_layer>`
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
            The full qualified class name of the new protocol class
            should be as ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: port number
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.Protocol` subclass

        Important:
            This method must be called from a non-abstract class, as the
            protocol map should be associated directly with specific
            transport layer protocol type.

        Raises:
            pcapkit.utilities.exceptions.UnsupportedCall: If called on
                :class:`Transport` itself.
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.Protocol` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this port is already
                registered and the incumbent differs from the replacement; the
                message names both. An unresolved
                :class:`~pcapkit.corekit.module.ModuleDescriptor` counts as
                different from the class it names. See
                :meth:`ProtocolBase.register
                <pcapkit.protocols.protocol.ProtocolBase.register>` for the
                guard this shares with ``register_protocol``.

        Note:
            :class:`~pcapkit.protocols.transport.tcp.TCP` and
            :class:`~pcapkit.protocols.transport.udp.UDP` each define their own
            ``__proto__`` rather than sharing one on :class:`Transport`.
            ``register_apptype`` reaches this method once per protocol and
            inspects two different registries, so it cannot warn spuriously.

        """
        if cls is Transport:
            raise UnsupportedCall(f'{cls.__name__} is an abstract class')

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
            warn(f'port {code} already registered, overwriting '
                 f'{incumbent!r} with {protocol!r}', RegistryWarning)
        cls.__proto__[code] = protocol

    @classmethod
    def analyze(cls, ports: 'tuple[int, int]', payload: 'bytes', **kwargs: 'Any') -> 'ProtocolBase':  # type: ignore[override] # pylint: disable=arguments-renamed
        """Analyse packet payload.

        Args:
            ports: Source & destination port numbers.
            payload: Packet payload.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed payload as a :class:`~pcapkit.protocols.protocol.Protocol`
            instance.

        """
        protocol = cls._lookup_next_layer(
            cls.__proto__, ports[0] if ports[0] in cls.__proto__ else ports[1])

        payload_io = io.BytesIO(payload)
        try:
            report = protocol(payload_io, len(payload), **kwargs)  # type: ignore[abstract]
        except Exception as exc:
            if isinstance(exc, StructError) and exc.eof:  # pylint: disable=no-member
                from pcapkit.protocols.misc.null import NoPayload as protocol  # pylint: disable=import-outside-toplevel # isort:skip
            else:
                from pcapkit.protocols.misc.raw import Raw as protocol  # pylint: disable=import-outside-toplevel # isort:skip
            # error = traceback.format_exc(limit=1).strip().rsplit(os.linesep, maxsplit=1)[-1]

            # log error
            logger.error(str(exc), exc_info=exc, stack_info=DEVMODE, stacklevel=stacklevel())

            report = protocol(payload_io, len(payload), **kwargs)  # type: ignore[abstract]
        return report

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
                      length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Notes:
            A header the data ends inside keeps that in its :attr:`info`, so
            that :meth:`from_data` rebuilds only what was captured
            (:issue:`1458`).

        """
        super().__post_init__(file, length, **kwargs)  # type: ignore[arg-type]
        keep_short_read(self)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @staticmethod
    def _make_port(port: 'Enum_AppType | int',
                   proto: 'Enum_TransportProtocol') -> 'Enum_AppType':
        """Resolve a port number to its application type.

        Arguments:
            port: port number, or the application type itself
            proto: transport protocol the port belongs to, which is what
                distinguishes e.g. TCP/80 from UDP/80

        Returns:
            The :class:`~pcapkit.const.reg.apptype.AppType` for ``port``.

        Important:
            :meth:`self.make <ProtocolBase.make>` accepts a bare :obj:`int` for a
            port, but the schema field converts it only on the way *out* (in
            :meth:`PortEnumField.pre_process
            <pcapkit.corekit.fields.numbers.PortEnumField.pre_process>`),
            so the schema attribute keeps whatever it was handed. Normalising
            here makes a constructed packet carry the same
            :class:`~pcapkit.const.reg.apptype.AppType` as a parsed one, so
            reading ``.port`` off it works on both paths.

        """
        if isinstance(port, Enum_AppType):
            return port
        return Enum_AppType.get(port, proto=proto)

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
            :meth:`ProtocolBase._import_next_layer
            <pcapkit.protocols.protocol.Protocol._import_next_layer>` passes
            it on as ``alias`` and :class:`~pcapkit.protocols.misc.raw.Raw`
            records it as :attr:`Data_Raw.protocol
            <pcapkit.protocols.data.misc.raw.Raw.protocol>`. Dropping it would
            make a payload on a port we do not decode indistinguishable from
            one on port 22. The lower port is the one carried, for the same
            reason it is the primary lookup key.
            :meth:`SCTP._decode_next_layer
            <pcapkit.protocols.transport.sctp.SCTP._decode_next_layer>` and
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
