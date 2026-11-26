# -*- coding: utf-8 -*-
"""IP - Internet Protocol
============================

.. module:: pcapkit.protocols.internet.ip.protocol

:mod:`pcapkit.protocols.internet.ip.protocol` contains
:class:`~pcapkit.protocols.internet.ip.protocol.IP` only,
which is a base class for Internet Protocol (IP)
protocol family [*]_, e.g.
:class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4` and
:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`.

.. [*] https://en.wikipedia.org/wiki/Internet_Protocol

.. versionchanged:: 1.6.0

   Constructing :class:`~pcapkit.protocols.internet.ip.protocol.IP` and its
   :meth:`~pcapkit.protocols.internet.ip.protocol.IP.from_data` give
   :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4` or
   :class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`, where they raised
   :exc:`TypeError`. The ``version`` keyword names the member; without it,
   octets give the one their Version field names, and fields are refused
   (:issue:`2574`).

"""
from typing import TYPE_CHECKING, Generic, cast, overload

from pcapkit.corekit.sentinels import NO_VALUE, NoValueType
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.protocol import _PT, _ST, _nothing_to_parse
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import IO, Any, Iterable, Mapping, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.corekit.context import ContextRegistry, ProtocolContext
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['IP']


class IP(Internet[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Base class for the IP protocol family.

    - Internet Protocol version 4 (:class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`) [:rfc:`791`]
    - Internet Protocol version 6 (:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`) [:rfc:`8200`]

    The IPsec protocols (:class:`~pcapkit.protocols.internet.ah.protocol.AH` and
    :class:`~pcapkit.protocols.internet.esp.protocol.ESP`) derive from
    :class:`~pcapkit.protocols.internet.ipsec.protocol.IPsec` instead.

    It dispatches on both paths, never giving an instance of this class
    (:issue:`2574`). ``version`` names the member; without it, octets give the
    one their Version field names, and fields are refused, since no field
    picks a member. :meth:`from_data` reads the ``version`` of its data. See
    :meth:`__new__`.

    """

    #: ``version``, which names the member and which :meth:`make` does not
    #: take, as a construction keyword (:issue:`2840`).
    __keywords__ = frozenset({'version'})

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["IPv4"], Literal["IPv6"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('IPv4', 'IPv6')

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', /, **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: As :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance; on this class, an instance of the member the
            ``version`` of ``data`` names, which both data models carry.

        Raises:
            ProtocolError: If that ``version`` is neither ``4`` nor ``6``, on this
                class.

        """
        if cls is not IP:
            return super().from_data(data, **kwargs)
        member = cls._member_of_version(data.get('version'))
        return cast('Self', member.from_data(data, **kwargs))

    ##########################################################################
    # Data models.
    ##########################################################################

    if not TYPE_CHECKING:
        # NOTE: For the docs' class signature (#1860): mypy rejects each overload of an abstract
        # class's ``__init__``, so it reads the one below and refuses this base as ``abstract`` (#3081).
        @overload  # pragma: no cover
        def __init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., /, *,
                     version: 'Optional[Literal[4, 6]]' = ...,
                     layer: 'Optional[str]' = ...,
                     protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = ...,
                     context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = ...,  # pylint: disable=line-too-long
                     ) -> 'None': ...
        @overload  # pragma: no cover
        def __init__(self, *, version: 'Optional[Literal[4, 6]]' = ...,
                     context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = ...,  # pylint: disable=line-too-long
                     **fields: 'Any') -> 'None': ...

    def __init__(self, file: 'IO[bytes] | bytes | NoValueType' = NO_VALUE,  # pylint: disable=super-init-not-called
                 length: 'Optional[int]' = None, /, *,
                 version: 'Optional[Literal[4, 6]]' = None,
                 layer: 'Optional[str]' = None,
                 protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                 context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                 **fields: 'Any') -> 'None':
        """Parse a protocol instance from its octets, or construct one from its fields.

        Args:
            file: Source packet stream; omitted to construct.
            length: Length of packet data.
            version: Version of IP, ``4`` or ``6``: the member :meth:`__new__`
                picks, which must be this class's own.
            layer: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.
            protocol: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`: on
                :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4`, a field
                given no ``file``.
            context: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.
            **fields: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.

        Raises:
            ProtocolError: If ``version`` names neither member, or is not this
                class's own version: that of the member it is or derives from,
                which a subclass outside the members does not have.

        .. versionchanged:: 1.8.0

           ``version`` is checked against the member, as :meth:`build`
           checks it (:issue:`2840`).

        """
        if isinstance(file, NoValueType):
            if version is not None:
                fields['version'] = version
            self._construct(context, self._call_fields(length, layer, protocol, fields))
            return
        if version is not None:
            type(self)._construction_member({'version': version})
        # NOTE: ``_parse``, as the base's ``__init__`` takes no ``version`` (#2840).
        self._parse(file, length, fields, layer=layer, protocol=protocol, context=context)

    def __new__(cls, file: 'Optional[IO[bytes] | bytes] | NoValueType' = NO_VALUE,
                length: 'Optional[int]' = None, /, **kwargs: 'Any') -> 'IP':
        """Create the member a parse or a construction of this class describes.

        The ``version`` keyword names the member. Without it, the octets give the
        member the Version field in their first four bits names, and fields are
        refused. That member's ``__init__`` then runs with the same arguments. A
        subclass of this class is created as itself.

        Args:
            file: Source packet stream, read here without being consumed;
                omitted to construct.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            An uninitialised instance of the member.

        Raises:
            TypeError: If ``file`` is :obj:`None`, on this class.
            ProtocolError: On this class, if ``version`` names neither member; if,
                without it, the octets are empty or their first four bits name
                neither version; or if fields come without it.

        """
        if cls is not IP:
            return super().__new__(cls, file, length, **kwargs)
        if isinstance(file, NoValueType):
            member = cls._construction_member(kwargs)
            return member.__new__(member)
        if file is None:
            raise _nothing_to_parse(IP)
        version = kwargs.get('version')
        if version is None:
            if isinstance(file, bytes):
                head = file[:1]
            else:
                offset = file.tell()
                head = file.read(1)
                file.seek(offset)
            if not head:
                raise ProtocolError('IP: no version in an empty packet')
            version = head[0] >> 4
        member = cls._member_of_version(version)
        return member.__new__(member, file, length, **kwargs)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @staticmethod
    def _member_of_version(version: 'Any') -> 'Type[IP]':
        """The member a ``version`` of ``4`` or ``6`` names.

        Args:
            version: Version of IP.

        Returns:
            :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4` or
            :class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`.

        Raises:
            ProtocolError: If ``version`` is neither, or is no :obj:`int`: a
                :obj:`bool` or a :obj:`float` is refused even where it equals one.

        """
        from pcapkit.protocols.internet.ipv4.protocol import IPv4  # isort: skip # pylint: disable=import-outside-toplevel
        from pcapkit.protocols.internet.ipv6.protocol import IPv6  # isort: skip # pylint: disable=import-outside-toplevel

        if isinstance(version, int) and not isinstance(version, bool):
            if version == 4:
                return cast('Type[IP]', IPv4)
            if version == 6:
                return cast('Type[IP]', IPv6)
        raise ProtocolError(f'IP: invalid version: {version!r}')

    @classmethod
    def _construction_member(cls, fields: 'dict[str, Any]') -> 'Type[Self]':
        """The member :meth:`build`, :meth:`from_data` and a call given no file construct.

        On this class, the member ``version`` names; on another, the class itself, of
        which ``version`` must name the member it is or derives from. ``version`` is
        taken out of ``fields``, as :meth:`make` does not read it.

        Args:
            fields: Construction keywords.

        Returns:
            The member, or the class itself.

        Raises:
            ProtocolError: If, on this class, ``version`` is missing; if it names
                neither member; or if it is not the class's own version, which a
                subclass outside the members does not have.

        .. versionadded:: 1.8.0

        """
        version = fields.pop('version', None)
        if cls is IP:
            if version is None:
                raise ProtocolError('IP: no version to build with; pass version=4 or version=6')
            return cast('Type[Self]', cls._member_of_version(version))
        if version is not None and not issubclass(cls, cls._member_of_version(version)):
            from pcapkit.protocols.internet.ipv4.protocol import IPv4  # isort: skip # pylint: disable=import-outside-toplevel
            from pcapkit.protocols.internet.ipv6.protocol import IPv6  # isort: skip # pylint: disable=import-outside-toplevel

            if not issubclass(cls, (IPv4, IPv6)):
                raise ProtocolError(f'{cls.__name__}: no version of its own to match '
                                    f'version={version!r}')
            raise ProtocolError(f'{cls.__name__}: version={version!r} names another member')
        return cls
