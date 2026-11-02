# -*- coding: utf-8 -*-
"""IP - Internet Protocol
============================

.. module:: pcapkit.protocols.internet.ip

:mod:`pcapkit.protocols.internet.ip` contains
:class:`~pcapkit.protocols.internet.ip.IP` only,
which is a base class for Internet Protocol (IP)
protocol family [*]_, e.g.
:class:`~pcapkit.protocols.internet.ipv4.IPv4` and
:class:`~pcapkit.protocols.internet.ipv6.IPv6`.

.. [*] https://en.wikipedia.org/wiki/Internet_Protocol

.. versionchanged:: 1.6.0

   Constructing :class:`~pcapkit.protocols.internet.ip.IP` and its
   :meth:`~pcapkit.protocols.internet.ip.IP.from_data` give
   :class:`~pcapkit.protocols.internet.ipv4.IPv4` or
   :class:`~pcapkit.protocols.internet.ipv6.IPv6`, where they raised
   :exc:`TypeError`. The ``version`` keyword names the member; without it,
   octets give the one their Version field names, and fields are refused
   (:issue:`2574`).

"""
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import IO, Any, Optional, Type

    from typing_extensions import Literal, Self

__all__ = ['IP']


class IP(Internet[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Base class for the IP protocol family.

    - Internet Protocol version 4 (:class:`~pcapkit.protocols.internet.ipv4.IPv4`) [:rfc:`791`]
    - Internet Protocol version 6 (:class:`~pcapkit.protocols.internet.ipv6.IPv6`) [:rfc:`8200`]

    The IPsec protocols (:class:`~pcapkit.protocols.internet.ah.AH` and
    :class:`~pcapkit.protocols.internet.esp.ESP`) derive from
    :class:`~pcapkit.protocols.internet.ipsec.IPsec` instead.

    It dispatches on both paths, never giving an instance of this class
    (:issue:`2574`). ``version`` names the member; without it, octets give the
    one their Version field names, and fields are refused, since no field
    picks a member. :meth:`from_data` reads the ``version`` of its data. See
    :meth:`__new__`.

    """

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
    def from_data(cls, data: '_PT | dict[str, Any]', **kwargs: 'Any') -> 'Self':
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

    def __init__(self, file: 'Optional[IO[bytes] | bytes]' = None,
                 length: 'Optional[int]' = None, *,
                 version: 'Optional[Literal[4, 6]]' = None, **kwargs: 'Any') -> 'None':
        """Initialisation.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            version: Version of IP, ``4`` or ``6``: the member :meth:`__new__`
                picks. Building from fields, it must be this class's own. Parsing,
                it is handed on unread, as the enclosing IP layer passes its own
                version under this name to the layer it carries.
            **kwargs: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.

        Raises:
            ProtocolError: If, building from fields, ``version`` names neither
                member, or is not this class's own version: that of the member
                it is or derives from, which a subclass outside the members
                does not have.

        """
        if file is not None:
            if version is not None:
                kwargs['version'] = version
        elif version is not None and not isinstance(self, self._member_of_version(version)):
            from pcapkit.protocols.internet.ipv4 import IPv4  # isort: skip # pylint: disable=import-outside-toplevel
            from pcapkit.protocols.internet.ipv6 import IPv6  # isort: skip # pylint: disable=import-outside-toplevel

            if not isinstance(self, (IPv4, IPv6)):
                raise ProtocolError(f'{type(self).__name__}: no version of its own to match '
                                    f'version={version!r}')
            raise ProtocolError(f'{type(self).__name__}: version={version!r} names another member')
        super().__init__(file, length, **kwargs)  # type: ignore[arg-type]

    def __new__(cls, file: 'Optional[IO[bytes] | bytes]' = None,
                length: 'Optional[int]' = None, **kwargs: 'Any') -> 'IP':
        """Create the member a construction of this class describes.

        The ``version`` keyword names the member, on either path. Without it,
        parsing octets gives the member the Version field in their first four
        bits names, and building from fields is refused, since no field picks a
        member. That member's ``__init__`` then runs with the same arguments. A
        subclass of this class is created as itself.

        Args:
            file: Source packet stream, read here without being consumed.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            An uninitialised instance of the member.

        Raises:
            ProtocolError: If ``version`` names neither member; or, without it,
                if building from fields, or if the octets are empty or name
                neither version.

        """
        if cls is not IP:
            return super().__new__(cls, file, length, **kwargs)
        version = kwargs.get('version')
        if version is None:
            if file is None:
                raise ProtocolError('IP: no version to build with; pass version=4 or version=6')
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
            :class:`~pcapkit.protocols.internet.ipv4.IPv4` or
            :class:`~pcapkit.protocols.internet.ipv6.IPv6`.

        Raises:
            ProtocolError: If ``version`` is neither, or is no :obj:`int`: a
                :obj:`bool` or a :obj:`float` is refused even where it equals one.

        """
        from pcapkit.protocols.internet.ipv4 import IPv4  # isort: skip # pylint: disable=import-outside-toplevel
        from pcapkit.protocols.internet.ipv6 import IPv6  # isort: skip # pylint: disable=import-outside-toplevel

        if isinstance(version, int) and not isinstance(version, bool):
            if version == 4:
                return cast('Type[IP]', IPv4)
            if version == 6:
                return cast('Type[IP]', IPv6)
        raise ProtocolError(f'IP: invalid version: {version!r}')
