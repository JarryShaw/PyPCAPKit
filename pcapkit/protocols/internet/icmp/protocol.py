# -*- coding: utf-8 -*-
"""ICMP - Internet Control Message Protocol
==============================================

.. module:: pcapkit.protocols.internet.icmp.protocol

:mod:`pcapkit.protocols.internet.icmp.protocol` contains
:class:`~pcapkit.protocols.internet.icmp.protocol.ICMP` only,
which is a base class for Internet Control Message
Protocol (ICMP) protocol family [*]_, e.g.
:class:`~pcapkit.protocols.internet.icmpv4.protocol.ICMPv4` and
:class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6`. Constructing the base gives the
one its ``version`` keyword names, from octets or from fields, and is refused
without it, since an ICMP message carries no version of its own. Its
:meth:`~pcapkit.protocols.internet.icmp.protocol.ICMP.from_data` gives the one whose data
model it is handed (:issue:`2574`).

.. [*] https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol

"""
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import IO, Any, Optional, Type

    from typing_extensions import Literal, Self

__all__ = ['ICMP']


class ICMP(Internet[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Abstract base class for ICMP protocol family.

    - Internet Control Message Protocol (:class:`~pcapkit.protocols.internet.icmpv4.protocol.ICMPv4`) [:rfc:`792`]
    - Internet Control Message Protocol for IPv6 (:class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6`)
      [:rfc:`4443`]

    It dispatches where the version is known, never giving an instance of this
    class (:issue:`2574`). ``version`` names the member, from octets or from
    fields, and nothing else does: an ICMP message carries no version of its
    own, and no field picks a member, so either is refused without it.
    :meth:`from_data` gives the member whose data model it is handed, and
    refuses a :obj:`dict`. See :meth:`__new__`.

    """

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["ICMP"], Literal["ICMPv6"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('ICMP', 'ICMPv6')

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: As :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance; on this class, an instance of the member whose data
            model ``data`` is.

        Raises:
            ProtocolError: If ``data`` is neither member's data model, on this
                class. A :obj:`dict` is refused: it carries no version, and its
                keys need not tell the members apart, as an Echo message's do not.

        """
        if cls is not ICMP:
            return super().from_data(data, **kwargs)

        from pcapkit.protocols.internet.icmpv4.data import ICMPv4 as Data_ICMPv4  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.internet.icmpv6.data import ICMPv6 as Data_ICMPv6  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4  # isort: skip # pylint: disable=import-outside-toplevel
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6  # isort: skip # pylint: disable=import-outside-toplevel

        if isinstance(data, Data_ICMPv4):
            return cast('Self', ICMPv4.from_data(data, **kwargs))
        if isinstance(data, Data_ICMPv6):
            return cast('Self', ICMPv6.from_data(data, **kwargs))
        raise ProtocolError('ICMP: invalid data: must be an ICMPv4 or ICMPv6 data model')

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
            version: Version of ICMP, ``4`` or ``6``: the member :meth:`__new__`
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
            from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4  # isort: skip # pylint: disable=import-outside-toplevel
            from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6  # isort: skip # pylint: disable=import-outside-toplevel

            if not isinstance(self, (ICMPv4, ICMPv6)):
                raise ProtocolError(f'{type(self).__name__}: no version of its own to match '
                                    f'version={version!r}')
            raise ProtocolError(f'{type(self).__name__}: version={version!r} names another member')
        super().__init__(file, length, **kwargs)  # type: ignore[arg-type]

    def __new__(cls, file: 'Optional[IO[bytes] | bytes]' = None,
                length: 'Optional[int]' = None, **kwargs: 'Any') -> 'ICMP':
        """Create the member a construction of this class describes.

        The ``version`` keyword names the member, on either path, and nothing
        else does: an ICMP message carries no version of its own, and no field
        picks a member. That member's ``__init__`` then runs with the same
        arguments. A subclass of this class is created as itself.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            An uninitialised instance of the member.

        Raises:
            ProtocolError: If ``version`` is missing, or names neither member.
                Without it, octets are refused as fields are: the IP layer names
                the version, by protocol number 1 or 58.

        """
        if cls is not ICMP:
            return super().__new__(cls, file, length, **kwargs)
        version = kwargs.get('version')
        if version is None:
            if file is not None:
                raise ProtocolError('ICMP: no version field; pass version=4 or version=6, '
                                    'or parse with ICMPv4 or ICMPv6')
            raise ProtocolError('ICMP: no version to build with; pass version=4 or version=6')
        member = cls._member_of_version(version)
        return member.__new__(member, file, length, **kwargs)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @staticmethod
    def _member_of_version(version: 'Any') -> 'Type[ICMP]':
        """The member a ``version`` of ``4`` or ``6`` names.

        Args:
            version: Version of ICMP.

        Returns:
            :class:`~pcapkit.protocols.internet.icmpv4.protocol.ICMPv4` or
            :class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6`.

        Raises:
            ProtocolError: If ``version`` is neither, or is no :obj:`int`: a
                :obj:`bool` or a :obj:`float` is refused even where it equals one.

        """
        from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4  # isort: skip # pylint: disable=import-outside-toplevel
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6  # isort: skip # pylint: disable=import-outside-toplevel

        if isinstance(version, int) and not isinstance(version, bool):
            if version == 4:
                return cast('Type[ICMP]', ICMPv4)
            if version == 6:
                return cast('Type[ICMP]', ICMPv6)
        raise ProtocolError(f'ICMP: invalid version: {version!r}')
