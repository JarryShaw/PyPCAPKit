# -*- coding: utf-8 -*-
"""Base Protocol
===================

.. module:: pcapkit.protocols.application.application

:mod:`pcapkit.protocols.application.application` contains only
:class:`~pcapkit.protocols.application.application.Application`,
which is a base class for application layer protocols, e.g.
:class:`HTTP/1.* <pcapkit.protocols.application.httpv1.HTTP>` and
:class:`HTTP/2 <pcapkit.protocols.application.httpv2.HTTP>`.

"""
from typing import TYPE_CHECKING, Generic, overload

from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.protocols.protocol import _PT, _ST, ProtocolBase
from pcapkit.protocols.schema.schema import keep_short_read, replay_short_read
from pcapkit.utilities.exceptions import IntError, UnsupportedCall

if TYPE_CHECKING:
    from typing import IO, Any, NoReturn, Optional

    from typing_extensions import Literal, Self

__all__ = ['Application']


class Application(ProtocolBase[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Abstract base class for application layer protocol family.

    An application layer protocol has no further *protocol* layer above it, so
    :meth:`_decode_next_layer` and :meth:`_import_next_layer` refuse to dispatch
    on a protocol number. What they do permit is the ``-1`` sentinel, which asks
    for the rest of the packet undissected and resolves to
    :class:`~pcapkit.protocols.misc.raw.Raw` -- trailing bytes are not a further
    protocol layer -- or to :class:`~pcapkit.protocols.misc.null.NoPayload` when
    nothing remains.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Application'  # type: Literal['Application']

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self) -> 'Literal["Application"]':
        """Protocol layer."""
        return self.__layer__

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None,
                      length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction arguments, please refer to
            :meth:`self.make <pcapkit.protocols.protocol.Protocol.make>`.

        """
        # call super post-init
        super().__post_init__(file, length, **kwargs)  # type: ignore[arg-type]

        # NOTE: A header the data ends inside keeps that in its ``info``, so
        # that :meth:`from_data` rebuilds only what was captured (:issue:`1458`).
        keep_short_read(self)

        # ``read`` may have dispatched the undissected remainder through
        # ``_decode_next_layer``, which already set the payload and the chain
        # (basis included); only a protocol that did not gets the empty default
        if getattr(self, '_next', None) is None:
            #: pcapkit.protocols.misc.null.NoPayload: Payload of current instance.
            self._next = NoPayload()
            #: pcapkit.corekit.protochain.ProtoChain: Protocol chain of current instance.
            self._protos = ProtoChain(self.__class__, self.alias)

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            IntError: This protocol doesn't support :meth:`__index__`.

        """
        raise IntError(f'{cls.__name__!r} object cannot be interpreted as an integer')

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
    # Utilities.
    ##########################################################################

    def _decode_next_layer(self, dict_: '_PT', proto: 'Optional[int]' = None, length: 'Optional[int]' = None, *,
                           packet: 'Optional[dict[str, Any]]' = None) -> '_PT':
        r"""Decode next layer protocol.

        Arguments:
            dict\_: info buffer
            proto: next layer protocol index; only the ``-1`` sentinel
                (the rest, undissected) is accepted
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <Protocol.unpack>`)

        Returns:
            Current protocol with the undissected remainder as payload.

        Raises:
            UnsupportedCall: ``proto`` is anything but ``-1``, i.e. a real
                protocol dispatch, which this protocol doesn't support.

        """
        if proto != -1:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object cannot dispatch protocol {proto!r}; "
                                  "only the undissected remainder (-1) is supported")
        return super()._decode_next_layer(dict_, -1, length, packet=packet)

    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[override]
                           packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index; only the ``-1`` sentinel
                (the rest, undissected) is accepted
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <Protocol.unpack>`)

        Returns:
            Instance of :class:`~pcapkit.protocols.misc.raw.Raw`, or of
            :class:`~pcapkit.protocols.misc.null.NoPayload` when nothing remains.

        Raises:
            UnsupportedCall: ``proto`` is anything but ``-1``, i.e. a real
                protocol dispatch, which this protocol doesn't support.

        """
        if proto != -1:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object cannot dispatch protocol {proto!r}; "
                                  "only the undissected remainder (-1) is supported")
        return super()._import_next_layer(-1, length, packet=packet)  # type: ignore[call-arg,misc]
