# -*- coding: utf-8 -*-
"""Base Protocol
===================

:mod:`pcapkit.protocols.transport.transport` contains
:class:`~pcapkit.protocols.transport.transport.Transport`,
which is a base class for transport layer protocols, eg.
:class:`~pcapkit.protocols.transport.transport.tcp.TCP` and
:class:`~pcapkit.protocols.transport.transport.udp.UDP`.

"""
import importlib
import io
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.protocols.protocol import PT, Protocol
from pcapkit.utilities.exceptions import StructError, UnsupportedCall, stacklevel
from pcapkit.utilities.logging import DEVMODE, logger

if TYPE_CHECKING:
    from typing import Any, Optional, Type

    from typing_extensions import Literal

__all__ = ['Transport']


class Transport(Protocol[PT], Generic[PT]):  # pylint: disable=abstract-method
    """Abstract base class for transport layer protocol family."""

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
    def register(cls, code: 'int', module: str, class_: str) -> 'None':
        """Register a new protocol class.

        Important:
            This method must be called from a non-abstract class, as the
            protocol map should be associated directly with specific
            transport layer protocol type.

        Arguments:
            code: port number
            module: module name
            class_: class name

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{module}.{class_}``.

        """
        if cls is Transport:
            raise UnsupportedCall(f'{cls.__name__} is an abstract class')

        cls.__proto__[code] = (module, class_)

    @classmethod
    def analyze(cls, ports: 'tuple[int, int]', payload: 'bytes', **kwargs: 'Any') -> 'Protocol':  # type: ignore[override] # pylint: disable=arguments-renamed
        """Analyse packet payload.

        Args:
            ports: Source & destination port numbers.
            payload: Packet payload.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed payload as a :class:`~pcapkit.protocols.protocol.Protocol`
            instance.

        """
        if ports[0] in cls.__proto__:
            module, name = cls.__proto__[ports[0]]
        else:
            module, name = cls.__proto__[ports[1]]
        protocol = cast('Type[Protocol]', getattr(importlib.import_module(module), name))

        payload_io = io.BytesIO(payload)
        try:
            report = protocol(payload_io, len(payload), **kwargs)  # type: ignore[abstract]
        except Exception as exc:
            if isinstance(exc, StructError) and exc.eof:  # pylint: disable=no-member
                from pcapkit.protocols.misc.null import NoPayload as protocol  # type: ignore[no-redef] # pylint: disable=import-outside-toplevel # isort:skip
            else:
                from pcapkit.protocols.misc.raw import Raw as protocol  # type: ignore[no-redef] # pylint: disable=import-outside-toplevel # isort:skip
            # error = traceback.format_exc(limit=1).strip().rsplit(os.linesep, maxsplit=1)[-1]

            # log error
            logger.error(str(exc), exc_info=exc, stack_info=DEVMODE, stacklevel=stacklevel())

            report = protocol(payload_io, len(payload), **kwargs)  # type: ignore[abstract]
        return report

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _decode_next_layer(self, dict_: 'PT', ports: 'tuple[int, int]', length: 'Optional[int]' = None) -> 'PT':  # type: ignore[override] # pylint: disable=arguments-renamed
        """Decode next layer protocol.

        The method will check if the next layer protocol is supported based on
        the source and destination port numbers. We will use the lower port
        number from both ports as the primary key to lookup the next layer.

        Arguments:
            dict_: info buffer
            ports: source & destination port numbers
            length: valid (*non-padding*) length

        Returns:
            Current protocol with next layer extracted.

        """
        sort_port = sorted(ports)
        proto = sort_port[0] if sort_port[0] in self.__proto__ else sort_port[1]
        return super()._decode_next_layer(dict_, proto, length)
