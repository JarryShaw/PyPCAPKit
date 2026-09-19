# -*- coding: utf-8 -*-
"""shared data models for flow tracing"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

__all__ = ['TraceFlowData', 'Deferred', 'DeferredPacket']

if TYPE_CHECKING:
    from typing import Any, Optional

    from pcapkit.foundation.reassembly.data.tcp import Datagram as TCP_Datagram
    from pcapkit.foundation.reassembly.tcp import TCP as TCP_Reassembly
    from pcapkit.foundation.traceflow.data.tcp import Index as TCP_Index


class Deferred:
    """A postponed reassembly of a traced flow's application layer.

    A traced flow's ``packet`` is the application-layer payload of the
    conversation, one datagram per direction. Producing it means reassembling the
    stream, which is neither free nor wanted by most callers of a *tracer* -- so
    the flow keeps the reassembler it was fed and this holds it until somebody
    reads
    :attr:`Index.packet <pcapkit.foundation.traceflow.data.tcp.Index.packet>`.

    Note:
        Deliberately not
        :class:`pcapkit.foundation.reassembly.data.data.Deferred`, and not shared
        with it. That one postpones a single ``analyze()`` call over bytes already
        in hand; this postpones a *submit* over a reassembler's buffers. The two
        subpackages are siblings and neither should depend on the other, so the
        twenty lines are written twice rather than one importing the other -- the
        same reason the two ``data/data.py`` modules mirror each other instead of
        merging.

    Args:
        reassembly: The flow's own
            :class:`~pcapkit.foundation.reassembly.tcp.TCP` reassembler, fed the
            segments of this conversation as they were traced.

    """

    __slots__ = ('reassembly',)

    def __init__(self, reassembly: 'TCP_Reassembly') -> 'None':
        self.reassembly = reassembly

    def __call__(self) -> 'tuple[TCP_Datagram, ...]':
        """Run the postponed reassembly.

        Returns:
            One reassembled datagram per direction of the conversation. Each
            carries its *own* postponed analysis in
            :attr:`Datagram.packet <pcapkit.foundation.reassembly.data.tcp.Datagram.packet>`,
            so parsing the payload as an application-layer protocol is still not
            paid for until that is read in turn.

        """
        return self.reassembly.datagram


class DeferredPacket:
    """Resolves a :class:`Deferred` ``packet`` field on first read.

    The reading half of the arrangement above, and the counterpart of
    :class:`pcapkit.foundation.reassembly.data.data.DeferredPacket`.

    A subclass has to list ``packet`` in its ``__additional__``. That is what makes
    the field lazy at all: :class:`~pcapkit.corekit.infoclass.Info` stores a field
    named there under a mangled key and maps it back on the way out, so ``packet``
    never lands in :attr:`~object.__dict__` itself -- which routes reading it
    through :meth:`__getattr__`, where the deferred reassembly can run, while
    ``dict(index)``, :meth:`to_dict` and iteration still report the field under its
    own name.

    """

    # NOTE: the ``super()`` calls below are suppressed for both checkers. They are
    # undefined *on this mixin*, which is what a mixin is -- the base arrives at
    # the point of use, where every subclass is declared
    # ``class X(DeferredPacket, Info)`` and :class:`~pcapkit.corekit.infoclass.Info`
    # supplies all three. Neither mypy nor pylint can see that from here, and
    # pylint calls it an *error* rather than a warning.

    def __analyse__(self) -> 'Optional[tuple[TCP_Datagram, ...]]':
        """Resolve a deferred reassembly, at most once.

        Returns:
            The flow's reassembled datagrams, or :data:`None` when the tracer was
            not asked to analyse the application layer.

        """
        key = self.__map__.get('packet', 'packet')
        value = self.__dict__[key]
        if isinstance(value, Deferred):
            value = value()
            self.__dict__[key] = value
        return value

    def __getattr__(self, name: 'str') -> 'Any':
        # NOTE: reached only for names absent from ``__dict__``, which ``packet``
        # always is -- see ``__additional__`` above. Everything else has to raise,
        # or a typo would silently answer with a reassembled flow.
        if name != 'packet':
            raise AttributeError(f'{type(self).__name__!r} object has no attribute {name!r}')
        return self.__analyse__()

    def __getitem__(self, name: 'str') -> 'Any':
        if name == 'packet':
            return self.__analyse__()
        return super().__getitem__(name)  # type: ignore[misc] # pylint: disable=no-member

    def __contains__(self, name: 'object') -> 'bool':
        # NOTE: ``Mapping.__contains__`` answers by fetching the value, which would
        # run the deferred reassembly merely to decide that the field exists.
        # ``packet`` is a declared field, so it is always there.
        return name == 'packet' or super().__contains__(name)  # type: ignore[misc] # pylint: disable=no-member

    def __str__(self) -> 'str':
        self.__analyse__()
        return super().__str__()

    def __repr__(self) -> 'str':
        self.__analyse__()
        return super().__repr__()

    def to_dict(self) -> 'dict[str, Any]':
        """Convert :class:`Index` into :obj:`dict`.

        Returns:
            The flow's fields, with ``packet`` reassembled if it had not been read
            yet -- a :obj:`dict` holding a :class:`Deferred` would leak an
            implementation detail into what is meant to be plain data.

        """
        self.__analyse__()
        return super().to_dict()  # type: ignore[misc] # pylint: disable=no-member


@info_final
class TraceFlowData(Info):
    """Data storage for flow tracing."""

    #: TCP traced flows.
    tcp: 'tuple[TCP_Index, ...]'

    if TYPE_CHECKING:
        def __init__(self, tcp: 'Optional[tuple[TCP_Index, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
