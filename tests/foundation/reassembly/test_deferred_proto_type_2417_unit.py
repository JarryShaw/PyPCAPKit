# -*- coding: utf-8 -*-
""":class:`Deferred`'s ``proto`` annotation admits what both reassemblers pass.

GitHub issue :issue:`2417`.
:class:`~pcapkit.foundation.reassembly.data.data.Deferred` typed its ``proto``
parameter :class:`~pcapkit.const.reg.transtype.TransType` and documented it as
the payload protocol type. That is what
:meth:`IP.submit <pcapkit.foundation.reassembly.ip.IP.submit>` passes, but
:meth:`TCP.submit <pcapkit.foundation.reassembly.tcp.TCP.submit>` passes a
``(source, destination)`` port pair, because
:meth:`Transport.analyze
<pcapkit.protocols.transport.transport.Transport.analyze>` overrides that
parameter to one. mypy 2.3.1 said so:

.. code-block:: text

   pcapkit/foundation/reassembly/tcp.py:754:64: error: Argument 2 to "Deferred" has incompatible type "tuple[Any, Any]"; expected "TransType"  [arg-type]

The class is now **generic** over that value's type rather than declaring a
union of the two, so each instance's ``proto`` and the parameter its ``analyze``
expects are the same type. ``proto`` is therefore annotated with the type
variable, and what the declaration admits is that variable's *constraints*.

That rejects the pairing above -- a port pair against an analyser declared over
``TransType`` -- which is the direction a real mismatch takes. The reverse
pairing is not rejected by mypy alone: ``aenum`` ships no type stubs, so under
``ignore_missing_imports`` the ``aenum.IntEnum`` base of
:class:`~pcapkit.const.reg.transtype.TransType` resolves to ``Any``, and a
``Deferred[TransType]`` built over the port-pair analyser type-checks clean.
That is a gap in the dependency's type coverage rather than in the type
parameter. It is also why these tests read the declaration at runtime instead
of resting on mypy.

The runtime value was always correct, so there is no behaviour to pin. What
these tests pin is the declared type against the values the reassemblers really
hand it. Two of them fail on anything but the generic:
:meth:`DeclaredProtoTypeTests.test_declared_type_admits_what_each_reassembler_passes`
requires each value to be admitted by *exactly one* constraint and the two by
different ones, and
:meth:`DeclaredProtoTypeTests.test_the_analyser_takes_the_same_type_variable_as_proto`
requires the analyser to take the variable ``proto`` names. Against the
regression's single class, and against the union that first widened it, both
report that ``proto`` is annotated with a type rather than a type parameter.

The "different ones" half is what the parameter buys over a union: a union
admits a port pair and a protocol type on *either* call, so it cannot tell a
``Deferred[TransType]`` from a ``Deferred[tuple[int, int]]`` and leaves each
analyser's first parameter unconstrained. Pinning the annotation's text instead
would pass for a union that happened to name the right classes while still
excluding one of them.

Both cases build their packets in memory, read no capture, and never *call* the
held analyser -- only :attr:`Deferred.proto` is read, so nothing here depends on
a parser. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import ast
import types
import typing
import unittest
from ipaddress import ip_address

from tests._support import reimport_once_per_class

#: Test tier (#1958): reads an annotation and two in-memory reassemblies, so the
#: same text and the same values on every leg; nothing version-specific to sweep.
__tier__ = 'LATEST'

#: TCP ``BUFID``: source address, source port, destination address, destination
#: port. ``TCP.submit`` passes positions 1 and 3 of this to ``Deferred``.
TCP_BUFID = (ip_address('192.0.2.1'), 12345, ip_address('198.51.100.2'), 443)


def admits(declared: 'object', value: 'object') -> 'bool':
    """Whether the type ``declared`` accepts ``value``.

    :func:`isinstance` cannot be asked this directly: it rejects a
    parameterized generic such as ``tuple[int, int]`` with :exc:`TypeError`,
    and a union holding one is rejected with it. So unions are walked member by
    member, and a subscripted type is checked against its origin and then
    element by element.

    Args:
        declared: The annotated type, already evaluated.
        value: The value to test against it.

    Returns:
        Whether ``declared`` admits ``value``.

    """
    origin = typing.get_origin(declared)
    args = typing.get_args(declared)

    if origin in (types.UnionType, typing.Union):
        return any(admits(arg, value) for arg in args)
    if origin is tuple:
        return (isinstance(value, tuple) and len(value) == len(args)
                and all(admits(arg, item) for arg, item in zip(args, value)))
    if origin is not None:
        return isinstance(value, origin)
    return isinstance(value, declared)  # type: ignore[arg-type]


def held(datagram: 'object') -> 'object':
    """The unresolved ``packet`` placeholder of ``datagram``.

    Reading ``datagram.packet`` would resolve it through
    :meth:`DeferredPacket.__analyse__ <pcapkit.corekit.packet.DeferredPacket.__analyse__>`,
    which runs the analyser. The placeholder itself sits in
    :attr:`~object.__dict__` under the mangled name
    :attr:`Info.__map__ <pcapkit.corekit.infoclass.Info.__map__>` records for the
    field, which is what is read here.

    Args:
        datagram: A reassembled datagram whose ``packet`` is still deferred.

    Returns:
        The placeholder, unresolved.

    """
    key = datagram.__map__.get('packet', 'packet')  # type: ignore[attr-defined]
    return datagram.__dict__[key]


class AdmitsTests(unittest.TestCase):
    """:func:`admits` is what the test below leans on, so it is pinned too."""

    def test_union_member_and_tuple_shape(self) -> None:
        self.assertTrue(admits(int | tuple[int, int], 17))
        self.assertTrue(admits(int | tuple[int, int], (80, 443)))
        self.assertFalse(admits(int | tuple[int, int], (80, 443, 8080)))
        self.assertFalse(admits(int | tuple[int, int], ('80', '443')))
        self.assertFalse(admits(int | tuple[int, int], b'80'))

    def test_a_parameterized_generic_would_break_isinstance(self) -> None:
        """Which is why :func:`admits` exists rather than a bare ``isinstance``."""
        with self.assertRaises(TypeError):
            isinstance((80, 443), tuple[int, int])  # type: ignore[misc]


class DeclaredProtoTypeTests(unittest.TestCase):
    """What each reassembler passes as ``proto``, against what is declared."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _proto_type_variable():
        """The type variable :class:`Deferred` annotates its ``proto`` with.

        ``proto`` names the class's own type parameter rather than a type, which
        is what ties it to the parameter ``analyze`` expects. The lookup is by
        exact name against ``__parameters__``, where a ``Generic[...]`` subclass
        keeps its variables, so an annotation naming a *type* -- the single
        class the regression declared, or the union that first widened it --
        fails here, with what it found rather than with an
        :exc:`AttributeError` from a class that has no type parameters at all.

        """
        from pcapkit.foundation.reassembly.data.data import Deferred

        annotation = Deferred.__init__.__annotations__['proto']
        by_name = {variable.__name__: variable
                   for variable in getattr(Deferred, '__parameters__', ())}
        if annotation not in by_name:
            raise AssertionError(
                f'Deferred.__init__ annotates proto {annotation!r}, which is not one of its '
                f'type parameters {tuple(by_name)!r}: the class is expected to be generic '
                'over what the analyser dispatches the payload on')
        return by_name[annotation]

    @classmethod
    def _declared_proto_types(cls):
        """What that type variable is constrained to, each one evaluated.

        A constraint is written as a string literal, since
        :class:`~pcapkit.const.reg.transtype.TransType` is imported under
        ``TYPE_CHECKING`` and nothing at runtime has it in scope; the namespace
        is rebuilt here rather than asking :func:`typing.get_type_hints`, which
        raises :exc:`NameError` on it. :class:`~typing.TypeVar` keeps such a
        constraint as the string itself from Python 3.14 and as a
        :class:`typing.ForwardRef` before it, so both spellings are unwrapped.

        Returns:
            The admissible types, in declaration order.

        """
        from pcapkit.const.reg.transtype import TransType

        return tuple(
            eval(getattr(constraint, '__forward_arg__', constraint),  # pylint: disable=eval-used
                 {'TransType': TransType})
            for constraint in cls._proto_type_variable().__constraints__
        )

    def _ip_proto(self):
        """The ``proto`` ``IP.submit`` hands to :class:`Deferred`."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data.ip import Packet
        from pcapkit.foundation.reassembly.ipv4 import IPv4

        reasm = IPv4()
        reasm(Packet((ip_address('192.0.2.1'), ip_address('198.51.100.2'), 42, TransType.UDP),
                     1, 0, 20, False, 25, b'ip-header', bytearray(b'hello'), 1000.0))
        datagram, = reasm.datagram
        return held(datagram).proto

    def _tcp_proto(self):
        """The ``proto`` ``TCP.submit`` hands to :class:`Deferred`."""
        from pcapkit.foundation.reassembly.data.tcp import Packet
        from pcapkit.foundation.reassembly.tcp import TCP

        reasm = TCP()
        reasm(Packet(TCP_BUFID, 1, 500, 1, False, True, False, 5, 1, 5,
                     b'', bytearray(b'hello'), 1000.0))
        datagram, = reasm.datagram
        return held(datagram).proto

    def test_ip_passes_the_payload_protocol_type(self) -> None:
        """IP reassembly reads it from the datagram's **Protocol** field."""
        from pcapkit.const.reg.transtype import TransType

        self.assertIs(self._ip_proto(), TransType.UDP)

    def test_tcp_passes_a_port_pair(self) -> None:
        """A reassembled stream carries no protocol number, so it keys on ports."""
        self.assertEqual(self._tcp_proto(), (TCP_BUFID[1], TCP_BUFID[3]))

    def test_the_analyser_takes_the_same_type_variable_as_proto(self) -> None:
        """The tie the type parameter exists for, read out of the annotation.

        The first parameter of ``analyze``'s :class:`~typing.Callable` is the
        variable ``proto`` names, so the declaration ties the two together
        instead of leaving the analyser's first parameter free. How far a type
        checker enforces that tie is asymmetric, for the reason the module
        docstring gives. The annotation is parsed rather than compared as text,
        which would break on any reformatting of it.

        """
        from pcapkit.foundation.reassembly.data.data import Deferred

        callable_ = ast.parse(Deferred.__init__.__annotations__['analyze'], mode='eval').body
        parameters, _ = callable_.slice.elts  # ``Callable[[...], ProtocolBase]``
        first, _ = parameters.elts            # ``[_KT, bytes]``
        self.assertEqual(first.id, self._proto_type_variable().__name__)

    def test_declared_type_admits_what_each_reassembler_passes(self) -> None:
        """The regression: the port pair was outside the declared type.

        Each value has to land on *exactly one* constraint, and the two on
        different ones -- otherwise the type parameter is not distinguishing the
        two reassemblers and a union would have done.

        """
        declared = self._declared_proto_types()
        matched = {}
        for name, value in (('ip', self._ip_proto()), ('tcp', self._tcp_proto())):
            with self.subTest(reassembler=name):
                admitting = [each for each in declared if admits(each, value)]
                self.assertEqual(len(admitting), 1,
                                 f'{value!r} is admitted by {admitting!r}, not by exactly '
                                 f'one of {declared!r}')
                matched[name] = admitting[0]
        # NOTE: a failing ``subTest`` does not stop the loop, so one of these may
        # be absent; reading it anyway would raise :exc:`KeyError` over the real
        # failure the subtest has already reported.
        if len(matched) == 2:
            self.assertNotEqual(matched['ip'], matched['tcp'],
                                f'both reassemblers resolved to {matched["ip"]!r}, so the type '
                                'parameter distinguishes nothing a union would not')

    def test_the_held_analyser_is_not_called_to_learn_this(self) -> None:
        """``packet`` is still deferred after ``proto`` has been read."""
        from pcapkit.foundation.reassembly.data.data import Deferred
        from pcapkit.foundation.reassembly.data.tcp import Packet
        from pcapkit.foundation.reassembly.tcp import TCP

        reasm = TCP()
        reasm(Packet(TCP_BUFID, 1, 500, 1, False, True, False, 5, 1, 5,
                     b'', bytearray(b'hello'), 1000.0))
        datagram, = reasm.datagram
        placeholder = held(datagram)
        self.assertIsInstance(placeholder, Deferred)
        self.assertEqual(placeholder.proto, (TCP_BUFID[1], TCP_BUFID[3]))
        self.assertIsInstance(held(datagram), Deferred)


if __name__ == '__main__':
    unittest.main()
