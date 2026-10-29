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

The port pair itself then moved: both constraints are *named registry values*,
so ``TCP.submit`` resolves each port through :meth:`Transport._make_port
<pcapkit.protocols.transport.transport.Transport._make_port>` and the constraint
is ``tuple[AppType_TCP, AppType_TCP]`` -- the *per-transport* registry, which
is what the resolution really answers with -- rather than ``tuple[int, int]``.
A deferred analysis now dispatches on a member of the registry
:attr:`TCP.src <pcapkit.protocols.transport.tcp.TCP.src>` reads from: the very
same member for a registered port, an equal one reached by a different route
for an unassigned one (see :meth:`ResolvedPortTests.test_an_unassigned_port_is_equal_to_the_parse_paths_own`),
and :meth:`Transport.analyze
<pcapkit.protocols.transport.transport.Transport.analyze>` declares that pair.
Unlike the generic itself, this half *is* a runtime change --
:class:`~pcapkit.const.reg.apptype.apptype.AppType` is a
:class:`~enum.StrEnum`, so it is no :obj:`int` at all and
``isinstance(port, int)`` is now :data:`False` -- which is what
:class:`ResolvedPortTests` pins.

Three cases fail on anything but the generic over named values:
:meth:`DeclaredProtoTypeTests.test_declared_type_admits_what_each_reassembler_passes`
requires each value to be admitted by *exactly one* constraint and the two by
different ones,
:meth:`DeclaredProtoTypeTests.test_the_analyser_takes_the_same_type_variable_as_proto`
requires the analyser to take the variable ``proto`` names, and
:meth:`ResolvedPortTests.test_submit_hands_over_resolved_application_types`
requires the values themselves to be members. Against the regression's single
class, and against the union that first widened it, the first two report that
``proto`` is annotated with a type rather than a type parameter; against the
bare port pair, the first fails because ``tuple[AppType_TCP, AppType_TCP]``
does not admit it and the third because an :obj:`int` is not a member.

The "different ones" half is what the parameter buys over a union: a union
admits a port pair and a protocol type on *either* call, so it cannot tell a
``Deferred[TransType]`` from a ``Deferred[tuple[AppType_TCP, AppType_TCP]]`` and leaves
each analyser's first parameter unconstrained. Pinning the annotation's text
instead would pass for a union that happened to name the right classes while
still excluding one of them.

Every case builds its packets in memory and reads no capture. Those in
:class:`DeclaredProtoTypeTests` never *call* the held analyser either -- only
:attr:`Deferred.proto` is read, so nothing there depends on a parser. Classes
are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import ast
import types
import typing
import unittest
from ipaddress import ip_address

from tests._support import reimport_once_per_class

#: Test tier (#1958): reads an annotation and a handful of in-memory
#: reassemblies, so the same text and the same values on every leg; nothing
#: version-specific to sweep.
__tier__ = 'LATEST'

#: TCP ``BUFID``: source address, source port, destination address, destination
#: port. ``TCP.submit`` passes positions 1 and 3 of this to ``Deferred``. Both
#: ports carry an IANA assignment -- ``italk`` and ``https`` -- so the resolved
#: members are named ones; :data:`UNASSIGNED_BUFID` covers the other case.
TCP_BUFID = (ip_address('192.0.2.1'), 12345, ip_address('198.51.100.2'), 443)

#: As :data:`TCP_BUFID`, but on ports IANA assigns no service to and lists in no
#: span of its own, which resolve to unregistered ``unknown`` members rather
#: than raising or coming back as :data:`None`.
UNASSIGNED_BUFID = (ip_address('192.0.2.1'), 50000, ip_address('198.51.100.2'), 65535)


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


def tcp_proto(bufid=TCP_BUFID):
    """The ``proto`` ``TCP.submit`` hands :class:`Deferred` for ``bufid``.

    One segment with a FIN, which closes the stream and so submits it complete:
    the partial branch of ``submit`` reports ``packet=None`` and builds no
    :class:`~pcapkit.foundation.reassembly.data.data.Deferred` to read.

    Args:
        bufid: The buffer identifier to reassemble under, i.e. where the ports
            come from.

    Returns:
        The placeholder's ``proto``, unresolved.

    """
    from pcapkit.foundation.reassembly.data.tcp import Packet
    from pcapkit.foundation.reassembly.tcp import TCP

    reasm = TCP()
    reasm(Packet(bufid, 1, 500, 1, False, True, False, 5, 1, 5,
                 b'', bytearray(b'hello'), 1000.0))
    datagram, = reasm.datagram
    return held(datagram).proto


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
        :class:`~pcapkit.const.reg.transtype.TransType` and
        :class:`~pcapkit.const.reg.apptype.tcp.TCP` are both imported
        under ``TYPE_CHECKING`` and nothing at runtime has either in scope; the
        namespace is rebuilt here rather than asking
        :func:`typing.get_type_hints`, which raises :exc:`NameError` on them.
        :class:`~typing.TypeVar` keeps such a constraint as the string itself
        from Python 3.14 and as a :class:`typing.ForwardRef` before it, so both
        spellings are unwrapped.

        Returns:
            The admissible types, in declaration order.

        """
        from pcapkit.const.reg.apptype import TCP as AppType_TCP
        from pcapkit.const.reg.transtype import TransType

        return tuple(
            eval(getattr(constraint, '__forward_arg__', constraint),  # pylint: disable=eval-used
                 {'TransType': TransType, 'AppType_TCP': AppType_TCP})
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

    def _tcp_proto(self, bufid=TCP_BUFID):
        """The ``proto`` ``TCP.submit`` hands to :class:`Deferred`."""
        return tcp_proto(bufid)

    def test_ip_passes_the_payload_protocol_type(self) -> None:
        """IP reassembly reads it from the datagram's **Protocol** field."""
        from pcapkit.const.reg.transtype import TransType

        self.assertIs(self._ip_proto(), TransType.UDP)

    def test_tcp_passes_a_port_pair(self) -> None:
        """A reassembled stream carries no protocol number, so it keys on ports.

        The pair compares equal to the bare port numbers it was resolved from --
        :meth:`AppType.__eq__ <pcapkit.const.reg.apptype.apptype.AppType.__eq__>`
        compares against :attr:`AppType.port
        <pcapkit.const.reg.apptype.apptype.AppType.port>` -- which is exactly why
        an equality assertion cannot tell the two apart and
        :class:`ResolvedPortTests` checks the members themselves.

        """
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


class ResolvedPortTests(unittest.TestCase):
    """The ports themselves, not the declaration: members rather than numbers.

    This is the half of :issue:`2417` that runs. The declaration above would be
    satisfied by a ``tuple[AppType_TCP, AppType_TCP]`` constraint over a ``submit`` that
    still passed bare numbers -- :func:`admits` would simply report that nothing
    admits the pair -- so what pins the resolution is reading the values.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_submit_hands_over_resolved_application_types(self) -> None:
        """Each port is the member its registry holds, carrying TCP's transport.

        Named outright rather than compared against a second
        :meth:`AppType.get <pcapkit.const.reg.apptype.apptype.AppType.get>` call,
        which would pass against a ``submit`` that resolved the wrong transport's
        registry as readily as the right one.

        """
        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        src, dst = tcp_proto()
        for port, member, service in ((TCP_BUFID[1], src, 'italk'),
                                      (TCP_BUFID[3], dst, 'https')):
            with self.subTest(port=port):
                self.assertIsInstance(member, AppType)
                self.assertEqual(member.port, port)
                self.assertEqual(member.svc, service)
                self.assertIs(member.proto, TransportProtocol.tcp)

    def test_each_port_is_a_member_of_the_per_transport_tcp_registry(self) -> None:
        """Not merely *an* ``AppType`` -- the TCP partition, exactly.

        ``proto=tcp`` sends :meth:`AppType.get
        <pcapkit.const.reg.apptype.apptype.AppType.get>` through
        :meth:`AppType._dispatch
        <pcapkit.const.reg.apptype.apptype.AppType._dispatch>` to
        :class:`~pcapkit.const.reg.apptype.tcp.TCP`, so ``type(...) is TCP``
        rather than merely ``isinstance(..., AppType)``. That is what lets the
        annotations name the narrow registry, and it is checked with ``is``
        because an ``isinstance`` against the base would also pass for a member
        of the UDP or SCTP partition -- which is the mistake the narrow
        annotation exists to catch.

        """
        from pcapkit.const.reg.apptype import TCP as AppType_TCP

        for bufid in (TCP_BUFID, UNASSIGNED_BUFID):
            for member in tcp_proto(bufid):
                with self.subTest(port=member.port):
                    self.assertIs(type(member), AppType_TCP)

    def test_an_unassigned_port_is_equal_to_the_parse_paths_own(self) -> None:
        """Equal and of one registry, but not the same object, and named apart.

        The claim worth stating precisely rather than overstating: for a
        *registered* port this resolution and the parse path's own give the very
        same member, but for an unassigned one they build equal members by
        different routes -- the parse path through
        :meth:`EnumField._unregistered_member
        <pcapkit.corekit.fields.numbers.EnumField._unregistered_member>`, named
        ``'<unassigned>'``, and this one through ``get``'s own, named
        ``'unknown'``. Both carry the same :attr:`AppType.port
        <pcapkit.const.reg.apptype.apptype.AppType.port>`, which is what every
        reader of the pair goes on to use.

        """
        from pcapkit.const.reg.apptype import TransportProtocol
        from pcapkit.protocols.schema.transport.tcp import TCP as Schema_TCP

        field = Schema_TCP.__fields__['srcport']

        registered, _ = tcp_proto()
        self.assertIs(field.post_process(TCP_BUFID[1], None), registered)
        self.assertIs(registered.proto, TransportProtocol.tcp)

        unassigned, _ = tcp_proto(UNASSIGNED_BUFID)
        parsed = field.post_process(UNASSIGNED_BUFID[1], None)
        self.assertEqual(parsed, unassigned)
        self.assertIsNot(parsed, unassigned)
        self.assertEqual(parsed.port, unassigned.port)
        self.assertEqual((parsed.name, unassigned.name), ('<unassigned>', 'unknown'))

    def test_a_resolved_port_is_no_longer_an_int(self) -> None:
        """The runtime change, stated as the thing a caller could notice.

        :class:`~pcapkit.const.reg.apptype.apptype.AppType` derives from
        :class:`str`, so the pair is outside ``tuple[int, int]`` at runtime as
        well as to a type checker, and that is what makes the old constraint
        wrong rather than merely loose. It still *compares* equal to the number,
        which is why nothing downstream of ``submit`` had to change.

        """
        src, _ = tcp_proto()
        self.assertNotIsInstance(src, int)
        self.assertEqual(src, TCP_BUFID[1])
        self.assertEqual(int(src), TCP_BUFID[1])
        self.assertEqual(hash(src), hash(TCP_BUFID[1]))

    def test_an_unassigned_port_resolves_rather_than_raising(self) -> None:
        """Every port a 16-bit field can hold has to come back as *something*.

        :meth:`AppType.get <pcapkit.const.reg.apptype.apptype.AppType.get>`
        answers a port in no IANA span with an unregistered ``unknown`` member
        and mints nothing into the registry (:issue:`860`), so resolving in
        ``submit`` cannot fail on a capture of traffic on an ephemeral port --
        which is most captures, and would otherwise have made this change a new
        way for reassembly to raise.

        """
        from pcapkit.const.reg.apptype import AppType

        src, dst = tcp_proto(UNASSIGNED_BUFID)
        for port, member in ((UNASSIGNED_BUFID[1], src), (UNASSIGNED_BUFID[3], dst)):
            with self.subTest(port=port):
                self.assertIsInstance(member, AppType)
                self.assertEqual(member.svc, 'unknown')
                self.assertEqual(member.port, port)

    def test_resolving_grows_no_registry(self) -> None:
        """Neither the application-type registry nor the next-layer one."""
        from pcapkit.const.reg.apptype import TCP as AppType_TCP
        from pcapkit.protocols.transport.tcp import TCP as TCP_Protocol

        before_apptype = len(AppType_TCP.__registry__)
        before_proto = sorted(TCP_Protocol.__proto__)

        tcp_proto(UNASSIGNED_BUFID)

        self.assertEqual(len(AppType_TCP.__registry__), before_apptype)
        self.assertEqual(sorted(TCP_Protocol.__proto__), before_proto)

    def test_the_pair_is_what_the_analyser_dispatches_on(self) -> None:
        """End to end: the resolved pair still selects the registered next layer.

        ``Transport.analyze`` keys :attr:`TCP.__proto__
        <pcapkit.protocols.transport.tcp.TCP.__proto__>` on the port, and that
        mapping is keyed by number, so the members have to reach it as the
        numbers they carry. Port 80 is bound to the version-dispatching HTTP
        class; the unassigned pair falls through to the registry's own fallback.

        """
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.tcp import TCP as TCP_Protocol

        http_bufid = (ip_address('192.0.2.1'), 54321, ip_address('198.51.100.2'), 80)
        self.assertIsInstance(
            TCP_Protocol.analyze(tcp_proto(http_bufid), b'GET / HTTP/1.1\r\n\r\n'), HTTP)
        self.assertIsInstance(
            TCP_Protocol.analyze(tcp_proto(UNASSIGNED_BUFID), b'not a protocol'), Raw)

    def test_a_custom_analyser_need_not_be_a_transport(self) -> None:
        """``__protocol_type__`` is an extension point, so ``_make_port`` is not read off it.

        The analyser plugged in here defines ``analyze`` and nothing else, which
        is all :attr:`ReassemblyBase.protocol
        <pcapkit.foundation.reassembly.reassembly.ReassemblyBase.protocol>`
        promises. Resolving the ports through it instead of through
        :class:`~pcapkit.protocols.transport.tcp.TCP` would raise
        :exc:`AttributeError` here, and it is the reassembly tests' own idiom.

        """
        from pcapkit.const.reg.apptype import AppType
        from pcapkit.foundation.reassembly.data.tcp import Packet
        from pcapkit.foundation.reassembly.tcp import TCP

        class Analyzer:  # pylint: disable=too-few-public-methods
            """Everything ``__protocol_type__`` is required to be."""

            @classmethod
            def analyze(cls, ports, payload):
                return (ports, payload)

        class TestTCP(TCP):
            __protocol_type__ = Analyzer

        reasm = TestTCP()
        reasm(Packet(TCP_BUFID, 1, 500, 1, False, True, False, 5, 1, 5,
                     b'', bytearray(b'hello'), 1000.0))
        datagram, = reasm.datagram
        ports, payload = datagram.packet
        self.assertEqual(payload, b'hello')
        self.assertEqual(ports, (TCP_BUFID[1], TCP_BUFID[3]))
        for member in ports:
            self.assertIsInstance(member, AppType)


if __name__ == '__main__':
    unittest.main()
