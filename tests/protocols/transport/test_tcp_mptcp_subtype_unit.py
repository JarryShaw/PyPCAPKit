# -*- coding: utf-8 -*-
"""``MPTCP.subtype`` is set for a schema built in memory, not only one parsed from bytes.

GitHub issue #566.

The construction path
---------------------

:class:`~pcapkit.protocols.schema.transport.tcp.MPTCP`, the base class every Multipath TCP
subtype schema inherits, declares ``subtype`` only under :data:`~typing.TYPE_CHECKING`:

.. code-block:: python

    if TYPE_CHECKING:
        #: MPTCP subtype.
        subtype: 'Enum_MPTCPOption'

so it is an annotation for a type checker, not a field any schema packs.
:meth:`_MPTCP.post_process <pcapkit.protocols.schema.transport.tcp._MPTCP.post_process>`
assigns ``schema.subtype`` once per option while parsing real bytes off the wire. Building
an option through :class:`~pcapkit.protocols.transport.tcp.TCP`'s convenience constructor --
``TCP(options=[(Enum_Option.Multipath_TCP, {'subtype': ..., **kwargs})], ...)`` -- never
unpacks anything: the dispatcher (``TCP._make_mode_mp``) calls the matching ``_make_mptcp_*``
maker to build the schema in memory and then hands that same schema straight to the matching
``_read_mptcp_*`` to build the :class:`~pcapkit.protocols.data.transport.tcp.MPTCP` data
model -- and every ``_read_mptcp_*`` method reads ``schema.subtype``. So
:meth:`TCP._make_mode_mp <pcapkit.protocols.transport.tcp.TCP._make_mode_mp>`, the single
dispatcher every ``_make_mptcp_*`` maker returns through, sets ``schema.subtype =
subtype_val`` right after building the schema -- the same assignment
:meth:`_MPTCP.post_process` makes for a real unpack, made unconditionally. Without it,
``TCP(options=[(Enum_Option.Multipath_TCP, {'subtype': Enum_MPTCPOption.MP_FAIL, 'dsn':
7})], ...)`` raises ``AttributeError: 'MPTCPFallback' object has no attribute 'subtype'``.

Why a real field is not the answer
-----------------------------------

``kind`` and ``length`` are real fields on ``MPTCP`` (#541), and the obvious next step is to
do the same for ``subtype``. That would be wrong here, and the difference is worth recording
so that a reader knows the pattern was considered as a whole rather than patched by reflex.

``kind`` and ``length`` are each the *sole* source of their own octet -- nothing else in any
subtype schema packs them, so a real field is the only way to get them onto the wire at all.
``subtype`` is not like that: every concrete subclass encodes it as 4 bits of its own
``test`` :class:`~pcapkit.corekit.fields.strings.BitField` (e.g.
``MPTCPCapable.test['subtype']``), which is what the wire format actually carries. Declaring
a second, independent ``Field`` for the same 4 bits would either double-pack them under two
names, or need a "derive this from another field, do not pack it yourself" kind of field --
which nothing in :mod:`pcapkit.corekit.fields` provides (every ``FieldBase`` subclass either
contributes its own bytes or selects among nested schemas; none merely mirrors a sibling
field's decoded value into a second attribute). So ``MPTCP.subtype`` stays an annotation,
populated on the *construction* path.

That leaves no other ``TYPE_CHECKING``-only *data* attribute on ``MPTCP`` itself: the class
body has ``kind`` and ``length`` (real fields) and ``subtype`` (set by the construction
path). The ``if TYPE_CHECKING: def __init__(...): ...`` blocks inside the concrete subclasses
below it are ordinary typed-signature stubs for the ``__init__`` that
:class:`~pcapkit.protocols.schema.schema.Schema` synthesises at runtime, not latent fields, so
they are not instances of this pattern.

Coverage
--------

Every case here goes through the *public* ``TCP`` convenience constructor, not
``_make_mptcp_*`` directly, because that in-memory, no-byte-round-trip path is exactly what
exposes the defect.

``MP_JOIN`` is asserted once per layout, since ``_make_mptcp_join`` reads ``self._flags`` to
pick between the three layouts of :rfc:`8684` section 3.2, and which layout gets built is
exactly what the flags decide. The flag ordering itself (#587), the three layouts' octets,
and the silent wrong-layout outcome that rules out a zero-valued default are covered in
:mod:`tests.protocols.transport.test_tcp_mptcp_join_flag_ordering_unit`.

``MP_FASTCLOSE`` is asserted directly as well. Its length arithmetic (#576), like every
option's, is covered per option in
:mod:`tests.protocols.transport.test_tcp_mptcp_length_arithmetic_unit`; what stays here is
only the ``subtype`` question this module is about.

"""
from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

#: Header fields shared by every constructed TCP segment in this module, matching
#: :data:`examples.generators.options.TCP_BASE` so these cases build through exactly the
#: keyword shape the fixture generator uses.
TCP_BASE = {
    'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'ack_no': 0,
    'ns': False, 'cwr': False, 'ece': False, 'urg': False, 'ack': False,
    'psh': False, 'rst': False, 'syn': True, 'fin': False,
    'window': 8192, 'checksum': b'\x00\x00', 'urgent': 0,
    'payload': b'',
}


def build_mptcp_option(subtype: 'object', *, header: 'Optional[dict[str, object]]' = None,
                       **kwargs: 'object') -> 'object':
    """Build a whole TCP segment carrying one Multipath TCP option, through the public API.

    Args:
        subtype: MPTCP subtype to construct.
        header: Overrides merged over :data:`TCP_BASE`, for the one subtype whose layout
            depends on the segment's own flags. Every other case leaves it :data:`None`
            and gets ``TCP_BASE`` unchanged, which is SYN-only.
        **kwargs: forwarded to the matching ``_make_mptcp_*`` maker as the option's own
            arguments.

    Returns:
        The constructed :class:`~pcapkit.protocols.transport.tcp.TCP` protocol instance.

    Note:
        ``pcapkit.protocols.transport.tcp`` and ``pcapkit.const.tcp.option`` are imported
        here, inside the function, rather than at module level. Several test modules
        elsewhere in this suite (see e.g.
        :func:`tests._support.purge_modules`) pop ``pcapkit``'s submodules out of
        ``sys.modules`` and let a later import re-create them, which produces a *new*
        ``Schema`` class object -- so a name bound at collection time (module level) can
        end up pointing at a schema class built from a stale ``Schema`` base, while
        :meth:`~pcapkit.corekit.fields.collections.OptionField.pack`'s own delayed
        ``from pcapkit.protocols.schema.schema import Schema`` resolves fresh against
        whatever is current when it actually runs. The two then fail
        ``isinstance(item, Schema)`` against each other despite both being named
        ``Schema``. Importing here instead, at call time, keeps this function on
        whichever ``pcapkit`` the rest of the suite is currently using -- the same
        precaution :meth:`tests.protocols.transport.test_tcp_udp_unit.TCPUDPUnitTests.test_tcp_mptcp_readers_cover_subtype_and_error_branches`
        already takes for the identical reason.

    """
    from pcapkit.const.tcp.option import Option as Enum_Option
    from pcapkit.protocols.transport.tcp import TCP

    args = dict(kwargs)
    args['subtype'] = subtype
    base = dict(TCP_BASE)
    base.update(header or {})
    return TCP(options=[(Enum_Option.Multipath_TCP, args)], **base)  # type: ignore[arg-type]


class TCPMPTCPSubtypeUnitTests(unittest.TestCase):
    """Every constructible MPTCP subtype round-trips ``.subtype`` through ``TCP()``.

    Without the construction path setting ``subtype``, every one of these raises
    ``AttributeError: '<schema class>' object has no attribute 'subtype'`` -- construction
    never gets as far as returning a :class:`~pcapkit.protocols.transport.tcp.TCP` instance
    at all, leaving no data model to assert on.

    """

    def test_mp_capable_subtype_round_trips(self) -> None:
        """``MP_CAPABLE`` built through ``TCP()`` reports its own subtype."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        tcp = build_mptcp_option(Enum_MPTCPOption.MP_CAPABLE, skey=0x0102030405060708)
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_CAPABLE)

    def test_add_addr_subtype_round_trips(self) -> None:
        """``ADD_ADDR`` built through ``TCP()`` reports its own subtype."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        tcp = build_mptcp_option(Enum_MPTCPOption.ADD_ADDR, addr_id=1, addr='192.0.2.1')
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.subtype, Enum_MPTCPOption.ADD_ADDR)

    def test_remove_addr_subtype_round_trips(self) -> None:
        """``REMOVE_ADDR`` built through ``TCP()`` reports its own subtype."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        tcp = build_mptcp_option(Enum_MPTCPOption.REMOVE_ADDR, addr_id=[1])
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.subtype, Enum_MPTCPOption.REMOVE_ADDR)

    def test_mp_prio_subtype_round_trips(self) -> None:
        """``MP_PRIO`` built through ``TCP()`` reports its own subtype."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        tcp = build_mptcp_option(Enum_MPTCPOption.MP_PRIO, addr_id=1)
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_PRIO)

    def test_dss_subtype_round_trips(self) -> None:
        """``DSS`` built through ``TCP()`` reports its own subtype.

        ``ack`` alone (no ``dsn``) keeps clear of the unrelated length-arithmetic defect
        of #576, which is not what this test is about.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        tcp = build_mptcp_option(Enum_MPTCPOption.DSS, ack=100)
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.subtype, Enum_MPTCPOption.DSS)

    def test_mp_fail_subtype_round_trips(self) -> None:
        """``MP_FAIL`` built through ``TCP()`` reports its own subtype."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        tcp = build_mptcp_option(Enum_MPTCPOption.MP_FAIL, dsn=7)
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_FAIL)

    def test_mp_join_subtype_round_trips_in_all_three_layouts(self) -> None:
        """``MP_JOIN`` built through ``TCP()`` reports its own subtype, whichever form.

        ``_make_mptcp_join`` reads ``self._flags`` to choose between the three layouts of
        :rfc:`8684` section 3.2, so ``TCP.make`` resolves the flags before it builds the
        options (#587); otherwise every one of these would raise ``AttributeError: 'TCP'
        object has no attribute '_flags'`` before ``subtype`` could come into it.

        All three forms are exercised rather than just the SYN one ``TCP_BASE`` selects,
        because the flags are what pick the layout: a regression that reached only one
        maker would otherwise pass here. What is asserted is this module's question --
        ``subtype`` survives in-memory construction -- and not the layouts' octets, which
        belong to
        :mod:`tests.protocols.transport.test_tcp_mptcp_join_flag_ordering_unit`.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        cases = (
            ('figure 5, SYN', {'syn': True, 'ack': False},
             {'backup': False, 'addr_id': 1, 'token': 7, 'nonce': 9}),
            ('figure 6, SYN/ACK', {'syn': True, 'ack': True},
             {'backup': False, 'addr_id': 2, 'hmac': bytes(8), 'nonce': 11}),
            ('figure 7, ACK', {'syn': False, 'ack': True},
             {'hmac': bytes(20)}),
        )

        for label, header, option in cases:
            with self.subTest(layout=label):
                tcp = build_mptcp_option(Enum_MPTCPOption.MP_JOIN, header=header,
                                         **option)
                data = tcp.info.options[Enum_Option.Multipath_TCP]  # type: ignore[attr-defined]

                self.assertEqual(data.subtype, Enum_MPTCPOption.MP_JOIN)

    def test_mp_fastclose_builds_and_reports_its_subtype(self) -> None:
        """``MP_FASTCLOSE`` builds through ``TCP()`` and reports its ``subtype``.

        MP_FASTCLOSE's maker, schema and parser agree on the RFC's 12 octets (#576), so the
        construction succeeds and the assertion this module exists for -- that
        ``subtype`` survives construction -- is made directly rather than through the
        shape of an exception.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        tcp = build_mptcp_option(Enum_MPTCPOption.MP_FASTCLOSE, key=9)
        data = tcp.info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_FASTCLOSE)
        self.assertEqual(data.length, 12)
        self.assertEqual(data.rkey, 9)


if __name__ == '__main__':
    unittest.main()
