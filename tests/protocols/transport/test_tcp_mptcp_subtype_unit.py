# -*- coding: utf-8 -*-
"""``MPTCP.subtype`` is set for a schema built in memory, not only one parsed from bytes.

GitHub issue #566, found while fixing #541 -- the same defect the ``EXPECTED_FAILURES``
table in :mod:`tests.protocols.test_option_roundtrip_unit` recorded for
``tcp-mptcp/MP_CAPABLE``, ``tcp-mptcp/ADD_ADDR``, ``tcp-mptcp/REMOVE_ADDR``,
``tcp-mptcp/MP_PRIO``, ``tcp-mptcp/DSS`` and ``tcp-mptcp/MP_FAIL`` until this fix, each with
a fragment of the form ``"'MPTCPCapable' object has no attribute 'subtype'"``.

Root cause
----------

:class:`~pcapkit.protocols.schema.transport.tcp.MPTCP`, the base class every Multipath TCP
subtype schema inherits, declared ``subtype`` only under :data:`~typing.TYPE_CHECKING`:

.. code-block:: python

    if TYPE_CHECKING:
        #: MPTCP subtype.
        subtype: 'Enum_MPTCPOption'

so it was an annotation for a type checker, never a real attribute any construction path
set. The only code that ever assigned ``schema.subtype`` was
:meth:`_MPTCP.post_process <pcapkit.protocols.schema.transport.tcp._MPTCP.post_process>`,
which runs once per option while parsing real bytes off the wire. Building an option through
:class:`~pcapkit.protocols.transport.tcp.TCP`'s convenience constructor --
``TCP(options=[(Enum_Option.Multipath_TCP, {'subtype': ..., **kwargs})], ...)`` -- never
unpacks anything: the dispatcher (``TCP._make_mode_mp``) calls the matching ``_make_mptcp_*``
maker to build the schema in memory and then hands that same schema straight to the matching
``_read_mptcp_*`` to build the :class:`~pcapkit.protocols.data.transport.tcp.MPTCP` data
model -- and every one of those eleven ``_read_mptcp_*`` methods reads ``schema.subtype``.
Filed measurement, pre-fix: ``TCP(options=[(Enum_Option.Multipath_TCP, {'subtype':
Enum_MPTCPOption.MP_FAIL, 'dsn': 7})], ...)`` raised
``AttributeError: 'MPTCPFallback' object has no attribute 'subtype'``.

Why a real field was not the fix
---------------------------------

#541 fixed the identical shape of problem for ``kind``/``length`` by declaring them as real
fields on ``MPTCP``, and the obvious next step is to do the same for ``subtype``. That would
be wrong here, and the difference is worth recording since this is the third
``TYPE_CHECKING``-only attribute this one class has had (``kind``, ``length`` in #541,
``subtype`` here) and a reader deserves to know the pattern was considered as a whole rather
than patched a third time by reflex.

``kind`` and ``length`` are each the *sole* source of their own octet -- nothing else in any
subtype schema packs them, so a real field was the only way to get them onto the wire at all.
``subtype`` is not like that: every concrete subclass already encodes it as 4 bits of its own
``test`` :class:`~pcapkit.corekit.fields.strings.BitField` (e.g.
``MPTCPCapable.test['subtype']``), which is what the wire format actually carries. Declaring
a second, independent ``Field`` for the same 4 bits would either double-pack them under two
names, or need a "derive this from another field, do not pack it yourself" kind of field --
which nothing in :mod:`pcapkit.corekit.fields` provides (every ``FieldBase`` subclass either
contributes its own bytes or selects among nested schemas; none merely mirrors a sibling
field's decoded value into a second attribute). So ``MPTCP.subtype`` stays an annotation, and
the fix is on the *construction* path instead: :meth:`TCP._make_mode_mp
<pcapkit.protocols.transport.tcp.TCP._make_mode_mp>`, the single dispatcher every
``_make_mptcp_*`` maker returns through, now sets ``schema.subtype = subtype_val`` right after
building the schema -- the same assignment :meth:`_MPTCP.post_process` already makes for a
real unpack, just made unconditionally.

That leaves no other ``TYPE_CHECKING``-only *data* attribute on ``MPTCP`` itself: the class
body has exactly ``kind``, ``length`` (both real fields since #541) and ``subtype`` (fixed
here by the construction path). The ``if TYPE_CHECKING: def __init__(...): ...`` blocks inside
the concrete subclasses below it are ordinary typed-signature stubs for the ``__init__`` that
:class:`~pcapkit.protocols.schema.schema.Schema` synthesises at runtime, not latent fields, so
they are not instances of this pattern.

Coverage
--------

Every case here goes through the *public* ``TCP`` convenience constructor, not
``_make_mptcp_*`` directly, because that in-memory, no-byte-round-trip path is exactly what
exposed the defect.

``MP_JOIN`` used to be left out, because it failed independently with ``AttributeError:
'TCP' object has no attribute '_flags'`` -- ``_make_mptcp_join`` reads ``self._flags`` to
pick between the three layouts of :rfc:`8684` section 3.2, and ``TCP.make`` assigned that
attribute only *after* it had built the options. That is a statement-ordering defect, not
this one, and #587 has since fixed it by hoisting the flag resolution above the option
build; the ``subtype`` assertion this module exists for is made for MP_JOIN below, once per
layout, since which layout gets built is exactly what the flags decide. The ordering defect
itself, the three layouts' octets, and the silent wrong-layout outcome that ruled out
fixing it with a zero-valued default are covered in
:mod:`tests.protocols.transport.test_tcp_mptcp_join_flag_ordering_unit`.

``MP_FASTCLOSE`` *is* covered, as of #576. When this module was written it was left out: fixing
``subtype`` got its construction past the ``AttributeError`` and into a second, independent
defect -- its declared length agreed with neither its own schema nor its own parser -- so the
case here could only assert the *shape of the exception* that defect raised. #576 has since
corrected all three sites, so the assertion is made directly. The length arithmetic itself is
covered per option in
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
    'srcport': 50000, 'dstport': 80, 'seq': 1, 'ack': 0,
    'ns': False, 'cwr': False, 'ece': False, 'urg': False, 'ack_flag': False,
    'psh': False, 'rst': False, 'syn': True, 'fin': False,
    'window': 8192, 'checksum': b'\x00\x00', 'urgent_pointer': 0,
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

    Pre-fix, every one of these raised ``AttributeError: '<schema class>' object has no
    attribute 'subtype'`` -- construction never got as far as returning a
    :class:`~pcapkit.protocols.transport.tcp.TCP` instance at all, so there is nothing to
    assert on the resulting data model until the fix lands.

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
        tracked as #576, which is not what this test is about.

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

        This module used to exclude MP_JOIN altogether: ``_make_mptcp_join`` reads
        ``self._flags`` to choose between the three layouts of :rfc:`8684` section 3.2,
        and ``TCP.make`` assigned that attribute only after it had already built the
        options, so every one of these raised ``AttributeError: 'TCP' object has no
        attribute '_flags'`` before ``subtype`` could come into it. #587 hoists the flag
        resolution above the option build.

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

        This was ``test_mp_fastclose_still_fails_but_no_longer_on_subtype`` when #579
        landed: it pinned that MP_FASTCLOSE no longer raised the ``subtype``
        ``AttributeError`` that #566 was about, while still raising ``ProtocolError:
        TCP: [OptNo 30] invalid format`` from the *other* defect it named -- the
        length disagreement filed as #576.

        #576 has since fixed that disagreement at all three sites (the parser's guard,
        which required 16; the schema, which packed 11; and the maker, which already
        declared the RFC's 12), so the construction now succeeds and the assertion this
        module exists for -- that ``subtype`` survives construction -- can be made
        directly instead of through the shape of an exception.

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
