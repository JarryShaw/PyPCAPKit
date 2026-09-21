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
exposed the defect. ``MP_JOIN`` is left out: it fails independently with
``AttributeError: 'TCP' object has no attribute '_flags'`` (``_make_mptcp_join`` reads
``self._flags``, which only the parse path ever sets), which is not this issue.

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


def build_mptcp_option(subtype: 'object', **kwargs: 'object') -> 'object':
    """Build a whole TCP segment carrying one Multipath TCP option, through the public API.

    Args:
        subtype: MPTCP subtype to construct.
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
    return TCP(options=[(Enum_Option.Multipath_TCP, args)], **TCP_BASE)  # type: ignore[arg-type]


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
