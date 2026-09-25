# -*- coding: utf-8 -*-
"""The application layer registry as a per-transport package.

GitHub issue #732. :file:`pcapkit/const/reg/apptype.py` was one
:class:`~aenum.StrEnum` holding 8,182 members across every transport protocol,
with a ``__members_proto__`` mapping that kept **one** member per
``(transport, port)`` pair -- so of the three services IANA assigns to port 80,
two were reachable only by attribute name and none of that was visible from a
lookup. It is now :mod:`pcapkit.const.reg.apptype`: a memberless
:class:`~pcapkit.const.reg.apptype.apptype.AppType` base and one registry per
transport protocol, each keyed on port by a
:class:`~pcapkit.corekit.multidict.MultiDict` that keeps every assignment.

Four properties carry the design and none of them held before, so each is
asserted directly rather than left to the generic sweeps in
:mod:`tests.const.test_const_enum_builtin_parity`:

#. the base holds **no** members, which is not a tidiness preference --
   :mod:`aenum` refuses to subclass an enumeration that has any, so a single
   member on the base makes all four registries impossible to declare;
#. a member is still an ``AppType``, which is what keeps the seven
   ``isinstance`` sites in :mod:`pcapkit.protocols` working across the split;
#. a colliding port keeps **every** service IANA assigned it, answering with one
   canonical member and keeping the rest reachable as named aliases;
#. :func:`~aenum.extend_enum` on an occupied port *appends* rather than
   displacing what was there, which is the silent data loss the old
   ``__members_proto__`` assignment performed.

"""

import unittest

__all__ = ['AppTypeSplitTests']


class AppTypeSplitTests(unittest.TestCase):
    """The shape of the split registry."""

    def test_the_base_registry_holds_no_members(self) -> None:
        """And that is what makes the four registries declarable at all."""
        import aenum

        from pcapkit.const.reg.apptype import AppType, TransportProtocol

        self.assertEqual(len(AppType.__members__), 0)
        self.assertEqual(list(AppType), [])
        self.assertIsNone(AppType.__registry__)

        # The constraint stated as a fact about aenum rather than as folklore: a
        # base with one member cannot be subclassed, so "no members" is load
        # bearing and a future member added to it would break the whole package.
        class WithMembers(aenum.StrEnum):
            http = 'http'

        with self.assertRaises(TypeError):
            class Impossible(WithMembers):  # pylint: disable=unused-variable
                https = 'https'

        # Extending the base has exactly that effect, so it is refused outright.
        with self.assertRaises(ValueError):
            aenum.extend_enum(AppType, 'junk', 1, 'junk', TransportProtocol.tcp)
        self.assertEqual(len(AppType.__members__), 0)

    def test_a_member_is_still_an_apptype(self) -> None:
        """What the seven ``isinstance`` sites in :mod:`pcapkit.protocols` rely on."""
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP, AppType

        for cls in (TCP, UDP, SCTP, DCCP):
            with self.subTest(registry=cls.__name__):
                self.assertTrue(issubclass(cls, AppType))
                member = next(iter(cls))
                self.assertIsInstance(member, AppType)
                self.assertIs(type(member), cls)

        # One service on two transports is two members, not one shared object --
        # they carry the same name and the same full ``proto``, and differ only in
        # which registry they belong to.
        self.assertIsNot(TCP.http, UDP.http)
        self.assertEqual(TCP.http.svc, UDP.http.svc)
        self.assertEqual(TCP.http.proto, UDP.http.proto)
        self.assertEqual(int(TCP.http), 80)

    def test_each_registry_has_its_own_port_key_space(self) -> None:
        """A mapping shared by the four would recreate the collision it removes."""
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP

        registries = [cls.__registry__ for cls in (TCP, UDP, SCTP, DCCP)]
        for index, registry in enumerate(registries):
            for other in registries[index + 1:]:
                self.assertIsNot(registry, other)

        # SCTP has 91 assignments against TCP's thousands; a shared mapping would
        # show them the same size.
        self.assertLess(len(SCTP.__registry__), len(TCP.__registry__))

    def test_a_colliding_port_keeps_every_service(self) -> None:
        """IANA assigns three services to TCP/80 and all three survive."""
        from pcapkit.const.reg.apptype import TCP

        port_80 = TCP.__registry__.getlist(80)
        self.assertEqual([member.svc for member in port_80],
                         ['http', 'www', 'www-http'])

        # All three are canonical members, not aliases of one another: the value
        # is the formatted string, not the port, so aenum never collapses them --
        # while ``__eq__``/``__hash__`` still compare as the port, which is why a
        # ``set`` cannot be used as the registry.
        self.assertEqual(len({member.name for member in port_80}), 3)
        self.assertIsNot(TCP.http, TCP.www)
        self.assertEqual(TCP.http, TCP.www)
        self.assertEqual(hash(TCP.http), hash(TCP.www))
        self.assertEqual(len({TCP.http, TCP.www, TCP.www_http}), 1)

    def test_a_port_lookup_returns_the_canonical_service(self) -> None:
        """One member, and the one the rest of the world names.

        IANA names no precedence among the services it registers on a port, and
        registry row order does not supply one: of the 44 colliding
        ``(port, transport)`` pairs it answers 28 the way :file:`/etc/services`
        does and 16 differently, giving ``l2f`` for 1701 and ``shilp`` for 2049.
        So the canonical member is curated from :file:`/etc/services`, which is
        what :func:`socket.getservbyport` reads.

        The expectations are written out rather than read from
        :file:`/etc/services` at run time: that file is absent on some platforms
        and differs between the ones that have it, so reading it would make this
        test assert whatever the host happened to say.
        """
        from pcapkit.const.reg.apptype import TCP, UDP

        for cls, port, svc in ((TCP, 80, 'http'), (TCP, 113, 'auth'), (TCP, 1701, 'l2tp'),
                               (TCP, 2049, 'nfs'), (TCP, 3478, 'stun'), (TCP, 631, 'ipp'),
                               (UDP, 80, 'http'), (UDP, 512, 'biff'), (UDP, 1701, 'l2tp'),
                               (UDP, 750, 'kerberos-iv')):
            with self.subTest(registry=cls.__name__, port=port):
                self.assertEqual(cls.get(port).svc, svc)
                self.assertEqual(cls.__canonical__[port], svc)

        # A port with one service needs no curating and must not be listed.
        self.assertNotIn(22, TCP.__canonical__)
        self.assertEqual(TCP.get(22).svc, 'ssh')

    def test_get_all_reaches_the_aliases(self) -> None:
        """Canonical first, then the rest -- never an empty result.

        Discarding the services a port lookup does not answer with would be
        inventing a registry IANA does not have, so they stay members and this is
        how they are reached.
        """
        from pcapkit.const.reg.apptype import TCP, AppType, TransportProtocol

        self.assertEqual([member.svc for member in TCP.get_all(80)],
                         ['http', 'www', 'www-http'])
        self.assertEqual([member.svc for member in TCP.get_all(2049)], ['nfs', 'shilp'])
        self.assertIs(TCP.get_all(80)[0], TCP.get(80))

        # Single-service and unassigned ports both answer with one member rather
        # than with a differently-shaped empty value.
        self.assertEqual([member.svc for member in TCP.get_all(22)], ['ssh'])
        minted = TCP.get_all(59001)
        self.addCleanup(self._purge_member, TCP, 'PORT_59001_tcp', 59001)
        self.assertEqual(len(minted), 1)
        self.assertEqual(minted[0].svc, 'unknown')

        # And it dispatches from the base exactly as ``get`` does.
        self.assertEqual(AppType.get_all(80, proto=TransportProtocol.tcp), TCP.get_all(80))

    def test_extend_enum_appends_to_an_occupied_port(self) -> None:
        """The old ``__members_proto__[proto][port] = obj`` displaced it silently."""
        import aenum

        from pcapkit.const.reg.apptype import UDP, TransportProtocol

        before = [member.svc for member in UDP.__registry__.getlist(80)]
        self.assertEqual(before, ['http', 'www', 'www-http'])

        aenum.extend_enum(UDP, 'unit_test_80', 80, 'unit-test-80', TransportProtocol.udp)
        self.addCleanup(self._purge_member, UDP, 'unit_test_80', 80)

        after = [member.svc for member in UDP.__registry__.getlist(80)]
        self.assertEqual(after, ['http', 'www', 'www-http', 'unit-test-80'])

        # Appending must not displace the answer either: the old code overwrote
        # the bucket, so a third-party registration silently became what every
        # lookup of that port returned.
        self.assertEqual(UDP.get(80).svc, 'http')
        self.assertIn('unit-test-80', [member.svc for member in UDP.get_all(80)])

    def test_every_registry_rejects_a_negative_value(self) -> None:
        """GitHub issue #647's guard, now over five classes rather than one.

        ``ValueError`` specifically, and from every one of them: an ``IntEnum``
        with ``settings=NoAlias`` -- the other way to keep two members on one port
        -- raises ``TypeError`` here instead and never reaches ``_missing_`` at
        all, which is why this registry values members on a string.
        """
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP, AppType

        for cls in (AppType, TCP, UDP, SCTP, DCCP):
            with self.subTest(registry=cls.__name__):
                with self.assertRaises(ValueError):
                    cls(-1)
                with self.assertRaises(ValueError):
                    cls(65536)

    def test_a_port_lookup_on_the_base_dispatches_by_transport(self) -> None:
        """Which is what keeps every ``AppType.get(port, proto=...)`` caller working."""
        from pcapkit.const.reg.apptype import SCTP, TCP, UDP, AppType, TransportProtocol

        self.assertIs(AppType.get(80, proto=TransportProtocol.tcp), TCP.get(80))
        self.assertIs(AppType.get(80, proto=TransportProtocol.udp), UDP.get(80))
        self.assertIs(AppType.get(80, proto='tcp'), TCP.get(80))
        self.assertIs(AppType.get(9899, proto=TransportProtocol.sctp), SCTP.get(9899))

        # A port with no transport protocol names no registry, and IANA makes no
        # such assignment, so this raises rather than picking one.
        with self.assertRaises(ValueError):
            AppType.get(80)

    def test_a_service_name_is_not_a_port_lookup(self) -> None:
        """GitHub issue #734's junk-minting path is gone rather than fixed.

        The old string branch tested ``key in __members_proto__``, which is keyed
        by transport protocol, so a name never matched and
        ``AppType.get('ssh')`` returned a **new** member with port ``-1`` instead
        of the one at 22. Nothing in :mod:`pcapkit` resolves a service by name, so
        it now raises; #734 stays open for whether a real name lookup is wanted.
        """
        from pcapkit.const.reg.apptype import TCP

        with self.assertRaises(ValueError):
            TCP.get('ssh')  # type: ignore[arg-type]
        self.assertNotIn(-1, TCP.__registry__)

    def test_unassigned_rows_are_documented_rather_than_declared(self) -> None:
        """The 1,004 ``port == -1`` rows and the 704 with no transport protocol.

        They are not members -- there is nothing for a member to be valued on --
        so they are rendered as a ``list-table`` in the docstring of the registry
        that owns them, which is what :mod:`sphinx.ext.autodoc` publishes.
        """
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, AppType

        for cls, service in ((AppType, '``argus``'), (TCP, '``7ksonar``'),
                             (SCTP, '``twosnakes``'), (DCCP, '``dccp-ping``')):
            with self.subTest(registry=cls.__name__):
                self.assertIsNotNone(cls.__doc__)
                self.assertIn('.. list-table::', cls.__doc__ or '')
                self.assertIn(service, cls.__doc__ or '')

        # No member carries the sentinel port, in any registry.
        for cls in (AppType, TCP, DCCP):
            with self.subTest(registry=cls.__name__):
                self.assertNotIn(-1, [member.port for member in cls])

    def test_a_real_port_with_no_transport_no_longer_resolves(self) -> None:
        """The one deliberate behaviour change, pinned so it cannot happen twice.

        124 registry entries carry a real port with an **empty** transport
        protocol column, and the old ``_missing_`` consulted them as a fallback
        tier after the transport-specific lookup missed -- so ``get(51,
        proto=tcp)`` answered ``reserved``, claiming a TCP assignment IANA never
        made. They are documented on the base class now, and the lookup mints an
        unknown port instead, which is the honest answer.
        """
        from pcapkit.const.reg.apptype import TCP, AppType

        resolved = AppType.get(51, proto='tcp')
        self.assertEqual(resolved.svc, 'unknown')
        self.assertEqual(resolved.port, 51)
        self.assertIs(type(resolved), TCP)
        self.addCleanup(self._purge_member, TCP, 'PORT_51_tcp', 51)

        # It is still documented, just not resolvable.
        self.assertIn('``reserved``', AppType.__doc__ or '')

    def test_get_rejects_an_out_of_range_port_as_the_constructor_does(self) -> None:
        """GitHub issue #758: ``get`` swallowed ``_missing_``'s own rejection.

        ``test_every_registry_rejects_a_negative_value`` above asserts ``cls(-1)``
        and ``cls(65536)`` and **never** ``.get``, which is how CI stayed green
        while ``AppType.get(-1, proto='tcp')`` minted ``PORT_-1_tcp`` -- a key no
        attribute access can reach, since it is not an identifier. ``_missing_``
        did raise; ``get``'s ``except ValueError`` caught that very rejection and
        minted regardless, leaving ``get`` more permissive than ``cls(...)``. So
        the assertion has to be on ``.get``, and on the registry not having grown:
        the defect was visible as ``len(TCP)`` going 6147 to 6148.
        """
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP, AppType, TransportProtocol

        for cls in (TCP, UDP, SCTP, DCCP):
            for port in (-1, 65536, 999999):
                with self.subTest(registry=cls.__name__, port=port):
                    before = len(cls)
                    with self.assertRaises(ValueError):
                        cls.get(port)
                    with self.assertRaises(ValueError):
                        cls.get_all(port)
                    with self.assertRaises(ValueError):
                        AppType.get(port, proto=cls.__transport__)
                    self.assertEqual(len(cls), before)
                    self.assertNotIn('PORT_%d_%s' % (port, cls.__transport__.name),
                                     cls.__members__)

        # Paid for by narrowing nothing: a valid but unassigned port is what the
        # mint is *for*, and it still answers with one.
        minted = AppType.get(59000, proto=TransportProtocol.tcp)
        self.addCleanup(self._purge_member, TCP, 'PORT_59000_tcp', 59000)
        self.assertEqual(minted.svc, 'unknown')
        self.assertEqual(minted.port, 59000)

    def test_a_span_on_two_transports_answers_each_with_its_own_row(self) -> None:
        """GitHub issue #760: source order decided, so the TCP row answered all four.

        IANA registers exactly two port *spans* on more than one transport
        protocol, and the crawler rendered one ``_missing_`` branch per registry
        row -- two branches with an identical condition, the second unreachable.
        Every registry therefore answered with the first: ``AppType.get(6010,
        proto='udp')`` returned a **UDP** member whose ``proto`` read ``tcp``.

        6665-6669 is why the duplicate is not simply collapsed into one branch
        carrying ``tcp | udp``: its two rows are different services -- ``ircu`` on
        TCP, IANA's ``reserved`` marker on UDP -- so a merged branch would have to
        discard one of them, and #732's ``TransportProtocol`` retype would then
        want a *named* combination for it. Each branch tests ``cls.__transport__``
        instead, which also stays right for a span naming one transport only.
        """
        from pcapkit.const.reg.apptype import SCTP, TCP, UDP, AppType

        for cls, port, svc in ((TCP, 6010, 'x11'), (UDP, 6010, 'x11'),
                               (TCP, 6666, 'ircu'), (UDP, 6666, 'reserved')):
            with self.subTest(registry=cls.__name__, port=port):
                resolved = AppType.get(port, proto=cls.__transport__)
                self.addCleanup(self._purge_member, cls, '%s_%d' % (svc, port), port)
                self.assertIs(type(resolved), cls)
                self.assertEqual(resolved.svc, svc)
                self.assertIs(resolved.proto, cls.__transport__)

        # A span IANA assigns to TCP and UDP assigns nothing to SCTP, so the third
        # registry mints rather than inheriting the TCP row -- which it did, as
        # ``<SCTP.x11: 6010 [tcp]>``.
        resolved = AppType.get(6010, proto='sctp')
        self.addCleanup(self._purge_member, SCTP, 'PORT_6010_sctp', 6010)
        self.assertEqual(resolved.svc, 'unknown')
        self.assertIs(resolved.proto, SCTP.__transport__)

    def test_every_transport_named_span_is_claimed_by_one_registry(self) -> None:
        """The structural half of #760, which is what survives the next crawl.

        :meth:`~pcapkit.const.reg.apptype.apptype.AppType._missing_` is generated,
        so the defect returns the moment
        :mod:`pcapkit.vendor.reg.apptype.apptype` stops emitting the test -- and
        it returns silently, because a shadowed branch is unreachable rather than
        wrong. This asserts the invariant over every branch instead of over the two
        spans that happen to collide today: a branch minting a member for a named
        transport protocol is claimed by that registry, and one minting for
        ``undefined`` claims nothing, since IANA's unassigned and reserved markers
        belong to whichever registry was asked.
        """
        import inspect
        import re

        from pcapkit.const.reg.apptype import AppType

        source = inspect.getsource(AppType._missing_.__func__)  # type: ignore[attr-defined]
        # NOTE: GitHub issue #768 changed the emitted form from
        # ``TransportProtocol.get('tcp')`` to the attribute access
        # ``TransportProtocol.tcp``, so the capture is a bare identifier now
        # rather than a quoted literal.
        branches = re.findall(r'\n        if (.+?):\n            #:.*?\n            '
                              r'return extend_enum\(.+?TransportProtocol\.(\w+)\)',
                              source)
        self.assertEqual(len(branches), 766)

        for condition, proto in branches:
            with self.subTest(condition=condition):
                claim = 'cls.__transport__ is TransportProtocol.%s' % proto
                if proto == 'undefined':
                    self.assertNotIn('cls.__transport__', condition)
                else:
                    # NOTE: anchored at the end rather than a bare `assertIn`,
                    # which would pass on a prefix collision -- e.g. `claim`
                    # ending in ``TransportProtocol.tc`` would falsely match a
                    # condition actually naming ``TransportProtocol.tcp``. Not
                    # reachable today, since none of the five declared names
                    # is a prefix of another, but the check should not depend
                    # on that being true to stay correct.
                    self.assertTrue(condition.endswith(claim), condition)

    def test_a_proto_naming_two_transports_is_refused_rather_than_resolved(self) -> None:
        """GitHub issue #759: the lowest set bit decided, silently.

        ``TransportProtocol`` is an :class:`~aenum.IntFlag` and a member carries the
        *whole* set IANA assigned the service, so ``tcp | udp`` is an ordinary value
        to read off one and therefore an ordinary thing to pass back in. It names
        two registries holding two different services for the same port, though,
        and a lookup answers with one member -- so there is no answer to which of
        them the composite meant. ``_dispatch`` resolved it through
        :func:`~pcapkit.utilities.compat.show_flag_values`, which iterates
        **LSB-first**, so every composite containing ``tcp`` -- the lowest declared
        bit -- dispatched into the TCP registry whatever else it named.

        The refusal is :exc:`~pcapkit.utilities.exceptions.ProtocolError` rather
        than a bare :exc:`ValueError` because in-library errors come from
        :mod:`pcapkit.utilities.exceptions`, and it is safe here in a way it is
        **not** in ``_missing_``:
        ``ConstEnumBuiltinParityTests.test_the_exception_is_not_an_in_library_one``,
        in :mod:`tests.const.test_const_enum_builtin_parity`, requires the
        constructor's guard to stay a non-:class:`BaseError` precisely because
        ``get``'s ``except ValueError`` fallback catches and discards it, and a
        ``BaseError`` would log at CRITICAL once per discarded default. Nothing
        catches this one -- it propagates out of ``get``/``get_all`` to the caller
        -- so a loud error is what it should be. It subclasses :exc:`ValueError` all
        the same, so the documented contract of both entry points still holds.
        """
        import sys

        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP, AppType, TransportProtocol
        from pcapkit.utilities.compat import show_flag_values
        from pcapkit.utilities.exceptions import BaseError, ProtocolError

        # NOTE: a loud BaseError sets ``sys.tracebacklimit`` to 0 process-wide
        # outside development mode, which would truncate the traceback of every
        # later failure in this process. Restored the way
        # ``QuietExceptionTests.setUp`` does it.
        saved = getattr(sys, 'tracebacklimit', None)

        def restore() -> None:
            if saved is None:
                if hasattr(sys, 'tracebacklimit'):
                    del sys.tracebacklimit
            else:
                sys.tracebacklimit = saved

        self.addCleanup(restore)

        # The mechanism, pinned rather than described: ``tcp`` is the lowest bit
        # and LSB-first iteration is why it used to win.
        self.assertEqual(show_flag_values(TransportProtocol.tcp | TransportProtocol.udp),
                         [TransportProtocol.tcp, TransportProtocol.udp])

        # #759's own reproduction. 888 carries ``cddbp`` on TCP and
        # ``accessbuilder`` on UDP, so the composite answered ``cddbp`` for a UDP
        # member -- and ``==`` read ``True``, since it compares on ``port`` alone.
        both = TransportProtocol.tcp | TransportProtocol.udp
        member = next(each for each in UDP.__registry__.getlist(888)
                      if each.svc == 'accessbuilder')
        with self.assertRaises(ProtocolError) as caught:
            AppType.get(888, proto=member.proto)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertIsInstance(caught.exception, BaseError)
        self.assertIn('tcp|udp', str(caught.exception))
        self.assertIn('2 transport protocols', str(caught.exception))

        # Every composite over the four declared bits, through all three entry
        # points -- ``get_all`` and ``_dispatch`` dispatch exactly as ``get`` does,
        # so a guard on one of them only would leave the other two resolving.
        singles = (TransportProtocol.tcp, TransportProtocol.udp,
                   TransportProtocol.sctp, TransportProtocol.dccp)
        composites = []
        for first in range(len(singles)):
            for second in range(first + 1, len(singles)):
                composites.append(singles[first] | singles[second])
        composites.append(TransportProtocol.tcp | TransportProtocol.udp | TransportProtocol.sctp)
        composites.append(singles[0] | singles[1] | singles[2] | singles[3])
        self.assertEqual(len(composites), 8)

        before = {cls: len(cls) for cls in (TCP, UDP, SCTP, DCCP)}
        for proto in composites:
            with self.subTest(proto=proto.name):
                with self.assertRaises(ProtocolError):
                    AppType.get(80, proto=proto)
                with self.assertRaises(ProtocolError):
                    AppType.get_all(80, proto=proto)
                with self.assertRaises(ProtocolError):
                    AppType._dispatch(80, proto)

        # And nothing was minted on the way out: #758's shape of defect was a
        # rejection that grew the registry anyway.
        self.assertEqual({cls: len(cls) for cls in (TCP, UDP, SCTP, DCCP)}, before)

        # A single bit is untouched, and so is ``undefined``: zero bits names no
        # registry rather than too many, which is a different refusal and stays the
        # plain ``ValueError`` ``test_a_port_lookup_on_the_base_dispatches_by_transport``
        # asserts.
        self.assertIs(AppType.get(80, proto=TransportProtocol.tcp), TCP.get(80))
        with self.assertRaises(ValueError) as plain:
            AppType.get(80, proto=TransportProtocol.undefined)
        self.assertNotIsInstance(plain.exception, ProtocolError)

        # On a registry subclass ``proto`` is documented as ignored -- it already
        # knows its own transport, so there is nothing ambiguous to refuse and the
        # composite must not start erroring there.
        self.assertIs(UDP.get(888, proto=both), member)
        self.assertEqual(TCP.get(888, proto=both).svc, 'cddbp')

    def test_every_multi_transport_member_refuses_its_own_proto(self) -> None:
        """All 10,625 of them, which is how the 46 differing answers were found.

        The measurement in #759, re-derived on ``fe80b8525``: sweeping every
        multi-transport member through ``AppType.get(m.port, proto=m.proto)`` gave
        0 exceptions, 0 mints and **46 answers naming a service other than the
        member's own**, at 20 distinct ports and 23 ``(port, service)`` pairs --
        each pair declared once in the TCP registry and once in UDP. Identical at
        ``932cb48d1``, so long-standing rather than a regression.

        Those 46 are three different things, and only the last is a wrong *answer*:

        #. all 46 name a service other than the member's own, which for 44 of them
           is :meth:`get`'s documented behaviour rather than a defect -- the member
           is simply not its port's canonical, and a single-bit lookup answers the
           canonical too;
        #. **23** -- the UDP-declared half -- came back as a member of the *TCP*
           registry, so ``type(result)`` and ``result.proto`` were wrong whatever
           the service string said;
        #. **2** named a service UDP's own lookup does not answer at all, and they
           are the whole of this bug's blast radius: port **888**, where
           ``accessbuilder`` resolved to TCP's ``cddbp``, and port **999**, where
           ``puprouter`` resolved to TCP's ``garcon`` against UDP's ``applix``.
           They are the two ports where :data:`__canonical__` genuinely disagrees
           between the two registries *and* the port carries a multi-transport
           member; #759's body found the first of them and generalised from it.

        Asserted over the whole population rather than over a sample, because the
        population is what the crawler regenerates: a future crawl that adds a
        service to a second transport adds members here, and they have to refuse
        too. The failures are collected rather than run through
        :meth:`~unittest.TestCase.subTest` -- 10,625 subtests would dominate the
        suite's own output, and each refusal logs at CRITICAL.

        Counted over members the crawler *declared*, so the figure does not depend
        on what else has run in this process: a mint carries ``svc == 'unknown'``
        and no generated member does, which makes that the filter.
        """
        import logging
        import sys

        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP, AppType
        from pcapkit.utilities.compat import show_flag_values
        from pcapkit.utilities.exceptions import ProtocolError

        saved_limit = getattr(sys, 'tracebacklimit', None)
        saved_level = logging.getLogger('pcapkit').level

        def restore() -> None:
            logging.getLogger('pcapkit').setLevel(saved_level)
            if saved_limit is None:
                if hasattr(sys, 'tracebacklimit'):
                    del sys.tracebacklimit
            else:
                sys.tracebacklimit = saved_limit

        self.addCleanup(restore)
        logging.getLogger('pcapkit').setLevel(logging.CRITICAL + 1)

        registries = [TCP, UDP, SCTP, DCCP]
        before = {cls.__name__: len(cls) for cls in registries}

        swept = 0
        answered = []  # type: list[tuple[str, int, str, str]]
        other = []  # type: list[tuple[str, int, str]]
        for cls in registries:
            for member in list(cls):
                if member.svc == 'unknown' or len(show_flag_values(member.proto)) <= 1:
                    continue
                swept += 1
                try:
                    result = AppType.get(member.port, proto=member.proto)
                except ProtocolError:
                    continue
                except Exception as exc:  # pylint: disable=broad-except
                    other.append((cls.__name__, member.port, type(exc).__name__))
                else:
                    answered.append((cls.__name__, member.port, member.svc, result.svc))

        self.assertEqual(answered, [])
        self.assertEqual(other, [])
        self.assertEqual(swept, 10625)
        self.assertEqual({cls.__name__: len(cls) for cls in registries}, before)

        # The 23 ``(port, service)`` pairs the sweep used to answer wrongly, named
        # so the count above is not the only thing pinning them. Each is a member
        # of both the TCP and the UDP registry -- 23 * 2 = 46 -- and each used to
        # come back as its port's TCP canonical instead, which is asserted here as
        # the state of ``__canonical__`` rather than by rerunning the old code.
        mismatched = (
            (42, 'name'), (63, 'whoispp'), (80, 'www'), (80, 'www-http'), (105, 'cso'),
            (351, 'bhoetty'), (352, 'bhoedap4'), (666, 'doom'), (888, 'accessbuilder'),
            (999, 'puprouter'), (1525, 'orasrv'), (1701, 'l2f'), (1989, 'mshnet'),
            (1992, 'ipsendmsg'), (2049, 'shilp'), (3000, 'remoteware-cl'),
            (3002, 'remoteware-srv'), (3478, 'turn'), (3478, 'stun-behavior'),
            (4444, 'nv-video'), (5349, 'turns'), (5349, 'stun-behaviors'),
            (9100, 'pdl-datastream'),
        )
        self.assertEqual(len(mismatched), 23)
        self.assertEqual(len({port for port, _ in mismatched}), 20)

        divergent = []  # type: list[tuple[str, int, str, str, str]]
        for port, svc in mismatched:
            for cls in (TCP, UDP):
                with self.subTest(registry=cls.__name__, port=port, svc=svc):
                    member = next(each for each in cls.__registry__.getlist(port)
                                  if each.svc == svc)
                    self.assertGreater(len(show_flag_values(member.proto)), 1)
                    with self.assertRaises(ProtocolError):
                        AppType.get(port, proto=member.proto)
                    # What it answered instead: the TCP registry's canonical, since
                    # ``tcp`` is the lowest bit of every one of these.
                    self.assertNotEqual(TCP.get(port).svc, svc)
                    # And the member is still reachable, under its own transport.
                    self.assertIn(member, cls.get_all(port))

                    # NOTE: the blast radius, derived from the LSB rule and this
                    # tree's ``__canonical__`` rather than by rerunning the old
                    # code. ``tcp`` is the lowest bit of all 46, so the TCP
                    # registry's answer is what the composite used to resolve to;
                    # where that differs from the member's own registry's answer,
                    # the lookup returned a service that registry does not answer
                    # at all. Everywhere else the two coincide, and the difference
                    # from ``svc`` is only that the member is not the canonical.
                    if TCP.get(port).svc != cls.get(port).svc:
                        divergent.append((cls.__name__, port, svc,
                                          TCP.get(port).svc, cls.get(port).svc))

        self.assertEqual(divergent, [
            ('UDP', 888, 'accessbuilder', 'cddbp', 'accessbuilder'),
            ('UDP', 999, 'puprouter', 'garcon', 'applix'),
        ])

    def test_one_transport_protocol_still_resolves_every_port_it_resolved_before(self) -> None:
        """The refusal narrows the composite case and nothing else.

        Every declared member of every registry, dispatched from the base under its
        own registry's **single** transport bit, has to land on the member that
        registry's own ``get`` answers with -- ``cls.get`` reaches ``_dispatch``'s
        early return for a class that holds members, so it never runs the guard and
        is an independent oracle for what the guard must not have changed.

        The population, measured on ``fe80b8525`` and unchanged by the fix, because
        four numbers here are easy to confuse:

        * **12,391** declared members -- 6,147 TCP, 6,143 UDP, 91 SCTP, 10 DCCP;
        * of those, **10,625** carry a multi-bit ``.proto`` and **1,766** a
          single-bit one. That is a property of the *members*, and it is not what
          this test partitions on;
        * they sit on **12,341** distinct ``(registry, port)`` pairs -- 6,121 TCP,
          6,119 UDP, 91 SCTP, 10 DCCP -- the other **50** sharing a port with
          another service, as IANA's three on TCP/80 do;
        * so the sweep below makes 12,341 distinct lookups, each passing **one**
          transport protocol whatever the member's own ``.proto`` holds.

        The digest is over those 12,341 rows, one per ``(registry, port)``, as
        ``registry|port|resolved service|int(resolved proto)``:
        ``3a457683c7b00609b06526aa02e3c361a910fa4a0e22d25ca16b4ab01acc053a``,
        identical either side of the fix and identical again when ``proto`` is
        passed as a name rather than as a flag. Restricted to the 1,766 single-bit
        ``.proto`` members it is 1,763 rows -- three of them share a port --
        digest ``308715ae6642a91be547d73e1c07f84bed7f27b7158951e831201c936807814b``,
        also identical either side.

        Declared members only, for the reason
        ``test_every_multi_transport_member_refuses_its_own_proto`` gives: a mint
        carries ``svc == 'unknown'``, and ``AppType.get(9899, proto=sctp)`` in
        ``test_a_port_lookup_on_the_base_dispatches_by_transport`` leaves one
        behind, so a count over every registry key would depend on test order.
        """
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP, AppType
        from pcapkit.utilities.compat import show_flag_values

        registries = [TCP, UDP, SCTP, DCCP]
        before = {cls.__name__: len(cls) for cls in registries}

        members = {cls.__name__: [each for each in cls if each.svc != 'unknown']
                   for cls in registries}
        self.assertEqual({name: len(rows) for name, rows in members.items()},
                         {'TCP': 6147, 'UDP': 6143, 'SCTP': 91, 'DCCP': 10})
        self.assertEqual(sum(len(rows) for rows in members.values()), 12391)
        widths = [len(show_flag_values(each.proto))
                  for rows in members.values() for each in rows]
        self.assertEqual(sum(1 for width in widths if width > 1), 10625)
        self.assertEqual(sum(1 for width in widths if width == 1), 1766)

        per_registry = {}  # type: dict[str, int]
        divergent = []  # type: list[tuple[str, int, str, str]]
        for cls in registries:
            ports = sorted({member.port for member in members[cls.__name__]})
            per_registry[cls.__name__] = len(ports)
            for port in ports:
                own = cls.get(port)
                for proto in (cls.__transport__, cls.__transport__.name):
                    resolved = AppType.get(port, proto=proto)  # type: ignore[arg-type]
                    if resolved is not own:
                        divergent.append((cls.__name__, port, resolved.svc, own.svc))

        self.assertEqual(divergent, [])
        self.assertEqual(per_registry, {'TCP': 6121, 'UDP': 6119, 'SCTP': 91, 'DCCP': 10})
        self.assertEqual(sum(per_registry.values()), 12341)
        self.assertEqual(sum(len(rows) for rows in members.values())
                         - sum(per_registry.values()), 50)
        self.assertEqual({cls.__name__: len(cls) for cls in registries}, before)

        # Spot-checked against the answers ``/etc/services`` gives, so the sweep
        # above cannot pass by agreeing with itself on a wrong value.
        for cls, port, svc in ((TCP, 80, 'http'), (UDP, 512, 'biff'), (TCP, 888, 'cddbp'),
                               (UDP, 888, 'accessbuilder'), (TCP, 22, 'ssh')):
            with self.subTest(registry=cls.__name__, port=port):
                self.assertEqual(AppType.get(port, proto=cls.__transport__).svc, svc)

    def test_no_lookup_call_site_in_the_library_builds_a_composite_proto(self) -> None:
        """Why refusing one breaks nothing, asserted rather than taken on trust.

        The refusal is only safe while every library caller passes a single
        transport protocol. There are ten call sites into the base registry's lookup
        outside :mod:`pcapkit.const`: one in ``Transport._make_port``, which passes
        the ``proto`` its six call sites hand it -- a literal member every time, two
        per transport in the TCP, UDP and SCTP protocol modules -- and three in each
        of the TCP, UDP and SCTP schemas' ``PortEnumField.post_process``, which
        binds ``proto`` to one literal member and then uses it for ``_dispatch`` and
        both ``get`` calls. None of them can pass a composite, because none of those
        modules builds one.

        Read off disk rather than through :func:`inspect.getsource`, so this needs
        no import of :mod:`pcapkit.protocols` -- whose runtime dependencies this
        tier does not gate on.

        :func:`~pcapkit.foundation.registry.register_apptype` is the one place that
        *does* handle a member's composite ``proto``, reading it off ``code.proto``
        when called with a member. It tests it with ``in`` and fans out to the TCP
        and UDP protocol registries rather than looking a port up, so it never
        reaches ``_dispatch`` and is unaffected -- asserted here so that a future
        rewrite routing it through the lookup does not do so silently.
        """
        import ast
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[2]
        if not (root / 'pcapkit' / 'protocols').is_dir():
            self.skipTest('no pcapkit sources next to the test tree')

        callers = [
            'pcapkit/protocols/transport/transport.py',
            'pcapkit/protocols/transport/tcp.py',
            'pcapkit/protocols/transport/udp.py',
            'pcapkit/protocols/transport/sctp.py',
            'pcapkit/protocols/schema/transport/tcp.py',
            'pcapkit/protocols/schema/transport/udp.py',
            'pcapkit/protocols/schema/transport/sctp.py',
            'pcapkit/foundation/registry/protocols.py',
            'pcapkit/corekit/fields/numbers.py',
        ]
        members = {'tcp', 'udp', 'sctp', 'dccp'}

        composites = []  # type: list[tuple[str, int]]
        lookups = []  # type: list[str]
        bindings = []  # type: list[tuple[str, str]]
        for relative in callers:
            path = root / relative
            with self.subTest(module=relative):
                self.assertTrue(path.is_file(), path)
                tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
                for node in ast.walk(tree):
                    # A ``TransportProtocol`` composite, however it is spelled.
                    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
                        if 'TransportProtocol' in ast.unparse(node):
                            composites.append((relative, node.lineno))
                    # What ``proto`` is bound to, for the schema fields that use a
                    # local rather than passing the member straight in. Only those
                    # three modules: ``Transport._decode_next_layer`` has a local of
                    # the same name holding a *port number* for the next-layer
                    # registry, which never reaches this lookup.
                    if isinstance(node, ast.Assign) and 'schema' in relative:
                        for target in node.targets:
                            if isinstance(target, ast.Name) and target.id == 'proto':
                                bindings.append((relative, ast.unparse(node.value)))
                    if not isinstance(node, ast.Call):
                        continue
                    name = (node.func.attr if isinstance(node.func, ast.Attribute) else
                            node.func.id if isinstance(node.func, ast.Name) else '')
                    if name not in ('get', 'get_all', '_dispatch', '_make_port'):
                        continue
                    arguments = [keyword.value for keyword in node.keywords
                                 if keyword.arg == 'proto']
                    if name in ('_dispatch', '_make_port') and len(node.args) > 1:
                        arguments.append(node.args[1])
                    for argument in arguments:
                        lookups.append('%s %s(proto=%s)' % (relative, name, ast.unparse(argument)))

        self.assertEqual(composites, [])

        # Every argument is one member, its name, or the single-member local that
        # ``_make_port`` and ``post_process`` bind -- never an expression that could
        # widen. Both the ``Enum_`` alias and the bare name, since the schema modules
        # import it under one and the transport modules under the other.
        permitted = {'proto'}
        for name in members:
            permitted.update({repr(name), 'TransportProtocol.%s' % name,
                              'Enum_TransportProtocol.%s' % name})
        for rendered in lookups:
            with self.subTest(call=rendered):
                self.assertIn(rendered.split('proto=', 1)[1].rstrip(')'), permitted)

        # Every local named ``proto`` in these modules is bound to exactly one
        # member, which is what makes the bare ``proto`` arguments above single-bit.
        self.assertEqual(sorted(bindings), [
            ('pcapkit/protocols/schema/transport/sctp.py', 'Enum_TransportProtocol.sctp'),
            ('pcapkit/protocols/schema/transport/tcp.py', 'Enum_TransportProtocol.tcp'),
            ('pcapkit/protocols/schema/transport/udp.py', 'Enum_TransportProtocol.udp'),
        ])

        # The sixteen the sweep found, so a new one cannot appear without this test
        # saying so. ``transport.py`` holds the single lookup and the six literal
        # ``_make_port`` arguments that feed it; each schema module holds three.
        self.assertEqual(sorted(lookups), [
            'pcapkit/protocols/schema/transport/sctp.py _dispatch(proto=proto)',
            'pcapkit/protocols/schema/transport/sctp.py get(proto=proto)',
            'pcapkit/protocols/schema/transport/sctp.py get(proto=proto)',
            'pcapkit/protocols/schema/transport/tcp.py _dispatch(proto=proto)',
            'pcapkit/protocols/schema/transport/tcp.py get(proto=proto)',
            'pcapkit/protocols/schema/transport/tcp.py get(proto=proto)',
            'pcapkit/protocols/schema/transport/udp.py _dispatch(proto=proto)',
            'pcapkit/protocols/schema/transport/udp.py get(proto=proto)',
            'pcapkit/protocols/schema/transport/udp.py get(proto=proto)',
            'pcapkit/protocols/transport/sctp.py _make_port(proto=Enum_TransportProtocol.sctp)',
            'pcapkit/protocols/transport/sctp.py _make_port(proto=Enum_TransportProtocol.sctp)',
            'pcapkit/protocols/transport/tcp.py _make_port(proto=Enum_TransportProtocol.tcp)',
            'pcapkit/protocols/transport/tcp.py _make_port(proto=Enum_TransportProtocol.tcp)',
            'pcapkit/protocols/transport/transport.py get(proto=proto)',
            'pcapkit/protocols/transport/udp.py _make_port(proto=Enum_TransportProtocol.udp)',
            'pcapkit/protocols/transport/udp.py _make_port(proto=Enum_TransportProtocol.udp)',
        ])

        # ``register_apptype`` reads a member's composite ``proto`` and must keep
        # testing it with ``in`` rather than looking a port up with it.
        source = (root / 'pcapkit' / 'foundation' / 'registry' / 'protocols.py').read_text(encoding='utf-8')
        self.assertIn('proto = code.proto', source)
        self.assertIn('if test not in proto:', source)

    @staticmethod
    def _purge_member(cls: type, name: str, port: int) -> None:
        """Undo an :func:`~aenum.extend_enum` so the registry is left as found.

        ``aenum`` offers no removal, so this reaches into the same three mappings
        :func:`~aenum.extend_enum` writes plus this registry's own
        :attr:`~pcapkit.const.reg.apptype.apptype.AppType.__registry__`. Without
        it a later test in the same process sees a member IANA never assigned.

        """
        member = cls.__members__.get(name)  # type: ignore[attr-defined]
        if member is None:
            return
        cls._member_map_.pop(name, None)  # type: ignore[attr-defined]
        if name in cls._member_names_:  # type: ignore[attr-defined]
            cls._member_names_.remove(name)  # type: ignore[attr-defined]
        cls._value2member_map_.pop(member.value, None)  # type: ignore[attr-defined]
        remaining = [each for each in cls.__registry__.getlist(port)  # type: ignore[attr-defined]
                     if each is not member]
        cls.__registry__.setlist(port, remaining)  # type: ignore[attr-defined]
        if not remaining:
            del cls.__registry__[port]  # type: ignore[attr-defined]


if __name__ == '__main__':
    unittest.main()
