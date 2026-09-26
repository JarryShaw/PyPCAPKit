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
        # they carry the same name and differ in which registry they belong to,
        # which since GitHub issue #806 is what ``proto`` says. It named the whole
        # IANA set on both of them before, so the two compared equal.
        self.assertIsNot(TCP.http, UDP.http)
        self.assertEqual(TCP.http.svc, UDP.http.svc)
        self.assertNotEqual(TCP.http.proto, UDP.http.proto)
        self.assertIs(TCP.http.proto, TCP.__transport__)
        self.assertIs(UDP.http.proto, UDP.__transport__)
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

    def test_a_bare_int_composite_is_refused_as_a_whole(self) -> None:
        """GitHub issue #759's old fix, superseded by the owner's #836 ruling.

        ``TransportProtocol`` dropped its :class:`~aenum.IntFlag` base in GitHub
        issue #808, so ``tcp | udp`` no longer builds a member at all -- it falls
        through to ``int.__or__`` and returns a bare :class:`int`. That bare int
        stays constructible by hand even though no member carries one since
        GitHub issue #806, which is why this guard is still needed and is tested
        with composites built here rather than read off a member.

        ``_dispatch`` used to resolve a composite through
        :func:`~pcapkit.utilities.compat.show_flag_values`, decoding its bits and
        answering :exc:`~pcapkit.utilities.exceptions.ProtocolError` naming every
        transport whose bit was set -- the fix for #759, where resolving one by
        picking the lowest set bit (``tcp``, iterating **LSB-first**) dispatched
        every composite containing it into the TCP registry whatever else it
        named. The owner's ruling on this PR (#836) retires that decoding
        instead of refining it: "since it's no longer a Flag, `|` joined values
        are no longer parsed and accepted, we will treat it as a whole, instead
        of splitting." A bare-int composite is therefore refused exactly like
        any other value that names no registry -- a stray bit, ``undefined``, or
        a number with nothing to do with any transport -- through the one plain
        :exc:`ValueError` :meth:`AppType._dispatch` already gives those. There is
        no longer a "too many transports" refusal distinct from a "no
        transport" one.
        """
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP, AppType, TransportProtocol
        from pcapkit.utilities.exceptions import ProtocolError

        # #759's own reproduction. 888 carries ``cddbp`` on TCP and
        # ``accessbuilder`` on UDP. The member's own ``proto`` was that
        # composite until #806; it is ``udp`` now, so the composite is built
        # here instead and the member's own value is asserted to be the
        # single bit that resolves cleanly.
        both = TransportProtocol.tcp | TransportProtocol.udp
        member = next(each for each in UDP.__registry__.getlist(888)
                      if each.svc == 'accessbuilder')
        self.assertIs(member.proto, TransportProtocol.udp)
        self.assertIs(AppType.get(888, proto=member.proto), member)
        with self.assertRaises(ValueError) as caught:
            AppType.get(888, proto=both)
        self.assertNotIsInstance(caught.exception, ProtocolError)
        self.assertIn(str(int(both)), str(caught.exception))
        self.assertIn('names no transport protocol registry', str(caught.exception))

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
            # NOTE: not ``proto.name`` -- ``proto`` is a bare ``int`` since
            # GitHub issue #808 dropped the ``IntFlag`` base composites used to
            # be built from, and a bare int has no ``.name``. ``hex`` still
            # tells the subTests apart on failure.
            with self.subTest(proto=hex(proto)):
                with self.assertRaises(ValueError) as via_get:
                    AppType.get(80, proto=proto)
                self.assertNotIsInstance(via_get.exception, ProtocolError)
                with self.assertRaises(ValueError) as via_get_all:
                    AppType.get_all(80, proto=proto)
                self.assertNotIsInstance(via_get_all.exception, ProtocolError)
                with self.assertRaises(ValueError) as via_dispatch:
                    AppType._dispatch(80, proto)
                self.assertNotIsInstance(via_dispatch.exception, ProtocolError)

        # And nothing was minted on the way out: #758's shape of defect was a
        # rejection that grew the registry anyway.
        self.assertEqual({cls: len(cls) for cls in (TCP, UDP, SCTP, DCCP)}, before)

        # A single bit resolves, and ``undefined`` is refused the identical way
        # a composite now is -- there is no longer a distinct refusal for
        # "too many transports" versus "no transport".
        self.assertIs(AppType.get(80, proto=TransportProtocol.tcp), TCP.get(80))
        with self.assertRaises(ValueError) as plain:
            AppType.get(80, proto=TransportProtocol.undefined)
        self.assertNotIsInstance(plain.exception, ProtocolError)

        # On a registry subclass ``proto`` is documented as ignored -- it already
        # knows its own transport, so there is nothing ambiguous to refuse and the
        # composite must not start erroring there.
        self.assertIs(UDP.get(888, proto=both), member)
        self.assertEqual(TCP.get(888, proto=both).svc, 'cddbp')

    def test_no_member_carries_a_multi_transport_proto(self) -> None:
        """GitHub issue #806: the composite that caused #759 is gone at the source.

        This test used to sweep the 10,625 multi-transport members through
        ``AppType.get(m.port, proto=m.proto)`` and require every one of them to be
        *refused*, because a member's own ``proto`` was the whole set IANA assigned
        the service and so named up to four registries. Retyping ``proto`` to the
        single transport protocol of the registry the member lives in removes that
        population outright: the sweep count goes from **10,625 to 0**, and a
        member's own ``proto`` is now the one thing a lookup can always be given.

        So the assertion inverts. Instead of "every multi-bit member refuses its own
        ``proto``" it is "no member has a multi-bit ``proto``, and every member
        resolves under its own" -- which is the same property the old test protected
        the callers from, established at generation time rather than defended at
        every entry point.

        The 23 ``(port, service)`` pairs #759 measured are kept and re-checked
        against the *new* behaviour, because they are the pairs where the defect was
        observable: each is declared in both the TCP and the UDP registry, and each
        used to come back as its port's TCP canonical. Every one of them now
        resolves inside its own registry. The two whose ``__canonical__`` genuinely
        disagrees between the registries -- port **888**, ``accessbuilder`` against
        TCP's ``cddbp``, and port **999**, ``puprouter`` against TCP's ``garcon``
        where UDP answers ``applix`` -- were the whole blast radius, and are the
        sharpest check that the answer now comes from the right registry.

        Asserted over the whole population rather than over a sample, because the
        population is what the crawler regenerates: a future crawl that adds a
        service to a second transport adds members here, and they have to be
        single-bit too. The failures are collected rather than run through
        :meth:`~unittest.TestCase.subTest`, since 12,391 subtests would dominate
        the suite's own output.

        Counted over members the crawler *declared*, so the figure does not depend
        on what else has run in this process: a mint carries ``svc == 'unknown'``
        and no generated member does, which makes that the filter.
        """
        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP, AppType
        from pcapkit.utilities.compat import show_flag_values

        registries = [TCP, UDP, SCTP, DCCP]
        before = {cls.__name__: len(cls) for cls in registries}

        declared = 0
        multi = []  # type: list[tuple[str, int, str, str]]
        foreign = []  # type: list[tuple[str, int, str, str]]
        for cls in registries:
            for member in list(cls):
                if member.svc == 'unknown':
                    continue
                declared += 1
                if len(show_flag_values(member.proto)) > 1:
                    multi.append((cls.__name__, member.port, member.svc, member.proto.name))
                if member.proto is not cls.__transport__:
                    foreign.append((cls.__name__, member.port, member.svc, member.proto.name))

        self.assertEqual(multi, [])
        self.assertEqual(foreign, [])
        self.assertEqual(declared, 12391)
        self.assertEqual({cls.__name__: len(cls) for cls in registries}, before)

        # The 23 ``(port, service)`` pairs #759 measured, kept so the counts above
        # are not the only thing pinning the fix. Each is a member of both the TCP
        # and the UDP registry -- 23 * 2 = 46 lookups -- and each used to answer
        # from TCP whichever registry it was declared in.
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
                    # Single-bit and its own registry's, where it used to be the
                    # ``tcp | udp`` these pairs all carried.
                    self.assertEqual(len(show_flag_values(member.proto)), 1)
                    self.assertIs(member.proto, cls.__transport__)
                    # And passing it back in resolves inside that registry rather
                    # than being refused -- ``get`` answers the port's canonical,
                    # which is the member itself where the member is canonical.
                    resolved = AppType.get(port, proto=member.proto)
                    self.assertIs(type(resolved), cls)
                    self.assertIs(resolved, cls.get(port))
                    # And the member is still reachable, under its own transport.
                    self.assertIn(member, cls.get_all(port))

                    # NOTE: the blast radius, still named. ``tcp`` was the lowest
                    # bit of all 46, so the TCP registry's answer is what the
                    # composite used to resolve to; where that differs from the
                    # member's own registry's answer, the lookup returned a service
                    # that registry does not answer at all. Those are the two rows
                    # below, and they are now answered from UDP as they should be.
                    if TCP.get(port).svc != cls.get(port).svc:
                        divergent.append((cls.__name__, port, svc,
                                          TCP.get(port).svc, cls.get(port).svc))

        self.assertEqual(divergent, [
            ('UDP', 888, 'accessbuilder', 'cddbp', 'accessbuilder'),
            ('UDP', 999, 'puprouter', 'garcon', 'applix'),
        ])
        self.assertEqual(AppType.get(888, proto=UDP.__transport__).svc, 'accessbuilder')
        self.assertEqual(AppType.get(999, proto=UDP.__transport__).svc, 'applix')

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
        * of those, **all 12,391** now carry a single-bit ``.proto`` and **0** a
          multi-bit one. It was 10,625 multi-bit against 1,766 single-bit until
          GitHub issue #806 retyped ``proto`` to the registry's own transport
          protocol. That is a property of the *members*, and it is not what this
          test partitions on;
        * they sit on **12,341** distinct ``(registry, port)`` pairs -- 6,121 TCP,
          6,119 UDP, 91 SCTP, 10 DCCP -- the other **50** sharing a port with
          another service, as IANA's three on TCP/80 do;
        * so the sweep below makes 12,341 distinct lookups, each passing **one**
          transport protocol, which is now also what every member's own ``.proto``
          holds.

        The sweep resolves each ``(registry, port)`` to the same member either side
        of #806, since the lookup key is the port and the registry and neither
        moved. What #806 does change is the *resolved member's* ``.proto``, so a
        digest over ``registry|port|resolved service|int(resolved proto)`` is not
        invariant across it and is deliberately not asserted here; the member-by-
        member rendering is pinned by
        ``test_every_member_renders_its_own_registrys_transport_protocol`` instead.

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
        self.assertEqual(sum(1 for width in widths if width > 1), 0)
        self.assertEqual(sum(1 for width in widths if width == 1), 12391)

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

        :func:`~pcapkit.foundation.registry.register_apptype` used to be the one
        place that handled a member's *composite* ``proto``, reading it off
        ``code.proto`` and testing it with ``in`` to fan out across the TCP and UDP
        protocol registries. GitHub issue #806 removed both halves of that: the
        member's ``proto`` is a single transport protocol, and the function takes
        ``*transport`` varargs, so it iterates the transports it was given and looks
        each one up in a mapping. The two source strings the fan-out was pinned by
        -- ``proto = code.proto`` and ``if test not in proto:`` -- are therefore
        asserted **absent**, and the new shape asserted present, so that a
        reintroduced fan-out cannot pass this test.
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

        # ``register_apptype`` takes the transports one at a time and resolves each
        # against a mapping, so neither half of the old fan-out may reappear. The
        # *shape* is pinned below on the live signature instead of here: a literal
        # ``*transport: 'TransportProtocol', class_: ...`` snippet would re-break on
        # every future change to the annotation (it already broke once, when the
        # #815 ruling added ``| str``) despite the shape it exists to protect never
        # having changed at the source-text level it was reading.
        source = (root / 'pcapkit' / 'foundation' / 'registry' / 'protocols.py').read_text(encoding='utf-8')
        self.assertNotIn('proto = code.proto', source)
        self.assertNotIn('if test not in proto:', source)
        self.assertIn('transport = (code.proto,)', source)
        self.assertIn('for proto in transport:', source)

        # Its signature, checked on the live object rather than on the text, since
        # the text above cannot show what the parameters bind to. ``class_`` is
        # positional again, at the sibling position ahead of ``*transport`` --
        # further maintainer ruling on #815, reversing the keyword-only shape this
        # test used to pin -- restoring consistency with ``register_tcp`` and its
        # siblings.
        import inspect

        from pcapkit.foundation.registry.protocols import register_apptype

        parameters = inspect.signature(register_apptype).parameters
        self.assertEqual([(name, parameter.kind.name) for name, parameter in parameters.items()],
                         [('code', 'POSITIONAL_OR_KEYWORD'), ('module', 'POSITIONAL_OR_KEYWORD'),
                          ('class_', 'POSITIONAL_OR_KEYWORD'), ('transport', 'VAR_POSITIONAL')])

        # Pure ``bind()`` is purely positional: it cannot see what ``module`` *is*,
        # so a third positional argument lands in ``class_`` regardless -- the very
        # swallow the keyword-only shape used to prevent. That the swallow does not
        # actually happen any more is not a fact ``bind()`` can show, because the
        # disambiguation runs in the function body, keyed on ``type(module)``, and
        # only takes place once ``register_apptype`` actually executes.
        from pcapkit.const.reg.apptype import TransportProtocol

        bound = inspect.signature(register_apptype).bind(80, object(), TransportProtocol.udp)
        self.assertEqual(bound.arguments['class_'], TransportProtocol.udp)
        self.assertNotIn('transport', bound.arguments)

        # So the branch itself is checked by actually calling the live function,
        # not by binding its signature: a class ``module`` sends the same third
        # argument to the real ``TCP``/``UDP`` registry as ``transport``, and a
        # ``str`` module leaves it in ``class_`` and registers the class it names.
        # ``tests/foundation/registry/test_protocols.py`` covers this branch and
        # its edge cases in full; this is the narrow claim that anchors it here.
        from unittest import mock

        from pcapkit.foundation.registry import protocols as apptype_registry
        from pcapkit.protocols.misc.raw import Raw

        missing = object()
        previous = apptype_registry.UDP.__proto__.get(65210, missing)
        try:
            with mock.patch.object(apptype_registry, 'register_protocol'):
                register_apptype(65210, Raw, TransportProtocol.udp)
            self.assertIs(apptype_registry.UDP.__proto__[65210], Raw)
        finally:
            if previous is missing:
                apptype_registry.UDP.__proto__.pop(65210, None)
            else:
                apptype_registry.UDP.__proto__[65210] = previous

    def test_the_new_dunders_are_byte_identical_to_the_percent_form(self) -> None:
        """GitHub issue #798: ``AppType``'s ``__new__``/``__repr__``/``__str__`` moved
        from ``%`` formatting to f-strings, and ``__new__``'s format sets every
        real member's underlying :class:`~aenum.StrEnum` value -- a far larger
        blast radius than an error path, so this is checked member by member
        rather than spot-checked.

        Swept over all 12,391 real members (TCP 6147, UDP 6143, SCTP 91,
        DCCP 10, matching the population GitHub issue #783 measured), each
        compared against what the pre-#798 ``%``-style formula would have
        produced for that same member's own ``svc``/``port``/``proto``. This
        is an invariance check -- it is true either side of #798's fix by
        construction, since both formulas render the same text for the same
        inputs -- rather than a regression test that fails on stock ``main``.

        Runs against a freshly imported, purged-and-restored ``pcapkit`` tree
        (as :class:`~tests.const.test_const_enum_builtin_parity.ConstEnumBuiltinParityTests`
        does) rather than whatever module instance an earlier test in this
        file left behind: several sibling tests here mint throwaway members
        via :func:`~aenum.extend_enum` and clean up with
        :meth:`~unittest.TestCase.addCleanup`, but the population counts below
        are only meaningful against a registry no other test has touched.
        """
        from tests._support import (ISOLATED_PREFIXES, purge_modules, restore_modules,
                                    snapshot_modules)

        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP

        registries = {'TCP': TCP, 'UDP': UDP, 'SCTP': SCTP, 'DCCP': DCCP}
        expected_counts = {'TCP': 6147, 'UDP': 6143, 'SCTP': 91, 'DCCP': 10}
        total = 0

        for name, cls in registries.items():
            count = 0
            for member in cls:
                count += 1
                total += 1
                svc, port, proto = member.svc, member.port, member.proto

                with self.subTest(registry=name, member=member.name, check='value'):
                    old_value = '%s [%d - %s]' % (svc, port, proto.name)  # pylint: disable=consider-using-f-string
                    self.assertEqual(str(member._value_), old_value)  # type: ignore[attr-defined]

                with self.subTest(registry=name, member=member.name, check='repr'):
                    old_repr = "<%s.%s: %d [%s]>" % (  # pylint: disable=consider-using-f-string
                        member.__class__.__name__, svc, port, proto.name)
                    self.assertEqual(repr(member), old_repr)

                with self.subTest(registry=name, member=member.name, check='str'):
                    old_str = '%s [%d - %s]' % (svc, port, proto.name)  # pylint: disable=consider-using-f-string
                    self.assertEqual(str(member), old_str)

            self.assertEqual(count, expected_counts[name], f'{name} population changed')

        self.assertEqual(total, 12391)

    def test_every_member_renders_its_own_registrys_transport_protocol(self) -> None:
        """GitHub issue #806, member by member over all 12,391.

        ``proto.name`` is folded into the member's underlying
        :class:`~aenum.StrEnum` *value* by ``__new__``, not merely into its display,
        so retyping ``proto`` rewrites ``TCP.http.value`` from
        ``'http [80 - tcp|udp|sctp]'`` to ``'http [80 - tcp]'``. ``_value_`` is the
        live key in ``_value2member_map_``, which is why the retype has to happen in
        the generated source rather than at runtime -- a member whose ``_value_``
        were edited afterwards would no longer be reachable by its own value.

        Checked against the formula rather than against the member's own ``proto``:
        the expected text is built from ``cls.__transport__``, which is declared once
        per registry and is independent of what any member carries. That is what
        makes this fail on stock ``4530424df``, where 10,625 of the 12,391 render a
        composite -- ``test_the_new_dunders_are_byte_identical_to_the_percent_form``
        derives its expectation from ``member.proto`` instead and so is invariant
        across this change by construction.

        Swept over every declared member of all four registries rather than
        spot-checked, since the blast radius is 85.7% of the enumeration.
        """
        from tests._support import (ISOLATED_PREFIXES, purge_modules, restore_modules,
                                    snapshot_modules)

        snapshot = snapshot_modules(ISOLATED_PREFIXES)
        purge_modules(['pcapkit'])
        self.addCleanup(restore_modules, snapshot, ISOLATED_PREFIXES)

        from pcapkit.const.reg.apptype import DCCP, SCTP, TCP, UDP

        expected_counts = {'TCP': 6147, 'UDP': 6143, 'SCTP': 91, 'DCCP': 10}
        total = 0
        wrong = []  # type: list[tuple[str, str, str, str]]

        for cls in (TCP, UDP, SCTP, DCCP):
            count = 0
            transport = cls.__transport__.name
            for member in cls:
                count += 1
                total += 1
                value = f'{member.svc} [{member.port} - {transport}]'
                if str(member._value_) != value:  # type: ignore[attr-defined]
                    wrong.append((cls.__name__, member.name, 'value', str(member._value_)))  # type: ignore[attr-defined]
                if str(member) != value:
                    wrong.append((cls.__name__, member.name, 'str', str(member)))
                shown = f'<{cls.__name__}.{member.svc}: {member.port} [{transport}]>'
                if repr(member) != shown:
                    wrong.append((cls.__name__, member.name, 'repr', repr(member)))
                # The value is the live lookup key, so it has to round-trip.
                if cls(value) is not member:
                    wrong.append((cls.__name__, member.name, 'lookup', value))
            self.assertEqual(count, expected_counts[cls.__name__],
                             f'{cls.__name__} population changed')

        self.assertEqual(wrong[:20], [])
        self.assertEqual(len(wrong), 0)
        self.assertEqual(total, 12391)

    def test_transport_protocol_dropped_its_flag_base(self) -> None:
        """GitHub issue #808: the base itself, once #806 removed every composite.

        Pins three things directly, so a regression that reintroduces the
        ``IntFlag`` base or renumbers the four transports fails here rather
        than only in the ``_dispatch`` refusal tests above:

        * ``TransportProtocol`` is a plain :class:`~aenum.IntEnum`, not a
          :class:`~enum.Flag` of any kind -- ``&``, ``^`` and ``~`` are gone
          along with ``|``'s member-composing behaviour.
        * ``tcp | udp`` no longer builds a named member: it falls through to
          ``int.__or__`` and returns a bare :class:`int`, so ``.name`` on the
          result raises :class:`AttributeError` rather than answering
          ``'tcp|udp'``.
        * The five members keep the exact integer values they had as Flag
          bits -- ``undefined`` 0, ``tcp`` 1, ``udp`` 2, ``sctp`` 4, ``dccp``
          8 -- since GitHub issue #808 is about the base class, not about
          renumbering members that predate it.

        Fails on stock ``ad4805f5f``: ``TransportProtocol`` there is still an
        ``IntFlag``, so ``issubclass(TransportProtocol, enum.Flag)`` is
        ``True``, and ``TransportProtocol.tcp | TransportProtocol.udp`` is a
        genuine composite member whose ``.name`` answers ``'tcp|udp'`` rather
        than raising :class:`AttributeError`.

        Also pins a change to plain iteration that is easy to miss because
        every *member's* own ``repr``/``str``/``.name``/``.value`` stay
        byte-identical: :class:`~enum.Flag` hides a zero-valued canonical
        member from ``list(cls)``/``for m in cls``, so stock iterates
        ``undefined`` out and yields the four real transports alone. A plain
        :class:`~aenum.IntEnum` has no such convention and yields all five.
        Nothing in :mod:`pcapkit` iterates ``TransportProtocol`` bare --
        ``apptype.py``'s own ``__init__.py`` populates ``__registries__``
        through ``__members__`` (5 either way, unaffected), never through
        iteration -- so this is a correctness fact about the change worth
        pinning, not a defect to fix.
        """
        import enum

        from pcapkit.const.reg.apptype import TransportProtocol

        self.assertTrue(issubclass(TransportProtocol, int))
        self.assertFalse(issubclass(TransportProtocol, enum.Flag))

        composite = TransportProtocol.tcp | TransportProtocol.udp
        self.assertNotIsInstance(composite, TransportProtocol)
        self.assertIsInstance(composite, int)
        self.assertEqual(int(composite), 3)
        with self.assertRaises(AttributeError):
            composite.name  # type: ignore[union-attr]

        self.assertEqual(
            {member.name: int(member) for member in
             (TransportProtocol.undefined, TransportProtocol.tcp, TransportProtocol.udp,
              TransportProtocol.sctp, TransportProtocol.dccp)},
            {'undefined': 0, 'tcp': 1, 'udp': 2, 'sctp': 4, 'dccp': 8})

        # 5 rather than 4: undefined is no longer hidden from iteration. Stock
        # ad4805f5f gives 4 here (tcp, udp, sctp, dccp only), so this half of
        # the test would also fail there, on a different assertion than the
        # ones above.
        self.assertEqual(len(list(TransportProtocol)), 5)
        self.assertEqual(len(TransportProtocol.__members__), 5)

    def test_get_refuses_an_unrecognised_name_rather_than_minting_it(self) -> None:
        """Maintainer ruling on this PR (#836), the ``TransportProtocol.get`` inline comment.

        ``TransportProtocol.get`` used to mint a brand-new member for any
        name it did not recognise. This PR's own prior revision minted at
        ``max_val + 1`` -- right after ``dccp``'s 8, so ``.get('bogus')``
        minted 9 -- rather than stock ``ad4805f5f``'s ``max_val * 2``
        doubling, which mints 16 for that same call; the difference between
        the two schemes is explained below. The maintainer's ruling refuses
        minting outright either way: "Do not allow extension of
        TransportProtocol at all." There is no bound left to walk and
        nothing left to mint, so the refusal is the one plain
        :class:`ValueError` every unrecognised name gets, whether or not it
        happens to spell a composite like ``'tcp|udp'``. A later round of
        this PR briefly gave the composite case its own, more specific
        message; the owner's ruling retired that split too -- "since it's
        no longer a Flag, `|` joined values are no longer parsed and
        accepted, we will treat it as a whole, instead of splitting" -- so
        ``'|'`` is not treated specially any more, here or in
        :meth:`AppType._dispatch` (see
        ``test_a_bare_int_composite_is_refused_as_a_whole``).

        This also retires a sharper defect the old minting scheme created,
        which is what this test used to be named for: 9 is exactly ``1 | 8``,
        the bits ``tcp`` and ``dccp`` declare, so an intermediate round of
        this same PR -- after minting had already moved to ``max_val + 1``
        but before this ruling -- decoded every ``proto`` reaching
        :meth:`AppType._dispatch` through
        :func:`~pcapkit.utilities.compat.show_flag_values` regardless of
        whether it was a genuine member, and answered "tcp|dccp names 2
        transport protocols" for a name that named neither. That shape never
        shipped in stock ``ad4805f5f``, whose ``max_val * 2`` doubling kept
        every minted value a fresh single bit, and it cannot happen now
        either, from the other direction: refusing the mint outright leaves
        :meth:`AppType._dispatch` nothing minted to mis-decode in the first
        place.

        Regression check: this fails against this PR's own prior head,
        ``3567359e2``, which still mints ``9`` and returns it rather than
        raising -- see the session report for the quoted failure.
        """
        from pcapkit.utilities.exceptions import ProtocolError

        from pcapkit.const.reg.apptype import TransportProtocol

        self.assertNotIn('unit_test_836_bogus', TransportProtocol.__members__)
        before = len(TransportProtocol.__members__)

        with self.assertRaises(ValueError) as caught:
            TransportProtocol.get('unit_test_836_bogus')
        # Plain ValueError -- not the ProtocolError the old
        # show_flag_values-based decoding briefly answered with for a
        # minted 9, back before this ruling retired minting entirely.
        self.assertNotIsInstance(caught.exception, ProtocolError)
        self.assertIn('unit_test_836_bogus', str(caught.exception))
        self.assertIn('is not a valid', str(caught.exception))

        # Refused, not minted: the registry is exactly as it was, and a
        # second distinct unrecognised name is refused the same way rather
        # than taking the next integer after a member that was never created.
        self.assertEqual(len(TransportProtocol.__members__), before)
        self.assertNotIn('unit_test_836_bogus', TransportProtocol.__members__)
        with self.assertRaises(ValueError):
            TransportProtocol.get('unit_test_836_bogus_two')
        self.assertEqual(len(TransportProtocol.__members__), before)

    def test_get_refuses_a_composite_spelled_string(self) -> None:
        """A ``'|'``-joined name is just another unrecognised name.

        :meth:`TransportProtocol.get` used to mint whatever string it did not
        recognise, including one spelling a composite -- ``'tcp|udp'`` -- as a
        brand-new, single-bit member whose own name lies about being one
        transport. That member's value would then satisfy the bare-int
        composite branch :meth:`AppType._dispatch` used to have just as
        readily as a genuinely OR-ed value, the mirror image of the
        minted-member defect above -- and that branch is gone now too (see
        ``test_a_bare_int_composite_is_refused_as_a_whole``).
        :func:`~pcapkit.foundation.registry.protocols.register_apptype`
        refuses the identical string the same generic way it refuses any
        other unrecognised one, and the owner's ruling on this PR -- "since
        it's no longer a Flag, `|` joined values are no longer parsed and
        accepted, we will treat it as a whole, instead of splitting" --
        settles :meth:`TransportProtocol.get` onto that same answer: ``'|'``
        is not special, it is simply not the name of a declared member. A
        review round of this PR briefly carved the composite case out with
        its own diagnostic message; the owner's ruling retired that too.
        """
        from pcapkit.const.reg.apptype import TransportProtocol

        self.assertNotIn('tcp|udp', TransportProtocol.__members__)
        with self.assertRaises(ValueError) as caught:
            TransportProtocol.get('tcp|udp')
        self.assertIn('tcp|udp', str(caught.exception))
        self.assertIn('is not a valid', str(caught.exception))
        self.assertNotIn('tcp|udp', TransportProtocol.__members__)

    def test_a_bare_int_with_a_stray_bit_names_no_registry_either(self) -> None:
        """A stray bit gets the exact same refusal a clean composite does.

        ``17`` is ``1 | 16`` -- ``tcp`` plus a bit no registry declares -- so
        it never named a clean composite of real transports the way ``3``
        (``tcp | udp``) once did either, back when ``_dispatch`` still
        decoded a bare int's bits at all. The owner's ruling on this PR
        (#836) retired that decoding entirely (see
        ``test_a_bare_int_composite_is_refused_as_a_whole``), so ``17`` and
        ``3`` are no longer two different cases -- both are simply an
        ``int`` that names no registry, and both get the identical plain
        ``ValueError`` any other unmatched value gets.
        """
        from pcapkit.const.reg.apptype import AppType
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ValueError) as caught:
            AppType.get(80, proto=17)
        self.assertNotIsInstance(caught.exception, ProtocolError)
        self.assertIn('names no transport protocol registry', str(caught.exception))

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
