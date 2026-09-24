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
