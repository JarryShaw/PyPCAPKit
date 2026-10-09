# -*- coding: utf-8 -*-
"""Handing a code back takes back the by-name entry its registration made. C.f. #1505.

Every code registrar in :mod:`pcapkit.foundation.registry.protocols` --
``register_tcp``, ``register_linktype`` and the rest -- ends by naming the class
it registered in :data:`pcapkit.protocols.__proto__`. Registering the shipped
entry back restored the code but never the name: ``register_tcp(80, Custom)``
then ``register_tcp(80, shipped)`` left ``'CUSTOM'`` behind for good, and a
custom class named like a built-in left the built-in displaced.

:mod:`tests.foundation.registry.test_registry_symmetry_unit` covers the plain
round trip for all nine registrars. These pin the cases it does not reach: a
displaced built-in name, a class still held by a second code, a name that was
there before the registration, which a restore must not take away, and a
built-in retaking its name from a custom class shadowing it -- plus a seeded
fuzz over all of those, checked after every call.

"""

from __future__ import annotations

import importlib.util
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestRegistryNameRestore(unittest.TestCase):
    """Restoring a code leaves :data:`pcapkit.protocols.__proto__` as it found it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

        from pcapkit.protocols import __proto__ as names
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        self.tables = (names, TCP.__proto__, UDP.__proto__, Frame.__proto__, PCAPNG.__proto__)
        self.saved = [dict(table) for table in self.tables]
        self.addCleanup(self._reset)
        self.names = names
        self.before = dict(names)

    def _reset(self) -> None:
        for table, copy in zip(self.tables, self.saved):
            table.clear()
            table.update(copy)

    def _custom(self, name: 'str') -> 'Any':
        from pcapkit.protocols.application.application import Application

        return type(name, (Application,), {'__module__': __name__})

    def _call(self, register: 'Any', *args: 'Any') -> None:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            register(*args)

    def assert_names_as_found(self) -> None:
        self.assertEqual(sorted(self.names), sorted(self.before))
        for name, entry in self.before.items():
            self.assertIs(self.names[name], entry, name)

    def test_restoring_a_code_removes_the_name_it_added(self) -> None:
        """The issue's reproduction: the custom name goes when port 80 is restored."""
        from pcapkit.foundation.registry import register_tcp
        from pcapkit.protocols.transport.tcp import TCP

        shipped = TCP.__proto__[80]
        custom = self._custom('Custom')

        self.assertNotIn('CUSTOM', self.names)
        self._call(register_tcp, 80, custom)
        self.assertIs(self.names['CUSTOM'], custom)
        self._call(register_tcp, 80, shipped)
        self.assertNotIn('CUSTOM', self.names)
        self.assert_names_as_found()

    def test_restoring_a_code_puts_back_the_name_it_displaced(self) -> None:
        """A custom class named like a built-in hands the built-in its name back."""
        from pcapkit.foundation.registry import register_tcp
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.transport.tcp import TCP

        shipped = TCP.__proto__[80]
        custom = self._custom('IPv4')

        self._call(register_tcp, 80, custom)
        self.assertIs(self.names['IPV4'], custom)
        self._call(register_tcp, 80, shipped)
        self.assertIs(self.names['IPV4'], IPv4)
        self.assert_names_as_found()

    def test_a_name_stays_while_another_code_still_holds_it(self) -> None:
        """The name goes with the last code dispatching to the class, not the first."""
        from pcapkit.foundation.registry import register_tcp, register_udp
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        tcp, udp = TCP.__proto__[80], UDP.__proto__[80]
        custom = self._custom('Custom')

        self._call(register_tcp, 80, custom)
        self._call(register_udp, 80, custom)
        self._call(register_tcp, 80, tcp)
        self.assertIs(UDP.__proto__[80], custom)
        self.assertIs(self.names['CUSTOM'], custom)
        self._call(register_udp, 80, udp)
        self.assert_names_as_found()

    def test_linktype_holds_the_name_from_both_registries(self) -> None:
        """``register_linktype`` writes Frame and PCAPNG, so both must be handed back."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.registry import register_linktype, register_pcap, register_pcapng
        from pcapkit.protocols.link.link import Link
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG

        frame, pcapng = Frame.__proto__[LinkType.ETHERNET], PCAPNG.__proto__[LinkType.ETHERNET]
        custom = type('Custom', (Link,), {'__module__': __name__})

        self._call(register_linktype, LinkType.ETHERNET, custom)
        self._call(register_pcap, LinkType.ETHERNET, frame)
        self.assertIs(self.names['CUSTOM'], custom)
        self._call(register_pcapng, LinkType.ETHERNET, pcapng)
        self.assert_names_as_found()

    def test_a_name_held_before_the_registration_is_kept(self) -> None:
        """A class named before it took a code keeps its name once the code goes back."""
        from pcapkit.foundation.registry import register_protocol, register_tcp
        from pcapkit.protocols.protocol import Protocol
        from pcapkit.protocols.transport.tcp import TCP

        shipped = TCP.__proto__[80]
        defined = type('Defined', (Protocol,), {'__module__': __name__})  # named by definition
        explicit = self._custom('Explicit')
        register_protocol(explicit)
        self.before = dict(self.names)
        self.assertIs(self.before['DEFINED'], defined)

        for custom in (defined, explicit):
            with self.subTest(name=custom.__name__):
                self._call(register_tcp, 80, custom)
                self._call(register_tcp, 80, shipped)
                self.assert_names_as_found()

    def test_re_registering_the_same_override_stays_quiet(self) -> None:
        """A repeated override neither warns nor loses the name it displaced."""
        from pcapkit.foundation.registry import register_tcp
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.warnings import RegistryWarning

        shipped = TCP.__proto__[80]
        custom = self._custom('HTTP')

        self._call(register_tcp, 80, custom)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            register_tcp(80, custom)
        self.assertEqual([str(item.message) for item in caught
                          if issubclass(item.category, RegistryWarning)], [])
        self.assertIs(self.names['HTTP'], custom)
        self._call(register_tcp, 80, shipped)
        self.assertIs(self.names['HTTP'], HTTP)
        self.assert_names_as_found()

    def test_a_built_in_over_its_own_shadow_is_undone_in_either_order(self) -> None:
        """Each restore undoes its own write, when a built-in retakes its name from a shadow.

        A custom ``IPv4`` at port 80 shadows the built-in. Registering the built-in
        at port 8080 takes the name back. Restoring 8080 must hand the name back to
        the shadow, which port 80 still dispatches to, and restoring 80 then hands
        it to the built-in. Done in the other order, the built-in keeps the name
        throughout.

        """
        from pcapkit.foundation.registry import register_tcp
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.transport.tcp import TCP

        s80, s8080 = TCP.__proto__[80], TCP.__proto__[8080]
        custom = self._custom('IPv4')
        for order in ((8080, 80), (80, 8080)):
            with self.subTest(restore=order):
                self._reset()
                self._call(register_tcp, 80, custom)
                self._call(register_tcp, 8080, IPv4)
                self.assertIs(self.names['IPV4'], IPv4)
                self._call(register_tcp, order[0], {80: s80, 8080: s8080}[order[0]])
                self.assertIs(self.names['IPV4'], custom if order[0] == 8080 else IPv4)
                self._call(register_tcp, order[1], {80: s80, 8080: s8080}[order[1]])
                self.assert_names_as_found()

    def test_any_sequence_restored_in_full_leaves_names_as_found(self) -> None:
        """Seeded fuzz: register at random, restore every code, compare with the start.

        Custom classes, some named like each other and some like built-ins, and the
        built-ins themselves (``IPv4`` and the three ``HTTP`` classes), go through
        ``register_tcp``, ``register_udp`` and ``register_apptype`` at a handful of
        shipped ports, with restores mixed in. Every code is then restored to its
        shipped entry, in a shuffled order, and the names must be exactly as found.

        Each step is checked too: a name shows the class of the latest registration
        still in place under it, or what it was found as once none is.

        """
        import random

        from pcapkit.foundation.registry import register_apptype, register_tcp, register_udp
        from pcapkit.protocols.application import http, httpv1, httpv2
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        registrars = {'tcp': register_tcp, 'udp': register_udp}
        shipped = {('tcp', code): TCP.__proto__[code] for code in (21, 80, 8080)}
        shipped.update({('udp', code): UDP.__proto__[code] for code in (80, 1701, 8080)})
        targets = sorted(shipped)
        builtins = [IPv4, http.HTTP, httpv1.HTTP, httpv2.HTTP]

        def expected(held: 'dict[Any, tuple[int, Any]]', name: 'str') -> 'Any':
            latest = max((entry for entry in held.values() if entry[1].__name__.upper() == name),
                         default=None, key=lambda entry: entry[0])
            return self.before.get(name) if latest is None else latest[1]

        rng = random.Random(1505)
        failures = []  # type: list[tuple[list[tuple[Any, ...]], str]]
        for _ in range(2000):
            pool = [self._custom(name) for name in ('IPv4', 'HTTP', 'Custom', 'Custom')] + builtins
            ops = []  # type: list[tuple[Any, ...]]
            for _ in range(rng.randint(1, 8)):
                draw, target = rng.random(), rng.choice(targets)
                if draw < 0.55:
                    ops.append(('register', target, rng.randrange(len(pool))))
                elif draw < 0.65:
                    ops.append(('apptype', rng.choice((80, 8080)), rng.randrange(len(pool))))
                else:
                    ops.append(('restore', target))
            final = list(targets)
            rng.shuffle(final)
            ops.extend(('restore', target) for target in final)

            held = {target: (0, shipped[target].klass) for target in targets}
            watched = set(self.before) | {cls.__name__.upper() for cls in pool}
            for step, op in enumerate(ops, 1):
                if op[0] == 'register':
                    self._call(registrars[op[1][0]], op[1][1], pool[op[2]])
                    held[op[1]] = (step, pool[op[2]])
                elif op[0] == 'apptype':
                    self._call(register_apptype, op[1], pool[op[2]], 'tcp', 'udp')
                    held[('tcp', op[1])] = held[('udp', op[1])] = (step, pool[op[2]])
                else:
                    self._call(registrars[op[1][0]], op[1][1], shipped[op[1]])
                    held[op[1]] = (step, shipped[op[1]].klass)
                wrong = [f'step {step}, {name}: {self.names.get(name)!r}, expected '
                         f'{expected(held, name)!r}' for name in sorted(watched | set(self.names))
                         if self.names.get(name) is not expected(held, name)]
                if wrong:
                    failures.append((ops[:step], wrong[0]))
                    break
            self._reset()

        failures.sort(key=lambda failure: len(failure[0]))
        self.assertEqual(failures[:1], [], f'{len(failures)} of 2000 sequences went wrong')


if __name__ == '__main__':
    unittest.main()
