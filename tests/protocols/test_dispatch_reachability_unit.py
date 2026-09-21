# -*- coding: utf-8 -*-
"""Every class that declares a dispatch code is reachable under it.

GitHub issue #548 asked for this directly:

    No test asserts that every ``TransType`` member with an implementing class
    is reachable through dispatch, which is why this survived. Such a test
    would be broadly useful -- it would catch the next missing registration
    rather than just this one.

:file:`test_dispatch_registry_unit.py` walks the problem from the other end: it
takes each of the 38 ``__proto__`` entries that *exist* and checks the class it
names can parse a packet. That cannot see a class nobody registered at all,
which is exactly how :class:`~pcapkit.protocols.link.ospf.OSPF` shipped
reachable from no table (fixed in #436). This module walks it from the class
side instead -- every
:class:`~pcapkit.protocols.protocol.ProtocolBase` descendant whose
:meth:`~pcapkit.protocols.protocol.Protocol.__index__` returns an enum member
is *claiming* to be reachable under that code, so the claim is checked.

Which registry a code belongs in is not restated here. It is read from
:data:`~pcapkit.foundation.registry.protocols._CODE_DESTINATIONS`, the enum
type -> destination table #570 shipped to back ``code=``, so the audit and the
registration mechanism cannot drift apart: an enum type added to that table
gets audited here the same day.

Nothing is parsed and no capture under :file:`examples/captures/` is read, so
this belongs to the unit tier.

"""
from __future__ import annotations

import importlib.util
import pkgutil
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests._support import purge_modules

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class Gap(NamedTuple):
    """One class that declares a code it cannot be reached under."""

    #: Fully qualified name of the class making the claim.
    protocol: 'str'
    #: ``__name__`` of the class owning the registry it should appear in.
    destination: 'str'
    #: The code its ``__index__`` returned.
    code: 'Any'
    #: What the registry actually holds under that code, or :data:`None`.
    found: 'Any'


def _resolve(entry: 'Any') -> 'tuple[Any, Any]':
    """The ``(module, name)`` a registry entry names.

    An entry is either a
    :class:`~pcapkit.corekit.module.ModuleDescriptor` -- the lazy form the
    built-in tables use -- or an already-imported class.

    """
    module = getattr(entry, 'module', None)
    if module is not None:
        return module, getattr(entry, 'name', None)
    return getattr(entry, '__module__', None), getattr(entry, '__name__', None)


def _descendants(cls: 'type') -> 'Any':
    """Every subclass of ``cls``, transitively."""
    for sub in cls.__subclasses__():
        yield sub
        yield from _descendants(sub)


def audit() -> 'tuple[list[Gap], int]':
    """Walk every indexed protocol class and report the ones nothing reaches.

    Returns:
        The gaps found, and how many reachable claims were verified -- the
        second number is what stops a silently-empty walk from passing as a
        clean audit.

    """
    import pcapkit.protocols as protopkg
    from pcapkit.foundation.registry.protocols import _CODE_DESTINATIONS
    from pcapkit.protocols.protocol import ProtocolBase

    # Import every protocol module, or ``__subclasses__`` sees only whatever
    # this process happened to touch first.
    for info in pkgutil.walk_packages(protopkg.__path__, prefix='pcapkit.protocols.'):
        importlib.import_module(info.name)

    gaps = []  # type: list[Gap]
    checked = 0

    for cls in sorted(set(_descendants(ProtocolBase)),
                      key=lambda item: (item.__module__, item.__name__)):
        try:
            code = cls.__index__()  # type: ignore[call-arg]
        except Exception:  # pylint: disable=broad-except
            continue  # declares no code, so claims no reachability
        if code is None:
            continue  # an abstract base, reached by nothing

        destinations = _CODE_DESTINATIONS.get(type(code))
        if destinations is None:
            continue  # no registry is keyed by this enum type

        for destination in destinations:
            entry = destination.__proto__.get(code)
            module, name = _resolve(entry) if entry is not None else (None, None)

            # Two spellings both count as reachable, for reasons that are
            # properties of the tables rather than of this audit:
            #
            # * the same *name*, because a built-in entry may name the package
            #   re-export rather than the defining module -- ``Frame.__proto__``
            #   holds ``pcapkit.protocols.link:Ethernet``, not
            #   ``pcapkit.protocols.link.ethernet:Ethernet``;
            # * the same *module*, because the project's rule is that a shared
            #   index may share a module -- ``InARP`` shares ``ARP``'s, and
            #   ``DRARP`` shares ``RARP``'s -- and a distinct one may not, per
            #   ``test_vlan_indices_follow_the_one_module_per_index_rule``. Both
            #   classes answer to the code and the module they share is what
            #   dispatches between them, so the sibling's name is not a mismatch.
            if name == cls.__name__ or module == cls.__module__:
                checked += 1
                continue

            gaps.append(Gap(f'{cls.__module__}.{cls.__name__}',
                            destination.__name__, code, name))

    return gaps, checked


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DispatchReachabilityTests(unittest.TestCase):
    """No protocol class declares a code that nothing dispatches."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_every_indexed_class_is_reachable_under_the_code_it_declares(self) -> None:
        """The invariant itself, over every class rather than a hand-picked few."""
        gaps, checked = audit()

        self.assertEqual(gaps, [], 'protocol classes declare codes nothing dispatches: '
                                   + '; '.join(f'{gap.protocol} says {gap.code!r} but '
                                               f'{gap.destination}.__proto__ holds '
                                               f'{gap.found!r}' for gap in gaps))

        # A walk that found nothing to check would also report no gaps, so pin
        # the floor. 23 claims verified when this landed -- the 21 distinct
        # classes plus ``InARP`` and ``DRARP`` reaching their siblings' entries,
        # and ``Ethernet`` counted once for ``Frame`` and once for ``PCAPNG``.
        self.assertGreaterEqual(checked, 23)

    def test_the_audit_detects_a_code_that_nothing_dispatches(self) -> None:
        """The guard has teeth: inject a gap and confirm the audit reports it.

        Without this, a bug that made :func:`audit` return early -- an import
        that silently failed, an ``except`` that swallowed too much -- would
        leave a permanently green test asserting nothing at all.

        """
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.link.link import Link

        # ``TransType.L2TP`` is genuinely unbound (issue #548), so a class
        # claiming it is exactly the shape this audit exists to catch.
        self.assertNotIn(TransType.L2TP, Internet.__proto__)

        class Unreachable(Link):  # pylint: disable=abstract-method
            """Declares 115 and is registered nowhere."""

            @classmethod
            def __index__(cls) -> 'Any':
                return TransType.L2TP

        try:
            gaps, _ = audit()
            names = [gap.protocol for gap in gaps]
            self.assertTrue(any(name.endswith('Unreachable') for name in names),
                            f'audit missed the injected gap; reported {names}')
        finally:
            # ``__subclasses__`` holds a weak reference, but the class is only
            # collected once nothing in this frame names it.
            del Unreachable

    def test_transtype_l2tp_is_unbound_because_v3_has_no_class(self) -> None:
        """115's gap is a missing *class*, not a missing registration.

        Issue #548 read the empty slot as an oversight. :rfc:`3931` §4.1.1 is
        what fills it: *"L2TPv3 over IP (both versions) utilizes the
        IANA-assigned IP protocol ID 115."* So 115 names the v3-over-IP header,
        which no class in this tree implements -- and this audit deliberately
        does **not** flag it, because nothing claims 115 in the first place.
        :class:`~pcapkit.protocols.link.l2tpv2.L2TPv2` raises from
        ``__index__`` rather than returning it.

        """
        import pcapkit.protocols.link as linkpkg
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.link.l2tp import L2TP
        from pcapkit.protocols.link.l2tpv2 import L2TPv2
        from pcapkit.utilities.exceptions import UnsupportedCall

        self.assertNotIn(TransType.L2TP, Internet.__proto__)
        for cls in (L2TP, L2TPv2):
            with self.subTest(cls=cls.__name__):
                with self.assertRaises(UnsupportedCall):
                    cls.__index__()

        modules = {info.name for info in pkgutil.iter_modules(linkpkg.__path__)}
        self.assertNotIn('l2tpv3', modules)

        gaps, _ = audit()
        self.assertNotIn(TransType.L2TP, [gap.code for gap in gaps])


if __name__ == '__main__':
    unittest.main()
