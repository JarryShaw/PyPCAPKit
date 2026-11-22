# -*- coding: utf-8 -*-
"""One callback registrar per kind of class, keyed by the name it is registered by. C.f. #2838.

The per-protocol ``register_reassembly_{ipv4,ipv6,tcp}_callback`` and
``register_traceflow_tcp_callback`` reached three reassemblers and one flow
tracer, took no ``index``, and left DTLS and a registered reassembler without
one. :func:`~pcapkit.foundation.registry.foundation.register_reassembly_callback`
and :func:`~pcapkit.foundation.registry.foundation.register_traceflow_callback`
replace them, with no shim: each looks the class up by name in the extractor's
own registry, so every class registered there is reached by one function.

The names are read from :attr:`Extractor.__reassembly__` and
:attr:`Extractor.__traceflow__` rather than listed here, so a reassembler
shipped tomorrow is covered tomorrow. Each test puts back every callback list it
touched. Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import importlib.util
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): a sweep over every registered reassembler and flow tracer.
__tier__ = 'LATEST'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))


def _resolved(entry: 'Any') -> 'Any':
    from pcapkit.corekit.module import ModuleDescriptor

    return entry.klass if isinstance(entry, ModuleDescriptor) else entry


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class CallbackRegistrarTests(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _keep(self, klass: 'Any') -> None:
        """Put ``klass``'s callback list back as it is now, after the test."""
        saved = list(klass.__callback_fn__)

        def restore() -> None:
            klass.__callback_fn__[:] = saved
        self.addCleanup(restore)

    def _cases(self) -> 'list[tuple[Any, str, Any]]':
        """``(registrar, name, class)`` for every reassembler and flow tracer the extractor holds."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.registry import register_reassembly_callback, register_traceflow_callback

        cases = [(register_reassembly_callback, name, _resolved(entry))
                 for name, entry in Extractor.__reassembly__.items()]
        cases += [(register_traceflow_callback, name, _resolved(entry))
                  for name, entry in Extractor.__traceflow__.items()]
        return cases

    def test_old_per_protocol_registrars_are_gone(self) -> None:
        """Removed with no alias, per public-signatures.rst's Incompatible Changes."""
        import pcapkit
        import pcapkit.foundation
        from pcapkit.foundation import registry
        from pcapkit.foundation.registry import foundation

        for name in ('register_reassembly_ipv4_callback', 'register_reassembly_ipv6_callback',
                     'register_reassembly_tcp_callback', 'register_traceflow_tcp_callback'):
            for module in (pcapkit, pcapkit.foundation, registry, foundation):
                with self.subTest(name=name, module=module.__name__):
                    self.assertFalse(hasattr(module, name))
                    self.assertNotIn(name, getattr(module, '__all__', ()))

    def test_every_registered_class_is_reached_by_name(self) -> None:
        """DTLS included: each name reaches the class registered under it, and only that one."""
        cases = self._cases()
        self.assertIn('dtls', {name for _, name, _ in cases})  # the extractor's table is read
        for _, _, klass in cases:
            self._keep(klass)

        for register, name, klass in cases:
            def callback(_: 'Any') -> None:
                return None

            with self.subTest(registrar=register.__name__, name=name):
                before = {other: list(other.__callback_fn__) for _, _, other in cases}
                register(name, callback)
                self.assertIs(klass.__callback_fn__[-1], callback)
                for other, callbacks in before.items():
                    expected = callbacks + [callback] if other is klass else callbacks
                    self.assertEqual(other.__callback_fn__, expected, other.__name__)

    def test_index_inserts_and_the_name_is_case_insensitive(self) -> None:
        for register, name, klass in self._cases():
            self._keep(klass)

            def first(_: 'Any') -> None:
                return None

            def second(_: 'Any') -> None:
                return None

            with self.subTest(registrar=register.__name__, name=name):
                register(name.upper(), first)
                register(name, second, index=0)
                self.assertIs(klass.__callback_fn__[0], second)
                self.assertIs(klass.__callback_fn__[-1], first)

    def test_a_registered_reassembler_gets_a_callback(self) -> None:
        """A reassembler registered with ``register_extractor_reassembly`` is reached too."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.foundation.reassembly.reassembly import Reassembly
        from pcapkit.foundation.registry import register_extractor_reassembly, register_reassembly_callback

        class Dummy2838(Reassembly):
            __protocol_name__ = 'Dummy2838'

            def reassembly(self, info: 'Any') -> None:
                self._dtgram.append(info)

            def submit(self, buf: 'Any', **kwargs: 'Any') -> 'list[Any]':
                return []

        register_extractor_reassembly('dummy-2838', Dummy2838)
        self.addCleanup(Extractor.__reassembly__.pop, 'dummy-2838')

        def callback(_: 'Any') -> None:
            return None

        register_reassembly_callback('dummy-2838', callback)
        self.assertEqual(Dummy2838.__callback_fn__, [callback])

    def test_a_bad_argument_writes_nothing(self) -> None:
        from pcapkit.foundation.registry import register_reassembly_callback, register_traceflow_callback
        from pcapkit.utilities.exceptions import RegistryError

        cases = self._cases()
        for _, _, klass in cases:
            self._keep(klass)
        before = {klass: list(klass.__callback_fn__) for _, _, klass in cases}

        def callback(_: 'Any') -> None:
            return None

        for register in (register_reassembly_callback, register_traceflow_callback):
            for protocol, func, expected in (
                ('no-such-protocol', callback, 'no .* is registered under'),
                (None, callback, 'must be a registered'),
                (b'tcp', callback, 'must be a registered'),
                ('tcp', 42, 'callback must be callable'),
            ):
                with self.subTest(registrar=register.__name__, protocol=protocol, callback=func):
                    with self.assertRaisesRegex(RegistryError, expected):
                        register(protocol, func)  # type: ignore[arg-type]
        for klass, callbacks in before.items():
            self.assertEqual(klass.__callback_fn__, callbacks, klass.__name__)


if __name__ == '__main__':
    unittest.main()
