# -*- coding: utf-8 -*-
"""GitHub issue #1770: :mod:`pcapkit.protocols.protocol` exports ``Protocol``.

The module's :attr:`__all__` was ``['ProtocolBase']``, so ``from
pcapkit.protocols.protocol import *`` did not bind
:class:`~pcapkit.protocols.protocol.Protocol`, the class its docstring and
:file:`protocol.rst` present as the module's user-facing one. It is listed now.

"""

import importlib.util
import unittest
from unittest import mock

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RegistryGuardWidthTests(unittest.TestCase):
    """The registry guard is wider than its error message, on purpose."""

    def test_the_guard_accepts_a_protocol_base_that_is_not_a_protocol(self) -> None:
        # The guard tests ProtocolBase because every built-in derives from it
        # and none from Protocol. The message still names Protocol, since its
        # reader is a third party who should subclass the public class (#1016).
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.protocol import Protocol, ProtocolBase

        self.assertFalse(issubclass(Raw, Protocol))
        with mock.patch.dict(ProtocolBase.__proto__):
            ProtocolBase.register(1, Raw)
            self.assertIs(ProtocolBase.__proto__[1], Raw)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtocolModuleAllTests(unittest.TestCase):
    """``import *`` of :mod:`pcapkit.protocols.protocol` binds ``Protocol``."""

    def test_protocol_is_in_all(self) -> None:
        from pcapkit.protocols import protocol

        self.assertIn('Protocol', protocol.__all__)
        self.assertIn('ProtocolBase', protocol.__all__)

    def test_star_import_binds_protocol(self) -> None:
        from pcapkit.protocols import protocol

        namespace = {}  # type: dict[str, object]
        exec('from pcapkit.protocols.protocol import *', namespace)  # pylint: disable=exec-used
        self.assertIs(namespace.get('Protocol'), protocol.Protocol)
        self.assertIs(namespace.get('ProtocolBase'), protocol.ProtocolBase)


if __name__ == '__main__':
    unittest.main()
