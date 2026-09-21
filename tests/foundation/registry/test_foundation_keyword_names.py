"""The registry helpers' documented keyword names must be the real ones.

:func:`~pcapkit.foundation.registry.foundation.register_extractor_engine`
once documented its first argument as ``engine`` while the signature
declared ``name``, so a caller following the docstring got a
:exc:`TypeError` rather than a registration -- noted in passing while
auditing the ``__init_subclass__`` keyword rename in #557. The docstring
has since been corrected to say ``name``, matching the signature, but
nothing pinned the pairing itself, so a future rename could put the two
back out of step just as silently as before.

These pin the keyword spelling directly against the real signature.

"""
from __future__ import annotations

import importlib.util
import inspect
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RegistryKeywordNameTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_register_extractor_engine_takes_name_not_engine(self) -> None:
        """``name=`` registers; ``engine=`` -- as documented -- does not."""
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.registry import foundation as registry

        descriptor = ModuleDescriptor('pcapkit.foundation.engines', 'Engine')

        with mock.patch.object(registry.Extractor, 'register_engine') as register_engine:
            registry.register_extractor_engine(name='unit-engine-by-keyword',
                                               module=descriptor)
        register_engine.assert_called_once_with('unit-engine-by-keyword', descriptor)

        with mock.patch.object(registry.Extractor, 'register_engine') as register_engine:
            with self.assertRaises(TypeError) as caught:
                registry.register_extractor_engine(engine='unit-engine-by-keyword',
                                                   module=descriptor)
        register_engine.assert_not_called()
        self.assertIn('engine', str(caught.exception))

    def test_register_extractor_engine_signature_names_name(self) -> None:
        """The documented keyword has to be the one the signature declares."""
        from pcapkit.foundation.registry import foundation as registry

        parameters = inspect.signature(registry.register_extractor_engine).parameters
        self.assertIn('name', parameters)
        self.assertNotIn('engine', parameters)


if __name__ == '__main__':
    unittest.main()
