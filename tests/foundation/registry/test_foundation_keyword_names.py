"""The registry helpers' documented keyword names must be the real ones.

:func:`~pcapkit.foundation.registry.foundation.register_extractor_engine`
documented its first argument as ``engine`` while the signature declared
``name``, so a caller following the docstring got a :exc:`TypeError`
rather than a registration -- noted in passing while auditing the
``__init_subclass__`` keyword rename in #557. A rename can put the two
out of step silently.

Since #2838 the entry it takes is ``engine``, the name
:meth:`Extractor.register_engine <pcapkit.foundation.extraction.Extractor.register_engine>`
gives it, so the engine name stays ``name`` and the class is ``engine``.

These pin the keyword spelling directly against the real signature.

"""
from __future__ import annotations

import importlib.util
import inspect
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RegistryKeywordNameTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_register_extractor_engine_takes_name_and_engine(self) -> None:
        """``name=`` and ``engine=`` register; ``module=`` does not."""
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.registry import foundation as registry

        descriptor = ModuleDescriptor('pcapkit.foundation.engines', 'Engine')

        with mock.patch.object(registry.Extractor, 'register_engine') as register_engine:
            registry.register_extractor_engine(name='unit-engine-by-keyword',
                                               engine=descriptor)
        register_engine.assert_called_once_with('unit-engine-by-keyword', descriptor)

        with mock.patch.object(registry.Extractor, 'register_engine') as register_engine:
            with self.assertRaises(TypeError) as caught:
                registry.register_extractor_engine(name='unit-engine-by-keyword',  # type: ignore[call-arg]
                                                   module=descriptor)
        register_engine.assert_not_called()
        self.assertIn('module', str(caught.exception))

    def test_register_extractor_engine_signature_mirrors_its_classmethod(self) -> None:
        """The documented keywords have to be the ones the classmethod declares."""
        from pcapkit.foundation.registry import foundation as registry

        parameters = inspect.signature(registry.register_extractor_engine).parameters
        wrapped = inspect.signature(registry.Extractor.register_engine).parameters
        self.assertEqual(list(parameters), ['name', 'engine'])
        self.assertEqual(list(parameters), list(wrapped))


if __name__ == '__main__':
    unittest.main()
