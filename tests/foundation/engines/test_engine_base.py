from __future__ import annotations

import importlib.util
import types
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EngineBaseTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_engine_metadata_extractor_call_and_close(self) -> None:
        from pcapkit.foundation.engines.engine import EngineBase

        class PlainEngine(EngineBase[str]):
            def __init__(self, extractor: object) -> None:
                self.ran = False
                super().__init__(extractor)

            def run(self) -> None:
                self.ran = True

            def read_frame(self) -> str:
                return 'frame'

        class NamedEngine(EngineBase[str]):
            __engine_name__ = 'Named'
            __engine_module__ = 'named.module'

            def run(self) -> None:
                pass

            def read_frame(self) -> str:
                return 'frame'

        extractor = types.SimpleNamespace(name='extractor')
        engine = PlainEngine(extractor)
        self.assertEqual(PlainEngine.name, 'PlainEngine')
        self.assertEqual(PlainEngine.module, __name__)
        self.assertEqual(engine.name, 'PlainEngine')
        self.assertEqual(engine.module, __name__)
        self.assertIs(engine.extractor, extractor)
        self.assertEqual(engine.read_frame(), 'frame')
        engine()
        self.assertTrue(engine.ran)
        self.assertIsNone(engine.close())

        named = NamedEngine(extractor)
        self.assertEqual(NamedEngine.name, 'Named')
        self.assertEqual(NamedEngine.module, 'named.module')
        self.assertEqual(named.name, 'Named')
        self.assertEqual(named.module, 'named.module')
        named.__engine_name__ = 'instance'
        named.__engine_module__ = 'instance.module'
        self.assertEqual(named.name, 'instance')
        self.assertEqual(named.module, 'instance.module')

    def test_engine_subclass_registration_explicit_and_default(self) -> None:
        from pcapkit.foundation.engines.engine import Engine

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_engine') as register:
            class Explicit(Engine[str], name='ExplicitEngine'):
                def run(self) -> None:
                    pass

                def read_frame(self) -> str:
                    return 'frame'

        register.assert_called_once_with('explicitengine', Explicit)

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_engine') as register:
            class Default(Engine[str]):
                __engine_name__ = 'DefaultEngine'

                def run(self) -> None:
                    pass

                def read_frame(self) -> str:
                    return 'frame'

        register.assert_called_once_with('defaultengine', Default)


if __name__ == '__main__':
    unittest.main()
