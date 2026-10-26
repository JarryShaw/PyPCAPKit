from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

#: Test tier (#1958): branches on the running interpreter's version or implementation.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class EngineBaseTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

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

    def test_engine_subclass_registration_is_opt_in(self) -> None:
        """Registration happens if and only if ``engine`` is given.

        This is the #514 opt-in contract. It guards against ``__init_subclass__``
        falling back to ``cls.name`` when the keyword is absent, which registers
        *every* subclass of the public class.

        The ``Default`` case is the load-bearing half: it sets
        ``__engine_name__``, so a fallback to ``cls.name`` would register it under
        ``'defaultengine'``. A class attribute is not a registry key, so it
        registers nothing.

        No version guard, and that is why the keyword is ``engine`` rather than
        ``name``: ``mcls``/``name``/``bases``/``namespace`` collide with
        :meth:`abc.ABCMeta.__new__`'s own parameters, which are
        positional-or-keyword before 3.11 and positional-only from 3.11, so below
        Python 3.11 such a class statement fails in the metaclass before
        ``__init_subclass__`` runs. ``engine`` is outside that set, so this runs
        everywhere. Verified on 3.10.21 and 3.14.7.

        """
        from pcapkit.foundation.engines.engine import Engine

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_engine') as register:
            class Explicit(Engine[str], engine='ExplicitEngine'):
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

        register.assert_not_called()

        # ... and ``__engine_name__`` keeps doing its own job regardless, which is
        # why it is not an opt-in: it names the engine, registered or not.
        self.assertEqual(Default.name, 'DefaultEngine')

    def test_engine_subclass_rejects_unrecognised_keyword(self) -> None:
        """A misspelled class keyword raises instead of being swallowed.

        ``Engine`` spells the registry key ``engine`` while ``Reassembly`` and
        ``TraceFlow`` spell the same idea ``protocol``, so guessing the wrong one
        is the expected mistake. Without the guard it lands in ``**kwargs``, is
        dropped by a bare ``super().__init_subclass__()``, and, registration being
        opt-in, the class silently goes unregistered.

        Unguarded by version on purpose: ``protocol`` is not one of the four
        names that collide with :meth:`abc.ABCMeta.__new__` below Python 3.11, so
        the guard is reached on every supported version. Verified on 3.10.21,
        where it raises ``UnsupportedCall`` as it does on 3.14.

        ``name`` is an unrecognised keyword here too, and is checked
        separately below because it is the one typo whose exception *type* is
        version-dependent: below 3.11 the metaclass collision fires before the
        guard, so it is a :exc:`TypeError` rather than an
        :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`. Loud either way,
        which is why the guard needs no special case for it.

        """
        from pcapkit.foundation.engines.engine import Engine
        from pcapkit.utilities.exceptions import UnsupportedCall

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_engine') as register:
            with self.assertRaises(UnsupportedCall) as caught:
                class Typo(Engine[str], protocol='wrong-keyword-for-engine'):
                    def run(self) -> None:
                        pass

                    def read_frame(self) -> str:
                        return 'frame'

        register.assert_not_called()
        self.assertIn('protocol', str(caught.exception))

        # ``name=`` is not the registry keyword, so it is a typo. It is
        # the one whose exception type is version-dependent: the metaclass
        # collision fires before the guard below 3.11.
        expected = UnsupportedCall if sys.version_info >= (3, 11) else TypeError
        with mock.patch('pcapkit.foundation.extraction.Extractor.register_engine') as register:
            with self.assertRaises(expected):
                class Collides(Engine[str], name='no-longer-the-keyword'):
                    def run(self) -> None:
                        pass

                    def read_frame(self) -> str:
                        return 'frame'

        register.assert_not_called()

    def test_registration_is_not_inherited_by_a_subclass(self) -> None:
        """A subclass of a *registered* class does not inherit its registration.

        This is #514's answer to what the ``*Base`` hierarchy was standing in for.
        The built-ins inherit the non-registering base as a substitute for a
        ``final`` marker -- so that subclassing them again cannot register the
        subclass under a name nobody chose. That worked, but it is a property of
        *which base you inherited*, so it cannot be varied per subclass, and
        under a ``cls.name`` fallback a subclass of a registered class
        re-registers itself under its own class name.

        Keying registration on the keyword instead gives both properties at once:
        the parent stays registered, the subclass does not re-register, and a
        subclass that *wants* registering can still ask for it. Which is why
        ``HTTP``, ``L2TP`` and ``IP`` can be open to inheritance without the
        anti-re-registration guarantee being weakened.

        Runs on every supported version: ``engine`` does not collide with
        :meth:`abc.ABCMeta.__new__`'s own parameters below 3.11, as ``name``
        would.

        """
        from pcapkit.foundation.engines.engine import Engine

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_engine') as register:
            class Parent(Engine[str], engine='ParentEngine'):
                def run(self) -> None:
                    pass

                def read_frame(self) -> str:
                    return 'frame'

        register.assert_called_once_with('parentengine', Parent)

        # the substitute for ``final``: inheriting a registered class registers
        # nothing, where a ``cls.name`` fallback would register it as 'derived'
        with mock.patch('pcapkit.foundation.extraction.Extractor.register_engine') as register:
            class Derived(Parent):
                pass

        register.assert_not_called()

        # ... and inheritance is still open to a subclass that asks to register
        with mock.patch('pcapkit.foundation.extraction.Extractor.register_engine') as register:
            class DerivedOptIn(Parent, engine='DerivedEngine'):
                pass

        register.assert_called_once_with('derivedengine', DerivedOptIn)
        self.assertTrue(issubclass(DerivedOptIn, Parent))

    def test_engine_registry_property_reads_the_extractor_table(self) -> None:
        """``Engine.registry`` is a class-level accessor, as on ``EnumSchema``.

        It has to live on the metaclass: a ``property`` in the class body would
        be an instance property, so ``Engine.registry`` would return the
        property object rather than the mapping.

        """
        from pcapkit.foundation.engines.engine import Engine
        from pcapkit.foundation.extraction import Extractor

        self.assertIs(Engine.registry, Extractor.__engine__)

        # read through a subclass too, which is the spelling the property exists
        # for. No class keyword here, so this works on every supported version.
        class Subclass(Engine[str]):
            def run(self) -> None:
                pass

            def read_frame(self) -> str:
                return 'frame'

        self.assertIs(Subclass.registry, Extractor.__engine__)


if __name__ == '__main__':
    unittest.main()
