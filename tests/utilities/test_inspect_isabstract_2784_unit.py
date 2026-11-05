# -*- coding: utf-8 -*-
"""#2784: :func:`pcapkit.utilities.inspect.isabstract` reads no abstract flag.

GraalPy freezes a class's ``__flags__`` at the first read, so a class whose flags are
read before :class:`abc.ABCMeta` sets ``__abstractmethods__`` never shows the abstract
flag there. :func:`inspect.isabstract` reads them first, so called from
``__init_subclass__`` it leaves an abstract class reported concrete from then on.
:func:`isabstract` derives the answer as :class:`abc.ABCMeta` does instead.

GraalPy is not installed here, so :func:`frozen_flags` stands in for it: a metaclass
whose ``__flags__`` keeps the value of its first read.
:mod:`tests.protocols.test_protocol_registry_2763_unit` uses it for the
auto-registration hook. The oracle is ``__abstractmethods__``, which
:class:`abc.ABCMeta` sets on every interpreter.

"""

import abc
import inspect
import unittest
import weakref
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): exercises ABC machinery, which differs by interpreter.
__tier__ = 'ALL'


def frozen_flags(meta: 'type') -> 'Any':
    """A subclass of the metaclass ``meta`` whose ``__flags__`` keeps the value of its first read.

    That is what GraalPy 25.4.4 does with every class (#2784).

    """
    read = type.__dict__['__flags__'].__get__
    frozen = weakref.WeakKeyDictionary()  # type: weakref.WeakKeyDictionary[type, int]

    class FrozenFlags(meta):  # type: ignore[misc,valid-type]
        @property
        def __flags__(cls) -> 'int':  # type: ignore[override]
            if cls not in frozen:
                frozen[cls] = read(cls)
            return frozen[cls]

    return FrozenFlags


class IsAbstractTests(unittest.TestCase):
    """:func:`~pcapkit.utilities.inspect.isabstract` against ``__abstractmethods__``."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)
        from pcapkit.utilities.inspect import isabstract

        self.isabstract = isabstract

    def test_the_answer_is_the_same_during_init_subclass_and_after(self) -> 'None':
        isabstract, during = self.isabstract, {}  # type: Any, dict[str, bool]

        class Base(abc.ABC):
            def __init_subclass__(cls, **kwargs: 'Any') -> 'None':
                super().__init_subclass__(**kwargs)
                during[cls.__name__] = isabstract(cls)

            @abc.abstractmethod
            def f(self) -> 'None': ...

            @abc.abstractmethod
            def g(self) -> 'None': ...

        class Inherits(Base):
            pass

        class OverridesOne(Base):
            def f(self) -> 'None': ...

        class OverridesBoth(OverridesOne):
            g = None  # type: ignore[assignment]

        class DeclaresItsOwn(OverridesBoth):
            @property
            @abc.abstractmethod
            def h(self) -> 'None': ...

        for klass, expected in ((Inherits, True), (OverridesOne, True),
                                (OverridesBoth, False), (DeclaresItsOwn, True)):
            with self.subTest(cls=klass.__name__):
                self.assertEqual(bool(klass.__abstractmethods__), expected)
                self.assertIs(during[klass.__name__], expected)
                self.assertIs(isabstract(klass), expected)

    def test_a_frozen_flag_leaves_the_answer(self) -> 'None':
        """Where the flags are read during ``__init_subclass__``, as GraalPy freezes them."""
        class Base(metaclass=frozen_flags(abc.ABCMeta)):
            def __init_subclass__(cls, **kwargs: 'Any') -> 'None':
                super().__init_subclass__(**kwargs)
                cls.__flags__  # pylint: disable=pointless-statement

            @abc.abstractmethod
            def f(self) -> 'None': ...

        class Inherits(Base):
            pass

        self.assertTrue(Inherits.__abstractmethods__)
        self.assertFalse(inspect.isabstract(Inherits))  # the stand-in misreports it, as GraalPy does
        self.assertTrue(self.isabstract(Inherits))

    def test_no_flag_is_read(self) -> 'None':
        class Unreadable(abc.ABCMeta):
            @property
            def __flags__(cls) -> 'int':  # type: ignore[override]
                raise AssertionError('__flags__ was read')

        class Base(metaclass=Unreadable):
            @abc.abstractmethod
            def f(self) -> 'None': ...

        class Concrete(Base):
            def f(self) -> 'None': ...

        self.assertTrue(self.isabstract(Base))
        self.assertFalse(self.isabstract(Concrete))

    def test_a_class_with_nothing_abstract_or_not_from_abcmeta_is_concrete(self) -> 'None':
        class Plain:
            @abc.abstractmethod
            def f(self) -> 'None': ...

        class Concrete(abc.ABC):
            pass

        for value in (Plain, Concrete, Concrete(), abc.ABC, abc.abstractmethod, None):
            with self.subTest(value=value):
                self.assertFalse(self.isabstract(value))


if __name__ == '__main__':
    unittest.main()
