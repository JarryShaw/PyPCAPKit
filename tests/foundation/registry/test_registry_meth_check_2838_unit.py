# -*- coding: utf-8 -*-
"""Every ``meth`` registrar refuses a pair that is not two callables. C.f. #2838.

A registrar taking ``meth: str | tuple[parser, constructor]`` checked only the
name form, against the ``_read_*`` methods, so ``register_tcp_option(code,
(1, 'x', 3))`` was stored and failed later, at parse or build time, with an
unrelated error. One shared check beside ``_check_code``, ``_check_meth``,
now refuses it with :exc:`~pcapkit.utilities.exceptions.RegistryError` before
any registry is written.

The registrars are every function in :data:`pcapkit.foundation.registry.__all__`
with a ``meth`` parameter, and the maps each writes are the ones its
``# NOTE: <map path>`` tag names, so a registrar added tomorrow is checked
tomorrow. A valid code is the first member of the enum its ``code`` annotation
names.

"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import re
import sys
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable

#: Test tier (#1958): a sweep over every registrar taking a parser.
__tier__ = 'LATEST'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: A wrapper's tag: one or more map paths on the comment line above its ``def``.
TAG = re.compile(r'^# NOTE: (?P<paths>\S.*)\ndef (?P<name>register_\w+)\(', re.MULTILINE)


def parser(*args: 'Any', **kwargs: 'Any') -> 'Any':
    raise NotImplementedError


#: ``meth`` values that are neither a name nor a pair of two callables.
BAD_METHS = (
    (1, 'x', 3),
    (parser, parser, parser),
    (parser,),
    (parser, 3),
    ('read', parser),
    [parser, parser],
    5,
    None,
)


def _registrars() -> 'list[tuple[Callable[..., None], Any, list[dict[Any, Any]]]]':
    """``(registrar, valid code, the maps its tag names)`` for every ``meth`` registrar."""
    from pcapkit.foundation import registry

    found = []
    for name in registry.__all__:
        func = getattr(registry, name)
        if 'meth' not in inspect.signature(func).parameters:
            continue
        module = sys.modules[func.__module__]
        tag = {match['name']: match['paths'] for match in TAG.finditer(inspect.getsource(module))}[name]
        maps = []
        for path in (item.strip() for item in tag.split(',')):
            owner, _, attr = path.rpartition('.')
            module_name, _, klass = owner.rpartition('.')
            maps.append(vars(getattr(importlib.import_module(module_name), klass))[attr])
        annotation = inspect.signature(func).parameters['code'].annotation
        kind = eval(annotation.split('|')[0].strip(), vars(module))  # pylint: disable=eval-used
        found.append((func, next(iter(kind)), maps))
    return found


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class MethCheckTests(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_sweep_finds_the_registrars(self) -> None:
        names = {func.__name__ for func, _, _ in _registrars()}
        self.assertIn('register_tls_extension', names)
        self.assertIn('register_ppp_control', names)
        self.assertIn('register_hip_parameter', names)
        self.assertNotIn('register_tcp', names)

    def test_a_bad_pair_is_refused_and_writes_nothing(self) -> None:
        from pcapkit.utilities.exceptions import RegistryError

        for func, code, maps in _registrars():
            for meth in BAD_METHS:
                with self.subTest(registrar=func.__name__, meth=meth):
                    before = [dict(table) for table in maps]
                    try:
                        with self.assertRaisesRegex(RegistryError, 'meth must be a method name or a '
                                                                   r'\(parser, constructor\) pair'):
                            func(code, meth)
                        self.assertEqual([dict(table) for table in maps], before)
                    finally:
                        for table, saved in zip(maps, before):
                            table.clear()
                            table.update(saved)

    def test_a_pair_of_two_callables_is_accepted(self) -> None:
        for func, code, maps in _registrars():
            with self.subTest(registrar=func.__name__):
                before = [dict(table) for table in maps]
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        func(code, (parser, parser))
                    self.assertTrue(any(table.get(key) == (parser, parser)
                                        for table in maps for key in table))
                finally:
                    for table, saved in zip(maps, before):
                        table.clear()
                        table.update(saved)

    def test_every_registrar_goes_through_the_shared_check(self) -> None:
        """One check beside ``_check_code``, which every such registrar calls by name."""
        from pcapkit.foundation.registry.protocols import protocol
        from pcapkit.utilities.exceptions import RegistryError

        self.assertTrue(callable(protocol._check_meth))
        for func, code, _ in _registrars():
            module = sys.modules[func.__module__]
            with self.subTest(registrar=func.__name__):
                self.assertIs(module._check_meth, protocol._check_meth)
                with mock.patch.object(module, '_check_meth', side_effect=RegistryError('shared')):
                    with self.assertRaisesRegex(RegistryError, '^shared$'):
                        func(code, 'not-checked-by-name-first')


if __name__ == '__main__':
    unittest.main()
