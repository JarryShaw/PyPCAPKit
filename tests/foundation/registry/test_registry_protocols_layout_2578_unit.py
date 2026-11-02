# -*- coding: utf-8 -*-
"""The protocol registries are a package, one module per layer. C.f. #2578.

The owner ruled that :mod:`pcapkit.foundation.registry.protocols` is split the
way :mod:`pcapkit.protocols` is: ``link``, ``internet``, ``transport``,
``application`` and ``misc``, beside ``protocol`` for what they share. The
package aggregates its submodules, so every public function resolves at
``pcapkit.foundation.registry.protocols.<name>`` and at
``pcapkit.foundation.registry.<name>``; a private helper of ``protocol`` has no
alias in the package, under the ruling on #1715 that a moved name keeps none.

These checks pin that:

* every public function is defined in exactly one submodule, named in its
  ``__all__``, and is the very object the package and
  :mod:`pcapkit.foundation.registry` export;
* the package's ``__all__`` is its submodules' together, and it binds none of
  the private helpers ``protocol`` defines;
* a wrapper tagged ``# NOTE: <map path>`` lives in the submodule named after the
  :mod:`pcapkit.protocols` subpackage holding the map's owner, and an untagged
  one is placed by ``UNTAGGED``, which is checked in both directions.

This module is unit-tier and reads no capture.

"""

import importlib
import importlib.util
import inspect
import pkgutil
import re
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): a structural check of where the registrars are defined.
__tier__ = 'LATEST'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The package being checked.
PACKAGE = 'pcapkit.foundation.registry.protocols'

#: Its submodules: the shared base, then one per :mod:`pcapkit.protocols` layer.
SUBMODULES = ('protocol', 'link', 'internet', 'transport', 'application', 'misc')

#: Private helpers of ``protocol``, which the package must not bind.
MOVED_PRIVATE = ('_check_code', '_register_name', '_NameLease', '_fold_lease',
                 '_release_name', '_iter_code_targets', '_NAME_LEASES', '_CODE_LEASES',
                 '_LEASE_LOCK', 'logger')

#: ``public function -> (submodule, why it carries no tag)``.
UNTAGGED = {
    'register_protocol_code': ('protocol', 'writes whichever maps its code names'),
    'register_linktype': ('misc', 'writes Frame\'s and PCAPNG\'s maps, which its siblings tag'),
    'register_apptype': ('transport', 'writes TCP\'s or UDP\'s map, which its siblings tag'),
}

#: A wrapper's tag: one or more map paths on the comment line above its ``def``.
TAG = re.compile(r'^# NOTE: (?P<paths>\S.*)\ndef (?P<name>register_\w+)\(', re.MULTILINE)


def _expected_home(path: 'str') -> 'str':
    """The submodule a wrapper of the map at ``path`` belongs in."""
    parts = path.split('.')
    if parts[:2] == ['pcapkit', 'protocols'] and len(parts) > 3 and parts[2] in SUBMODULES[1:]:
        return parts[2]
    return 'protocol'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RegistryProtocolsLayoutTests(unittest.TestCase):
    """Where each protocol registrar is defined, and where it resolves."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _submodules(self) -> 'dict[str, object]':
        package = importlib.import_module(PACKAGE)
        found = {info.name.rpartition('.')[2]
                 for info in pkgutil.iter_modules(package.__path__)}
        self.assertEqual(sorted(found), sorted(SUBMODULES))
        return {stem: importlib.import_module(f'{PACKAGE}.{stem}') for stem in SUBMODULES}

    def test_every_public_function_resolves_to_its_one_definition(self) -> None:
        import pcapkit.foundation.registry as registry

        package = importlib.import_module(PACKAGE)
        homes = {}  # type: dict[str, str]
        for stem, module in self._submodules().items():
            defined = {name for name, value in vars(module).items()
                       if inspect.isfunction(value) and value.__module__ == module.__name__
                       and not name.startswith('_')}
            self.assertEqual(sorted(defined), sorted(module.__all__),
                             f'{stem}: a public function is missing from __all__, or vice versa')
            for name in module.__all__:
                with self.subTest(module=stem, name=name):
                    self.assertNotIn(name, homes, f'{name} is exported by two submodules')
                    homes[name] = stem
                    obj = getattr(module, name)
                    self.assertTrue(inspect.isfunction(obj))
                    self.assertEqual(obj.__module__, module.__name__)
                    self.assertIs(getattr(package, name), obj)
                    self.assertIs(getattr(registry, name), obj)
                    self.assertIn(name, registry.__all__)

        self.assertEqual(sorted(package.__all__), sorted(homes))
        self.assertEqual(len(package.__all__), len(set(package.__all__)))

    def test_the_package_defines_nothing_and_aliases_no_private_helper(self) -> None:
        package = importlib.import_module(PACKAGE)
        base = self._submodules()['protocol']
        for name in MOVED_PRIVATE:
            with self.subTest(name=name):
                self.assertIn(name, vars(base))
                self.assertNotIn(name, vars(package))
        for name, value in vars(package).items():
            if inspect.isfunction(value) or inspect.isclass(value):
                with self.subTest(name=name):
                    self.assertNotEqual(value.__module__, PACKAGE)

    def test_each_wrapper_lives_in_its_maps_layer(self) -> None:
        package = importlib.import_module(PACKAGE)
        placed = {}  # type: dict[str, str]
        for stem, module in self._submodules().items():
            for match in TAG.finditer(inspect.getsource(module)):
                name = match['name']
                placed[name] = stem
                for path in (path.strip() for path in match['paths'].split(',')):
                    with self.subTest(wrapper=name, map=path):
                        self.assertEqual(stem, _expected_home(path))
        self.assertIn('register_sctp_chunk', placed)  # the pattern matches the sources

        for name, (stem, _) in UNTAGGED.items():
            with self.subTest(untagged=name):
                self.assertNotIn(name, placed, f'{name} carries a tag; drop it from UNTAGGED')
                self.assertEqual(getattr(package, name).__module__, f'{PACKAGE}.{stem}')
        self.assertEqual(sorted(set(package.__all__) - set(placed) - set(UNTAGGED)), [],
                         'a public registrar has no tag and no UNTAGGED entry')


if __name__ == '__main__':
    unittest.main()
