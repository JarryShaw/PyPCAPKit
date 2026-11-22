# -*- coding: utf-8 -*-
"""Every registry wrapper mirrors the classmethod it calls. C.f. #2834 and #2838.

Through 1.6 the class-registering wrappers took ``(code, module, class_)`` and
built the :class:`~pcapkit.corekit.module.ModuleDescriptor` the caller could
write itself, and ``register_apptype(code, module, class_, *transport)`` bound
its third positional by the type of its second. Under the convention ruled on
#2834 (``public-signatures.rst``), a wrapper takes the one entry its classmethod
takes, under that classmethod's parameter name, and whatever follows it is
keyword-only.

The classmethod is found from the wrapper's ``# NOTE: <map path>`` tag: the
owner's ``register`` for ``__proto__``, ``register_<kind>`` for ``__<kind>__``,
or the one ``NAMED`` gives. ``UNTAGGED`` names it for a wrapper writing several
owners' maps, and ``SELECTORS`` the leading parameters that pick a registry
rather than mirror one. Each table is checked against
:data:`pcapkit.foundation.registry.__all__` in both directions.

"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import re
import sys
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): a structural sweep over every public registrar.
__tier__ = 'LATEST'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: A wrapper's tag: one or more map paths on the comment line above its ``def``.
TAG = re.compile(r'^# NOTE: (?P<paths>\S.*)\ndef (?P<name>register_\w+)\(', re.MULTILINE)

#: ``map path -> its classmethod``, where that is not ``register_<kind>``.
NAMED = {
    'pcapkit.protocols.protocol.ProtocolBase.__registry__': 'register_protocol',
    'pcapkit.foundation.extraction.Extractor.__output__': 'register_dumper',
    'pcapkit.foundation.traceflow.traceflow.TraceFlow.__output__': 'register_dumper',
    'pcapkit.foundation.reassembly.reassembly.ReassemblyBase.__callback_fn__': 'register',
    'pcapkit.foundation.traceflow.traceflow.TraceFlowBase.__callback_fn__': 'register_callback',
}

#: ``wrapper -> the classmethod it mirrors``, for a wrapper with no tag.
UNTAGGED = {
    'register_dumper': 'pcapkit.foundation.extraction.Extractor.register_dumper',
    'register_linktype': 'pcapkit.protocols.misc.pcap.frame.protocol.Frame.register',
    'register_apptype': 'pcapkit.protocols.transport.transport.Transport.register',
}

#: ``wrapper -> its leading parameters that pick the registry written``.
SELECTORS = {
    'register_engine_reassembly': ('engine',),
    'register_reassembly_callback': ('protocol',),
    'register_traceflow_callback': ('protocol',),
}

#: ``wrapper -> why it mirrors no one classmethod``.
EXCUSED = {
    'register_protocol_code': 'writes whichever maps its code names, by each one\'s register',
}


def _resolve(path: 'str') -> 'Any':
    """The class or attribute a dotted ``module.Class[.attr]`` path names."""
    parts = path.split('.')
    for cut in range(len(parts) - 1, 0, -1):
        try:
            target = importlib.import_module('.'.join(parts[:cut]))
        except ImportError:
            continue
        for attr in parts[cut:]:
            target = getattr(target, attr)
        return target
    raise AssertionError(path)


def _classmethod(path: 'str') -> 'Any':
    """The ``register*`` classmethod writing the map at ``path``."""
    owner, _, attr = path.rpartition('.')
    kind = attr[2:-2]
    name = NAMED.get(path, 'register' if kind == 'proto' else f'register_{kind}')
    return getattr(_resolve(owner), name)


def _wrapped() -> 'dict[str, list[Any]]':
    """``wrapper -> the classmethods it mirrors``, one per map its tag names."""
    from pcapkit.foundation import registry

    wrapped = {}  # type: dict[str, list[Any]]
    for name in registry.__all__:
        if name in EXCUSED:
            continue
        if name in UNTAGGED:
            wrapped[name] = [_resolve(UNTAGGED[name])]
            continue
        module = sys.modules[getattr(registry, name).__module__]
        tags = {match['name']: match['paths'] for match in TAG.finditer(inspect.getsource(module))}
        wrapped[name] = [_classmethod(path.strip()) for path in tags[name].split(',')]
    return wrapped


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class WrapperSignatureTests(unittest.TestCase):

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_tables_name_real_public_wrappers(self) -> None:
        from pcapkit.foundation import registry

        for table in (UNTAGGED, SELECTORS, EXCUSED):
            self.assertEqual(sorted(set(table) - set(registry.__all__)), [])
        self.assertEqual(sorted(set(UNTAGGED) & set(EXCUSED)), [])
        wrapped = _wrapped()
        self.assertEqual(sorted(set(registry.__all__) - set(wrapped) - set(EXCUSED)), [])
        for name in UNTAGGED:
            module = sys.modules[getattr(registry, name).__module__]
            self.assertNotIn(name, {match['name'] for match in TAG.finditer(inspect.getsource(module))},
                             f'{name} is tagged now; drop it from UNTAGGED')

    def test_every_wrapper_mirrors_its_classmethod(self) -> None:
        from pcapkit.foundation import registry

        for name, methods in _wrapped().items():
            parameters = list(inspect.signature(getattr(registry, name)).parameters.values())
            positional = [p.name for p in parameters if p.kind is p.POSITIONAL_OR_KEYWORD]
            keyword = {p.name for p in parameters if p.kind is p.KEYWORD_ONLY}
            selectors = list(SELECTORS.get(name, ()))
            for method in methods:
                with self.subTest(wrapper=name, wraps=method.__qualname__):
                    wrapped = list(inspect.signature(method).parameters.values())
                    mirrored = [p.name for p in wrapped if p.kind is p.POSITIONAL_OR_KEYWORD][:2]
                    self.assertEqual(positional, selectors + mirrored,
                                     'the key and the entry, under the classmethod\'s names')
                    rest = {p.name for p in wrapped} - set(mirrored)
                    self.assertEqual(sorted(rest - keyword), [],
                                     'what follows the entry is keyword-only')
                    self.assertEqual([p.name for p in parameters
                                      if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD)], [],
                                     'a keyword set is closed')

    def test_no_wrapper_takes_a_module_and_class_name(self) -> None:
        from pcapkit.foundation import registry

        for name in registry.__all__:
            with self.subTest(wrapper=name):
                parameters = inspect.signature(getattr(registry, name)).parameters
                self.assertNotIn('class_', parameters)
                self.assertNotIn('module', parameters)

    def test_register_apptype_takes_transport_by_keyword(self) -> None:
        """Its third positional no longer changes meaning with the type of its second."""
        from pcapkit.foundation.registry import register_apptype
        from pcapkit.protocols.misc.raw.protocol import Raw

        parameters = inspect.signature(register_apptype).parameters
        self.assertEqual([(p.name, p.kind.name) for p in parameters.values()],
                         [('code', 'POSITIONAL_OR_KEYWORD'), ('protocol', 'POSITIONAL_OR_KEYWORD'),
                          ('transport', 'KEYWORD_ONLY')])
        self.assertIsNone(parameters['transport'].default)
        with self.assertRaises(TypeError):
            register_apptype(65220, Raw, 'udp')  # type: ignore[misc]


if __name__ == '__main__':
    unittest.main()
