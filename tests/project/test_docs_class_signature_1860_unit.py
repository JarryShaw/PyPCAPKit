# -*- coding: utf-8 -*-
"""Pins the docs build's class signatures to the constructor a call runs.

GitHub issue #1860: Sphinx 9.1 takes a class signature from any ``__new__`` the
class defines or inherits, before ``__init__``. ``sphinx-autodoc-typehints`` 3.15
takes a ``__new__`` defined beside the ``__init__``, as :func:`inspect.signature`
does. :class:`~pcapkit.protocols.protocol.ProtocolBase`,
:class:`~pcapkit.corekit.infoclass.Info`,
:class:`~pcapkit.protocols.schema.schema.Schema` and the reassembly and
flow-tracing bases each define a ``__new__`` that only passes ``*args`` and
``**kwargs`` through, so their classes rendered that catch-all, and their
class docstrings lost the types of the parameters they list.

``restore_class_signature`` in :file:`docs/source/conf.py` gives such a class its
``__init__``'s parameters, and ``constructor_for_types`` has the library read the
parameter types from that ``__init__``. The expected signatures are the ones the
build showed before 3.15, where it had one.

The tests call the hooks directly and replay the signature event through Sphinx's
own :class:`~sphinx.events.EventManager`. They need Sphinx and
the pinned ``sphinx-autodoc-typehints`` and skip without them, but run no build.

"""

from __future__ import annotations

import inspect
import types
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests.project.test_docs_ambiguous_xrefs_1775_unit import (HAS_SPHINX, SPHINX_SKIP_REASON, connections,
                                                               load_conf)

if TYPE_CHECKING:
    from typing import Any

#: The event the signature hook answers.
EVENT = 'autodoc-process-signature'

#: The catch-all the build rendered for these classes.
CATCH_ALL = '(*args, **kwargs)'


def app_for(conf: 'Any') -> 'Any':
    """A stand-in application carrying the settings the hooks read."""
    config = types.SimpleNamespace(autodoc_preserve_defaults=conf.autodoc_preserve_defaults,
                                   strip_signature_backslash=False)
    return types.SimpleNamespace(config=config, pdb=False)


def emit(conf: 'Any', app: 'Any', event: 'str', *args: 'Any', library: 'Any' = None) -> 'Any':
    """What the build's handlers for ``event`` answer, in the order the build runs them.

    Each handler is passed ``app`` and then ``args``. ``library`` stands in for a
    handler an extension connects at :meth:`Sphinx.connect
    <sphinx.application.Sphinx.connect>`'s default priority; :file:`conf.py`'s
    handlers follow with the priorities its ``setup`` gives them.

    """
    # pylint: disable=import-outside-toplevel
    from sphinx.application import Sphinx
    from sphinx.events import EventManager

    events = EventManager(app)
    events.add(event)
    if library is not None:
        events.connect(event, library, inspect.signature(Sphinx.connect).parameters['priority'].default)
    for name, handler, priority in connections(conf):
        if name == event:
            events.connect(name, handler, priority)
    return events.emit_firstresult(event, *args)


def resolve(name: 'str') -> 'Any':
    """The object at the dotted ``name``, which may name a nested class."""
    import pkgutil  # pylint: disable=import-outside-toplevel
    return pkgutil.resolve_name(name)


#: Each class, and the signature restored for it.
RESTORED = {
    'pcapkit.protocols.application.ftp.FTP': '(file=None, length=None, **kwargs)',
    'pcapkit.dumpkit.pcap.PCAPIO': '(fname, *, protocol, byteorder=sys.byteorder, nanosecond=False, **kwargs)',
    'pcapkit.foundation.reassembly.ipv4.IPv4': '(*, strict=True, store=True, timeout=None)',
    'pcapkit.foundation.traceflow.tcp.TCP': ('(fout, format, byteorder=sys.byteorder, nanosecond=False, '
                                             'bidirectional=True, analyse=False)'),
    'pcapkit.corekit.infoclass.Info': '(dict_=None, **kwargs)',
    'pcapkit.corekit.infoclass.MultiInfo': '(mapping=None)',
    'pcapkit.interface.misc.Stream': '(filename, packets, conversations)',
    'pcapkit.protocols.schema.transport.udp.UDP': ('(srcport=NO_VALUE, dstport=NO_VALUE, len=NO_VALUE, '
                                                   'checksum=NO_VALUE, payload=NO_VALUE, trailer=NO_VALUE, *, '
                                                   '__packet__=None, **kwargs)'),
}

#: Classes whose signature is left to the other handlers: a class not yet
#: finalised, whose ``__init__`` is generated on its first construction; a class
#: whose ``__new__`` takes parameters of its own; a class with no ``__new__`` at all.
LEFT_ALONE = (
    'pcapkit.protocols.data.application.ftp.FTP',
    'pcapkit.corekit.fields.strings.DecodedString',
    'pcapkit.foundation.extraction.Extractor',
)


class Forwarding:
    """A base whose ``__init__`` names no parameters of its own."""

    def __init__(self, *args: 'Any', **kwargs: 'Any') -> 'None':
        pass


class Built(Forwarding):
    """A class whose ``__new__`` takes the parameters, ahead of the base's ``__init__``."""

    def __new__(cls, value: 'str', raw: 'bytes') -> 'Built':  # pylint: disable=unused-argument
        return super().__new__(cls)


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class ClassSignatureTests(unittest.TestCase):
    """``restore_class_signature`` gives these classes their ``__init__``'s parameters."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def setUp(self) -> 'None':
        # NB: the library's handler needs a real environment; here it is only
        # checked to be called.
        patcher = mock.patch.object(self.conf, 'typehints_process_signature', return_value=None)
        self.library = patcher.start()
        self.addCleanup(patcher.stop)
        self.app = app_for(self.conf)

    def restore(self, name: 'str', what: 'str' = 'class') -> 'Any':
        """The hook's own answer for the class at ``name``."""
        return self.conf.restore_class_signature(self.app, what, name, resolve(name), {}, CATCH_ALL, None)

    def test_classes_get_their_init_parameters(self) -> 'None':
        """Each rendered ``(*args, **kwargs)``, or ``PCAPIO`` its base's ``(fname, **kwargs)``."""
        for name, expected in RESTORED.items():
            with self.subTest(name=name):
                self.assertEqual(self.restore(name), (expected, None))

    def test_restored_parameters_are_the_init_parameters(self) -> 'None':
        """The names and kinds are the ``__init__``'s, and :func:`inspect.signature`'s where it has them."""
        from sphinx.util.inspect import signature_from_str  # pylint: disable=import-outside-toplevel
        for name in RESTORED:
            cls = resolve(name)
            init = self.conf.hidden_init(cls)
            restored = signature_from_str(self.restore(name)[0])
            shape = [(param.name, param.kind) for param in restored.parameters.values()]
            with self.subTest(name=name):
                self.assertEqual(shape, [(param.name, param.kind)
                                         for param in list(inspect.signature(init).parameters.values())[1:]])
                public = inspect.signature(cls).parameters.values()
                if [param.kind for param in public] != [inspect.Parameter.VAR_POSITIONAL,
                                                       inspect.Parameter.VAR_KEYWORD]:
                    self.assertEqual(shape, [(param.name, param.kind) for param in public])

    def test_other_classes_are_left_alone(self) -> 'None':
        """Nothing hides these classes' constructor, or it is not known before first construction."""
        for name in LEFT_ALONE:
            with self.subTest(name=name):
                self.assertIsNone(self.restore(name))
        self.assertIsNone(self.restore('pcapkit.protocols.application.ftp.FTP', what='attribute'))
        self.library.assert_not_called()

    def test_new_with_parameters_is_left_to_autodoc(self) -> 'None':
        """Walking past it would restore the base's ``(*args, **kwargs)`` over ``(value, raw)``."""
        self.assertIsNone(self.conf.hidden_init(Built))
        self.assertIsNone(self.conf.restore_class_signature(self.app, 'class', 'Built', Built, {}, '(value, raw)',
                                                            None))
        self.library.assert_not_called()

    def test_library_handler_still_runs(self) -> 'None':
        """From 3.14 it records the class, and only a recorded class gets its type parameters."""
        name = 'pcapkit.foundation.reassembly.ipv4.IPv4'
        self.restore(name)
        self.library.assert_called_once_with(self.app, 'class', name, resolve(name), {}, CATCH_ALL, None)

    def test_setup_connects_it_ahead_of_the_library(self) -> 'None':
        """At the library's priority the library would answer first, with the catch-all."""
        from sphinx.application import Sphinx  # pylint: disable=import-outside-toplevel
        default = inspect.signature(Sphinx.connect).parameters['priority'].default
        wired = [(event, priority) for event, handler, priority in connections(self.conf)
                 if handler is self.conf.restore_class_signature]
        self.assertEqual([event for event, _ in wired], [EVENT])
        self.assertLess(wired[0][1], default)

    def test_build_restores_the_signature(self) -> 'None':
        """Through the event, the catch-all the library answers is replaced."""
        name = 'pcapkit.protocols.application.ftp.FTP'
        result = emit(self.conf, self.app, EVENT, 'class', name, resolve(name), {}, CATCH_ALL, None,
                      library=lambda *args: (CATCH_ALL, None))
        self.assertEqual(result, (RESTORED[name], None))


@unittest.skipUnless(HAS_SPHINX, SPHINX_SKIP_REASON)
class ConstructorTypesTests(unittest.TestCase):
    """``constructor_for_types`` has the library read parameter types from the ``__init__``."""

    conf = None  # type: Any

    @classmethod
    def setUpClass(cls) -> 'None':
        cls.conf = load_conf()

    def test_init_behind_a_pass_through_new_is_read(self) -> 'None':
        """Each class docstring lists the ``__init__`` parameters, which lost their types."""
        for name in ('pcapkit.foundation.reassembly.ipv4.IPv4', 'pcapkit.foundation.traceflow.tcp.TCP',
                     'pcapkit.corekit.infoclass.Info', 'pcapkit.corekit.infoclass.MultiInfo'):
            cls = resolve(name)
            with self.subTest(name=name):
                self.assertEqual(self.conf.typehints_constructor_name(cls), '__new__')
                self.assertEqual(self.conf.constructor_for_types(cls), '__init__')

    def test_overloaded_init_keeps_the_library_choice(self) -> 'None':
        """Reading it would add an ``Overloads`` field to every protocol class."""
        cls = resolve('pcapkit.protocols.application.ftp.FTP')
        self.assertEqual(self.conf.constructor_for_types(cls), self.conf.typehints_constructor_name(cls))

    def test_other_classes_keep_the_library_choice(self) -> 'None':
        """A class with no pass-through ``__new__`` in the way is left as the library reads it."""
        for name in ('pcapkit.dumpkit.pcap.PCAPIO', 'pcapkit.corekit.fields.strings.DecodedString',
                     'pcapkit.protocols.data.application.ftp.FTP'):
            cls = resolve(name)
            with self.subTest(name=name):
                self.assertEqual(self.conf.constructor_for_types(cls), self.conf.typehints_constructor_name(cls))

    def test_builder_inited_points_the_library_at_it(self) -> 'None':
        """Each module that reads the choice for the docstring types reads this one."""
        modules = (self.conf.typehints_docstring_handler, self.conf.typehints_hints)
        cls = resolve('pcapkit.foundation.reassembly.ipv4.IPv4')
        with mock.patch.object(modules[0], 'constructor_name', modules[0].constructor_name), \
                mock.patch.object(modules[1], 'constructor_name', modules[1].constructor_name):
            self.conf.read_constructor_types_from_init(None)
            for module in modules:
                self.assertIs(module.constructor_name, self.conf.constructor_for_types)
            self.assertEqual(self.conf.typehints_hints.documenting_class('x', cls), (cls, '__init__'))

    def test_setup_connects_it(self) -> 'None':
        """Unconnected, the library goes on reading the pass-through ``__new__``."""
        wired = [event for event, handler, _ in connections(self.conf)
                 if handler is self.conf.read_constructor_types_from_init]
        self.assertEqual(wired, ['builder-inited'])


if __name__ == '__main__':
    unittest.main()
