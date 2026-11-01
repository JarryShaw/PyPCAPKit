# -*- coding: utf-8 -*-
"""The ``__proto_dest__`` declaration the default template renders (#2392).

The enum type -> destination pairing lives on the enumeration registry classes
themselves, as a ``__proto_dest__`` dunder (GitHub issue #2392) -- the mirror
of ``__proto_key__``, which each destination declares to name the enum its own
registry is keyed by.

The :file:`pcapkit/const/` modules that carry it are generated, so the
declaration is made in the crawler
(:attr:`~pcapkit.vendor.default.Vendor.PROTO_DEST`) and rendered by
:data:`~pcapkit.vendor.default.LINE`. That is what this file pins, from the
template side:

* :class:`RenderProtoDestTests` -- :func:`~pcapkit.vendor.default.render_proto_dest`
  renders a declaration that is valid, re-importable Python, and renders
  *nothing at all* for an empty :attr:`~pcapkit.vendor.default.Vendor.PROTO_DEST`.
* :class:`TemplateProtoDestTests` -- the same through :data:`LINE`: the import
  line and the class-body declaration both appear when a crawler declares a
  destination, and the rendered module is byte-identical to the committed
  rendering when it does not. That second assertion is the load-bearing one:
  only a handful of registries declare a destination, so a template change that
  touched the other generated modules would rewrite most of :mod:`pcapkit.const`
  on the next crawl.
* :class:`CrawlerProtoDestTests` -- the declaring crawlers name exactly the
  destinations the registries need, no other crawler declares one, and the
  committed ``ARPHRD`` module is its crawler's rendering.

Nothing here crawls: :meth:`Vendor.__init__` fetches its registry and writes the
constant file as a side effect of construction, so the one crawler constructed
below is ``ARPHRD``, whose registry is a ``DATA`` literal, writing to a
temporary file.

"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import pkgutil
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): the vendor extra is installed on latest alone, the same
#: reasoning as tests/vendor/test_vendor_dest_path_unit.py.
__tier__ = 'LATEST'

#: Every distribution importing :mod:`pcapkit.vendor` needs; see
#: :file:`tests/vendor/test_vendor_dest_path_unit.py`.
VENDOR_DEPS = ('requests', 'bs4')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: ``crawler module -> ((module, class), ...)``, the destinations the declaring
#: crawlers name (#2392, #2533), with ``LinkType`` naming two: a link-layer
#: header type keys the next-layer registry of both capture file formats.
EXPECTED = {
    'pcapkit.vendor.reg.ethertype': (('pcapkit.protocols.link.link', 'Link'),),
    'pcapkit.vendor.reg.transtype': (('pcapkit.protocols.internet.internet', 'Internet'),),
    'pcapkit.vendor.reg.linktype': (('pcapkit.protocols.misc.pcap.frame', 'Frame'),
                                    ('pcapkit.protocols.misc.pcapng', 'PCAPNG')),
    'pcapkit.vendor.sctp.payload_protocol_identifier': (('pcapkit.protocols.transport.sctp',
                                                         'SCTP'),),
    'pcapkit.vendor.linux.arphrd': (('pcapkit.protocols.link.linux_sll', 'LinuxSLL'),),
}


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class RenderProtoDestTests(unittest.TestCase):
    """:func:`~pcapkit.vendor.default.render_proto_dest` renders re-importable Python."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_an_empty_declaration_renders_nothing(self) -> None:
        """Not an empty tuple literal, not a blank line -- the empty string.

        Anything else would appear in every generated module, since only a
        handful of the crawlers declare a destination.
        """
        from pcapkit.vendor.default import render_proto_dest

        self.assertEqual(render_proto_dest(()), '')

    def test_the_rendered_declaration_executes_and_resolves(self) -> None:
        """Rendered as a real class body, ``__proto_dest__`` resolves to the class.

        :func:`exec` rather than a string comparison, because what the template
        owes the generated module is *valid Python naming the right class*, not
        one particular spelling of it. A declaration rendered as, say, a bare
        :class:`tuple` of strings would pass a substring check and fail here.
        """
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.vendor.default import render_proto_dest
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG

        descriptors = (ModuleDescriptor('pcapkit.protocols.misc.pcap.frame', 'Frame'),
                       ModuleDescriptor('pcapkit.protocols.misc.pcapng', 'PCAPNG'))
        source = ('from pcapkit.corekit.module import ModuleDescriptor\n\n\n'
                  'class Rendered:\n' + render_proto_dest(descriptors) + '    pass\n')

        namespace = {}  # type: dict
        exec(compile(source, '<rendered>', 'exec'), namespace)  # nosec B102 # pylint: disable=exec-used

        self.assertEqual([entry.klass for entry in namespace['Rendered'].__proto_dest__],
                         [Frame, PCAPNG])

    def test_the_declaration_is_a_lazy_descriptor_not_an_import(self) -> None:
        """The rendered text names no class to import.

        :mod:`pcapkit.const` sits strictly below :mod:`pcapkit.protocols`, so a
        generated module that imported :class:`~pcapkit.protocols.link.link.Link`
        to declare it would be a circular import. The lazy
        :class:`~pcapkit.corekit.module.ModuleDescriptor` is what avoids that,
        and is why the declaration uses it (#2392).
        """
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.vendor.default import render_proto_dest

        rendered = render_proto_dest((ModuleDescriptor('pcapkit.protocols.link.link', 'Link'),))

        self.assertIn("ModuleDescriptor('pcapkit.protocols.link.link', 'Link'),", rendered)
        self.assertNotIn('import Link', rendered)
        self.assertNotIn('from pcapkit.protocols', rendered)


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class TemplateProtoDestTests(unittest.TestCase):
    """:data:`~pcapkit.vendor.default.LINE` renders the declaration, and only then."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _render(dest: 'tuple' = ()) -> 'str':
        from pcapkit.vendor.default import LINE

        return LINE('Hardware', 'Hardware Type [:rfc:`826`]',
                    'isinstance(value, int) and 0 <= value <= 65535',
                    "#: Ethernet\n    Ethernet = 1", 'return None',
                    'pcapkit.vendor.arp.hardware', dest)

    def test_no_declaration_leaves_the_rendering_untouched(self) -> None:
        """The output for a crawler that declares none, character for character.

        Pinned against the committed :mod:`pcapkit.const.arp.hardware` rather
        than against a copy of the template: ``arp/hardware`` declares no
        destination, so its import block and class body are what the template
        renders with no declaration to add.
        """
        rendered = self._render()

        self.assertNotIn('ModuleDescriptor', rendered)
        self.assertNotIn('__proto_dest__', rendered)
        self.assertIn('from pcapkit.corekit.enum import EnumRegistry\n'
                      'from pcapkit.utilities.exceptions import EnumValueError\n', rendered)
        self.assertIn('class Hardware(EnumRegistry, IntEnum):\n'
                      '    """[Hardware] Hardware Type [:rfc:`826`]"""\n'
                      '\n'
                      '    #: Ethernet\n', rendered)

    def test_a_declaration_adds_its_import_and_its_class_attribute(self) -> None:
        """Both halves, and the import in its isort position.

        The import matters as much as the attribute: a class body naming
        ``ModuleDescriptor`` without it is a generated module that raises
        :exc:`NameError` on import.
        """
        from pcapkit.corekit.module import ModuleDescriptor

        rendered = self._render((ModuleDescriptor('pcapkit.protocols.link.link', 'Link'),))

        self.assertIn('from pcapkit.corekit.enum import EnumRegistry\n'
                      'from pcapkit.corekit.module import ModuleDescriptor\n'
                      'from pcapkit.utilities.exceptions import EnumValueError\n', rendered)
        self.assertIn('    __proto_dest__ = (\n'
                      "        ModuleDescriptor('pcapkit.protocols.link.link', 'Link'),\n"
                      '    )\n'
                      '\n'
                      '    #: Ethernet\n', rendered)

    def test_the_rendered_module_imports_and_declares_the_destination(self) -> None:
        """The whole rendering executes, and the enumeration carries the dunder.

        An enumeration class body turns a plain assignment into a *member*, so
        the name has to be a dunder for ``aenum`` to leave it as an attribute.
        This is what pins that: a non-dunder spelling would make the rendered
        module declare a member instead, and ``__proto_dest__`` would be absent.
        """
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.link.link import Link

        rendered = self._render((ModuleDescriptor('pcapkit.protocols.link.link', 'Link'),))

        namespace = {}  # type: dict
        exec(compile(rendered, '<rendered>', 'exec'), namespace)  # nosec B102 # pylint: disable=exec-used
        klass = namespace['Hardware']

        self.assertEqual([entry.name for entry in klass], ['Ethernet'])
        self.assertIn('__proto_dest__', vars(klass))
        self.assertEqual([entry.klass for entry in klass.__proto_dest__], [Link])


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class CrawlerProtoDestTests(unittest.TestCase):
    """Exactly the expected crawlers declare a destination, with the right values."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _crawlers() -> 'dict':
        """``module name -> crawler class`` for every crawler under :mod:`pcapkit.vendor`."""
        import pcapkit.vendor as vendorpkg
        from pcapkit.vendor.default import Vendor

        found = {}  # type: dict
        for info in pkgutil.walk_packages(vendorpkg.__path__, prefix='pcapkit.vendor.'):
            module = importlib.import_module(info.name)
            for _, klass in inspect.getmembers(module, inspect.isclass):
                if (issubclass(klass, Vendor) and klass is not Vendor
                        and klass.__module__ == info.name):
                    found[info.name] = klass
        return found

    def test_the_declaring_crawlers_name_the_destinations_the_registries_need(self) -> None:
        crawlers = self._crawlers()
        for name, expected in EXPECTED.items():
            with self.subTest(crawler=name):
                self.assertIn(name, crawlers)
                self.assertEqual(tuple(tuple(entry) for entry in crawlers[name].PROTO_DEST),
                                 expected)

    def test_no_other_crawler_declares_one(self) -> None:
        """The rest inherit the empty default, so none of their output declares one.

        Not a style point: a crawler that gained a destination by accident would
        add an import and an attribute to its generated module on the next
        crawl, and -- worse -- would make ``code=`` infer a destination for an
        enumeration that keys no ``__proto__`` at all.
        """
        declaring = {name for name, klass in self._crawlers().items() if klass.PROTO_DEST}

        self.assertEqual(declaring, set(EXPECTED))

    def test_every_declared_destination_resolves_to_a_protocol_class(self) -> None:
        """A path that cannot be imported is a defect, and these are hand-written."""
        from pcapkit.protocols.protocol import ProtocolBase

        for name, klass in self._crawlers().items():
            for descriptor in klass.PROTO_DEST:
                with self.subTest(crawler=name, destination=descriptor.name):
                    self.assertTrue(issubclass(descriptor.klass, ProtocolBase))

    def test_the_committed_arphrd_module_is_the_crawlers_rendering(self) -> None:
        """Regenerating ``ARPHRD`` reproduces the committed module, declaration included (#2533).

        A regeneration pin, not the change's fail-before proof: it holds whenever
        crawler and committed module agree, so it passes without the declaration
        too. ``EXPECTED`` and the inference tests in
        :file:`tests/protocols/test_protocol_code_registration_unit.py` are what
        fail without it.

        Its crawler reads a ``DATA`` literal rather than fetching, so the whole
        render runs offline; it writes to a temporary file here, not to
        :file:`pcapkit/const/`.
        """
        import pathlib
        import tempfile
        from unittest import mock

        import pcapkit.const.linux.arphrd as committed
        from pcapkit.vendor.linux.arphrd import ARPHRD

        with tempfile.TemporaryDirectory(prefix='pcapkit-vendor-arphrd-') as tmp:
            dest = pathlib.Path(tmp, 'arphrd.py')
            with mock.patch.object(ARPHRD, '_dest_path', return_value=str(dest)):
                ARPHRD()
            rendered = dest.read_text(encoding='utf-8')

        self.assertEqual(rendered, pathlib.Path(committed.__file__).read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
