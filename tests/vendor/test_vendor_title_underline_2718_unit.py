# -*- coding: utf-8 -*-
"""A regenerated :mod:`pcapkit.const` module's title underline runs six past its title (#2718).

The *Heading Case and Shape* section of
:file:`docs/source/contributing/conventions/documentation.rst` rules that a module
docstring's ``=`` title underline is the title's length plus six.
:file:`tests/project/test_docs_module_title_underline_2718_unit.py` holds the
committed modules to it, and checks that every crawler template computes its
underline from its title; this suite renders the modules themselves.

Each crawler that writes through :meth:`Vendor.context
<pcapkit.vendor.default.Vendor.context>` is driven through it with
:meth:`~pcapkit.vendor.default.Vendor.process` stubbed to an empty enumeration,
by the ``cls.__new__(cls)`` bypass
:file:`tests/vendor/test_vendor_mh_lla_code_1848_unit.py` uses to skip
:meth:`Vendor.__init__ <pcapkit.vendor.default.Vendor.__init__>`'s fetch and
write. A crawler with a ``context`` of its own calls template lambdas its module
defines, and each one it names is called directly, with the crawler's name,
docstring and module and an empty string for everything else. Either way the
text is the module a regeneration writes, members aside, and its heading is
measured as the committed modules' are.

"""
from __future__ import annotations

import importlib.util
import inspect
import pathlib
import sys
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): drives the vendor crawlers directly, the same reasoning
#: as tests/vendor/test_vendor_mh_lla_code_1848_unit.py.
__tier__ = 'LATEST'

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs, as
#: :file:`tests/vendor/test_user_agent_unit.py` explains.
VENDOR_DEPS = ('requests', 'bs4', 'html5lib')

#: Whether the crawlers are importable at all.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)

#: How far the underline runs past the title.
OVERHANG = 6


def heading(text: 'str') -> 'tuple[str, str]':
    """The title and underline a rendered module's docstring opens on."""
    lines = text.split('\n')
    index = next(index for index, line in enumerate(lines) if line.startswith('"""'))
    return lines[index][3:].strip(), lines[index + 1].strip() if index + 1 < len(lines) else ''


def render(cls: 'Any', base: 'Any') -> 'list[str]':
    """The module text each template ``cls`` writes through renders for it, ``base`` being the default crawler."""
    if cls.context is base.context:
        crawler = cls.__new__(cls)
        crawler.NAME = cls.__name__
        crawler.DOCS = cls.__doc__
        crawler.process = lambda data: ([], [])
        return [crawler.context([])]

    module = sys.modules[cls.context.__module__]
    texts = []  # type: list[str]
    for name in cls.context.__code__.co_names:
        template = getattr(module, name, None)
        if not (callable(template) and getattr(template, '__name__', None) == '<lambda>'):
            continue
        args = {param: '' for param, spec in inspect.signature(template).parameters.items()
                if spec.default is inspect.Parameter.empty}
        args.update(NAME=cls.__name__, DOCS=cls.__doc__, MODL=cls.__module__)
        texts.append(template(**args))
    return texts


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class RegeneratedHeadingTests(unittest.TestCase):
    """Every module a crawler renders keeps the rule."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)
        import pcapkit.vendor as vendor
        resolved = pathlib.Path(vendor.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'{vendor.__name__} was imported from {resolved}, which is '
                          f'outside {ROOT}; install this checkout with `pip install -e .` to '
                          f'run this suite against it')

    def test_every_regenerated_underline_runs_six_past_its_title(self) -> 'None':
        """A crawler whose rendered heading misses, or that renders none, names itself."""
        import pcapkit.vendor as vendor
        from pcapkit.vendor.default import Vendor

        off = []  # type: list[str]
        for name in vendor.__all__:
            cls = getattr(vendor, name)
            texts = render(cls, Vendor)
            if not texts:
                off.append(f'{cls.__module__}.{name}: no template rendered')
            for text in texts:
                title, underline = heading(text)
                if not underline or set(underline) != {'='}:
                    off.append(f'{cls.__module__}.{name}: no = underline under {title!r}')
                elif len(underline) != len(title) + OVERHANG:
                    off.append(f'{cls.__module__}.{name}: {len(underline)} for a title of {len(title)}')
        self.assertTrue(vendor.__all__, 'no crawler to render')
        self.assertEqual(off, [])


if __name__ == '__main__':
    unittest.main()
