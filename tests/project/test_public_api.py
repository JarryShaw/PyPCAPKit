# -*- coding: utf-8 -*-
"""The public API surface holds together.

Four invariants about :attr:`__all__`, none of which anything else in the suite
checked before:

#. every public subpackage survives ``from <package> import *``;
#. every name in every public module's :attr:`__all__` actually resolves;
#. every public package lists everything public it holds, bar an allowlist of
   exclusions that had to be written down one at a time;
#. the three re-export aggregators list *everything* public they hold, with no
   allowlist at all.

The first two exist because of GitHub issue #515. ``pcapkit/protocols/data``
listed ``'HOPOPT_QuickStartOption'`` in its :attr:`__all__` and never bound it,
so a plain ``from pcapkit.protocols.data import *`` raised
:exc:`AttributeError`. Commit ``1831bb60b`` had split ``QuickStartOption`` into
Request and Report variants and updated the *intermediate*
``pcapkit/protocols/data/internet/__init__.py`` -- but not the aggregator above
it, which re-exports the same names a second time under the same prefixes.

It stayed broken for about three and a half years. That is the interesting part:
the failure is a one-line typo with a loud, immediate, deterministic symptom, and
nothing caught it, because nothing in the suite ever star-imported the package.
A name in :attr:`__all__` is otherwise inert -- it is read by ``import *`` and by
Sphinx, and by nothing that the tests exercised.

Star-importing is therefore the whole mechanism here: ``from x import *`` is the
one operation that reads every entry of :attr:`__all__` and raises on the first
one that does not resolve. :meth:`PublicAPISurfaceTests.test_star_import_of_every_public_subpackage`
performs the real statement, so the user-visible symptom is what regresses;
:meth:`PublicAPISurfaceTests.test_every_all_entry_resolves` then does the cheaper
:func:`hasattr` sweep over every module rather than only the packages, and names
the offending symbol instead of failing on the first one.

Two scoping decisions, both measured rather than assumed.

**:mod:`pcapkit.vendor` is excluded.** Its modules ``import requests`` and
``import bs4``, which come from the ``vendor`` extra (:file:`pyproject.toml`) and
are *not* installed by ``pip install -e '.[test]'``. This module is unit-tier --
see :mod:`tests._tiers` -- so it has to pass on exactly that install, and
importing :mod:`pcapkit.vendor` there would fail on the missing dependency rather
than on anything to do with :attr:`__all__`. Very little is hidden by the
exclusion, and what is hidden was measured rather than assumed: the same sweep was
run by hand over :mod:`pcapkit.vendor` on a machine that *does* have the extra,
across the package and its 134 public descendants. Every one of them imports,
every one declares :attr:`__all__`, and every entry of every :attr:`__all__`
resolves. The single defect it holds is the duplicate described at the end of this
docstring, in :mod:`pcapkit.vendor` and :mod:`pcapkit.vendor.mh`.

Nothing else is excluded, and no import is wrapped in a skip. That is deliberate
and also measured: with ``dpkt``, ``scapy``, ``emoji``, ``cryptography`` and
``pycrate`` all absent, every one of the 325 non-vendor modules still imports,
because each optional dependency is already guarded at its import site -- e.g.
``pcapkit/toolkit/scapy.py`` catches :exc:`ModuleNotFoundError` and degrades to
``scapy = None`` with a warning. So an import failure in this sweep is a real
defect and is allowed to fail the test, rather than being softened into a skip
that would let the next :attr:`__all__` bug through.

**The converse -- every public attribute appears in :attr:`__all__` -- holds for
every public *package*, against a written-down allowlist of exclusions.** That is
issue #533, and scope is what makes it a test rather than noise.

Applied to every *module* the converse flags 2848 names across 286. That is not a
failing test, it is a wall: a module's namespace holds whatever it imported in
order to do its job, and none of that is its public surface. Applied to the 52
public *packages* it flags 45 across 12 -- small enough to read, triage, and write
down one at a time. A package's namespace is a composed thing: it holds what its
:file:`__init__.py` chose to pull in, so a public attribute it has and does not
export is a decision in one direction or the other, and the assertion exists to
make that decision explicit instead of leaving it to be guessed at.

:data:`DELIBERATE_NON_EXPORTS` is where the decisions are recorded, and it is
load-bearing rather than an escape hatch: without it the assertion is
unsatisfiable, and with it every exclusion is something somebody wrote down and a
reviewer can argue with. Of the 45, 23 were genuine omissions and are exported as
of the commit that added this assertion -- among them the six
``register_*_callback`` and ``register_extractor_*`` functions that
:mod:`pcapkit.foundation` withheld while listing the other 27 registry functions,
``ReassemblyManager`` and ``TraceFlowManager``, which are defined *below* the
:attr:`__all__` literal that forgot them and imported by name from six modules, and
the three decorators :mod:`pcapkit.utilities` advertises in its own module
docstring. The 22 that remain are listed with their reasons, and
:meth:`~PublicAPISurfaceTests.test_the_non_export_allowlist_is_tight` stops the
list rotting into a silencer: every entry has to name a package that exists, an
attribute that package really holds, and a name its :attr:`__all__` really omits,
so an entry stops being true the moment the tree moves under it.

:data:`AGGREGATORS` keeps an assertion of its own even though the package-wide one
now covers those three, because the guarantee is a stronger one: it admits no
allowlist at all. Those three packages are pure re-export surfaces -- each
wildcard-imports its children and re-lists their names, so every public attribute
it has came from a child that already chose to export it, and any name missing from
its :attr:`__all__` is an oversight by construction. That is precisely how #515
happened, and this is the assertion that makes the next one fail immediately
instead of in three years.

Three further assertions cover the rest of the family, because a name can fail to
be exported in more ways than by being misspelled. Each of the three failed
against the tree this module was written on, and each is fixed in the same commit:

* :meth:`~PublicAPISurfaceTests.test_no_misspelled_all` --
  ``pcapkit/const/pcapng/__init__.py`` spelled it ``___all__``, with *three*
  leading underscores. Nothing reads that name, so the package simply had no
  :attr:`__all__`: ``hasattr(module, '__all__')`` was :data:`False` and
  ``from pcapkit.const.pcapng import *`` fell back to "every public name",
  leaking its 7 submodules on top of the 7 enums it meant to publish. This is the
  quietest member of the family -- a misspelling here does not raise, it silently
  widens the public surface.
* :meth:`~PublicAPISurfaceTests.test_every_public_package_declares_all` -- the
  same defect seen from the other side, and the one that catches "forgot it
  entirely" rather than "typed it wrong". All 52 public packages declare
  :attr:`__all__` once ``pcapng`` is fixed.
* :meth:`~PublicAPISurfaceTests.test_no_duplicate_all_entries` --
  ``'MH_HandoverACKStatus'`` appeared *twice* in both :mod:`pcapkit.const` and
  :mod:`pcapkit.const.mh`, and the duplicate sat in the slot that should have held
  ``'MH_HandoverInitiateStatus'``. A duplicate is harmless on its own, which is
  why it survived; what made it a defect is that it displaced a real name. The
  class exists at ``pcapkit/const/mh/handover_initiate_status.py`` and is used by
  :mod:`pcapkit.protocols.internet.mh`, yet it was never imported into the package
  and so ``pcapkit.const.mh.MH_HandoverInitiateStatus`` did not resolve at all.
  Note that a duplicate is invisible to
  :meth:`~PublicAPISurfaceTests.test_every_all_entry_resolves`, because the name
  it repeats does resolve -- only counting the entries finds it.

One gap remains, and it is recorded rather than closed because it lies outside
this module's reach. :mod:`pcapkit.vendor` is excluded from the sweep for the
dependency reason above, and it carries the *same* displaced-duplicate defect in
``pcapkit/vendor/__init__.py`` and ``pcapkit/vendor/mh/__init__.py``. That one is
worse than its :mod:`pcapkit.const` twin rather than merely parallel:
``pcapkit/vendor/__main__.py`` builds its crawler target list out of
``pcapkit.vendor.__all__``, so the missing ``MH_HandoverInitiateStatus`` means the
``handover_initiate_status`` crawler is absent from the default target list *and*
from ``--target mh``, and has therefore never run. Fixing it needs the ``vendor``
extra installed to be testable here, so it belongs to a separate change; when it
lands, drop ``'vendor'`` from :data:`EXCLUDED_ROOTS` and this module will cover it
too.

"""
from __future__ import annotations

import functools
import importlib
import pkgutil
import types
import unittest

#: First path component under ``pcapkit.`` whose subtree the sweep skips.
#: :mod:`pcapkit.vendor` needs the ``vendor`` extra (``requests``,
#: ``beautifulsoup4``) at import time, and the unit tier does not have it.
EXCLUDED_ROOTS = frozenset({'vendor'})

#: The packages whose whole job is to re-export their children, and which
#: therefore have to list every public name they hold -- with no allowlist, unlike
#: every other package. See the module docstring for why these three are held to
#: the stricter form.
AGGREGATORS = (
    'pcapkit.protocols.data',
    'pcapkit.protocols.schema',
    'pcapkit.foundation.registry',
)

#: Public attributes a public package holds and deliberately does not export,
#: keyed by the package. Adding a name here is an API decision to be argued for in
#: review -- it is not the way to quiet a failure of
#: :meth:`~PublicAPISurfaceTests.test_every_public_package_exports_every_public_attribute`.
#: Three kinds of thing are in here, and nothing else should be.
#:
#: **The abstract bases** -- ``Field``, ``Engine``, ``Reassembly``,
#: ``IP_Reassembly``, ``TraceFlow``, ``Protocol``, ``Application``, ``Internet``,
#: ``Link``, ``Transport``. Each is imported by its package explicitly, under a
#: "Base Class" comment, and left out of that package's :attr:`__all__`; nine
#: packages do the same thing the same way. Neither :mod:`pcapkit.all` -- the
#: library index, whose stated job is to hold "all things from :mod:`pcapkit`" --
#: nor :mod:`pcapkit.corekit` exports any of them either. Three independent export
#: surfaces agreeing is a convention rather than nine separate oversights, so they
#: stay reachable by their documented dotted path and out of ``import *``.
#:
#: **Names another module's import dragged in** -- ``Info`` and ``info_final``
#: belong to :mod:`pcapkit.corekit.infoclass`, which is where they are documented
#: and exported from; the reassembly and traceflow packages import them only to
#: build their manager classes. ``TYPE_CHECKING`` is :mod:`typing`'s. Re-exporting
#: any of them would claim ownership of a name this package does not own.
#:
#: **Import-time machinery, and one leaked loop variable.**
#: :mod:`pcapkit` imports ``BaseError``, ``DEVMODE`` and ``DevModeWarning`` to wire
#: up the ``tbtrim`` excepthook, not to publish them -- the top-level surface is
#: interface functions, macros and protocols, and those three are documented under
#: :mod:`pcapkit.utilities`. ``ROOT`` is bound only on the non-``DEVMODE`` branch,
#: so exporting it would make ``from pcapkit import *`` raise
#: :exc:`AttributeError` under ``PCAPKIT_DEVMODE=1`` -- a fresh #515 rather than a
#: fix for one. ``pcapkit.protocols.name`` is the loop variable of the
#: ``for name in __all__`` that builds ``__proto__``, left behind in the namespace;
#: renaming it ``_name`` would express that better than this entry does, but that
#: is a change to a module body rather than to an export list.
DELIBERATE_NON_EXPORTS = {
    'pcapkit': ('BaseError', 'DEVMODE', 'DevModeWarning', 'ROOT'),
    'pcapkit.corekit.fields': ('Field',),
    'pcapkit.foundation.engines': ('Engine',),
    'pcapkit.foundation.reassembly': ('IP_Reassembly', 'Info', 'Reassembly',
                                      'TYPE_CHECKING', 'info_final'),
    'pcapkit.foundation.traceflow': ('Info', 'TYPE_CHECKING', 'TraceFlow',
                                     'info_final'),
    'pcapkit.protocols': ('Protocol', 'TYPE_CHECKING', 'name'),
    'pcapkit.protocols.application': ('Application',),
    'pcapkit.protocols.internet': ('Internet',),
    'pcapkit.protocols.link': ('Link',),
    'pcapkit.protocols.transport': ('Transport',),
}


def _unlisted_public_attributes(module: 'types.ModuleType') -> 'list[str]':
    """Public attributes of ``module`` that its :attr:`__all__` does not name.

    Submodules are skipped. A submodule becomes an attribute of its parent package
    as a side effect of being imported, whether or not the parent means to
    re-export it, so counting them would flag every package that has children.

    """
    declared = getattr(module, '__all__', ())
    return sorted(
        attribute for attribute in dir(module)
        if not attribute.startswith('_')
        and attribute not in declared
        and not isinstance(getattr(module, attribute), types.ModuleType)
    )


def _is_excluded(name: 'str') -> 'bool':
    """Whether ``name`` -- a dotted module path under ``pcapkit.`` -- is skipped.

    Private components (a leading underscore on any part below the root) and the
    :data:`EXCLUDED_ROOTS` subtrees are not part of the public surface this
    module is about.

    """
    tail = name[len('pcapkit.'):]
    parts = tail.split('.')
    if any(part.startswith('_') for part in parts):
        return True
    return parts[0] in EXCLUDED_ROOTS


@functools.lru_cache(maxsize=1)
def public_modules() -> 'tuple[tuple[str, bool], ...]':
    """Every public module under :mod:`pcapkit`, as ``(name, is_package)``.

    Recursion is written out rather than delegated to
    :func:`pkgutil.walk_packages` on purpose. ``walk_packages`` imports each
    package in order to walk into it and, with no ``onerror`` callback, swallows
    any :exc:`ImportError` that raises -- which would silently drop a whole
    subtree from the sweep and quietly weaken every assertion built on it. Here
    the exclusion is applied *before* the import, so nothing that should be
    checked can go missing without the import error surfacing.

    """
    import pcapkit

    found = [('pcapkit', True)]

    def walk(package: 'types.ModuleType', prefix: 'str') -> None:
        for info in pkgutil.iter_modules(package.__path__, prefix):
            if _is_excluded(info.name):
                continue
            found.append((info.name, info.ispkg))
            if info.ispkg:
                walk(importlib.import_module(info.name), info.name + '.')

    walk(pcapkit, 'pcapkit.')
    return tuple(found)


class PublicAPISurfaceTests(unittest.TestCase):
    def test_public_modules_were_actually_found(self) -> None:
        # A bug in the walk above would turn every other test in this class into
        # a silent pass over an empty list, so pin the shape of what it returns.
        # The floor is deliberately far below the 325 modules / 52 packages found
        # when this was written: it catches "found nothing", not "the library
        # gained a module".
        modules = public_modules()
        packages = [name for name, is_package in modules if is_package]

        self.assertGreater(len(modules), 200,
                           'the module walk found implausibly few modules')
        self.assertGreater(len(packages), 40,
                           'the module walk found implausibly few packages')
        for name in ('pcapkit', 'pcapkit.protocols.data', 'pcapkit.protocols.schema',
                     'pcapkit.foundation.registry', 'pcapkit.const.mh'):
            self.assertIn((name, True), modules, f'{name} missing from the walk')
        self.assertFalse([name for name, _ in modules if _is_excluded(name)],
                         'the walk yielded a module it was supposed to exclude')

    def test_star_import_of_every_public_subpackage(self) -> None:
        # The statement from issue #515, run against every public package rather
        # than the one that happened to be reported. `from x import *` is the only
        # operation that reads every entry of __all__, which is why a broken entry
        # survived three and a half years of a green suite.
        for name, is_package in public_modules():
            if not is_package:
                continue
            with self.subTest(package=name):
                namespace = {}  # type: dict[str, object]
                try:
                    exec(f'from {name} import *', namespace)  # pylint: disable=exec-used
                except AttributeError as exc:
                    self.fail(
                        f'`from {name} import *` raised AttributeError: {exc}\n'
                        f"Something in {name}.__all__ is not bound in the module. "
                        f'Either the name is misspelled, or it was renamed in a child '
                        f'module and this __all__ was not updated with it -- which is '
                        f'exactly how #515 happened.'
                    )

                # A star-import binds every name in __all__, so the namespace it
                # filled is the proof each one resolved -- not merely that the
                # statement did not raise.
                module = importlib.import_module(name)
                for symbol in getattr(module, '__all__', ()):
                    self.assertIn(symbol, namespace,
                                  f'{name}.__all__ names {symbol!r}, but `import *` did not bind it')

    def test_every_all_entry_resolves(self) -> None:
        # The same invariant as above, over every module rather than only the
        # packages, and reported as a complete list instead of failing on
        # whichever name `import *` happened to reach first.
        unresolved = {}  # type: dict[str, list[str]]
        for name, _ in public_modules():
            module = importlib.import_module(name)
            declared = getattr(module, '__all__', None)
            if declared is None:
                continue
            missing = [symbol for symbol in declared if not hasattr(module, symbol)]
            if missing:
                unresolved[name] = missing

        self.assertEqual(unresolved, {},
                         'these __all__ entries name something the module does not have, '
                         'so `from <module> import *` raises AttributeError on it')

    def test_all_entries_are_strings(self) -> None:
        # `import *` raises TypeError rather than AttributeError when __all__
        # holds a non-string, which is a different failure with a much less
        # obvious message. Cheap to rule out.
        for name, _ in public_modules():
            module = importlib.import_module(name)
            declared = getattr(module, '__all__', None)
            if declared is None:
                continue
            with self.subTest(module=name):
                offenders = [symbol for symbol in declared if not isinstance(symbol, str)]
                self.assertEqual(offenders, [], f'{name}.__all__ holds a non-string entry')

    def test_no_misspelled_all(self) -> None:
        # `pcapkit/const/pcapng/__init__.py` spelled it `___all__`. Nothing reads
        # that name, so the package had no __all__ at all and its star-import
        # silently widened to every public name. A misspelling here never raises,
        # which is why only a check like this one finds it.
        offenders = {}  # type: dict[str, list[str]]
        for name, _ in public_modules():
            module = importlib.import_module(name)
            # Any attribute that is `all` once stripped of underscores, but is not
            # exactly `__all__`: `___all__`, `__all___`, `__all_`, `_all__`.
            misspelled = sorted(
                attribute for attribute in vars(module)
                if attribute != '__all__'
                and '_' in attribute
                and attribute.strip('_') == 'all'
            )
            if misspelled:
                offenders[name] = misspelled

        self.assertEqual(offenders, {},
                         'these modules hold an __all__-lookalike attribute, which nothing '
                         'reads -- so the module has no effective __all__ and `import *` '
                         'falls back to exporting every public name it happens to hold')

    def test_every_public_package_declares_all(self) -> None:
        # The converse of the misspelling check: it catches "forgot __all__"
        # rather than "typed it wrong". A re-export package with no __all__ leaks
        # its submodules into every star-import of it.
        undeclared = [name for name, is_package in public_modules()
                      if is_package and not hasattr(importlib.import_module(name), '__all__')]

        self.assertEqual(undeclared, [],
                         'these public packages declare no __all__, so `import *` on them '
                         'exports every public name including their submodules')

    def test_no_duplicate_all_entries(self) -> None:
        # A duplicate is harmless in itself -- `import *` binds the name twice and
        # nothing notices -- so it survives review. It matters because of what it
        # displaces: 'MH_HandoverACKStatus' appeared twice in pcapkit.const.mh
        # while sitting in the slot that should have held
        # 'MH_HandoverInitiateStatus', which was consequently never exported.
        # test_every_all_entry_resolves cannot see this, because the repeated name
        # does resolve; only counting the entries finds it.
        duplicated = {}  # type: dict[str, list[str]]
        for name, _ in public_modules():
            module = importlib.import_module(name)
            declared = getattr(module, '__all__', None)
            if declared is None:
                continue
            repeats = sorted({symbol for symbol in declared if declared.count(symbol) > 1})
            if repeats:
                duplicated[name] = repeats

        self.assertEqual(duplicated, {},
                         'these __all__ lists name the same symbol more than once; check '
                         'whether the duplicate displaced a name that should be there')

    def test_aggregators_export_every_public_attribute(self) -> None:
        # The converse of test_every_all_entry_resolves, and viable only here --
        # see the module docstring for the measurement behind that. These three
        # packages re-export their children wholesale, so a public attribute they
        # hold but do not list is an oversight rather than a judgement call.
        for name in AGGREGATORS:
            unlisted = _unlisted_public_attributes(importlib.import_module(name))
            with self.subTest(package=name):
                self.assertEqual(
                    unlisted, [],
                    f'{name} re-exports these publicly but leaves them out of __all__, '
                    f'so `from {name} import *` does not provide them: {unlisted}'
                )

    def test_every_public_package_exports_every_public_attribute(self) -> None:
        # The same converse as above, over all 52 public packages rather than the
        # three aggregators, against DELIBERATE_NON_EXPORTS: issue #533. This is the
        # only assertion in the class that reads __all__ as the *expectation* --
        # every other one reads it as the input, and an attribute that exists while
        # nothing names it satisfies all of them.
        for name, is_package in public_modules():
            if not is_package:
                continue
            allowed = DELIBERATE_NON_EXPORTS.get(name, ())
            unlisted = [attribute
                        for attribute in _unlisted_public_attributes(importlib.import_module(name))
                        if attribute not in allowed]
            with self.subTest(package=name):
                self.assertEqual(
                    unlisted, [],
                    f'{name} holds these public attributes but leaves them out of __all__, '
                    f'so `from {name} import *` does not provide them and Sphinx does not '
                    f'see them as exported: {unlisted}. Add them if they are meant to be '
                    f'public; if the omission is deliberate, record them in '
                    f'DELIBERATE_NON_EXPORTS with the reason, which is what makes the '
                    f'intent reviewable instead of indistinguishable from an oversight.'
                )

    def test_the_non_export_allowlist_is_tight(self) -> None:
        # DELIBERATE_NON_EXPORTS is the whole reason the assertion above can be
        # satisfied at all, so it gets an assertion of its own. Any of three kinds of
        # staleness turns an entry into an exclusion nobody decided, silently
        # excusing the next real omission of that name: the package is gone, the
        # attribute is gone, or the name has since been added to __all__ and the
        # entry now excuses nothing while looking as though it does.
        packages = {name for name, is_package in public_modules() if is_package}

        self.assertEqual(sorted(set(DELIBERATE_NON_EXPORTS) - packages), [],
                         'DELIBERATE_NON_EXPORTS names packages that are not in the public '
                         'walk, so those entries exclude nothing')

        absent = {}  # type: dict[str, list[str]]
        redundant = {}  # type: dict[str, list[str]]
        for name, allowed in DELIBERATE_NON_EXPORTS.items():
            if name not in packages:
                continue
            module = importlib.import_module(name)
            declared = getattr(module, '__all__', ())
            missing = [symbol for symbol in allowed if not hasattr(module, symbol)]
            listed = [symbol for symbol in allowed if symbol in declared]
            if missing:
                absent[name] = missing
            if listed:
                redundant[name] = listed

        self.assertEqual(absent, {},
                         'DELIBERATE_NON_EXPORTS names attributes these packages do not have; '
                         'the name was renamed or removed and the entry was left behind')
        self.assertEqual(redundant, {},
                         'DELIBERATE_NON_EXPORTS names attributes these packages now export '
                         'anyway, so the entry is dead and should be deleted -- leaving it '
                         'would excuse the name if it were ever dropped from __all__ again')


if __name__ == '__main__':
    unittest.main()
