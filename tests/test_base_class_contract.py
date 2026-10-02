# -*- coding: utf-8 -*-
"""The ``*Base``/public split, asserted rather than left to convention.

Five class pairs carry the same contract, and GitHub issue #514 settled what it
is: **library classes inherit the ``*Base``; users inherit the public class, and
only a subclass of the public class auto-registers.** So
``descendants(Protocol) == 0`` is the invariant to enforce, not a defect to fix.

================= ============================================== =================
Suite             ``*Base``                                      public
================= ============================================== =================
protocols         :class:`pcapkit.protocols.protocol.ProtocolBase`  ``Protocol``
engines           :class:`pcapkit.foundation.engines.engine.EngineBase` ``Engine``
reassembly        :class:`pcapkit.foundation.reassembly.reassembly.ReassemblyBase` ``Reassembly``
traceflow         :class:`pcapkit.foundation.traceflow.traceflow.TraceFlowBase` ``TraceFlow``
dumpers           :class:`pcapkit.dumpkit.common.DumperBase`      ``Dumper``
================= ============================================== =================

Two different things are checked here, and the split between them is deliberate
because only one of them is a behaviour claim.

:class:`BaseClassAliasTests` is the part with teeth. Until #514 part (c), 82
import statements across the library read ``from ... import ProtocolBase as
Protocol`` -- binding the *base* to the *public* name -- so a module went on to
say ``class Application(Protocol)`` while in fact inheriting ``ProtocolBase``.
Nothing was wrong at runtime; the classes were correct. What was wrong is that
the source said the opposite of what it did, and that is not a cosmetic
complaint: the aliasing was a *convention* rather than a mechanism, so a sweep
over it could miss a site and nothing would fail. It missed one twice --
issue #506 (a runtime import in ``schema/schema.py`` unreachable for three
years) and issue #513 (the ``extraction.py`` gates rejecting the library's own
built-ins for three years). These two tests replace the convention with
something that fails.

The sweep and the migration are both complete: all 82 sites are renamed, the
last 54 (all ``ProtocolBase``, across ``pcapkit/protocols/`` and three
``pcapkit/foundation/`` modules) having landed in #514 part (c) once #726 and
#742 merged. :data:`PENDING_ALIAS_PATHS` is therefore empty -- its intended end
state -- and :func:`is_pending` is trivially ``False`` for every path; the dict
stays as a mechanism rather than being deleted, in case a future ``*Base``
family needs the same transitional carve-out.

:class:`RegistrationGateTests` is a regression pin, not a new behaviour. Every
assertion in it already held before part (c), because parts (a) and (b)
(pull requests #547 and #570) made registration opt-in on a keyword. It is written down
because the ruling promotes it from an accident of where the hook happens to live
into the specification, and an unasserted specification is one refactor away from
being untrue. The property worth noticing is the last one: a library-style
subclass cannot opt in *even if it tries*, because the ``*Base`` hook does not
accept the keyword at all. That is the ``final``-substitute the split was built
to provide, and it is stronger than a convention.

.. note::

   :class:`RegistrationGateTests` mutates the process-global registries, so each
   test restores exactly the keys it added. It deliberately does not assert on
   ``descendants(Public)`` directly -- any other module in the same session that
   defines a subclass of a public class (``DummyProtocol`` in
   :file:`tests/protocols/schema/test_schema_unit.py` is one, and it exists on
   purpose) would make that count non-zero and the assertion order-dependent.
   The invariant is asserted over the *library's own* classes instead, which is
   what it is actually about and is immune to collection order.

   It fires, though, and GitHub issue #981 is the reproduction:
   ``tests.protocols.application.test_http_unit`` run before this module, one
   process, plain :mod:`unittest`, desyncs
   :class:`RegistrationGateTests.test_user_style_subclass_registers_when_it_opts_in`
   on all four suites. That test's own ``setUp`` calls
   :func:`tests._support.purge_modules` on ``pcapkit`` and re-imports it from
   source, which mints a *second generation* of every ``pcapkit`` class --
   deliberately asymmetric, see that function's own docstring, and ordinarily
   reconciled straight back by :func:`tests.conftest.restore_module_table`'s
   autouse fixture. Plain :mod:`unittest` never loads that fixture, so the
   second generation stays live: this module's own top-level ``from
   pcapkit... import Engine, EngineBase, ...`` is now bound to the *first*
   generation, while ``Dumper.__init_subclass__`` and
   ``Extractor.register_engine``/``register_reassembly``/``register_traceflow``
   each re-import their collaborators locally and so see the *second*. A
   dynamically-created ``UserOptIn_engines(Engine, engine=...)`` is then a
   first-generation class handed to a second-generation
   ``issubclass(..., EngineBase)`` check -- which is false, two same-named but
   distinct classes -- and the ``dumpers`` suite's registration lands in the
   second generation's ``Extractor.__output__`` while
   :meth:`RegistrationGateTests.registry` keeps reading the first generation's,
   so the key the test just added looks absent. :class:`RegistrationGateTests`
   closes this by never trusting its own module-level import for anything it
   compares a *live* class against: :meth:`~RegistrationGateTests.setUp`
   re-resolves every base/public pair and the ``Extractor`` singleton through
   :func:`importlib.import_module` -- a no-op lookup in :data:`sys.modules`
   when nothing has reimported, and the current generation when something has
   -- so the suite always compares like generation to like, regardless of what
   ran before it in the same process.

"""
from __future__ import annotations

import ast
import importlib
import pkgutil
import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT

import pcapkit
from pcapkit.dumpkit.common import Dumper, DumperBase
from pcapkit.foundation.engines.engine import Engine, EngineBase
from pcapkit.foundation.extraction import Extractor
from pcapkit.foundation.reassembly.reassembly import Reassembly, ReassemblyBase
from pcapkit.foundation.traceflow.traceflow import TraceFlow, TraceFlowBase
from pcapkit.protocols.protocol import Protocol, ProtocolBase

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Every ``*Base`` name mapped to the public name it must never be aliased to.
#: Keyed on the base rather than the public name because the base is what an
#: import statement names; the alias is the thing being outlawed.
BASE_TO_PUBLIC = {
    'ProtocolBase': 'Protocol',
    'EngineBase': 'Engine',
    'ReassemblyBase': 'Reassembly',
    'DumperBase': 'Dumper',
    'TraceFlowBase': 'TraceFlow',
}

#: ``FieldBase``/``Field`` is *not* in this table, and the omission is the
#: point. That pair is not registration-motivated -- ``Field`` has no
#: ``__init_subclass__`` and adds a real ``__init__`` and a ``template``
#: property -- so aliasing it is a legitimate abbreviation rather than a
#: misstatement. #514 excludes it explicitly.
NOT_IN_SCOPE = frozenset({'FieldBase'})

#: Paths still carrying the alias because another open pull request owns them,
#: mapped to that pull request. A prefix rather than a file list, because #726
#: owns the whole ``pcapkit/protocols/`` subtree and enumerating its ~50 sites
#: would turn this into a changelog.
#:
#: Each entry is a promise, not an exemption: when the named pull request lands,
#: the alias comes out and the entry goes with it. **An empty dict is the end
#: state**, and :meth:`BaseClassAliasTests.test_no_library_module_imports_a_base_under_its_public_name`
#: fails on an entry that has stopped matching anything, so a stale promise
#: cannot sit here unnoticed once its pull request merges. #514 part (c) landed
#: the last 54 sites, so this is now empty and every alias check below runs
#: unconditionally.
PENDING_ALIAS_PATHS = {}  # type: dict[str, int]


def is_pending(rel: 'str') -> 'bool':
    """Is ``rel`` owned by an open pull request?

    Args:
        rel: repo-relative POSIX path.

    Returns:
        Whether some entry of :data:`PENDING_ALIAS_PATHS` covers it.

    """
    return any(rel.startswith(prefix) for prefix in PENDING_ALIAS_PATHS)


def iter_library_sources() -> 'Iterator[tuple[str, ast.Module]]':
    """Every module under :file:`pcapkit/`, as a parsed tree.

    Yields:
        The repo-relative POSIX path and the parsed module.

    """
    for path in sorted((ROOT / 'pcapkit').rglob('*.py')):
        rel = path.relative_to(ROOT).as_posix()
        yield rel, ast.parse(path.read_text(encoding='utf-8'))


def find_alias_imports(tree: 'ast.Module') -> 'list[tuple[int, str, str]]':
    """Locate every ``import <X>Base as <X>`` in ``tree``.

    Args:
        tree: parsed module to search.

    Returns:
        One ``(lineno, base name, alias)`` triple per offending import.

    """
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        for alias in node.names:
            name = alias.name.rpartition('.')[2]
            if name in NOT_IN_SCOPE or alias.asname is None:
                continue
            if BASE_TO_PUBLIC.get(name) == alias.asname:
                found.append((node.lineno, name, alias.asname))
    return found


class BaseClassAliasTests(unittest.TestCase):
    """No library module may call a ``*Base`` class by its public name."""

    def test_no_library_module_imports_a_base_under_its_public_name(self) -> None:
        """Source-level sweep: the alias must not appear.

        This is the source-level half, and it is the half that sees the ~53
        aliases that live inside ``if TYPE_CHECKING:``. Those have no runtime
        effect at all -- they exist so an annotation can say ``Protocol`` -- so
        :meth:`test_library_modules_do_not_bind_the_public_name_at_runtime`
        cannot see them and this one has to.

        """
        offenders = {}
        for rel, tree in iter_library_sources():
            hits = find_alias_imports(tree)
            if hits:
                offenders[rel] = hits

        unexpected = {rel: hits for rel, hits in offenders.items()
                      if not is_pending(rel)}
        self.assertEqual(
            unexpected, {},
            'a library module imports a *Base class under its public name, so its '
            'source now says the opposite of what it does; import the base under '
            'its own name and rename the references. C.f. #514.'
        )

        # A pending entry that has stopped matching anything is worth failing on
        # too: it means the pull request landed and the promise above is now a lie.
        stale = sorted(prefix for prefix in PENDING_ALIAS_PATHS
                       if not any(rel.startswith(prefix) for rel in offenders))
        self.assertEqual(
            stale, [],
            'PENDING_ALIAS_PATHS names a path that no longer carries the alias; '
            'drop the entry now that its pull request has landed.'
        )

    def test_library_modules_do_not_bind_the_public_name_at_runtime(self) -> None:
        """Runtime sweep: importing the module must not expose the public name.

        The complement to the source-level check, and not redundant with it.
        This one is what notices a module that reaches the base through some
        other spelling -- ``Protocol = ProtocolBase``, a re-export, a
        ``globals()`` write -- rather than through an ``import ... as ...`` an
        AST walk can recognise.

        A module legitimately binds the public name when it imports the *public
        class itself*, so identity is what is asserted, not absence: the name
        may exist, it just may not be the base.

        """
        pending = tuple(rel.removesuffix('.py').replace('/', '.')
                        for rel in PENDING_ALIAS_PATHS)

        offenders = []
        for info in pkgutil.walk_packages(pcapkit.__path__, prefix='pcapkit.'):
            if info.name.startswith(pending) or info.name.startswith('pcapkit.vendor.'):
                continue
            module = __import__(info.name, fromlist=['__name__'])
            for base_name, public_name in BASE_TO_PUBLIC.items():
                base = globals()[base_name]
                bound = getattr(module, public_name, None)
                if bound is base:
                    offenders.append(f'{info.name}.{public_name} is {base_name}')

        self.assertEqual(
            offenders, [],
            'a module binds a public class name to the *Base class at runtime. '
            'C.f. #514.'
        )


class RegistrationGateTests(unittest.TestCase):
    """Only a subclass of the public class registers -- pinned, per suite."""

    def setUp(self) -> None:
        """Re-resolve every base/public pair and the ``Extractor`` singleton, fresh.

        GitHub issue #981: this module's own top-level ``from pcapkit... import
        Engine, EngineBase, ...`` binds whatever generation of those classes was
        live when *this module* was imported. A sibling test that purges
        ``pcapkit`` from :data:`sys.modules` and re-imports it --
        :func:`tests._support.purge_modules`, deliberately asymmetric; see its own
        docstring -- mints a new generation that :meth:`make_subclass` and
        :meth:`registry` would otherwise silently disagree about, because
        ``Dumper.__init_subclass__`` and ``Extractor.register_engine`` /
        ``register_reassembly`` / ``register_traceflow`` each re-import their own
        collaborators locally and so always see the *current* generation, not the
        one this module's import statement captured.

        :func:`tests.conftest.restore_module_table`'s autouse fixture reconciles
        the two generations back together after every test, but only under
        :program:`pytest` -- plain :mod:`unittest` loads no ``conftest`` at all, so
        the mismatch survives into this test. The fix is to never compare this
        module's own stale import against something that might be live-generation:
        :func:`importlib.import_module` here returns the module straight out of
        :data:`sys.modules` when nothing has reimported it (a no-op lookup, no
        reload) and the current generation when something has, so every
        comparison below is generation-consistent regardless of what ran earlier
        in this process.

        """
        engine_mod = importlib.import_module('pcapkit.foundation.engines.engine')
        reassembly_mod = importlib.import_module('pcapkit.foundation.reassembly.reassembly')
        traceflow_mod = importlib.import_module('pcapkit.foundation.traceflow.traceflow')
        dumper_mod = importlib.import_module('pcapkit.dumpkit.common')
        protocol_mod = importlib.import_module('pcapkit.protocols.protocol')
        self._extractor = importlib.import_module('pcapkit.foundation.extraction').Extractor

        #: ``(label, base, public, keyword, registry accessor)`` per suite,
        #: resolved fresh in :meth:`setUp` rather than carried as a class
        #: attribute -- see this method's own docstring. The protocols suite is
        #: absent on purpose: its name registry is ``pcapkit.protocols.__proto__``
        #: and its hook takes no registration keyword of this shape, so it is
        #: covered by :meth:`test_library_classes_are_not_descendants_of_the_public_class`
        #: and by ``tests/protocols/`` instead.
        self.SUITES = (
            ('engines', engine_mod.EngineBase, engine_mod.Engine, 'engine', 'ENGINE'),
            ('reassembly', reassembly_mod.ReassemblyBase, reassembly_mod.Reassembly,
             'protocol', 'REASSEMBLY'),
            ('traceflow', traceflow_mod.TraceFlowBase, traceflow_mod.TraceFlow,
             'protocol', 'TRACEFLOW'),
            ('dumpers', dumper_mod.DumperBase, dumper_mod.Dumper, 'fmt', 'OUTPUT'),
        )  # type: tuple[tuple[str, type, type, str, str], ...]

        #: ``(label, base, public)`` per suite, including ``protocols`` --
        #: :meth:`test_library_classes_are_not_descendants_of_the_public_class`'s
        #: own set, resolved the same fresh way for the same reason.
        self._descendant_pairs = (
            ('protocols', protocol_mod.ProtocolBase, protocol_mod.Protocol),
            ('engines', engine_mod.EngineBase, engine_mod.Engine),
            ('reassembly', reassembly_mod.ReassemblyBase, reassembly_mod.Reassembly),
            ('traceflow', traceflow_mod.TraceFlowBase, traceflow_mod.TraceFlow),
            ('dumpers', dumper_mod.DumperBase, dumper_mod.Dumper),
        )  # type: tuple[tuple[str, type, type], ...]

    def registry(self, which: 'str') -> 'dict[str, Any]':
        """The name-keyed registry for a suite.

        Args:
            which: suite tag from :attr:`SUITES`.

        Returns:
            The live registry mapping, not a copy.

        """
        return {
            'ENGINE': self._extractor.__engine__,
            'REASSEMBLY': self._extractor.__reassembly__,
            'TRACEFLOW': self._extractor.__traceflow__,
            'OUTPUT': self._extractor.__output__,
        }[which]

    def make_subclass(self, name: 'str', base: 'type', **kwargs: 'Any') -> 'type':
        """Create a subclass, restoring any registry key it adds.

        Args:
            name: name for the new class.
            base: the class to subclass.
            **kwargs: class keywords to pass at definition.

        Returns:
            The new class.

        """
        snapshots = [(tag, dict(self.registry(tag))) for _, _, _, _, tag in self.SUITES]

        def restore() -> 'None':
            for tag, before in snapshots:
                live = self.registry(tag)
                for key in set(live) - set(before):
                    del live[key]

        self.addCleanup(restore)
        return type(name, (base,), {}, **kwargs)

    def test_library_style_subclass_does_not_register(self) -> None:
        """``class X(Base)`` -- the library's own shape -- registers nothing."""
        for label, base, _, _, tag in self.SUITES:
            with self.subTest(suite=label):
                before = set(self.registry(tag))
                self.make_subclass(f'LibraryStyle_{label}', base)
                self.assertEqual(set(self.registry(tag)) - before, set())

    def test_library_style_subclass_cannot_opt_in_at_all(self) -> None:
        """``class X(Base, <keyword>=...)`` is a :exc:`TypeError`.

        This is the ``final`` substitute the split exists to provide, and it is
        the strongest assertion in this module: a library class cannot register
        itself *by accident or on purpose*, because the registration keyword
        never reaches a hook that understands it. The keyword falls through to
        :meth:`object.__init_subclass__`, which takes none.

        Asserting the exception rather than merely "no registry change" is what
        distinguishes this from the test above -- a silent no-op would satisfy
        that one and still leave the keyword looking supported.

        """
        for label, base, _, keyword, _ in self.SUITES:
            with self.subTest(suite=label):
                with self.assertRaises(TypeError):
                    self.make_subclass(f'LibraryOptIn_{label}', base,
                                       **{keyword: f'library_opt_in_{label}'})

    def test_user_style_subclass_does_not_register_without_the_keyword(self) -> None:
        """``class X(Public)`` alone still registers nothing. C.f. #547."""
        for label, _, public, _, tag in self.SUITES:
            with self.subTest(suite=label):
                before = set(self.registry(tag))
                self.make_subclass(f'UserStyle_{label}', public)
                self.assertEqual(set(self.registry(tag)) - before, set())

    def test_user_style_subclass_registers_when_it_opts_in(self) -> None:
        """``class X(Public, <keyword>=...)`` is the one shape that registers."""
        for label, _, public, keyword, tag in self.SUITES:
            with self.subTest(suite=label):
                key = f'user_opt_in_{label}'
                before = set(self.registry(tag))
                self.make_subclass(f'UserOptIn_{label}', public, **{keyword: key})
                self.assertEqual(set(self.registry(tag)) - before, {key})

    def test_library_classes_are_not_descendants_of_the_public_class(self) -> None:
        """No class shipped under :file:`pcapkit/` subclasses a public class.

        The invariant #514 settled, asserted over the library's own classes so
        that a subclass created by another test module cannot affect the result
        -- see this module's note on why ``descendants(Public)`` itself is not
        the thing to assert.

        """
        for label, base, public in self._descendant_pairs:
            with self.subTest(suite=label):
                found, pending = set(), [base]
                while pending:
                    for sub in pending.pop().__subclasses__():
                        if sub not in found:
                            found.add(sub)
                            pending.append(sub)

                offenders = sorted(
                    f'{cls.__module__}.{cls.__qualname__}' for cls in found
                    if cls is not public
                    and issubclass(cls, public)
                    and (cls.__module__ == 'pcapkit'
                         or cls.__module__.startswith('pcapkit.'))
                )
                self.assertEqual(
                    offenders, [],
                    f'a library class subclasses {public.__name__} and so '
                    f'auto-registers; library classes inherit '
                    f'{base.__name__}. C.f. #514.'
                )


if __name__ == '__main__':
    unittest.main()
