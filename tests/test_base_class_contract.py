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

The sweep is complete but the migration is not: 28 of the 82 sites are renamed,
and the other 54 sit in paths that open pull requests own -- see
:data:`PENDING_ALIAS_PATHS`, which is the whole of the remaining work and
shrinks to nothing as those land. The four non-``protocols`` families
(``Engine`` 8 sites, ``Reassembly`` 3, ``Dumper`` 2, ``TraceFlow`` 2) are
finished; every one of the 54 outstanding is a ``ProtocolBase`` site.

:class:`RegistrationGateTests` is a regression pin, not a new behaviour. Every
assertion in it already held before part (c), because parts (a) and (b)
(issues #547 and #570) made registration opt-in on a keyword. It is written down
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

"""
from __future__ import annotations

import ast
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
#: cannot sit here unnoticed once its pull request merges.
PENDING_ALIAS_PATHS = {
    'pcapkit/protocols/': 726,
    'pcapkit/foundation/registry/protocols.py': 726,
    'pcapkit/foundation/extraction.py': 742,
    'pcapkit/foundation/traceflow/traceflow.py': 742,
}


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

    #: ``(label, base, public, keyword, registry accessor)`` per suite. The
    #: protocols suite is absent on purpose: its name registry is
    #: ``pcapkit.protocols.__proto__`` and its hook takes no registration
    #: keyword of this shape, so it is covered by
    #: :meth:`test_library_classes_are_not_descendants_of_the_public_class` and
    #: by ``tests/protocols/`` instead.
    SUITES = (
        ('engines', EngineBase, Engine, 'engine', 'ENGINE'),
        ('reassembly', ReassemblyBase, Reassembly, 'protocol', 'REASSEMBLY'),
        ('traceflow', TraceFlowBase, TraceFlow, 'protocol', 'TRACEFLOW'),
        ('dumpers', DumperBase, Dumper, 'fmt', 'OUTPUT'),
    )

    @staticmethod
    def registry(which: 'str') -> 'dict[str, Any]':
        """The name-keyed registry for a suite.

        Args:
            which: suite tag from :attr:`SUITES`.

        Returns:
            The live registry mapping, not a copy.

        """
        return {
            'ENGINE': Extractor.__engine__,
            'REASSEMBLY': Extractor.__reassembly__,
            'TRACEFLOW': Extractor.__traceflow__,
            'OUTPUT': Extractor.__output__,
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
        for label, base, public in (('protocols', ProtocolBase, Protocol),
                                    ('engines', EngineBase, Engine),
                                    ('reassembly', ReassemblyBase, Reassembly),
                                    ('traceflow', TraceFlowBase, TraceFlow),
                                    ('dumpers', DumperBase, Dumper)):
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
