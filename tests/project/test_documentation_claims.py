# -*- coding: utf-8 -*-
"""Tests for documentation that states something checkable about the code.

Most of what #546 collected is prose, and prose cannot fail a test. These are the
parts that can, so that the specific defects it found cannot come back silently:

* ``no_eof`` was documented **backwards** on :class:`~pcapkit.foundation.extraction.Extractor`
  while :func:`~pcapkit.interface.core.extract` documented it correctly. Two
  docstrings for one parameter disagreed, and the flag is on the primary public
  entry point, so a caller reading the wrong one gets a non-terminating
  extraction. :class:`TestNoEOFDocumentedOnce` pins the two together *and* to the
  branch in the code that decides the behaviour, so a future edit to either
  docstring alone fails here rather than in somebody's capture loop.

* ``Extractor._flag_r`` was referenced by :mod:`pcapkit`'s own documentation but
  was the one flag missing from the ``if TYPE_CHECKING:`` block that documents
  its siblings, so the reference pointed at nothing.
  :class:`TestExtractorFlagsDocumented` asserts every flag the constructor
  assigns is declared, which is the general form of that defect.

#546's item 2 -- ``register_extractor_engine`` documenting a parameter named
``engine`` where the signature reads ``name`` -- is **not** tested here, because
:file:`tests/test_docstring_contract.py` already checks that property across the
whole of :mod:`pcapkit` and carried the defect as a :data:`KNOWN_DEFECTS` entry
reading "owned by the registry docstring change". Fixing it is therefore a
*deletion* from that tuple rather than a new test, and a second checker here would
only be a narrower copy of a better one.

Deliberately **not** tested here either: whether a Sphinx cross-reference
resolves. That is a property of the built inventory, not of the source, and the
honest check for it is a nitpicky ``sphinx-build`` -- some 20 minutes, and it needs
the docs toolchain installed. A unit test that re-implemented Sphinx's resolution
rules would pass while the real build failed, which is worse than not testing it.
The measured counts are recorded in the pull request instead.

"""

from __future__ import annotations

import ast
import inspect
import pathlib
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class TestNoEOFDocumentedOnce(unittest.TestCase):
    """``no_eof`` means "keep going", and both docstrings have to say so."""

    @staticmethod
    def _no_eof_line(doc: 'str | None') -> 'str':
        for line in (doc or '').splitlines():
            stripped = line.strip()
            if stripped.startswith('no_eof:'):
                return ' '.join(stripped.split())
        raise AssertionError('no no_eof entry found in docstring')

    def test_extractor_and_extract_agree(self) -> None:
        """The two public docstrings for ``no_eof`` say the same thing."""
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.interface.core import extract

        self.assertEqual(
            self._no_eof_line(inspect.getdoc(Extractor.__init__)),
            self._no_eof_line(inspect.getdoc(extract)),
            'Extractor.__init__ and extract() document no_eof differently; they '
            'are the same flag and disagreeing is how #546 arose',
        )

    def test_documented_sense_matches_the_code(self) -> None:
        """The docstring says "not raise", and the code continues on EOF.

        The behaviour is decided by an ``if`` on ``_flag_n`` with a ``continue``
        in its body, inside the ``except (EOFError, StopIteration)`` handler of
        ``record_frames``: the flag makes extraction *carry on*. So the
        documentation has to be phrased as suppressing the error, not as raising
        it.

        Note:
            The condition was a bare ``if self._flag_n:`` until #620, which is why
            this checks for the ``continue`` under a test *mentioning* the flag
            rather than for that exact line -- the flag now shares the condition
            with a termination check, since on its own it never stopped. That also
            means this test does not distinguish #620's defect from its fix: it
            pins the documented *sense* of the flag, not that the loop ends.
            :file:`tests/foundation/test_extraction_no_eof.py` pins the ending.

        """
        from pcapkit.foundation.extraction import Extractor

        line = self._no_eof_line(inspect.getdoc(Extractor.__init__))
        self.assertIn('not raise', line,
                      f'no_eof is documented as {line!r}, but the flag suppresses '
                      'the EOF stop rather than raising')

        tree = ast.parse(textwrap.dedent(inspect.getsource(Extractor.record_frames)))

        # Find the handler for EOFError and confirm it can `continue` on the flag.
        handlers = [node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)]
        eof_handlers = [
            h for h in handlers
            if h.type is not None and 'EOFError' in ast.unparse(h.type)
        ]
        self.assertTrue(eof_handlers, 'record_frames no longer handles EOFError')

        continues_on_flag = False
        for handler in eof_handlers:
            for node in ast.walk(handler):
                if (isinstance(node, ast.If)
                        and '_flag_n' in ast.unparse(node.test)
                        and any(isinstance(inner, ast.Continue) for inner in node.body)):
                    continues_on_flag = True
        self.assertTrue(
            continues_on_flag,
            'record_frames no longer continues on _flag_n when EOF is reached, so '
            'the documented sense of no_eof may have changed',
        )


class TestExtractorFlagsDocumented(unittest.TestCase):
    """Every ``_flag_*`` the constructor sets is a documented attribute."""

    @staticmethod
    def _parse_extraction() -> 'ast.ClassDef':
        path = ROOT / 'pcapkit' / 'foundation' / 'extraction.py'
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == 'Extractor':
                return node
        raise AssertionError('Extractor class not found in extraction.py')

    def test_assigned_flags_are_declared(self) -> None:
        """``self._flag_x = ...`` in ``__init__`` implies a ``_flag_x`` declaration.

        The declarations live in the class's ``if TYPE_CHECKING:`` block, each
        with a ``#:`` comment, and that is what Sphinx documents them from. A
        flag that is assigned but never declared is undocumented, and any
        ``:attr:`` reference to it is dead -- which is what happened to
        ``_flag_r``.

        """
        cls = self._parse_extraction()

        assigned = set()
        for node in ast.walk(cls):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == 'self'
                            and target.attr.startswith('_flag_')):
                        assigned.add(target.attr)

        declared = {
            node.target.id
            for node in ast.walk(cls)
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id.startswith('_flag_')
        }

        self.assertTrue(assigned, 'no _flag_* assignments found; the test has '
                                  'stopped checking anything')
        self.assertEqual(
            assigned - declared, set(),
            'these Extractor flags are assigned but not declared, so they are '
            f'undocumented: {sorted(assigned - declared)}',
        )


if __name__ == '__main__':
    unittest.main()
