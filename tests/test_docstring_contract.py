# -*- coding: utf-8 -*-
"""Every ``Args:`` name and ``Raises:`` clause, checked against the code itself.

GitHub issue #501 fixed one wrong exception name and forty stale ``Args:``
labels by hand. Issue #519 then showed the class was not exhausted -- more
phantom ``Raises:`` clauses and more ``Args:`` entries naming parameters that do
not exist -- because nothing in the suite *derives* the answer from the code.
A docstring label is not executed, so no existing test could notice that
:meth:`Frame.register <pcapkit.protocols.misc.pcap.frame.Frame.register>`
documented a ``module`` argument it does not accept.

That is what this module closes, the same way
:file:`tests/protocols/test_dispatch_registry_unit.py` closed the dispatch-table
gap: the checks walk every function under :file:`pcapkit/` and compare each
docstring against the real signature and the real ``raise`` statements, so a
docstring written tomorrow is checked tomorrow rather than being a snapshot of
what was wrong in 2026.

Three properties are asserted, and the split between them is deliberate --
each is sound on its own, and the softer judgements are recorded rather than
asserted:

:meth:`DocstringParameterTests.test_documented_parameters_exist`
    A documented name that is not a parameter *and* has no ``**kwargs`` to
    absorb it is a guaranteed :exc:`TypeError` at call time. No intent needs to
    be guessed: ``Frame.register(code=..., module=...)`` simply fails. This is
    the invariant with no false positives, so it is the one asserted hardest.

:meth:`DocstringParameterTests.test_section_headers_are_not_swallowed`
    A napoleon section header indented *inside* the parameter block is parsed
    by napoleon as a parameter entry, so ``Returns:`` over-indented by four
    spaces renders as ``:param Returns:`` **and the return documentation
    disappears from the rendered page**. Sphinx reports nothing.

:meth:`DocstringRaisesTests.test_documented_exceptions_are_reachable`
    An exception documented by a function that cannot raise it. The check is
    deliberately conservative -- see :func:`_reachable` -- because a false
    positive here would make the suite fail on a correct docstring, which is
    worse than missing one.

Why a documented name may legitimately be absent from the signature, which is
the trap this module has to avoid: this project documents keyword arguments
consumed from ``**kwargs``, and does so correctly.
:meth:`Protocol.__init__ <pcapkit.protocols.protocol.Protocol.__init__>`
documents ``_layer`` and ``_protocol`` and really does read them
(``kwargs.pop('_layer', None)``), and :meth:`Frame.unpack
<pcapkit.protocols.misc.pcap.frame.Frame.unpack>` documents ``\\_seek_set`` as
"forwarded to :meth:`self.read <read>` through ``**kwargs``", which is exactly
true. Deleting either would destroy real documentation, so the presence of
``**kwargs`` exonerates a name here and those cases are excluded by
construction rather than by being listed.

:meth:`Raw.__post_init__ <pcapkit.protocols.misc.raw.Raw.__post_init__>` shows
how sharp that trap is, and it caught a reviewing scanner during this change.
It documents ``error`` and ``alias``, has neither in its signature, and its body
assigns a *local* ``alias`` from ``self._info.protocol.name`` -- which reads
exactly like a docstring naming a parameter that does not exist. It is not:
``__post_init__`` forwards ``**kwargs`` to :meth:`~pcapkit.protocols.misc.raw.Raw.unpack`,
which dispatches to :meth:`Raw.read <pcapkit.protocols.misc.raw.Raw.read>`, and
``read`` declares both as keyword-only parameters and uses them. The local
variable merely shares a name with the keyword. A checker that reported this
would be asking for correct documentation to be deleted, which is the outcome
the ``**kwargs`` exclusion exists to prevent.

That exclusion has a known cost, recorded so it is not mistaken for coverage.
:meth:`Reassembly.__init_subclass__
<pcapkit.foundation.reassembly.reassembly.Reassembly.__init_subclass__>` and
:meth:`TraceFlow.__init_subclass__
<pcapkit.foundation.traceflow.traceflow.TraceFlow.__init_subclass__>` both
document ``name`` where the parameter is ``protocol``, and both have
``**kwargs``, so both are invisible here even though their bodies use
``protocol`` and never read ``kwargs['name']``. Catching those needs the intent
behind a keyword, not just its absence from the signature -- ``src_ip`` and
``dst_ip`` on :meth:`IPv6_Route.__post_init__
<pcapkit.protocols.internet.ipv6_route.IPv6_Route.__post_init__>` look
identical and are very likely legitimate keywords forwarded to ``super()``.
Guessing between the two would fail correct docstrings, so this module does not
guess.

Note the RST escape in that last one. ``\\_seek_set`` is written with a
backslash so Sphinx does not read the leading underscore as emphasis, which is
why :func:`_documented_names` normalises ``\\_`` before comparing: a plain
string match drops that entry and then reports a defect that is not there.

:data:`KNOWN_DEFECTS` carries the findings this change did not fix, each with
the reason. :meth:`DocstringParameterTests.test_known_defects_are_still_defects`
asserts every one of them still reproduces, so the list cannot rot -- when the
owning change lands, that test fails and the entry has to be removed rather
than sitting there forever describing a bug that is gone.

That is not a hypothetical. The list was written against ``980e52f0c`` and had
an entry for ``pcapkit/vendor/ipx/socket.py``'s ``process``, which documented
``data`` where the parameter was ``soup``. Rebasing this change onto
``c8fd97bcd`` picked up #511, which retired the HTML scrape and renamed that
parameter to ``data`` as a side effect -- so the defect was gone, and this test
failed on exactly that subtest and nothing else. The entry was removed. Worth
knowing that the failure is reported through :meth:`~unittest.TestCase.subTest`,
and ``pytest-subtests`` is not a dependency here, so pytest prints the parent
test as ``PASSED`` while exiting non-zero: read the exit code, not the summary
line.

Everything here reads :file:`pcapkit/` source and imports nothing but the
standard library, so it reads no capture under :file:`examples/captures/` and
belongs to the unit tier.

"""
from __future__ import annotations

import ast
import pathlib
import unittest
from typing import TYPE_CHECKING, NamedTuple

from tests._tiers import ROOT

if TYPE_CHECKING:
    from typing import Iterator, Optional

#: Package whose docstrings are checked.
PACKAGE = ROOT / 'pcapkit'

#: Napoleon headers that open a parameter block. ``Args`` is the house
#: spelling, but ``Arguments`` is used 200-odd times and ``Parameters`` and
#: ``Keyword Args`` a handful more, and a checker that matched only ``Args``
#: would silently skip every one of them -- which is how a census of this
#: class undercounts by a tenth.
PARAM_SECTIONS = frozenset({
    'Args', 'Arguments', 'Parameters', 'Keyword Args', 'Keyword Arguments',
})

#: Every other napoleon section header. Used twice: to stop a parameter block
#: at the next section, and to notice one that has been indented *into* the
#: parameter block by mistake.
OTHER_SECTIONS = frozenset({
    'Attributes', 'Example', 'Examples', 'Note', 'Notes', 'Raises',
    'References', 'Return', 'Returns', 'See Also', 'Todo', 'Warning',
    'Warnings', 'Warns', 'Yield', 'Yields',
})


class Finding(NamedTuple):
    """One docstring defect, keyed so it survives the lines moving."""

    #: Path relative to the repository root, e.g. ``pcapkit/vendor/ipx/packet.py``.
    module: 'str'
    #: The function's own name, not its qualified name -- ``ast`` gives this
    #: cheaply and it is unique enough within a module to identify the site.
    function: 'str'
    #: The documented name, or the swallowed section header, or the exception.
    subject: 'str'


class Known(NamedTuple):
    """A :class:`Finding` left unfixed, and why."""

    finding: 'Finding'
    #: Why it is still here. A bare list of defects rots into a list of
    #: things nobody remembers; the reason is what makes an entry reviewable.
    reason: 'str'


#: Defects this change deliberately left alone, every one because the file
#: belongs to another concurrent change and editing it would silently discard
#: that work. The corrections are recorded in the issue thread; nothing here
#: is a claim that the docstring is right.
KNOWN_DEFECTS = (
    Known(Finding('pcapkit/foundation/registry/foundation.py',
                  'register_extractor_engine', 'engine'),
          "documents 'engine' where the parameter is 'name'; owned by the "
          'registry docstring change'),
    Known(Finding('pcapkit/protocols/internet/ipv4.py',
                  '_make_ipv4_options', 'option'),
          "documents 'option' where the parameter is 'options'; ipv4.py is "
          'owned by another change'),
    Known(Finding('pcapkit/vendor/ipx/packet.py', 'process', 'data'),
          "documents 'data' where the parameter is 'soup'; pcapkit/vendor is "
          'generated-adjacent and owned elsewhere. Note the sibling '
          'pcapkit/vendor/ipx/socket.py carried the identical defect and no '
          'longer does, so that umbrella covers the file rather than the '
          'directory -- see the module docstring'),
    Known(Finding('pcapkit/vendor/mh/binding_ack_flag.py', 'context', 'soup'),
          "documents 'soup: Parsed HTML source.' where the parameter is 'data' "
          "and holds CSV rows. Nothing was renamed here despite the "
          '``# pylint: disable=arguments-renamed`` pragma -- the parameter '
          'matches the base ``Vendor.context(self, data)`` in '
          'pcapkit/vendor/default.py:288, which documents it as '
          "'data: CSV data.'. The line was copy-pasted from a sibling whose "
          "process()/context() really does take 'soup', so both the name and "
          'the description are wrong'),
    Known(Finding('pcapkit/vendor/mh/binding_update_flag.py', 'context', 'soup'),
          "documents 'soup' where the parameter is 'data'"),
    Known(Finding('pcapkit/vendor/mh/handover_ack_flag.py', 'context', 'soup'),
          "documents 'soup' where the parameter is 'data'"),
    Known(Finding('pcapkit/vendor/mh/handover_initiate_flag.py', 'context', 'soup'),
          "documents 'soup' where the parameter is 'data'"),
    Known(Finding('pcapkit/vendor/pcapng/option_type.py', 'context', 'data'),
          "documents 'data: CSV data.' where the parameter is 'soup' and holds "
          'parsed HTML -- the name and the description are both wrong'),
    Known(Finding('pcapkit/vendor/vlan/priority_level.py', 'process', 'data'),
          "documents 'data' where the parameter is 'soup'"),
)

#: Swallowed section headers left unfixed, for the same ownership reason.
KNOWN_SWALLOWED = (
    Known(Finding('pcapkit/protocols/internet/ipv4.py', '_make_opt_e_sec', 'Returns'),
          'the ``Returns:`` header is indented into the ``Args:`` block, so '
          'napoleon renders ``:param Returns:`` and drops the return '
          'documentation; ipv4.py is owned by another change'),
)


def _header(line: 'str') -> 'Optional[str]':
    """The section name ``line`` opens, or :obj:`None`."""
    stripped = line.strip()
    return stripped[:-1].strip() if stripped.endswith(':') else None


def _documented_names(doc: 'str') -> 'tuple[list[tuple[str, bool]], list[str]]':
    """Parameter entries and swallowed section headers in ``doc``.

    Returns a list of ``(name, was_given_an_explicit_type)`` pairs and a list
    of section headers found at entry depth.

    Indentation is measured relative to the section header rather than against
    a fixed column, because the absolute column depends on how deeply the
    function is nested: a module-level function carries ``Args:`` at four
    spaces and its entries at eight, a method carries them at eight and twelve.
    A checker keyed on the absolute column matches one and silently skips the
    other.

    It is *not* for the reason an earlier draft of this docstring gave, which
    said ``__doc__`` is dedented at compile time so the source and runtime
    columns differ. That is true of ``__doc__`` and irrelevant here, because
    :func:`functions` reads ``ast.get_docstring(node, clean=False)``, which
    preserves the raw source indentation. Measured on 3.14.7 for a method whose
    ``Args:`` sits at eight spaces::

        get_docstring(clean=False)  ->  indents [0, 8, 12, 12]
        get_docstring(clean=True)   ->  indents [0, 0,  4,  4]
        compiled __doc__            ->  indents [0, 0,  4,  4]

    So this module never sees the dedented form at all. The relative
    measurement is right, but for the nesting reason above rather than that
    one -- recorded because a wrong rationale in a checker for wrong
    rationales is worth correcting explicitly.

    """
    lines = doc.splitlines()
    names = []  # type: list[tuple[str, bool]]
    swallowed = []  # type: list[str]
    index = 0
    while index < len(lines):
        if _header(lines[index]) not in PARAM_SECTIONS:
            index += 1
            continue
        base = len(lines[index]) - len(lines[index].lstrip())
        index += 1
        while index < len(lines):
            line = lines[index]
            if not line.strip():
                index += 1
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= base:
                break
            if indent == base + 4 and ':' in line:
                label = line.split(':', 1)[0].strip()
                if label in OTHER_SECTIONS:
                    swallowed.append(label)
                    index += 1
                    continue
                # ``\_seek_set`` is the RST escape for a leading underscore.
                name = label.replace('\\_', '_')
                typed = name.endswith(')') and '(' in name
                if typed:
                    name = name.split('(')[0].strip()
                name = name.lstrip('*')
                if name and ' ' not in name:
                    names.append((name, typed))
            index += 1
    return names, swallowed


def _documented_exceptions(doc: 'str') -> 'list[str]':
    """Exception names in ``doc``'s ``Raises:`` section."""
    lines = doc.splitlines()
    found = []  # type: list[str]
    index = 0
    while index < len(lines):
        if _header(lines[index]) != 'Raises':
            index += 1
            continue
        base = len(lines[index]) - len(lines[index].lstrip())
        index += 1
        while index < len(lines):
            line = lines[index]
            if not line.strip():
                index += 1
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= base:
                break
            if indent == base + 4 and ':' in line:
                name = line.split(':', 1)[0].strip()
                if name and ' ' not in name:
                    found.append(name.rsplit('.', 1)[-1])
            index += 1
    return found


def functions() -> 'Iterator[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef, str]]':
    """Every documented function under :file:`pcapkit/`, with its module path."""
    for path in sorted(PACKAGE.rglob('*.py')):
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'), str(path))
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
            continue
        relative = path.relative_to(ROOT).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            doc = ast.get_docstring(node, clean=False)
            if doc:
                yield relative, node, doc


def _raised_names(node: 'ast.AST') -> 'set[str]':
    """Exception names raised directly in ``node``'s body.

    Two limits, both measured rather than assumed, and both able only to *miss*
    a phantom -- neither can fail a correct docstring:

    * Only :class:`ast.Name` and :class:`ast.Attribute` raise targets are
      resolved, so a computed ``raise REGISTRY[code]`` would register neither as
      a matching raise nor, in :func:`_calls_anything_callable`, as a call.
      Currently inert: across ``pcapkit/`` the 858 raise targets break down as
      856 ``Name`` and 2 ``Attribute``, and **no** ``Subscript``.
    * :func:`ast.walk` descends into nested ``def``\\ s, so a ``raise`` inside a
      local helper is attributed to the function enclosing it. 11 documented
      functions contain a nested ``def`` and 3 of those raise inside it.

    That second one reads like a bug and is in fact the right answer here, which
    is why it is left alone. In all three cases the nested ``def`` is a local
    helper the enclosing body actually calls, so the exception really does
    propagate out of the enclosing function: :meth:`HIP._read_param_locator_set
    <pcapkit.protocols.internet.hip.HIP._read_param_locator_set>` documents
    ``ProtocolError`` and raises none itself, but its ``_read_locator`` helper
    does and it calls that helper once per locator. Attributing the raise
    outward is therefore correct, and the clause is not a phantom. It would only
    mislead for a nested ``def`` that is *returned* rather than called, which
    this package does not currently do.

    """
    raised = set()  # type: set[str]
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Raise) or sub.exc is None:
            continue
        exc = sub.exc
        if isinstance(exc, ast.Call):
            exc = exc.func
        if isinstance(exc, ast.Name):
            raised.add(exc.id)
        elif isinstance(exc, ast.Attribute):
            raised.add(exc.attr)
    return raised


def _calls_anything_callable(node: 'ast.AST') -> 'bool':
    """Whether the body calls a method or free function that could raise.

    Data-model construction is excluded: this project's ``_read_*`` methods
    build :class:`~pcapkit.corekit.infoclass.Info` subclasses whose names begin
    ``Data_`` or ``Schema_``, and neither those nor :meth:`Info.__update__` can
    raise a protocol error -- ``ProtocolError`` appears nowhere in
    :file:`pcapkit/corekit/` outside one comment. Anything else counts as
    possibly-raising, which is what keeps :func:`_reachable` conservative.

    """
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        else:  # pragma: no cover
            continue
        if name.startswith(('Data_', 'Schema_')):
            continue
        if name in ('bool', 'int', 'str', 'bytes', 'len', 'tuple', 'list',
                    'dict', 'set', 'cast', 'warn', '__update__'):
            continue
        return True
    return False


def _reachable(node: 'ast.AST', exception: 'str') -> 'bool':
    """Whether ``exception`` might be raised from ``node``.

    Answers "might", not "is": :obj:`True` is returned whenever the body calls
    anything whose own body is not inspected here, so the only way to get
    :obj:`False` is a body that raises nothing and calls nothing but data-model
    construction. Every phantom this catches is therefore a function whose
    whole body is visible, which is the case that needs no interprocedural
    analysis to settle -- and a docstring is never failed on a guess.

    """
    raised = _raised_names(node)
    if exception in raised or 'Exception' in raised:
        return True
    if any(isinstance(sub, ast.Raise) and sub.exc is None for sub in ast.walk(node)):
        return True  # bare ``raise`` re-raises whatever was caught
    return _calls_anything_callable(node)


def parameter_defects() -> 'list[Finding]':
    """Documented names that are not parameters and have no ``**kwargs``."""
    defects = []  # type: list[Finding]
    for module, node, doc in functions():
        args = node.args
        real = {arg.arg for arg in (args.posonlyargs + args.args + args.kwonlyargs)}
        if args.vararg:
            real.add(args.vararg.arg)
        if args.kwarg:
            # ``**kwargs`` absorbs any keyword, so a name that is missing from
            # the signature may still be a keyword this function or one it
            # forwards to really consumes. Not decidable here, and wrongly
            # failing a correct docstring is the worse error.
            continue
        seen = set()  # type: set[str]
        for name, _ in _documented_names(doc)[0]:
            if name in real or name in ('self', 'cls') or name in seen:
                continue
            seen.add(name)
            defects.append(Finding(module, node.name, name))
    return defects


def swallowed_headers() -> 'list[Finding]':
    """Section headers indented inside a parameter block."""
    return [Finding(module, node.name, label)
            for module, node, doc in functions()
            for label in _documented_names(doc)[1]]


def unreachable_exceptions() -> 'list[Finding]':
    """Documented exceptions the function demonstrably cannot raise."""
    return [Finding(module, node.name, exception)
            for module, node, doc in functions()
            for exception in _documented_exceptions(doc)
            if not _reachable(node, exception)]


class DocstringParameterTests(unittest.TestCase):
    """``Args:`` entries against the real signatures."""

    def test_documented_parameters_exist(self) -> 'None':
        """No function documents a parameter it cannot accept.

        Restricted to functions without ``**kwargs``, where passing the
        documented name is a guaranteed :exc:`TypeError` and no intent has to
        be inferred.

        """
        allowed = {known.finding for known in KNOWN_DEFECTS}
        unexpected = [finding for finding in parameter_defects() if finding not in allowed]
        self.assertEqual(unexpected, [], '\n'.join(
            ['%d docstring(s) name a parameter that does not exist:' % len(unexpected)]
            + ['  %s  %s() documents %r' % finding for finding in unexpected]))

    def test_section_headers_are_not_swallowed(self) -> 'None':
        """No napoleon section header sits inside a parameter block.

        An over-indented ``Returns:`` renders as ``:param Returns:`` and the
        return documentation is lost from the page without any warning.

        """
        allowed = {known.finding for known in KNOWN_SWALLOWED}
        unexpected = [finding for finding in swallowed_headers() if finding not in allowed]
        self.assertEqual(unexpected, [], '\n'.join(
            ['%d section header(s) indented into a parameter block:' % len(unexpected)]
            + ['  %s  %s() swallowed %r' % finding for finding in unexpected]))

    def test_known_defects_are_still_defects(self) -> 'None':
        """Every :data:`KNOWN_DEFECTS` entry still reproduces.

        This is what stops the list rotting. When the change that owns one of
        these files corrects the docstring, this test fails and the entry must
        be deleted -- rather than staying here describing a bug that is gone
        and quietly excusing a new one that is not.

        """
        for group, finder in ((KNOWN_DEFECTS, parameter_defects),
                              (KNOWN_SWALLOWED, swallowed_headers)):
            current = set(finder())
            for known in group:
                with self.subTest(entry=known.finding):
                    self.assertIn(known.finding, current,
                                  'fixed, so remove this entry -- %s' % known.reason)


class DocstringRaisesTests(unittest.TestCase):
    """``Raises:`` clauses against the real ``raise`` statements."""

    def test_documented_exceptions_are_reachable(self) -> 'None':
        """No function documents an exception it cannot raise."""
        unexpected = unreachable_exceptions()
        self.assertEqual(unexpected, [], '\n'.join(
            ['%d phantom Raises: clause(s):' % len(unexpected)]
            + ['  %s  %s() documents %r' % finding for finding in unexpected]))

    def test_commented_out_raise_leaves_no_clause_behind(self) -> 'None':
        """A commented-out ``raise`` never keeps its ``Raises:`` clause.

        :meth:`HTTP._read_http_none
        <pcapkit.protocols.application.httpv2.HTTP._read_http_none>` is where
        this went wrong: the ``raise ProtocolError(...)`` was commented out and
        replaced by a :class:`~pcapkit.utilities.warnings.ProtocolWarning`,
        and the ``Raises:`` clause stayed. Downgrading a raise to a warning is
        a deliberate act, so the docstring beside it gets checked.

        This check is not redundant with
        :meth:`DocstringRaisesTests.test_documented_exceptions_are_reachable`,
        and ``_read_http_none`` is precisely the case that proves it. Of the six
        phantom clauses #519 counted, that reachability check finds only five:
        ``_read_http_none``'s body opens ``if any(header.flags):``, and ``any``
        is not in :func:`_calls_anything_callable`'s inert-call list, so the
        function is judged possibly-raising and is never reported. Widening that
        list until it caught this one would be the wrong fix -- every name added
        to it is a promise that nothing behind that name raises, which is how a
        conservative checker turns into one that fails correct docstrings. The
        commented-out ``raise`` is much stronger evidence than the absence of a
        live one, so it gets its own assertion. Delete either test and one of
        the six stops being covered.

        """
        stale = []  # type: list[str]
        for path in sorted(PACKAGE.rglob('*.py')):
            lines = path.read_text(encoding='utf-8').splitlines()
            commented = {}  # type: dict[int, str]
            for number, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped.startswith('#'):
                    continue
                body = stripped.lstrip('#').strip()
                if body.startswith('raise ') and '(' in body:
                    commented[number] = body[len('raise '):].split('(')[0].strip()
            if not commented:
                continue
            relative = path.relative_to(ROOT).as_posix()
            tree = ast.parse('\n'.join(lines), str(path))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                doc = ast.get_docstring(node, clean=False)
                if not doc:
                    continue
                end = getattr(node, 'end_lineno', node.lineno)
                documented = set(_documented_exceptions(doc))
                for number, exception in commented.items():
                    if not node.lineno <= number <= end:
                        continue
                    if exception in documented and exception not in _raised_names(node):
                        stale.append('%s:%d  %s() documents %r but its only '
                                     'raise is commented out'
                                     % (relative, number, node.name, exception))
        self.assertEqual(stale, [], '\n'.join(['stale clause(s):'] + stale))


if __name__ == '__main__':
    unittest.main()
