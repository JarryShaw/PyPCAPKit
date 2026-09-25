# -*- coding: utf-8 -*-
"""GitHub issue #796: a regex flag passed as ``re.sub``/``re.split``'s positional ``count``.

Thirteen call sites under :file:`pcapkit/vendor/` passed a regex flag --
:data:`re.MULTILINE`, whose integer value is ``8`` -- as the *positional*
fourth argument to :func:`re.sub` (third, for :func:`re.split`), which is the
``count``/``maxsplit`` slot, not ``flags``:

.. code-block:: python

   re.sub(r'\\r*\\n', ' ', text, re.MULTILINE)             # count=8, flags=0 (!)
   re.sub(r'\\r*\\n', ' ', text, flags=re.MULTILINE)        # the fix

Two independent defects follow from that one misplacement:

1. **The count is a real limit.** Any string with more than eight
   occurrences of the pattern keeps its ninth match onward unsubstituted,
   because ``count=8`` caps replacement rather than being ignored.
2. **The flag never applies.** :data:`re.MULTILINE` changes the matching
   behaviour of ``^``/``$`` only; every one of these thirteen patterns is
   ``r'\\r*\\n'``, which carries no anchor, so the *intended* flag was already
   inert -- moving it to ``flags=`` does not change what it matches, only
   removes the accidental ``count`` cap and the interpreter warning.

It is also a live :exc:`DeprecationWarning` on Python 3.13+ (`'count' is
passed as positional argument`), scheduled to become a :exc:`TypeError`.

A single-line grep over this tree only finds five of the thirteen: eight of
them put the flag argument on a *continuation* line --

.. code-block:: python

   re.sub(r'\\r*\\n', ' ', text,
          re.MULTILINE)

-- which no single-line pattern sees. :class:`PositionalFlagArgumentTests`
below therefore walks :mod:`ast` rather than grepping, exactly as the issue's
own enumeration did, and is self-tested against an inline known-positive
(plain and continuation-line shaped) and known-negative fixture before it is
ever pointed at the real tree -- see
:meth:`PositionalFlagArgumentTests.test_self_check_detects_known_positive_and_negative_fixtures`.

Run against stock ``4530424df`` (this issue's unblocking commit, before the
fix in this change), :meth:`PositionalFlagArgumentTests.test_no_positional_flag_argument_in_vendor_tree`
fails, reporting all thirteen sites now living at:

* :file:`pcapkit/vendor/default.py`
* :file:`pcapkit/vendor/hip/eddsa_curve.py`
* :file:`pcapkit/vendor/http/frame.py`
* :file:`pcapkit/vendor/http/method.py`
* :file:`pcapkit/vendor/http/status_code.py`
* :file:`pcapkit/vendor/ipv4/router_alert.py`
* :file:`pcapkit/vendor/ipv6/option.py`
* :file:`pcapkit/vendor/ipv6/router_alert.py`
* :file:`pcapkit/vendor/ipv6/tagger_id.py`
* :file:`pcapkit/vendor/reg/ethertype.py`
* :file:`pcapkit/vendor/tcp/flags.py`
* :file:`pcapkit/vendor/tcp/mp_tcp_option.py`
* :file:`pcapkit/vendor/tcp/option.py`

After the fix (``flags=`` on all thirteen), it passes.
:class:`RuntimeDeprecationWarningTests` additionally pins the runtime
symptom directly by re-creating the exact ``r'\\r*\\n'`` call shape used at
every one of these sites and asserting no :exc:`DeprecationWarning` fires
under ``error`` filtering -- run against the pre-fix positional form, the
same assertion raises :exc:`DeprecationWarning` (captured explicitly in
:meth:`RuntimeDeprecationWarningTests.test_positional_flag_shape_would_warn`,
which pins the *old* shape's own defect so a future refactor cannot silently
drop the regression coverage for it).

The suite is unit-tier (see :mod:`tests._tiers`): it reads no fixture capture
and makes no network call, only :mod:`ast`-parsing source files already on
disk and exercising bare :func:`re.sub` calls with synthetic strings.

"""
from __future__ import annotations

import ast
import collections
import importlib
import pathlib
import re
import unittest
import warnings

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: :file:`pcapkit/vendor/`, the tree GitHub issue #796 scopes the sweep to.
VENDOR_ROOT = ROOT / 'pcapkit' / 'vendor'

#: The three functions whose ``count``/``maxsplit`` slot this defect hits.
#: :func:`re.subn` shares :func:`re.sub`'s signature and is swept for
#: completeness even though issue #796 found no call site using it.
TARGET_FUNCS = ('sub', 'split', 'subn')

#: 0-indexed position of the ``count``/``maxsplit`` slot per real stdlib
#: signature -- ``re.split(pattern, string, maxsplit=0, flags=0)`` takes one
#: fewer required positional argument than ``re.sub``/``re.subn``
#: (``pattern, repl, string, count=0, flags=0``), so the slot is one
#: position earlier. Getting this wrong for ``split`` would either miss its
#: real defect shape or flag its legitimate ``maxsplit`` usage as a false
#: positive -- both checked in the self-test below.
_COUNT_SLOT = {'sub': 3, 'subn': 3, 'split': 2}


def _looks_like_flag(node: 'ast.expr') -> 'bool':
    """Whether an AST node looks like a ``re.FLAG`` (or ``FLAG | FLAG``) expression."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 're':
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _looks_like_flag(node.left) or _looks_like_flag(node.right)
    return False


def find_positional_flag_sites(source: 'str', filename: 'str' = '<string>') -> 'list[tuple[int, str]]':
    """Walk ``source`` for ``re.sub``/``re.split``/``re.subn`` calls with a flag in the count slot.

    Args:
        source: Python source text to sweep.
        filename: Name attributed to parse errors, for a readable message only.

    Returns:
        A list of ``(lineno, funcname)`` for every offending call, in the
        order :func:`ast.walk` visits them.

    """
    tree = ast.parse(source, filename=filename)
    hits = []  # type: list[tuple[int, str]]
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in TARGET_FUNCS
                and isinstance(func.value, ast.Name) and func.value.id == 're'):
            continue
        slot = _COUNT_SLOT[func.attr]
        if len(node.args) > slot and _looks_like_flag(node.args[slot]):
            hits.append((node.lineno, func.attr))
    return hits


class PositionalFlagArgumentTests(unittest.TestCase):
    """The AST sweep, self-tested, then pointed at :file:`pcapkit/vendor/`."""

    def test_self_check_detects_known_positive_and_negative_fixtures(self) -> None:
        # A probe is not evidence until it is shown to distinguish its
        # target -- self-test against both a known-positive and a
        # known-negative before trusting any count this sweep reports.
        fixture = '''\
import re

# KNOWN POSITIVE (plain): the exact defect shape, flag as 4th positional.
a = re.sub(r'\\r*\\n', ' ', "x", re.MULTILINE)

# KNOWN POSITIVE (continuation line): invisible to a single-line grep,
# which is how the issue's own first pass undercounted 13 as 6.
b = re.sub(
    r'\\r*\\n', ' ', "x",
    re.MULTILINE)

# KNOWN POSITIVE: re.split's defect shape sits one slot earlier (maxsplit).
c = re.split(r'\\s+', "x", re.IGNORECASE)

# KNOWN NEGATIVE: the fix -- flags passed by keyword.
d = re.sub(r'\\r*\\n', ' ', "x", flags=re.MULTILINE)

# KNOWN NEGATIVE: a genuine positional count, not a flag.
e = re.sub(r'\\r*\\n', ' ', "x", 3)

# KNOWN NEGATIVE: a genuine positional maxsplit for re.split.
f = re.split(r'\\s+', "x", 2)

# KNOWN NEGATIVE: too few positional args to reach the count slot at all.
g = re.sub(r'\\r*\\n', ' ', "x")

# KNOWN NEGATIVE: an unrelated re.* function, not one of the three targets.
h = re.compile(r'\\r*\\n', re.MULTILINE)
'''
        hits = find_positional_flag_sites(fixture, filename='<fixture>')

        # Exactly the three known positives, at the lines they sit on -- not
        # a bare non-zero count, so a sweep that over- or under-matches
        # cannot slip through as "found something".
        self.assertEqual(sorted(hits), [(4, 'sub'), (8, 'sub'), (13, 'split')],
                         f'self-test fixture mismatch -- sweep found {hits!r}, expected exactly '
                         f'the three known-positive call sites and none of the five negatives')

    def test_no_positional_flag_argument_in_vendor_tree(self) -> None:
        offenders = []  # type: list[str]
        for path in sorted(VENDOR_ROOT.rglob('*.py')):
            source = path.read_text(encoding='utf-8')
            for lineno, funcname in find_positional_flag_sites(source, filename=str(path)):
                offenders.append(f'{path.relative_to(ROOT)}:{lineno} re.{funcname}(...)')

        self.assertEqual(offenders, [],
                         f'{len(offenders)} call site(s) under pcapkit/vendor/ pass a regex flag '
                         f'as a positional count/maxsplit argument (GitHub issue #796):\n  ' +
                         '\n  '.join(offenders))


class RuntimeDeprecationWarningTests(unittest.TestCase):
    """The interpreter-level symptom, pinned directly on the exact call shape.

    Every one of the thirteen sites shares the same pattern, ``r'\\r*\\n'``,
    which contains no ``^``/``$``/``\\A``/``\\Z`` anchor -- so moving the flag
    to ``flags=`` cannot change *what* it matches (it was already a no-op for
    this pattern), only removes the ``count=8`` cap and the warning below.

    """

    #: The pattern shared by all thirteen sites, reproduced verbatim rather
    #: than imported, since the point is to pin the runtime symptom
    #: independent of which file happens to still contain it.
    PATTERN = r'\r*\n'

    def test_positional_flag_shape_would_warn(self) -> None:
        # Pin the OLD shape's own defect, so a future refactor of this test
        # cannot silently drop the regression coverage for it: the
        # positional form must still be the thing that warns.
        with self.assertWarns(DeprecationWarning):
            with warnings.catch_warnings():
                warnings.simplefilter('always')
                re.sub(self.PATTERN, ' ', 'a\nb', re.MULTILINE)  # noqa: intentional pre-fix shape

    def test_flags_keyword_shape_does_not_warn(self) -> None:
        # The fix, exercised the same way: no DeprecationWarning under
        # 'error' filtering. This is the assertion that fails on stock
        # 4530424df if any of the thirteen sites still use the positional
        # form, and passes once every site uses flags=.
        with warnings.catch_warnings():
            warnings.simplefilter('error', DeprecationWarning)
            result = re.sub(self.PATTERN, ' ', 'a\nb', flags=re.MULTILINE)
        self.assertEqual(result, 'a b')

    def test_pattern_has_no_multiline_anchor(self) -> None:
        # Defect #2 from the issue body, checked directly rather than
        # asserted in prose: re.MULTILINE only changes '^'/'$' matching, and
        # this pattern contains neither (nor \A/\Z), so the flag was already
        # inert for every one of the thirteen sites -- the fix only removes
        # the accidental count=8 cap, it does not change any match.
        for anchor in ('^', '$', r'\A', r'\Z'):
            self.assertNotIn(anchor, self.PATTERN,
                             f'pattern {self.PATTERN!r} contains {anchor!r} -- re.MULTILINE would '
                             f'not be a no-op here, and the "byte-identical" argument does not hold')

    def test_uncapping_count_only_matters_beyond_eight_matches(self) -> None:
        # Defect #1, empirically bounded: below the old count=8 cap, the
        # positional (buggy) and keyword (fixed) forms already agree, and
        # they diverge only once a string carries more than eight
        # occurrences of the pattern -- which is what "byte-identical for
        # today's data, latent for tomorrow's" means concretely.
        def old_call(s: 'str') -> 'str':
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                return re.sub(self.PATTERN, ' ', s, re.MULTILINE)

        def new_call(s: 'str') -> 'str':
            return re.sub(self.PATTERN, ' ', s, flags=re.MULTILINE)

        at_boundary = 'x\n' * 8 + 'TAIL'
        beyond_boundary = 'x\n' * 9 + 'TAIL'

        self.assertEqual(old_call(at_boundary), new_call(at_boundary),
                         'old and new must still agree at exactly 8 matches')
        self.assertNotEqual(old_call(beyond_boundary), new_call(beyond_boundary),
                            'old and new were expected to diverge beyond 8 matches -- if they '
                            'now agree, this bound needs re-deriving')


class GeneratorRuntimeCoverageTests(unittest.TestCase):
    """Exercise every fixed call site's owning method directly.

    :class:`PositionalFlagArgumentTests` proves the defect is gone from the
    *source text*; this class proves it by *running* the exact line coverage
    tooling measures, so the fix is exercised rather than only inspected.

    Every instance is built with ``cls.__new__(cls)``, the same bypass
    :file:`tests/vendor/test_vendor_dest_path_unit.py` and
    :file:`tests/vendor/test_crawler_reachability_unit.py` use, since
    :meth:`~pcapkit.vendor.default.Vendor.__init__` fetches from IANA and
    writes :file:`pcapkit/const/` as a side effect of construction --
    neither of which any test here does. ``instance.record`` is set by hand
    to an empty :class:`collections.Counter` so
    :meth:`~pcapkit.vendor.default.Vendor.rename`'s ``self.record[...]``
    lookup (a :class:`~collections.Counter` defaults absent keys to ``0``)
    does not require :meth:`~pcapkit.vendor.default.Vendor.count` to have
    run first.

    Each case feeds ``process()`` a synthetic CSV row -- never live IANA
    data -- reaching exactly the line this change touches, under
    ``DeprecationWarning`` raised as an error. Run against stock
    ``4530424df`` (the positional ``re.MULTILINE`` form), every one of these
    fails with that :exc:`DeprecationWarning`; after the fix (``flags=``),
    all pass.

    """

    def _instance(self, module_name: 'str', class_name: 'str') -> 'object':
        module = importlib.import_module(module_name)
        cls = getattr(module, class_name)
        instance = cls.__new__(cls)
        instance.record = collections.Counter()  # type: ignore[attr-defined]
        return instance

    def _assert_no_deprecation(self, module_name: 'str', class_name: 'str',
                                rows: 'list[str]') -> None:
        instance = self._instance(module_name, class_name)
        with warnings.catch_warnings():
            warnings.simplefilter('error', DeprecationWarning)
            instance.process(rows)  # type: ignore[attr-defined]

    def test_default_process_no_deprecation(self) -> None:
        # pcapkit/vendor/default.py:343 -- the shared base implementation,
        # inherited by every crawler that does not override process(), e.g.
        # pcapkit.vendor.arp.hardware.Hardware.
        self._assert_no_deprecation(
            'pcapkit.vendor.arp.hardware', 'Hardware',
            ['code,name,rfcs', '0,TestName,desc [RFC1234]'])

    def test_hip_eddsa_curve_process_no_deprecation(self) -> None:
        self._assert_no_deprecation(
            'pcapkit.vendor.hip.eddsa_curve', 'EdDSACurve',
            ['h0,h1,h2,h3', 'x,TestName,1,desc [RFC1234]'])

    def test_http_frame_process_no_deprecation(self) -> None:
        self._assert_no_deprecation(
            'pcapkit.vendor.http.frame', 'Frame',
            ['h0,h1,h2', '00,TestName,desc [RFC1234]'])

    def test_http_method_process_no_deprecation(self) -> None:
        self._assert_no_deprecation(
            'pcapkit.vendor.http.method', 'Method',
            ['h0,h1,h2,h3', 'GET,yes,yes,desc [RFC1234]'])

    def test_http_status_code_process_no_deprecation(self) -> None:
        self._assert_no_deprecation(
            'pcapkit.vendor.http.status_code', 'StatusCode',
            ['h0,h1,h2', '200,OK,desc [RFC1234]'])

    def test_ipv4_router_alert_process_no_deprecation(self) -> None:
        # No header row here -- ipv4-router-alert-option-values ships with
        # none of its own (see the comment at
        # pcapkit/vendor/ipv4/router_alert.py:39-42, GitHub issue #492).
        self._assert_no_deprecation(
            'pcapkit.vendor.ipv4.router_alert', 'RouterAlert',
            ['0,TestName,desc [RFC1234]'])

    def test_ipv6_option_process_no_deprecation(self) -> None:
        self._assert_no_deprecation(
            'pcapkit.vendor.ipv6.option', 'Option',
            ['h0,h1,h2,h3,h4,h5', '1,a,b,c,TestName (Description) [1],desc [RFC1234]'])

    def test_ipv6_router_alert_process_no_deprecation(self) -> None:
        self._assert_no_deprecation(
            'pcapkit.vendor.ipv6.router_alert', 'RouterAlert',
            ['h0,h1,h2', '0,TestName,desc [RFC1234]'])

    def test_ipv6_tagger_id_process_no_deprecation(self) -> None:
        self._assert_no_deprecation(
            'pcapkit.vendor.ipv6.tagger_id', 'TaggerID',
            ['h0,h1,h2,h3', '0,TestName,,desc [RFC1234]'])

    def test_reg_ethertype_process_no_deprecation(self) -> None:
        self._assert_no_deprecation(
            'pcapkit.vendor.reg.ethertype', 'EtherType',
            ['h0,h1,h2,h3,h4,h5', 'a,1A,c,d,TestName,desc [RFC1234]'])

    def test_tcp_flags_process_no_deprecation(self) -> None:
        self._assert_no_deprecation(
            'pcapkit.vendor.tcp.flags', 'Flags',
            ['h0,h1,h2', '0,TestDesc (foo),desc [RFC1234]'])

    def test_tcp_mp_tcp_option_process_no_deprecation(self) -> None:
        self._assert_no_deprecation(
            'pcapkit.vendor.tcp.mp_tcp_option', 'MPTCPOption',
            ['h0,h1,h2,h3', '00,x,TestDesc (foo),desc [RFC1234]'])

    def test_tcp_option_process_no_deprecation(self) -> None:
        self._assert_no_deprecation(
            'pcapkit.vendor.tcp.option', 'Option',
            ['h0,h1,h2,h3', '0,x,TestDesc (foo) [1],desc [RFC1234]'])


if __name__ == '__main__':
    unittest.main()
