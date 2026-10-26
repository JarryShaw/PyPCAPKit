# -*- coding: utf-8 -*-
"""Which CI job installs the dependency each ``HAS_*`` gate asks for.

:mod:`tests._tiers` answers "may this module read that capture". This module
answers the neighbouring question: **when a test is gated on an optional
dependency, does the job whose selection reaches that test actually install
it?**

The reason it needs asking is that the failure mode is silence. A
``@unittest.skipUnless(HAS_CRYPTO, ...)`` whose dependency nobody installs does
not fail -- it skips, and :program:`pytest` run as CI runs it (``-q``, no
``-r``) prints neither the count against the flag nor the reason. So the leg
goes green, the required check passes, and the tests are simply not run. That
happened twice, with #729 (``dpkt``) and #738 (``cryptography``, ``emoji``,
``pycrate``), and both times it was found by hand months later. #745 is the
ticket for stopping the third instance, and this module is its machinery.

The chain it ties together, per flag, is three links long, and each is derived
rather than remembered:

1. **What the flag gates**, from :func:`gated_scopes` -- an :mod:`ast` pass over
   every ``test_*.py`` looking at :func:`unittest.skipUnless` decorators on
   classes *and* on methods. A text search finds the method-level ones and
   misses the class-level ones entirely, which is most of them: ``HAS_EMOJI``'s
   methods, for one, are gated by class decorators alone.
2. **What the flag requires**, from :func:`flag_requirements` -- the module
   names its defining expression probes, read out of the source rather than
   listed here. A flag defined in one module and imported by another
   (``HAS_EMOJI`` lives in :file:`tests/integration/_helpers.py`) resolves
   through the import.
3. **Which jobs reach it and what they install**, from :func:`pytest_jobs` --
   the jobs of :file:`.github/workflows/unit-tests.yml` that run
   :program:`pytest`, each with the extras of its ``pip install -e '.[...]'``
   line and the shape of its selection.

Only one link is a hand-written table: :data:`MODULE_PROVIDERS`, mapping an
import name to the distribution that ships it. That cannot be derived without
installing the distribution -- ``bs4`` comes from ``beautifulsoup4``,
``pycrate_asn1dir`` from ``pycrate``, ``pcapfile`` from ``pypcapfile`` -- so it
is declared, and
:meth:`~tests.test_tier_guard.DependencyGateCoverageTests.test_every_gated_flag_is_classified`
makes an unmapped module a failure rather than a silent pass. Which *extra*
carries a distribution is read back out of :file:`pyproject.toml`, so renaming
an extra or emptying it is caught too.

One thing this deliberately does not model, recorded here rather than left to
be discovered: **environment markers.** ``PyPCAPFile = [ "pypcapfile;
python_version < '3.12'" ]`` resolves to nothing on every leg from 3.12 up,
so an install line carrying that extra would satisfy this module while only the
legs below 3.12 ran the tests. :func:`requirement_key`
strips the marker and :func:`provided_by` ignores it; the marker text is kept
on :class:`Requirement` so a diagnostic can say so.

**Which of two distributions owns a shared import name is modelled, not
tripwired**, and #762 is the history of why that distinction matters. ``pcap``
is shipped by both ``pypcap`` and ``pcap-ct``, and ``HAS_PYPCAP`` tells them
apart by requiring ``pcap`` and *not* ``pcap._pcap``. :func:`flag_requirements`
resolves the positive half correctly, per flag -- ``HAS_PYPCAP`` needs
``{'pcap'}`` and ``HAS_PCAP_CT`` needs ``{'pcap._pcap'}`` -- but
:func:`extras_providing`'s :data:`MODULE_PROVIDERS` lookup truncates to the
*top-level* package (``module.partition('.')[0]``) before looking anything up,
so ``pcap._pcap`` lands on the very same ``'pcap'`` entry as plain ``pcap`` and
:func:`dependency_gate_gaps` cannot tell PyPCAP's install from PCAP_CT's: a job
installing either would read as satisfying *both* flags' gates. #751 put each
extra on a *different* job's install line and neither job's selection reaches
the *other* flag's gate -- confirmed with :func:`job_reaches` directly -- so
that blind spot never actually bit; a first attempt at closing it (an
allowlist naming the "correct" distribution per ``(job, flag)`` pair) turned
out to be exactly the same shape of trust with an extra layer: it agreed with
whatever the job installed rather than checking it, so flipping a job's
install line and the allowlist entry together stayed silently green.

:func:`ambiguous_satisfactions` closes it for real, using two pieces of
information :func:`dependency_gate_gaps` never needed on its own.
:func:`module_flag_exclusions` recovers the *negative* half
:func:`flag_requirements` correctly drops -- ``HAS_PYPCAP``'s own ``not
importable('pcap._pcap')`` -- and :func:`module_providers` resolves that
excluded module *exactly*, not truncated: only ``pcap-ct`` really ships
``pcap._pcap``, so it alone is what the negation disqualifies from plain
``pcap``'s two-wide entry. Subtracting the two leaves exactly one legitimate
distribution for each flag, derived from the source rather than hand-written,
so a job installing the wrong half changes what actually resolves without
changing what is "legitimate" -- which is precisely what makes the mismatch
visible. Scoped to :data:`MUTUALLY_EXCLUSIVE_IMPORTS` rather than to every name
:data:`MODULE_PROVIDERS` happens to list more than one requirement string for:
``html5lib`` has two entries there too, but both name the *same* one
distribution (``beautifulsoup4``) reached two ways, not a second one that
could win the import instead -- a length-based scope would have flagged the
first job to gain the unrelated ``vendor`` extra with nothing wrong to report.

"""
from __future__ import annotations

import ast
import functools
import pathlib
import re
from typing import TYPE_CHECKING, NamedTuple

from tests import _tiers

if TYPE_CHECKING:
    from typing import Iterator, Optional

__all__ = [
    'WORKFLOW', 'PYPROJECT', 'LATEST_LEG_CONDITION', 'EDITABLE_INSTALL', 'CORE', 'MODULE_PROVIDERS',
    'NON_DISTRIBUTION_FLAGS', 'MUTUALLY_EXCLUSIVE_IMPORTS', 'DEPENDENCY_GATE_EXCLUSIONS',
    'Requirement', 'Gate', 'Job', 'Gap', 'Exclusion', 'AmbiguousProvider',
    'requirement_key', 'provided_by', 'declared_requirements', 'extras_providing',
    'module_providers', 'contested_imports',
    'gated_scopes', 'module_gates', 'flag_requirements', 'module_flag_requirements',
    'flag_exclusions', 'module_flag_exclusions',
    'pytest_jobs', 'job_sections',
    'job_reaches', 'dependency_gate_gaps', 'describe_gap',
    'ambiguous_satisfactions', 'describe_ambiguous_satisfaction',
]

#: The workflow holding every blocking job that runs :program:`pytest`.
#: :file:`experimental.yml` runs the unit tier as well, on legs nothing waits on
#: (#1732), and :file:`cron-vendor.yml` runs ``tests/const`` and ``tests/vendor``
#: over a freshly crawled tree, where a failure discards modules rather than
#: failing the job (#1853); neither is read here. Other workflows install
#: ``.[all]`` somewhere -- a docs build, a conda recipe, and the lint pass --
#: and none of them invokes the suite;
#: :file:`python-compatibility.yml` installs a bare ``.`` and only compiles and
#: imports, and :file:`codeql-analysis.yml` installs nothing explicitly at all
#: (CodeQL's own autobuild step). That is exactly why this module keys on *jobs that
#: run pytest* rather than on install lines anywhere in the workflow tree: some
#: of those install ``.[all,dev]`` -- carrying ``pypcapfile``, ``pyshark``
#: and ``scapy`` through the ``dev`` extra #910 added when it narrowed ``all``
#: to core addons only -- so a guard reading those lines would satisfy nearly
#: every flag here vacuously.
WORKFLOW = _tiers.ROOT / '.github' / 'workflows' / 'unit-tests.yml'
#: Where the extras are declared.
PYPROJECT = _tiers.ROOT / 'pyproject.toml'
#: The ``if:`` of a step that runs on the ``latest`` leg alone (#1958), which is
#: how :func:`pytest_jobs` tells that leg's install line from every leg's.
LATEST_LEG_CONDITION = 'matrix.python-version == needs.python-versions.outputs.latest'
#: An editable install of the checkout, its one group the extras: pip's own
#: ``pip install -e '.[...]'``, or ``util/pip_install.py -e '.[...]'``, which runs
#: it for most install steps (#1967). Every reader of an install line uses it.
EDITABLE_INSTALL = re.compile(r"(?:pip install|util/pip_install\.py) -e '\.\[([^]]*)\]'")

#: Stands in for ``[project] dependencies`` where an extra name is expected:
#: what ``pip install -e .`` installs with no extra asked for at all. Spelled
#: with brackets so it cannot collide with a real extra name.
CORE = '<core>'

#: Import name -> the requirement that has to appear in an extra for it to be
#: importable. Several alternatives mean any one of them suffices.
#:
#: Keyed on the *top-level* package by default, so ``pcapfile.savefile``
#: resolves through ``pcapfile`` -- :func:`module_providers` and
#: :func:`extras_providing` both fall back to that truncated key when a dotted
#: path has no entry of its own. ``pcap._pcap`` is the one exception, and
#: deliberately so: it has its own, more specific entry below, because unlike
#: every other truncation in this table, the *submodule* and its *top-level
#: package* are shipped by different, mutually exclusive distributions (see
#: :data:`MUTUALLY_EXCLUSIVE_IMPORTS`) -- collapsing them would make the two
#: indistinguishable, which is exactly the #762 defect
#: :func:`ambiguous_satisfactions` exists to catch.
#:
#: Declared rather than derived because an import name and a distribution name
#: are different strings often enough to matter, and the only way to learn the
#: mapping mechanically is to install the distribution and look -- which no
#: test may do. :data:`NON_DISTRIBUTION_FLAGS` covers the flags that ask about
#: something pip cannot install at all.
MODULE_PROVIDERS = {
    # ``pip install -e .`` installs these whatever extras follow.
    'aenum': (CORE,),
    'chardet': (CORE,),
    'dictdumper': (CORE,),
    'tbtrim': (CORE,),
    # The one entry no extra carries, and deliberately so. ``mypy`` is a
    # lint-tier tool: it ships as a :file:`Pipfile` ``[dev-packages]`` entry
    # (``mypy = "*"``), :file:`.github/workflows/lint.yml` installs it directly
    # (``pip install -U vermin pylint mypy bandit``), and no
    # :file:`pyproject.toml` extra declares it at all -- so
    # :func:`extras_providing` resolves it to the empty set and every pytest
    # job reaching a ``HAS_MYPY`` gate is reported as a :class:`Gap`. That is
    # the honest answer rather than a :exc:`KeyError` for a missing entry: the
    # gate really is dark in CI, and
    # :data:`DEPENDENCY_GATE_EXCLUSIONS`'s ``HAS_MYPY`` entry is where the reason
    # for declining to close it lives (#779). Spelled as a requirement string
    # anyway, so the day some extra does carry mypy the gap closes itself
    # rather than needing this table rewritten.
    'mypy': ('mypy',),
    # The other lint-tier tool with a gate, and the counter-example to the entry
    # above rather than a copy of it. ``isort`` is a ``test`` extra requirement
    # (#766), so :func:`extras_providing` resolves it to ``{'test'}``, every
    # pytest job installs it, and ``HAS_ISORT`` is a satisfied gate with no
    # :data:`DEPENDENCY_GATE_EXCLUSIONS` entry at all -- which is the whole point
    # of listing it here: the guard *counts* a gate it could not see without
    # the entry, and finds nothing to report.
    #
    # Why the opposite ruling from ``mypy``, whose gap is declined above: that
    # entry's reason turns on lint.yml already running mypy over the whole
    # package, so a pytest leg would pay for a second copy of an existing check.
    # No such check exists for isort. lint.yml installs "vermin pylint mypy
    # bandit" and its own header says isort is deliberately not among them --
    # it appears only in cron-vendor.yml, as a formatter that rewrites the
    # generated constants on a schedule rather than as a check -- so excluding
    # this flag would have left `make isort`'s verdict unverified everywhere,
    # which is the #766 complaint. Cost does not argue the other way either:
    # isort is a pure-Python wheel and the Makefile's isort lines together measure
    # about 1.5s, against the ~238 MB and licence questions that keep ``NGAP``
    # out of ``all``.
    'isort': ('isort',),
    # The linter ``HAS_PYLINT`` asks for, whose message store the #1923 pragma
    # check reads. Like ``mypy`` above, no extra declares it: the Pipfile's
    # ``[dev-packages]`` and lint.yml's direct install are what carry it, so the
    # gate is dark on every pytest job and its exclusion says why.
    'pylint': ('pylint',),
    # ``beautifulsoup4`` ships ``bs4``; ``html5lib`` is an *extra of* that
    # distribution, so ``beautifulsoup4`` alone does not provide it. That
    # distinction is why ``HAS_CRAWLER_DEPS`` is satisfied by the ``test``
    # extra on every job and ``HAS_VENDOR_DEPS`` only where ``vendor`` joins it,
    # the ``latest`` legs (#1958): the ``test`` extra carries plain
    # ``beautifulsoup4``, and only ``vendor`` and ``dev`` carry
    # ``beautifulsoup4[html5lib]``. The second alternative below is not a
    # second *distribution* -- pyproject.toml never declares bare
    # ``html5lib`` -- so this is one distribution reached two ways, not the
    # kind of ambiguity :data:`MUTUALLY_EXCLUSIVE_IMPORTS` names.
    'bs4': ('beautifulsoup4',),
    'html5lib': ('beautifulsoup4[html5lib]', 'html5lib'),
    'requests': ('requests',),
    'cryptography': ('cryptography',),
    'dpkt': ('dpkt',),
    'emoji': ('emoji',),
    'scapy': ('scapy',),
    'pyshark': ('pyshark',),
    # ``pycrate`` ships one distribution holding every specification it has
    # compiled; ``pycrate_asn1dir`` is the package the NGAP protocol reads.
    'pycrate_asn1dir': ('pycrate',),
    'pcapfile': ('pypcapfile',),
    # Both distributions ship a top-level ``pcap`` -- genuinely either, which
    # is why this entry stays two-wide and why ``pcap`` is the one name in
    # :data:`MUTUALLY_EXCLUSIVE_IMPORTS`.
    'pcap': ('pypcap', 'pcap-ct'),
    # Only ``pcap-ct`` ships this exact submodule; ``pypcap``'s own ``pcap``
    # package has no ``_pcap`` member at all. This is what
    # ``HAS_PYPCAP = _importable('pcap') and not _importable('pcap._pcap')``
    # actually distinguishes on, and what :func:`module_flag_exclusions` and
    # :func:`ambiguous_satisfactions` use to prune ``pcap-ct`` back out of
    # ``HAS_PYPCAP``'s candidates -- see :func:`ambiguous_satisfactions`'s own
    # docstring.
    'pcap._pcap': ('pcap-ct',),
    # The :file:`docs/source/conf.py` imports at module level, which the
    # ``HAS_SPHINX`` gate on its hook tests (#1775) asks for. Only the ``docs``
    # extra carries them.
    'sphinx': ('Sphinx',),
    'sphinx_autodoc_typehints': ('sphinx-autodoc-typehints',),
    # The reST parser Sphinx renders the const comments with, which the
    # ``HAS_DOCUTILS`` gate on #1846's rendering check asks for. No extra
    # declares it: Sphinx requires it, so the ``docs`` extra is what installs it.
    # The bare name is listed as well, as with ``html5lib`` above, and the day an
    # extra declares docutils itself this entry has to change: the bare name goes
    # live alongside Sphinx, :func:`contested_imports` reports docutils, and the
    # :data:`MUTUALLY_EXCLUSIVE_IMPORTS` liveness test fails until the entry is
    # cut to ``('docutils',)``. The ``latest`` legs install the ``docs`` extra
    # (#1958), which is what closes the ``HAS_DOCUTILS`` gate there.
    'docutils': ('Sphinx', 'docutils'),
    # The theme ``HAS_FURO`` asks for, whose table wrapper the #1861 transform
    # test runs. Only the ``docs`` extra carries it.
    'furo': ('furo',),
    # The strict XML parser ``HAS_LXML`` asks for (#1894): util/ci_timing.py
    # reads JUnit and util/pyshark_encap_map.py reads PDML with it, and neither
    # falls back to a laxer parser. The ``test`` extra carries it with a
    # ``platform_python_implementation == 'CPython'`` marker, because PyPI has
    # no wheel for GraalPy or PyPy 8.0, so the gate skips on experimental.yml's
    # GraalPy leg and on unit-tests.yml's PyPy legs (#1958). That is no
    # :data:`DEPENDENCY_GATE_EXCLUSIONS` entry: this module does not model
    # markers, every module gated on it is ``LATEST``, which no PyPy leg runs,
    # and this module does not read experimental.yml, so every job it reads
    # satisfies the gate, and an entry would describe a gap that is not there.
    'lxml': ('lxml',),
}

#: Flags whose condition is not a distribution, with what it is instead. A flag
#: here needs no :data:`MODULE_PROVIDERS` entry and can never be a gap, because
#: no install line could close it.
NON_DISTRIBUTION_FLAGS = {
    'HAS_PROC_FD': (
        'asks whether /proc/self/fd is a directory, i.e. whether this kernel '
        'exposes the procfs file-descriptor listing -- nothing pip installs'
    ),
    # tests/project/test_pyshark_encap_map.py (#851/#853). Asks whether the
    # tshark/editcap binaries are on PATH -- a Wireshark install, not a Python
    # distribution any pyproject.toml extra could ever provide. Declared here
    # rather than left as an unprefixed shutil.which check: the latter was
    # tried first and made the AST scan blind to two classes skipping on every
    # CI leg, which is the opposite of what "no unaccounted HAS_* gate" was
    # meant to prevent.
    'HAS_WIRESHARK': (
        'asks whether the tshark/editcap binaries are on PATH -- a Wireshark '
        'install, not a Python distribution any extra could provide'
    ),
}

#: Top-level import names two (or more) genuinely *mutually exclusive*
#: distributions can ship, where installing the wrong one silently satisfies
#: the wrong flag. Declared explicitly rather than inferred from
#: ``len(MODULE_PROVIDERS[name]) > 1``, because that length counts alternative
#: *requirement strings*, not competing distributions -- ``html5lib`` also has
#: two entries in :data:`MODULE_PROVIDERS` and is not this: both name the same
#: one distribution (``beautifulsoup4``), reached two ways, and a job that
#: happened to gain the ``vendor`` extra would trip a length-based check with
#: no wrong half to report. ``pcap`` is the one name that is genuinely
#: contested -- ``pypcap`` and ``pcap-ct`` are two different sdists that both
#: create a top-level ``pcap`` package -- and :func:`ambiguous_satisfactions`
#: is scoped to exactly this set.
#:
#: Hand-written rather than computed, for the same reason
#: :data:`DEPENDENCY_GATE_EXCLUSIONS` is: a human decides *that* a name is
#: contested, with a reason worth reading. What is checked, not trusted, is
#: whether this set still matches reality: a liveness test asserts it equals
#: :func:`contested_imports`, so a name going contested without a matching
#: entry here -- the omission a hand-written set cannot itself notice -- fails
#: loudly instead of silently reopening #762 under a different name.
MUTUALLY_EXCLUSIVE_IMPORTS = frozenset({'pcap'})


class Exclusion(NamedTuple):
    """A gap that is known, deliberate, and not to be reported as a failure."""

    #: Job name -> the top-level packages that job knowingly does not install.
    #: Checked for *exact* equality against what :func:`dependency_gate_gaps`
    #: derives, in both directions. An entry that has stopped being true fails
    #: the guard rather than sitting here forever: a bare skip list rots into
    #: the same invisibility the gap itself had, which is #745's own warning.
    dark: 'dict[str, tuple[str, ...]]'
    #: Why the dependency is not installed. Prose, for the next reader.
    reason: 'str'


#: Gaps that are deliberate. Every entry states the jobs and packages it covers,
#: and
#: :meth:`~tests.test_tier_guard.DependencyGateCoverageTests.test_each_exclusion_still_describes_a_gap_that_is_really_there`
#: fails if the derived gap is wider, narrower, or gone.
DEPENDENCY_GATE_EXCLUSIONS = {
    'HAS_PYPCAP': Exclusion(
        dark={'integration': ('pcap',), 'gate': ('pcap',)},
        reason=(
            'pypcap ships no wheel: it compiles a C extension against libpcap and needs '
            'both its headers and its shared library, and its pre-generated pcap.c does '
            'not build against the Python 3.12+ C API at all (measured, see the PyPCAP '
            'extra in pyproject.toml). So the extra carries a '
            "\"python_version < '3.12'\" marker: installing it takes a toolchain step, "
            'and only Python 3.10 and 3.11 can use the result. #738 records the same '
            'exclusion, if less precisely -- pypcap needs the headers, pcap-ct below does '
            'not. The flag also requires pcap._pcap to be *absent*, which is how it tells '
            "upstream pypcap from pcap-ct; see this module's docstring.\n\n"
            "The owner's ruling on #751 is to build it in CI rather than decline it, and to "
            'drop the build if CI proves a poor fit for it. pypcap-parity installs a '
            'toolchain plus libpcap headers and builds it on Python 3.11, '
            "pypcap-parity-ktlo on 3.10, and engine-tests' PyPCAP cell builds it on 3.10 "
            'and 3.11 and records 3.12 onwards as not installable. integration and gate '
            'stay dark deliberately: the ruling on #751 is a dedicated job, not one more '
            "install line on either. If pypcap-parity's build step does not fit CI, the "
            'fix is deleting that job and widening this exclusion to name it too, with '
            'the failing run linked.'
        ),
    ),
    'HAS_PCAP_CT': Exclusion(
        dark={'test': ('pcap',), 'gate': ('pcap',)},
        reason=(
            'pcap-ct needs no toolchain, contrary to how #738 grouped it with pypcap: it '
            'and libpcap both publish py3-none-any wheels. Two other reasons stand, '
            'though. Both are published only as pre-releases, which is why '
            'pyproject.toml keeps them out of the all extra -- and its ctypes loader '
            'calls find_library("pcap"), so a system libpcap has to be present on the '
            'runner at run time. A green install would therefore not imply the engine '
            'can start.\n\n'
            "#751's dedicated engine-tests job covers it: its PCAP_CT cell installs "
            'PCAP_CT and a system libpcap (apt-get libpcap0.8) on Python 3.11-3.15, plus '
            'the non-blocking KTLO 3.10 (#1633), with one venv per Python version and '
            'engine (#849). PCAP_CT therefore never shares an environment with PyPCAP, '
            'which matters because pypcap and pcap-ct both install a top-level ``pcap`` '
            'module and cannot coexist -- see '
            "pcapkit/foundation/engines/_pcap_backend.py's own docstring. test and gate "
            "stay dark on purpose, per #751's ruling that per-engine coverage gets its "
            'own job rather than one more install line on either. The latest legs '
            'install every engine pip can install there (#1958); PCAP_CT alone also '
            "needs that system libpcap, which engine-tests' PCAP_CT cell installs, "
            'latest included.'
        ),
    ),
    'HAS_PYPCAPFILE': Exclusion(
        dark={'test': ('pcapfile',), 'integration': ('pcapfile',), 'gate': ('pcapfile',)},
        reason=(
            'Not because the gated tests fail: with the extra installed they pass (#747 '
            'in the toolkit, #748 in the engine, the defects #745 excluded this flag '
            '"pending" on). What keeps it dark is the marker. PyPCAPFile is declared '
            "\"pypcapfile; python_version < '3.12'\", because released 0.12.0 imports the "
            'imp module that 3.12 removed, so the extra resolves to nothing on Python 3.12 '
            'onwards. Adding it to test would satisfy this guard -- which does not model '
            'markers -- while every leg from 3.12 up went on skipping: partial coverage '
            'bought with exactly the false confidence #745 exists to remove.\n\n'
            "#751's ruling covers it with a dedicated job instead. engine-tests' "
            'PyPCAPFile cell runs the HAS_PYPCAPFILE methods in test_pypcapfile_unit.py '
            '(plus test_pypcapfile_engine.py) on every Python it runs, 3.10 to 3.15 (#849): '
            "on 3.10 and 3.11 it installs the ordinary extra, and on 3.12 onwards, where "
            "pyproject.toml's marker would resolve it to nothing, it installs the raw "
            'pypcapfile distribution instead (expect: unsupported), bypassing the marker so '
            "the tests run for real and assert the engine's own version-aware decline (see "
            "this workflow's own engine-tests comment). pypcap-parity and "
            'pypcap-parity-ktlo do the same for the gated methods in '
            'test_new_engine_parity_runtime.py, on 3.11 and 3.10, which the marker allows. '
            'This guard takes selection and extras from the YAML, not from what a given '
            "cell resolves to, so in general it does not model markers (see this module's "
            'docstring); for PyPCAPFile the workflow bypasses the marker itself, so that '
            'caveat leaves no gap here. test, integration and gate stay dark on purpose, '
            "per #751's ruling that per-engine coverage gets its own job rather than one "
            'more install line on any of them.'
        ),
    ),
    'HAS_MYPY': Exclusion(
        dark={'test': ('mypy',), 'gate': ('mypy',)},
        reason=(
            'Not a missing *runtime* dependency, and not a gap an install line fixes. '
            'mypy is a type checker: the method it gates runs mypy over the generated '
            'pcapkit/const/reg/apptype/apptype.py and requires a clean result (#770), '
            'which is a lint question asked from a unit test rather than a code path '
            'pcapkit executes. It belongs to the lint tier accordingly -- a Pipfile '
            '[dev-packages] entry that `make mypy` resolves, and a direct '
            '"pip install -U vermin pylint mypy bandit" in lint.yml -- and no '
            'pyproject.toml extra declares it at all.\n\n'
            'So the fix this guard would otherwise propose -- put an extra carrying mypy '
            "on a pytest job's install line -- is the wrong one, and declining it is what "
            'this entry records. A pytest leg that installed mypy would pay for a second, '
            'slower copy of a check lint.yml already runs across the whole package, and it '
            'would make every unit-test leg depend on the type checker resolving. Note too '
            'that lint.yml runs no pytest at all, so pytest_jobs() never sees the one job '
            'that does install mypy: an extra added for its benefit would satisfy this '
            'guard without changing what runs anywhere. What the gate buys instead is that '
            'the check runs wherever mypy happens to be importable -- a developer '
            "checkout, `make mypy`'s own environment -- and skips *visibly* where it is "
            'not. Visibly is the whole point of #779: an inline try/except ImportError '
            'skipTest works but is invisible to this module by construction, since '
            '_gates_of() walks a decorator list and never a function body. That is the dark-test hazard #745 exists to stop.\n\n'
            'The sibling isort check (#766) had the identical invisible shape and was '
            'fixed the other way -- a HAS_ISORT gate plus isort in the test extra, so it '
            'is a satisfied gate with no entry here. The two rulings disagree for a '
            'reason that is specific to this paragraph rather than to lint tools in '
            'general: the "second copy of a check lint.yml already runs" argument above '
            'is what declines mypy, and lint.yml installs no isort at all (its header '
            'records that deliberately -- isort appears only in cron-vendor.yml, as a '
            'formatter rather than as a check), so for isort there was no first copy to '
            'defer to and excluding it would have left `make isort` verified nowhere. '
            'This entry is therefore narrow: it is not a precedent that a gate on a lint '
            'tool gets excluded, only that a gate duplicating an existing lint.yml check '
            'does.\n\n'
            'test and gate are the jobs whose selection reaches '
            'tests/vendor/test_vendor_reg_apptype_generator_unit.py -- test by its '
            'ignore shape, gate by running the whole suite. engine-tests runs one '
            'explicit TEST_PATHS list per matrix.engine cell (#849), and none names '
            'tests/vendor/, so it never reaches this gate; integration and pypcap-parity '
            'select by fixture tier and never collect that module. That is why none of '
            'them is listed, and '
            ':meth:`~tests.test_tier_guard.DependencyGateCoverageTests\
.test_each_exclusion_still_describes_a_gap_that_is_really_there` fails if that '
            'stops being true. If a lint extra is ever declared in pyproject.toml, the '
            'right change is to delete this entry and let the gap close on its own rather '
            'than to widen it.'
        ),
    ),
    'HAS_PYLINT': Exclusion(
        dark={'project-tests': ('pylint',), 'gate': ('pylint',)},
        reason=(
            'The method it gates (#1923) looks every pylint pragma name in pcapkit/ up in '
            "pylint's own message store, with the plugins `make pylint` loads, so it needs "
            'pylint, which no pytest job installs. pylint is a lint-tier tool, as mypy is: '
            'a Pipfile [dev-packages] entry that `make pylint` resolves, and a direct '
            '"pip install -U vermin pylint mypy bandit" in lint.yml, which runs no pytest; '
            'no pyproject.toml extra declares it. The argument that declines HAS_MYPY above '
            'declines it here: lint.yml already runs pylint over the whole package, and an '
            'unknown pragma name shows there as W0012 unknown-option-value, so a pytest leg '
            'that installed pylint would pay for a second copy of that check. What runs '
            'instead is the ungated check in the same module, a project pin that '
            'project-tests runs (#1954), which holds each '
            'pragma name to the pinned KNOWN_MESSAGES list; the lookup keeps that list '
            'honest wherever pylint is importable, a developer checkout included, and skips '
            'visibly elsewhere.'
        ),
    ),
}


class Requirement(NamedTuple):
    """One requirement string of an extra, split into what matching needs."""

    #: PEP 503 normalised distribution name.
    name: 'str'
    #: Extras asked of it, e.g. ``{'html5lib'}`` for ``beautifulsoup4[html5lib]``.
    extras: 'frozenset[str]'
    #: The environment marker, when there was one. Kept for diagnostics only --
    #: see this module's docstring on why markers are not evaluated.
    marker: 'Optional[str]'
    #: The requirement exactly as :file:`pyproject.toml` spells it.
    text: 'str'


class Gate(NamedTuple):
    """One ``skipUnless(HAS_*, ...)`` decorator found in the suite."""

    #: The flag name, e.g. ``'HAS_CRYPTO'``.
    flag: 'str'
    #: Module holding the decorator, relative to :data:`~tests._tiers.ROOT`.
    module: 'str'
    #: Line the decorated definition starts on.
    lineno: 'int'
    #: Enclosing class name, for a method-level gate and for a class-level gate
    #: alike; :data:`None` for a module-level function.
    class_name: 'Optional[str]'
    #: The decorated function's name, or :data:`None` for a class-level gate.
    func_name: 'Optional[str]'


class Job(NamedTuple):
    """A job of :data:`WORKFLOW` that runs :program:`pytest`.

    Normally one :class:`Job` per YAML job -- but ``engine-tests`` (#849) is
    not one static install line and one static selection: each
    ``matrix.engine`` cell installs a different extra and runs a different,
    explicit list of test files, so :func:`pytest_jobs` yields one
    :class:`Job` per engine for it, all sharing the one YAML job ``name``.
    That is deliberate rather than an oddity to special-case away:
    :func:`dependency_gate_gaps` aggregates by ``(flag, job.name)``, and a gate
    reached by *any* of a job's per-engine variants is exactly what "this job
    reaches this gate" has to mean when one job's cells do not all install
    and select the same thing.

    """

    #: Job name as the workflow spells it.
    name: 'str'
    #: Extras of its ``pip install -e '.[...]'`` line, in declaration order.
    extras: 'tuple[str, ...]'
    #: How the job selects tests: ``'fixture-tier'`` when it asks
    #: :func:`~tests._tiers.fixture_tier_paths` for the selection,
    #: ``'ignore'`` when it subtracts ``--ignore`` flags from the whole suite,
    #: ``'whole-suite'`` when it passes no selection at all, ``'explicit'``
    #: when it names literal test-file paths (see :attr:`paths`), and
    #: ``'project-pins'`` when it runs what :func:`~tests._tiers.project_pin_paths`
    #: prints (#1954).
    selection: 'str'
    #: The literal test-file paths named by an ``'explicit'`` selection, empty
    #: for every other shape. Compared to :class:`Gate`.\ ``module`` by exact
    #: string equality -- unlike ``'fixture-tier'``, there is no directory or
    #: node-ID form here, because that is not the shape ``TEST_PATHS`` takes.
    paths: 'tuple[str, ...]' = ()
    #: The test tier a ``'fixture-tier'`` selection is limited to on every leg
    #: (#1958): ``'ALL'`` for a job none of whose legs is ``latest``, which asks
    #: :func:`~tests._tiers.fixture_tier_paths` for that tier alone, :data:`None`
    #: for one whose ``latest`` leg asks for every tier, and for every other shape.
    tier: 'Optional[str]' = None
    #: Extras of the job's ``latest``-only install step (#1958), empty when it has
    #: none. That leg's selection holds every other leg's, so a gate the job
    #: reaches runs there with these installed; see :func:`dependency_gate_gaps`.
    latest_extras: 'tuple[str, ...]' = ()


class Gap(NamedTuple):
    """A gated test a job reaches without installing what it is gated on."""

    #: The flag.
    flag: 'str'
    #: The job that reaches it.
    job: 'str'
    #: Top-level packages the job does not install, sorted.
    missing: 'tuple[str, ...]'
    #: The gates this applies to, sorted by module and line.
    gates: 'tuple[Gate, ...]'


class AmbiguousProvider(NamedTuple):
    """A satisfied gate resolved through an import name more than one distribution ships.

    Not a :class:`Gap` -- the job in question *did* install something that
    provides the module, so :func:`dependency_gate_gaps` calls it satisfied.
    What this reports is the question that function never asks: whether the
    thing it installed is the *right* one of several possible providers, or
    merely one of them.

    """

    #: The flag.
    flag: 'str'
    #: The job whose install line satisfied it.
    job: 'str'
    #: The import name more than one *distribution* ships.
    module: 'str'
    #: Every distribution :func:`extras_providing`/:func:`dependency_gate_gaps`
    #: would credit with shipping ``module`` -- the *unnarrowed* set, keyed on
    #: ``module``'s top-level package the way that function always is.
    providers: 'frozenset[str]'
    #: Of those, the ones the job's install line actually resolves. What
    #: :func:`dependency_gate_gaps` treats as proof the gate is satisfied.
    satisfied: 'frozenset[str]'
    #: The distribution(s) that would *genuinely* leave the flag true --
    #: :func:`module_providers`'s exact-path-aware reading of ``module``, minus
    #: whatever :func:`module_flag_exclusions` says this flag needs absent.
    #: ``satisfied`` is flagged as ambiguous precisely when it disagrees with
    #: this set: resolving to something outside it, or to more than one thing
    #: even inside it.
    valid: 'frozenset[str]'


def requirement_key(text: 'str') -> 'Requirement':
    """Split one requirement string into a :class:`Requirement`.

    Deliberately not a PEP 508 parser: it handles what the extras in
    :file:`pyproject.toml` actually use -- a name, optional bracketed extras, an
    optional version specifier, and an optional ``;`` marker -- and normalises
    the name per PEP 503 so ``pcap-ct``, ``pcap_ct`` and ``PCAP.CT`` compare
    equal. Anything it cannot split yields a :class:`Requirement` whose name is
    the stripped text, which fails to match rather than matching wrongly.

    """
    body, _, marker = text.partition(';')
    body = body.strip()
    marker = marker.strip() or None

    match = re.match(r'^([A-Za-z0-9._-]+)\s*(?:\[([^]]*)\])?', body)
    if match is None:
        return Requirement(body, frozenset(), marker, text)

    name = re.sub(r'[-_.]+', '-', match.group(1)).lower()
    extras = frozenset(
        re.sub(r'[-_.]+', '-', part.strip()).lower()
        for part in (match.group(2) or '').split(',') if part.strip()
    )
    return Requirement(name, extras, marker, text)


def provided_by(requirements: 'tuple[Requirement, ...]', provider: 'str') -> 'bool':
    """Whether ``requirements`` installs ``provider``.

    ``provider`` is spelled as a requirement too, so ``'beautifulsoup4'`` is
    satisfied by ``beautifulsoup4[html5lib]`` -- asking for an extra installs
    the base distribution -- while ``'beautifulsoup4[html5lib]'`` is *not*
    satisfied by plain ``beautifulsoup4``. That asymmetry is the whole point:
    it is what separates ``HAS_CRAWLER_DEPS``, which the ``test`` extra
    satisfies, from ``HAS_VENDOR_DEPS``, which needs ``vendor`` as well.

    """
    wanted = requirement_key(provider)
    return any(
        candidate.name == wanted.name and wanted.extras <= candidate.extras
        for candidate in requirements
    )


def _strip_comment(line: 'str') -> 'str':
    """``line`` up to its first ``#`` that is not inside a double-quoted string."""
    quoted = False
    for index, char in enumerate(line):
        if char == '"':
            quoted = not quoted
        elif char == '#' and not quoted:
            return line[:index]
    return line


def _toml_array(text: 'str', name: 'str') -> 'Optional[tuple[Requirement, ...]]':
    """The ``name = [ ... ]`` array of double-quoted strings in ``text``.

    A targeted scan rather than :mod:`tomllib`, which is 3.11+ while the oldest
    leg to run the suite is 3.8 (``test-ktlo``'s, #1633, #1738) -- and a guard that skips on
    some legs is the shape of invisibility this whole module exists to remove.
    Comments are stripped first, quote-aware, because the arrays here are
    heavily annotated; the brackets inside ``"requests[socks]"`` are what makes
    a naive "up to the first ``]``" slice wrong.

    """
    match = re.search(rf'(?m)^{re.escape(name)}\s*=\s*\[', text)
    if match is None:
        return None

    depth = 0
    body = []  # type: list[str]
    for line in text[match.end() - 1:].splitlines(keepends=True):
        stripped = _strip_comment(line)
        body.append(stripped)
        for char in stripped:
            if char == '[':
                depth += 1
            elif char == ']':
                depth -= 1
        if depth <= 0:
            break
    return tuple(requirement_key(item) for item in re.findall(r'"([^"]*)"', ''.join(body)))


def _toml_section(text: 'str', header: 'str') -> 'str':
    """The body of TOML table ``header``, up to the next table header."""
    match = re.search(rf'(?ms)^\[{re.escape(header)}\]\n(.*?)(?=^\[|\Z)', text)
    if match is None:
        raise AssertionError(f'{PYPROJECT} has no [{header}] table')
    return match.group(1)


@functools.lru_cache(maxsize=1)
def declared_requirements() -> 'dict[str, tuple[Requirement, ...]]':
    """Extra name -> its requirements, with :data:`CORE` for the base install."""
    text = PYPROJECT.read_text(encoding='utf-8')

    core = _toml_array(_toml_section(text, 'project'), 'dependencies')
    if core is None:
        raise AssertionError(f'{PYPROJECT} declares no [project] dependencies')

    declared = {CORE: core}
    extras = _toml_section(text, 'project.optional-dependencies')
    for name in re.findall(r'(?m)^([A-Za-z0-9._-]+)\s*=\s*\[', extras):
        requirements = _toml_array(extras, name)
        assert requirements is not None  # it was just matched
        declared[name] = requirements
    return declared


def _top_level_providers(module: 'str') -> 'tuple[str, ...]':
    """:data:`MODULE_PROVIDERS`'s entry for ``module``'s top-level package.

    The one place that table is subscripted, so that a module nobody has mapped
    fails with a message naming it and naming the fix rather than with a bare
    ``KeyError: 'mypy'`` out of a dict lookup three call sites deep. Auditing
    gates is the whole purpose of this module, so crashing opaquely on the first
    unrecognised one is the worst answer available; #779 is what that cost, and
    :func:`_disqualified_providers` below is the message shape this follows.

    For a mapped module it is the same tuple a subscript returns, so only the
    failure for an unmapped one differs from a bare lookup.

    """
    top_level = module.partition('.')[0]
    try:
        return MODULE_PROVIDERS[top_level]
    except KeyError:
        raise AssertionError(
            f'{module!r} has no MODULE_PROVIDERS entry (looked up under its top-level '
            f'{top_level!r}), so nothing here knows which distribution ships it or which '
            f'extra would install it. Add a MODULE_PROVIDERS[{top_level!r}] entry naming '
            f'the requirement string(s) that provide it -- and, when no pyproject.toml '
            f'extra carries any of them, a DEPENDENCY_GATE_EXCLUSIONS entry for the flag '
            f'saying why the jobs reaching its gates decline it. A flag whose condition no '
            f'extra could ever satisfy belongs in NON_DISTRIBUTION_FLAGS instead.'
        ) from None


def module_providers(module: 'str') -> 'frozenset[str]':
    """Every distribution (or :data:`CORE`) :data:`MODULE_PROVIDERS` says could ship ``module``.

    Unlike :func:`extras_providing`, keyed on the dotted path *exactly as given*
    when :data:`MODULE_PROVIDERS` has a dedicated entry for it -- ``pcap._pcap``
    resolves to ``('pcap-ct',)`` alone rather than falling back to plain
    ``pcap``'s two-wide entry. Falls back to the top-level package otherwise,
    the same rule :func:`extras_providing` always uses, which is what makes an
    unmapped module a failure there rather than a silent pass here too (the
    fallback goes through :func:`_top_level_providers`, so it raises the same
    :exc:`AssertionError` naming the module that that function's own lookup
    does).

    :func:`ambiguous_satisfactions` is the reason this exists: it needs the
    narrower, exact-path answer to tell a distribution that genuinely,
    uniquely ships a submodule apart from the wider set that merely ships its
    top-level package -- see that function's own docstring.

    """
    return frozenset(MODULE_PROVIDERS.get(module, _top_level_providers(module)))


def contested_imports() -> 'frozenset[str]':
    """What :data:`MUTUALLY_EXCLUSIVE_IMPORTS` should be, derived rather than trusted.

    For each :data:`MODULE_PROVIDERS` entry, counts how many of its
    alternative requirement strings some declared extra actually provides --
    not how many alternatives the entry merely lists. ``html5lib``'s two
    alternatives (``beautifulsoup4[html5lib]``, plain ``html5lib``) resolve to
    one *live* distribution, because pyproject.toml never declares bare
    ``html5lib`` under any extra; ``pcap``'s two (``pypcap``, ``pcap-ct``)
    resolve to two. A top-level name qualifies once two or more of its
    alternatives are live -- genuinely reachable by installing a real,
    different thing -- which is exactly the question
    :func:`ambiguous_satisfactions` has to ask, and exactly what separates
    ``pcap`` from the ``html5lib`` near-miss automatically.

    This is the liveness half :data:`MUTUALLY_EXCLUSIVE_IMPORTS` does not have
    on its own: a hand-written set can go stale exactly the way this module's
    own docstring warns a skip list does (#745) -- it would not notice a
    *third* contested name go undeclared, only a wrong entry among the ones
    already there. Comparing this function's answer against the hand-written
    set is what closes that gap.

    """
    declared = declared_requirements()

    def _is_live(provider: 'str') -> 'bool':
        return provider == CORE or any(
            provided_by(requirements, provider) for requirements in declared.values())

    contested = set()  # type: set[str]
    for module, providers in MODULE_PROVIDERS.items():
        if sum(1 for provider in providers if _is_live(provider)) >= 2:
            contested.add(module.partition('.')[0])
    return frozenset(contested)


@functools.lru_cache(maxsize=None)
def extras_providing(module: 'str') -> 'frozenset[str]':
    """Every extra (or :data:`CORE`) whose requirements make ``module`` importable.

    Raises :exc:`AssertionError` -- through :func:`_top_level_providers`, which
    names the module and the table to add it to -- for a module with no
    :data:`MODULE_PROVIDERS` entry, which is what makes a newly gated dependency
    a failure rather than a pass. An entry no extra carries is a different thing
    and is *not* an error: it resolves to the empty set, so every job reaching
    the gate is reported as a :class:`Gap`, which is what ``mypy`` is.

    """
    providers = _top_level_providers(module)
    declared = declared_requirements()
    satisfying = set()  # type: set[str]
    for provider in providers:
        if provider == CORE:
            # Not a distribution name to look up: `pip install -e .` installs
            # it whatever extras follow, so only CORE itself provides it.
            satisfying.add(CORE)
            continue
        satisfying.update(name for name, requirements in declared.items()
                          if provided_by(requirements, provider))
    return frozenset(satisfying)


def _module_probes(node: 'ast.AST') -> 'bool':
    """Whether ``node`` is a call that asks whether a module is importable."""
    func = node.func if isinstance(node, ast.Call) else None
    if isinstance(func, ast.Attribute):
        return func.attr in ('find_spec', 'import_module')
    if isinstance(func, ast.Name):
        return func.id in ('find_spec', 'import_module')
    return False


def _string_args(node: 'ast.Call', names: 'dict[str, tuple[str, ...]]') -> 'Iterator[str]':
    """String arguments of ``node``, resolving a name through ``names``."""
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            yield arg.value
        elif isinstance(arg, ast.Name):
            yield from names.get(arg.id, ())


def _string_sequence(node: 'ast.expr', names: 'dict[str, tuple[str, ...]]') -> 'tuple[str, ...]':
    """The strings of a tuple/list literal, or of a name bound to one."""
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(element.value for element in node.elts
                     if isinstance(element, ast.Constant) and isinstance(element.value, str))
    if isinstance(node, ast.Name):
        return names.get(node.id, ())
    return ()


def _probed_modules(node: 'ast.AST', names: 'dict[str, tuple[str, ...]]',
                    helpers: 'dict[str, ast.FunctionDef]',
                    negated: 'bool' = False,
                    seen: 'Optional[frozenset[str]]' = None,
                    *, want_negated: 'bool' = False) -> 'Iterator[str]':
    """Module names ``node`` requires to be importable, or requires *absent*.

    Walked by hand rather than with :func:`ast.walk` for one reason: polarity.
    ``HAS_PYPCAP = _importable('pcap') and not _importable('pcap._pcap')``
    requires the first and requires the *absence* of the second, and a flat walk
    cannot tell them apart -- it would report ``HAS_PYPCAP`` as needing a module
    whose presence makes it false.

    ``want_negated`` picks which side this call collects: :data:`False`, the
    default, yields the positively-required modules. :data:`True` yields the
    mirror image -- the modules a negated probe asks to be absent -- which is
    what :func:`module_flag_exclusions` asks for. A module is never yielded by
    both calls on the same expression: exactly one of ``negated == want_negated``
    holds at the point a probe is reached.

    A call to a module-level helper contributes both its own string arguments
    (``_importable('pcap._pcap')``) and whatever its body probes
    (``_has_pypcapfile()``, which names its modules inside), because the suite
    uses both shapes. ``seen`` stops a recursive helper from looping.

    """
    if seen is None:
        seen = frozenset()

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        yield from _probed_modules(node.operand, names, helpers, not negated, seen,
                                   want_negated=want_negated)
        return

    if isinstance(node, ast.Call):
        helper = node.func.id if isinstance(node.func, ast.Name) else None
        if _module_probes(node):
            if negated == want_negated:
                yield from _string_args(node, names)
            return
        if helper is not None and helper in helpers and helper not in seen:
            if negated == want_negated:
                yield from _string_args(node, names)
                for statement in helpers[helper].body:
                    yield from _probed_modules(statement, names, helpers,
                                               negated, seen | {helper},
                                               want_negated=want_negated)
            return

    for child in ast.iter_child_nodes(node):
        yield from _probed_modules(child, names, helpers, negated, seen,
                                   want_negated=want_negated)


def _string_bindings(tree: 'ast.Module', expression: 'ast.expr') -> 'dict[str, tuple[str, ...]]':
    """Names bound to string sequences, module-level and comprehension alike.

    Two shapes, both in use: ``RUNTIME_DEPS = ('tbtrim', ...)`` at module level,
    and the loop variable of ``for name in ('requests', 'bs4')`` inside the
    flag's own generator expression. Without the second, every flag written as
    ``all(find_spec(name) ... for name in (...))`` would resolve to no modules
    at all and read as though it gated on nothing.

    """
    bindings = {}  # type: dict[str, tuple[str, ...]]
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    sequence = _string_sequence(node.value, bindings)
                    if sequence:
                        bindings[target.id] = sequence

    for node in ast.walk(expression):
        if isinstance(node, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
            for generator in node.generators:
                if isinstance(generator.target, ast.Name):
                    sequence = _string_sequence(generator.iter, bindings)
                    if sequence:
                        bindings[generator.target.id] = sequence
    return bindings


def module_flag_requirements(path: 'pathlib.Path') -> 'dict[str, frozenset[str]]':
    """``HAS_*`` flags this module defines, and the modules each requires.

    Public for the same reason :func:`module_gates` is: the shapes it has to
    understand are best pinned against source written to exercise them one at a
    time, rather than against whichever of them the suite happens to use.

    """
    try:
        tree = ast.parse(path.read_text(encoding='utf-8'))
    except (OSError, SyntaxError):
        return {}

    helpers = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    definitions = {}  # type: dict[str, frozenset[str]]
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.startswith('HAS_'):
                bindings = _string_bindings(tree, node.value)
                definitions[target.id] = frozenset(
                    _probed_modules(node.value, bindings, helpers))
    return definitions


def module_flag_exclusions(path: 'pathlib.Path') -> 'dict[str, frozenset[str]]':
    """``HAS_*`` flags this module defines, and the modules each requires *absent*.

    The mirror of :func:`module_flag_requirements`, collecting exactly the
    negated probes that function drops. Dropping them there is safe --
    :func:`dependency_gate_gaps` only ever asks "is something installed that
    provides the positive requirement", and a job's install line cannot make a
    module *un*-importable, so the negative half never changes what that
    question needs. It stops being safe the moment two distributions can ship
    the same positive import name, because then *which* distribution is
    providing it decides the negative half's answer too -- which is exactly
    what :func:`ambiguous_satisfactions` uses this for (#762): ``HAS_PYPCAP``'s
    ``pcap`` requirement is satisfied by either ``pypcap`` or ``pcap-ct``, but
    only the first also leaves its own ``not importable('pcap._pcap')``
    requirement true, and this is what says so.

    Most flags have nothing here -- an empty result means "no negated probe",
    not "unresolved"; :func:`module_flag_requirements` is still what decides
    whether the flag was understood at all.

    """
    try:
        tree = ast.parse(path.read_text(encoding='utf-8'))
    except (OSError, SyntaxError):
        return {}

    helpers = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    definitions = {}  # type: dict[str, frozenset[str]]
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.startswith('HAS_'):
                bindings = _string_bindings(tree, node.value)
                definitions[target.id] = frozenset(
                    _probed_modules(node.value, bindings, helpers, want_negated=True))
    return definitions


def _flag_imports(path: 'pathlib.Path') -> 'dict[str, str]':
    """``HAS_*`` flags this module imports, and the module path each came from."""
    try:
        tree = ast.parse(path.read_text(encoding='utf-8'))
    except (OSError, SyntaxError):
        return {}

    imported = {}  # type: dict[str, str]
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            for alias in node.names:
                if alias.name.startswith('HAS_') and alias.asname is None:
                    imported[alias.name] = node.module.replace('.', '/') + '.py'
    return imported


@functools.lru_cache(maxsize=1)
def flag_requirements() -> 'dict[tuple[str, str], frozenset[str]]':
    """``(module, flag)`` -> the modules that flag needs importable.

    Resolved per file rather than per flag name, because one flag name can
    probe different modules in different files: ``HAS_RUNTIME`` names the core
    dependencies in most modules, and in
    :file:`tests/foundation/engines/test_runtime_engines.py` it names those
    plus ``dpkt``, ``scapy`` and ``pyshark``. Keyed on the name alone, one
    module's requirements would be demanded of every other module that gates on
    it, or they would excuse it.

    A module that gates on a flag it imports resolves through the import, so
    ``tests/integration/test_cli_subprocess.py`` gets ``HAS_EMOJI``'s
    requirements from :file:`tests/integration/_helpers.py` where it is defined.

    """
    definitions = {}  # type: dict[str, dict[str, frozenset[str]]]
    for path in sorted(_tiers.TESTS_ROOT.rglob('*.py')):
        relative = path.relative_to(_tiers.ROOT).as_posix()
        definitions[relative] = module_flag_requirements(path)

    resolved = {}  # type: dict[tuple[str, str], frozenset[str]]
    for relative, flags in definitions.items():
        for flag, modules in flags.items():
            resolved[(relative, flag)] = modules

    for gate in gated_scopes():
        if (gate.module, gate.flag) in resolved:
            continue
        origin = _flag_imports(_tiers.ROOT / gate.module).get(gate.flag)
        if origin is not None and gate.flag in definitions.get(origin, {}):
            resolved[(gate.module, gate.flag)] = definitions[origin][gate.flag]
    return resolved


@functools.lru_cache(maxsize=1)
def flag_exclusions() -> 'dict[tuple[str, str], frozenset[str]]':
    """``(module, flag)`` -> the modules that flag needs *not* importable.

    The mirror of :func:`flag_requirements`, built the same way and for the
    same per-file reason (see that function's own docstring) -- and empty for
    every ``(module, flag)`` pair :func:`flag_requirements` resolves at all,
    except the handful with a genuine negated probe. See
    :func:`module_flag_exclusions` for why that handful matters.

    """
    definitions = {}  # type: dict[str, dict[str, frozenset[str]]]
    for path in sorted(_tiers.TESTS_ROOT.rglob('*.py')):
        relative = path.relative_to(_tiers.ROOT).as_posix()
        definitions[relative] = module_flag_exclusions(path)

    resolved = {}  # type: dict[tuple[str, str], frozenset[str]]
    for relative, flags in definitions.items():
        for flag, modules in flags.items():
            resolved[(relative, flag)] = modules

    for gate in gated_scopes():
        if (gate.module, gate.flag) in resolved:
            continue
        origin = _flag_imports(_tiers.ROOT / gate.module).get(gate.flag)
        if origin is not None and gate.flag in definitions.get(origin, {}):
            resolved[(gate.module, gate.flag)] = definitions[origin][gate.flag]
    return resolved


@functools.lru_cache(maxsize=1)
def gated_scopes() -> 'tuple[Gate, ...]':
    """Every ``skipUnless(HAS_*, ...)`` gate in a module :program:`pytest` collects.

    Restricted to ``test_*.py`` for the same reason
    :class:`~tests.test_tier_guard.FixtureTierSelectionTests` restricts its own
    scan: ``python_files`` in :file:`pyproject.toml` is what pytest collects, so
    a gate in a helper module gates nothing. Class-level and method-level
    decorators are both collected, and the class-level ones are the majority --
    when #745 was fixed, ``HAS_DPKT`` reached 20 methods through 6 class
    decorators and 8 through a method decorator -- counted by exact-match AST
    identifiers the way this function itself matches them, not by a substring
    search, which would (elsewhere) fold ``HAS_PYPCAP`` together with
    ``HAS_PYPCAPFILE``.

    """
    gates = []  # type: list[Gate]
    for path in sorted(_tiers.TESTS_ROOT.rglob('test_*.py')):
        gates.extend(module_gates(path, path.relative_to(_tiers.ROOT).as_posix()))
    return tuple(gates)


def module_gates(path: 'pathlib.Path', relative: 'Optional[str]' = None) -> 'tuple[Gate, ...]':
    """The gates of one module, in source order.

    Split out from :func:`gated_scopes` so it can be driven against a module
    written for the purpose, the way :func:`~tests.test_tier_guard.write_module`
    drives
    :func:`~tests._tiers.audit_module` -- a decorator written to be wrong cannot
    live in a module :program:`pytest` collects.

    """
    relative = relative if relative is not None else path.as_posix()
    try:
        tree = ast.parse(path.read_text(encoding='utf-8'))
    except (OSError, SyntaxError):
        return ()

    gates = []  # type: list[Gate]
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        gates.extend(_gates_of(node, relative, node.name))
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                gates.extend(_gates_of(child, relative, node.name))

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            gates.extend(_gates_of(node, relative, None))
    return tuple(sorted(gates, key=lambda gate: (gate.lineno, gate.flag)))


def _gates_of(node: 'ast.AST', relative: 'str', class_name: 'Optional[str]') -> 'Iterator[Gate]':
    """The ``HAS_*`` gates decorating one class or function definition."""
    func_name = None if isinstance(node, ast.ClassDef) else node.name  # type: ignore[attr-defined]
    for decorator in node.decorator_list:  # type: ignore[attr-defined]
        if not isinstance(decorator, ast.Call):
            continue
        attribute = decorator.func
        named = (attribute.attr if isinstance(attribute, ast.Attribute)
                 else attribute.id if isinstance(attribute, ast.Name) else '')
        if named != 'skipUnless':
            continue
        for inner in ast.walk(decorator):
            if isinstance(inner, ast.Name) and inner.id.startswith('HAS_'):
                lineno = node.lineno  # type: ignore[attr-defined]
                yield Gate(inner.id, relative, lineno, class_name, func_name)


def job_sections(text: 'str') -> 'dict[str, str]':
    """Every top-level job of the workflow, as name -> YAML body.

    A text slice rather than a YAML parse, for the reason
    :func:`~tests.test_tier_guard.job_section` gives: a two-space-indented
    ``key:`` line is what marks a job boundary in this file however its body is
    written, and that function slices one job the same way. The two are checked
    against each other so the duplication cannot drift.

    """
    body = re.search(r'(?ms)^jobs:\n(.*)\Z', text)
    if body is None:
        raise AssertionError(f'{WORKFLOW} has no jobs: block')

    sections = {}  # type: dict[str, str]
    for match in re.finditer(r'(?m)^  ([\w-]+):\n(.*?)(?=^  [\w-]+:\n|\Z)',
                             body.group(1), re.DOTALL):
        sections[match.group(1)] = match.group(2)
    return sections


def _engine_matrix_variants(name: 'str', section: 'str') -> 'Optional[tuple[Job, ...]]':
    """One :class:`Job` per ``matrix.engine`` cell, for a job shaped like ``engine-tests``.

    Returns :data:`None` when ``section`` shows no such structure, so
    :func:`pytest_jobs`'s caller falls back to its ordinary one-install-line
    reading. Detected on ``matrix.engine`` appearing at all, rather than on the
    job's name: this guard finds things by what a section *does*, the same
    rule :func:`pytest_jobs` already applies to the step that runs
    :program:`pytest`.

    ``engine-tests`` (#849) installs a shared baseline (``pip install -e
    '.[test]'``) and then, per cell, one more extra chosen by a ``case
    "$ENGINE" in ...`` block assigning ``EXTRA=``, and runs a *different*,
    explicit ``TEST_PATHS=`` list chosen by an identically-shaped ``case``
    in its pytest step. Modelling that as one :class:`Job` with every engine's
    extra and a ``'whole-suite'`` selection -- the reading a single static
    install-line/selection pair would produce -- is exactly the false
    confidence #745 exists to catch: it would credit the Scapy cell with
    PyPCAP's install and credit every cell with reaching every other engine's
    tests. One :class:`Job` per engine, sharing this job's ``name``, is what
    :func:`dependency_gate_gaps`'s ``(flag, job.name)`` aggregation expects --
    see :class:`Job`'s own docstring.

    Every regex below runs against a comment-stripped copy of ``section``
    (bare ``#``-prefixed lines dropped), not ``section`` itself. Without that,
    a *commented-out* ``ENGINE) TEST_PATHS="..."`` arm placed after the live
    one would silently win a later cell's entry -- ``dict()`` over
    ``re.findall()`` is last-wins -- which is the same comment-vs-code
    confusion #849's own cross-review found in this file's ``pip install -e``
    scan, relocated into this function's case-arm scan instead.

    This also, separately, asserts that the workflow's own ``engine:`` matrix
    list agrees with the ``case "$ENGINE" in ...`` arms it is supposed to
    describe: built purely from the case arms, the :class:`Job` entries would
    go on crediting an engine deleted from that list (the ordinary way to
    retire a cell) with coverage it does not have, silently.

    """
    code = '\n'.join(line for line in section.splitlines() if not line.strip().startswith('#'))

    if 'matrix.engine' not in code:
        return None

    declared_match = re.search(r'(?m)^[ \t]*engine:\n((?:[ \t]*-[ \t]*\w+[ \t]*\n)+)', code)
    if declared_match is None:
        raise AssertionError(
            f'the {name!r} job varies by matrix.engine but this guard found no '
            f"'engine:' matrix list of bare '- NAME' entries, and cannot tell which "
            f'engines the matrix itself declares'
        )
    declared_engines = frozenset(re.findall(r'-[ \t]*(\w+)', declared_match.group(1)))

    base_installs = EDITABLE_INSTALL.findall(code)
    if len(base_installs) != 1:
        raise AssertionError(
            f'the {name!r} job varies by matrix.engine but has {len(base_installs)} '
            f"baseline \"pip install -e '.[...]'\" lines, and this guard cannot tell "
            f'which extras every cell would always have'
        )
    base_extras = tuple(extra.strip() for extra in base_installs[0].split(','))

    engine_extra = dict(re.findall(r'(\w+)\)\s*EXTRA=(\w+);', code))
    engine_paths = {
        engine: tuple(paths.split())
        for engine, paths in re.findall(r'(\w+)\)\s*TEST_PATHS="([^"]+)"', code)
    }
    if not engine_paths:
        raise AssertionError(
            f'the {name!r} job varies by matrix.engine but this guard found no '
            f'\'ENGINE) TEST_PATHS="..."\' case mapping engine names to test paths, and '
            f'cannot tell what any cell runs'
        )

    case_engines = frozenset(engine_paths) | frozenset(engine_extra)
    if declared_engines != case_engines:
        only_declared = sorted(declared_engines - case_engines)
        only_case = sorted(case_engines - declared_engines)
        raise AssertionError(
            f'the {name!r} job\'s matrix.engine list ({sorted(declared_engines)}) does not '
            f'match the engines its \'case "$ENGINE" in ...\' arms cover '
            f'({sorted(case_engines)}): {only_declared} have no case arm, '
            f'{only_case} have a case arm but are not in the matrix list -- this guard '
            f'cannot tell which of the two is stale'
        )

    variants = []  # type: list[Job]
    for engine, paths in engine_paths.items():
        extra = engine_extra.get(engine)
        if extra is None:
            raise AssertionError(
                f'the {name!r} job runs {engine!r}\'s tests ({" ".join(paths)}) but this '
                f"guard found no matching 'ENGINE) EXTRA=...' case for it, and cannot tell "
                f'what that cell installs'
            )
        variants.append(Job(name, base_extras + (extra,), 'explicit', paths))
    return tuple(variants)


def pytest_jobs(workflow: 'Optional[pathlib.Path]' = None) -> 'tuple[Job, ...]':
    """The jobs of ``workflow`` that run :program:`pytest`.

    Keyed on running the suite, not on holding an install line: other
    workflows install ``.[all]`` somewhere, some as ``.[all,dev]`` -- which
    does carry ``pypcapfile``, through the ``dev`` extra #910 added when it
    narrowed ``all`` to core addons only -- and never invoke :program:`pytest`,
    so a guard that looked at install lines anywhere would pass vacuously. The
    exception, :file:`cron-vendor.yml`, runs only ``tests/const`` and
    ``tests/vendor``, over a freshly crawled tree, and a failure there discards
    modules rather than failing the job (#1853), so it is not read here either.
    Within this workflow the ``changelog`` job is excluded by the same rule; it
    installs nothing and runs a generator.

    The ``workflow`` argument exists so the guard can be pointed at a doctored
    copy and shown to fail; see
    :meth:`~tests.test_tier_guard.DependencyGateFalsifiabilityTests\
.test_removing_crypto_from_the_test_job_is_caught`.

    """
    text = (workflow or WORKFLOW).read_text(encoding='utf-8')
    jobs = []  # type: list[Job]
    for name, section in job_sections(text).items():
        # A KTLO job (#1738) writes its steps as a YAML alias of its gating
        # twin's -- `steps: *test-steps` -- so its slice holds no pytest line and
        # is skipped here: it installs and selects what the twin does, so it
        # reaches no gate the twin does not.
        if 'python -m pytest' not in section:
            continue

        variants = _engine_matrix_variants(name, section)
        if variants is not None:
            jobs.extend(variants)
            continue

        # Scoped to the step that runs pytest, not to the job, and found by what
        # the step does rather than by what it is called. Both matter: the
        # `gate` job's *comment* says "no --ignore, no tier selection" and the
        # `integration` job's names `fixture_tier_paths()`, so classifying on
        # the whole job section reads `gate` as an ignore-selection job and
        # credits it with reaching only the unit tier. Matching on the step name
        # would work only until a step is renamed.
        steps = re.findall(r'(?ms)^      - name: [^\n]*\n(.*?)(?=^      - name:|\Z)', section)

        # #1958: a step whose `if:` runs it on `latest` alone holds that leg's
        # install line, read apart from the one every leg runs.
        latest_steps = [step for step in steps if LATEST_LEG_CONDITION in step.partition('run:')[0]]
        latest_installs = [extras for step in latest_steps
                           for extras in EDITABLE_INSTALL.findall(step)]
        if len(latest_installs) > 1:
            raise AssertionError(
                f'the {name!r} job has {len(latest_installs)} latest-only '
                f"\"pip install -e '.[...]'\" lines, and this guard cannot tell which "
                f'extras that leg would have'
            )
        installs = EDITABLE_INSTALL.findall(section)
        installs = [extras for extras in installs if extras not in latest_installs] \
            if latest_installs else installs
        if len(installs) != 1:
            raise AssertionError(
                f'the {name!r} job runs pytest but has {len(installs)} '
                f"\"pip install -e '.[...]'\" lines, and this guard cannot tell which "
                f'extras the run would have'
            )
        running = [step for step in steps if 'python -m pytest' in step]
        if len(running) != 1:
            raise AssertionError(
                f'the {name!r} job runs pytest in {len(running)} of its steps, and this '
                f'guard reads the selection off exactly one of them'
            )

        run_block = running[0]
        tier = None  # type: Optional[str]
        if 'fixture_tier_paths' in run_block:
            selection = 'fixture-tier'
            # #1958: a step that asks for every tier on some leg reaches what that
            # leg runs; one that only ever asks for one tier reaches that tier.
            asked = set(re.findall(r"join\(fixture_tier_paths\(([^)]*)\)\)", run_block))
            if '' not in asked and len(asked) == 1:
                tier = ast.literal_eval(asked.pop())
        elif '--ignore' in run_block:
            selection = 'ignore'
        elif 'project_pin_paths' in run_block:
            selection = 'project-pins'
        else:
            selection = 'whole-suite'

        jobs.append(Job(name, tuple(extra.strip() for extra in installs[0].split(',')),
                        selection, tier=tier,
                        latest_extras=tuple(extra.strip() for extra in latest_installs[0].split(','))
                        if latest_installs else ()))
    return tuple(jobs)


def job_reaches(job: 'Job', gate: 'Gate') -> 'bool':
    """Whether ``job``'s selection would collect the tests ``gate`` guards.

    Each selection shape is answered its own way, and none of them
    reimplements the workflow's own list:

    * ``'whole-suite'`` reaches everything under :file:`tests/`.
    * ``'ignore'`` is the unit tier less the project pins (#1954), so
      :func:`~tests._tiers.is_unit_tier` and :func:`~tests._tiers.is_project_pin`
      answer it -- and
      :meth:`~tests.test_tier_guard.WorkflowAgreementTests\
.test_ignore_flags_match_the_fixture_tier_constants`
      is what keeps that equivalence true. It is the ``latest`` leg's: the
      others also leave out the ``LATEST`` test tier,
      :func:`~tests._tiers.latest_tier_paths` (#1958), which changes no answer,
      since every leg shares the job's one install line. The same holds for a
      ``'fixture-tier'`` job with a ``latest`` leg, whose other legs ask for the
      ``ALL`` tier alone.
    * ``'project-pins'`` is :func:`~tests._tiers.is_project_pin`, the job running
      exactly what :func:`~tests._tiers.project_pin_paths` prints.
    * ``'explicit'`` is exact membership in :attr:`Job.paths` -- the literal
      ``TEST_PATHS`` list a ``matrix.engine`` cell of ``engine-tests`` (#849)
      runs, at file granularity (that job names whole files, never node IDs).
    * ``'fixture-tier'`` is whatever
      :func:`~tests._tiers.fixture_tier_paths` returns for the job's
      :attr:`Job.tier`, which is what the job itself runs. Its node-ID entries
      are honoured at method granularity: a
      selection naming one method of a module does not reach a gate on a
      *different* method of it.

    "Reaches" means the job runs **at least one** test the gate guards, which is
    the question the guard is asking -- one missing extra makes every test under
    that gate skip, so one selected test is enough for the install line to
    matter. A node ID naming one method of a class therefore does reach a
    class-level gate on that class, even though the class's other methods run
    elsewhere; :class:`Gap` counts gate decorators rather than methods, so nothing
    is double-counted by that. The strict reading -- "every test the gate guards"
    -- would be the unsafe one, because it would let a job that runs one gated
    test out of three off the hook entirely.

    """
    if job.selection == 'whole-suite':
        return True
    if job.selection == 'ignore':
        return _tiers.is_unit_tier(gate.module) and not _tiers.is_project_pin(gate.module)
    if job.selection == 'project-pins':
        return _tiers.is_project_pin(gate.module)
    if job.selection == 'explicit':
        return gate.module in job.paths

    for entry in _tiers.fixture_tier_paths(job.tier):
        module, _, scope = entry.partition('::')
        if not scope:
            candidate = _tiers.ROOT / module
            if module == gate.module:
                return True
            if candidate.is_dir() and gate.module.startswith(module.rstrip('/') + '/'):
                return True
            continue
        if module != gate.module:
            continue
        parts = scope.split('::')
        if gate.func_name is None:
            if parts[0] == gate.class_name:
                return True
        elif parts[-1] == gate.func_name and (gate.class_name is None
                                              or gate.class_name in parts):
            return True
    return False


def dependency_gate_gaps(workflow: 'Optional[pathlib.Path]' = None) -> 'tuple[Gap, ...]':
    """Every gated test a :program:`pytest` job reaches without its dependency.

    Aggregated per ``(flag, job)`` rather than per gate: one missing extra
    darkens every gate on that flag at once, and a reader wants "the ``test``
    job reaches N ``HAS_CRYPTO`` methods and installs no ``cryptography``",
    not one copy of it per method.

    """
    requirements = flag_requirements()
    gaps = {}  # type: dict[tuple[str, str], tuple[set[str], list[Gate]]]

    for job in pytest_jobs(workflow):
        # #1958: a job's `latest` leg runs every test its other legs do, so a
        # gate it reaches runs there with that leg's extras too. The other legs
        # run the `ALL` tier with the job's own line, and skip what it lacks.
        available = frozenset(job.extras) | frozenset(job.latest_extras) | {CORE}
        for gate in gated_scopes():
            if gate.flag in NON_DISTRIBUTION_FLAGS:
                continue
            modules = requirements.get((gate.module, gate.flag))
            if not modules or not job_reaches(job, gate):
                continue

            missing = {module.partition('.')[0] for module in modules
                       if not (extras_providing(module) & available)}
            if not missing:
                continue
            entry = gaps.setdefault((gate.flag, job.name), (set(), []))
            entry[0].update(missing)
            entry[1].append(gate)

    return tuple(
        Gap(flag, job, tuple(sorted(missing)), tuple(gates))
        for (flag, job), (missing, gates) in sorted(gaps.items())
    )


def describe_gap(gap: 'Gap') -> 'str':
    """A failure message naming the flag, the job, the fix, and what goes dark."""
    extras = sorted(set().union(*(extras_providing(module) for module in gap.missing)))
    where = '\n'.join(
        f'    {gate.module}:{gate.lineno} '
        f'{gate.class_name or ""}{"::" if gate.class_name and gate.func_name else ""}'
        f'{gate.func_name or ""}'.rstrip()
        for gate in gap.gates
    )
    return (
        f"the {gap.job!r} job of .github/workflows/unit-tests.yml reaches {len(gap.gates)} "
        f'{gap.flag} gate(s), and nothing in its \"pip install -e \'.[...]\'\" line '
        f'provides: {", ".join(gap.missing)} -- so they skip, and `pytest -q` prints neither the '
        f'skip count against this flag nor its reason, which is how #729 and #738 stayed '
        f'invisible for months. Add one of the extras {extras} to that job\'s install '
        f'line, or record the gap in tests._dependency_gates.'
        f'DEPENDENCY_GATE_EXCLUSIONS with a reason.\n{where}'
    )


def _disqualified_providers(excluded_modules: 'frozenset[str]') -> 'frozenset[str]':
    """Distributions a flag's own negation rules out, exact entries only.

    Deliberately does *not* fall back to a top-level entry the way
    :func:`module_providers` does for a *required* module: an excluded module
    with no entry of its own would otherwise borrow its top-level package's
    whole provider set, and if that top-level name is itself contested (in
    :data:`MUTUALLY_EXCLUSIVE_IMPORTS`) the borrowed set disqualifies *every*
    candidate rather than the one the negation actually names -- a finding
    with a wrong diagnosis rather than the right one, or none at all. Failing
    loudly and naming what is missing is the fix; a caller is only ever
    exposed to this for a module that is actually reached by a real gate,
    since :func:`ambiguous_satisfactions` only calls this once it has already
    confirmed the *required* module it is checking is contested -- an
    excluded module unrelated to any contested name never reaches here at
    all.

    """
    disqualified = set()  # type: set[str]
    for excluded in excluded_modules:
        exact = MODULE_PROVIDERS.get(excluded)
        if exact is None:
            top_level = excluded.partition('.')[0]
            if top_level in MUTUALLY_EXCLUSIVE_IMPORTS:
                raise AssertionError(
                    f'{excluded!r} is excluded by a negated probe but has no exact '
                    f'MODULE_PROVIDERS entry, and its top-level {top_level!r} is in '
                    f'MUTUALLY_EXCLUSIVE_IMPORTS -- falling back to that entry would '
                    f"disqualify more than the negation actually names. Add a "
                    f'dedicated MODULE_PROVIDERS[{excluded!r}] entry.'
                )
            continue  # not contested; module_providers()'s ordinary fallback is fine
        disqualified.update(exact)
    return frozenset(disqualified) - {CORE}


def ambiguous_satisfactions(
    workflow: 'Optional[pathlib.Path]' = None,
) -> 'tuple[AmbiguousProvider, ...]':
    """Every satisfied gate resolved through the wrong half of a contested import name.

    :func:`dependency_gate_gaps` only ever asks "does at least one distribution
    this job installs ship this module" -- which is blind to *which* one.
    ``pcap`` is shipped by both ``pypcap`` and ``pcap-ct``, and (via that
    function's own top-level truncation) so, as far as it can tell, is
    ``pcap._pcap``. A job that installed the wrong one of the two would still
    read as satisfied there; see this module's own docstring for the full
    shape of that gap (#762).

    This is the check that notices, scoped to exactly the names
    :data:`MUTUALLY_EXCLUSIVE_IMPORTS` declares genuinely contested --
    deliberately *not* every name :data:`MODULE_PROVIDERS` lists more than one
    requirement string for. ``html5lib`` also has two entries there, and is
    not this: both name the same one distribution reached two ways, not two
    distributions that could each independently win the import, so scoping on
    ``len(MODULE_PROVIDERS[...]) > 1`` instead would false-positive on it the
    moment some job gained the ``vendor`` extra.

    For a gated module in that set, the *true* set of distributions that would
    actually leave the flag true is :func:`module_providers`'s exact-path
    reading of the module (already narrower for ``pcap._pcap``, which only
    ``pcap-ct`` really ships) minus whatever :func:`module_flag_exclusions`
    says the same flag needs *absent* (which is how ``HAS_PYPCAP`` -- true
    only when ``pcap._pcap`` is *not* importable -- prunes ``pcap-ct`` back
    out of plain ``pcap``'s two-wide entry, with no table to hand-maintain).
    A finding is reported when what :func:`dependency_gate_gaps` would call
    "satisfied" disagrees with that true set: resolving to a distribution
    outside it (the #762 shape -- the job installed the wrong half), or to
    more than one distribution even inside it (genuinely still ambiguous).

    A module no installed extra resolves to any distribution for is what
    :func:`dependency_gate_gaps` already reports as a :class:`Gap`, so it is
    skipped here too rather than duplicated.

    """
    requirements = flag_requirements()
    exclusions = flag_exclusions()
    declared = declared_requirements()
    findings = []  # type: list[AmbiguousProvider]

    for job in pytest_jobs(workflow):
        available_extras = frozenset(job.extras) | {CORE}
        for gate in gated_scopes():
            if gate.flag in NON_DISTRIBUTION_FLAGS:
                continue
            modules = requirements.get((gate.module, gate.flag))
            if not modules or not job_reaches(job, gate):
                continue

            for module in modules:
                if module.partition('.')[0] not in MUTUALLY_EXCLUSIVE_IMPORTS:
                    continue

                # Only computed once the module above is confirmed contested,
                # not for every gate this job reaches: an excluded module with
                # no MODULE_PROVIDERS entry of its own raises here (see
                # _disqualified_providers), and a flag with nothing to do with
                # a contested name must never pay for that (#762).
                excluded_modules = exclusions.get((gate.module, gate.flag), frozenset())
                disqualified = _disqualified_providers(excluded_modules)

                providers = _top_level_providers(module)
                satisfied = frozenset(
                    provider for provider in providers
                    if provider == CORE or any(
                        provided_by(declared[extra], provider)
                        for extra in available_extras if extra in declared
                    )
                )
                if not satisfied:
                    continue  # dependency_gate_gaps already reports this as a Gap

                valid = module_providers(module) - disqualified
                if satisfied == (satisfied & valid) and len(satisfied) <= 1:
                    continue  # everything that resolved is legitimate, and unambiguous

                findings.append(AmbiguousProvider(gate.flag, job.name, module,
                                                  frozenset(providers), satisfied, valid))

    seen = set()  # type: set[tuple[str, str, str]]
    unique = []  # type: list[AmbiguousProvider]
    for finding in findings:
        key = (finding.flag, finding.job, finding.module)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    return tuple(sorted(unique, key=lambda finding: (finding.flag, finding.job, finding.module)))


def describe_ambiguous_satisfaction(finding: 'AmbiguousProvider') -> 'str':
    """A failure message naming the flag, the job, and why the satisfaction is untrusted."""
    illegitimate = sorted(finding.satisfied - finding.valid)
    if illegitimate:
        verdict = (
            f'it resolves to {illegitimate}, which the flag\'s own negated probe '
            f'excludes (module_flag_exclusions), not to {sorted(finding.valid)}'
        )
    else:
        verdict = (
            f'it resolves to more than one legitimate distribution at once, '
            f'{sorted(finding.satisfied)}'
        )
    return (
        f"the {finding.job!r} job reaches a {finding.flag} gate satisfied through "
        f'{finding.module!r}, which more than one distribution ships '
        f'({sorted(finding.providers)}) -- {verdict}. This is the #762 shape: a job '
        f'installing the wrong half of an ambiguous shared import name would read as '
        f'satisfied purely because it installs *some* distribution that ships the same '
        f'top-level module. Fix the job\'s install line, or -- if the flag\'s own probe '
        f'genuinely cannot distinguish the two -- correct '
        f'tests._dependency_gates.MODULE_PROVIDERS or the flag\'s negated probe so it can.'
    )
