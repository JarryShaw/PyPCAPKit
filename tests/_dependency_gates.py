# -*- coding: utf-8 -*-
"""Which CI job installs the dependency each ``HAS_*`` gate asks for.

:mod:`tests._tiers` answers "may this module read that capture". This module
answers the neighbouring question that nothing asked before: **when a test is
gated on an optional dependency, does the job whose selection reaches that test
actually install it?**

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
   14 methods are gated by two class decorators.
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
python_version < '3.12'" ]`` resolves to nothing on three of the five matrix
legs, so an install line carrying that extra would satisfy this module while
two legs ran the tests and three went on skipping them. :func:`requirement_key`
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
    'WORKFLOW', 'PYPROJECT', 'CORE', 'MODULE_PROVIDERS', 'NON_DISTRIBUTION_FLAGS',
    'MUTUALLY_EXCLUSIVE_IMPORTS', 'DEPENDENCY_GATE_EXCLUSIONS',
    'Requirement', 'Gate', 'Job', 'Gap', 'Exclusion', 'AmbiguousProvider',
    'requirement_key', 'provided_by', 'declared_requirements', 'extras_providing',
    'module_providers', 'contested_imports',
    'gated_scopes', 'module_gates', 'flag_requirements', 'module_flag_requirements',
    'flag_exclusions', 'module_flag_exclusions',
    'pytest_jobs', 'job_sections',
    'job_reaches', 'dependency_gate_gaps', 'describe_gap',
    'ambiguous_satisfactions', 'describe_ambiguous_satisfaction',
]

#: The workflow holding every job that runs :program:`pytest`, and the only one
#: that runs it at all. Five of the other seven install ``.[all]`` somewhere --
#: a docs build, a conda recipe, a vendor crawl, the lint pass, and the release
#: packaging workflow -- and none of them invokes the suite;
#: :file:`python-compatibility.yml` installs a bare ``.`` and only compiles and
#: imports, and :file:`codeql-analysis.yml` installs nothing explicitly at all
#: (CodeQL's own autobuild step). That is exactly why this module keys on *jobs that
#: run pytest* rather than on install lines anywhere in the workflow tree:
#: ``.[all]`` carries ``pypcapfile``, ``pyshark`` and ``scapy``, so a guard
#: reading those lines would satisfy nearly every flag here vacuously.
WORKFLOW = _tiers.ROOT / '.github' / 'workflows' / 'unit-tests.yml'
#: Where the extras are declared.
PYPROJECT = _tiers.ROOT / 'pyproject.toml'

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
    # ``beautifulsoup4`` ships ``bs4``; ``html5lib`` is an *extra of* that
    # distribution, so ``beautifulsoup4`` alone does not provide it. That
    # distinction is the whole reason ``HAS_CRAWLER_DEPS`` is satisfied in CI
    # and ``HAS_VENDOR_DEPS`` is not: the ``test`` extra carries plain
    # ``beautifulsoup4``, and only ``vendor`` and ``all`` carry
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
}

#: Flags whose condition is not a distribution, with what it is instead. A flag
#: here needs no :data:`MODULE_PROVIDERS` entry and can never be a gap, because
#: no install line could close it.
NON_DISTRIBUTION_FLAGS = {
    'HAS_PROC_FD': (
        'asks whether /proc/self/fd is a directory, i.e. whether this kernel '
        'exposes the procfs file-descriptor listing -- nothing pip installs'
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
            "\"python_version < '3.12'\" marker: adding it would mean a toolchain step on "
            'the 3.10 and 3.11 legs and nothing at all on the other three. #738 records '
            'the same exclusion, if less precisely -- pypcap needs the headers, pcap-ct '
            'below does not. The flag also requires pcap._pcap to be *absent*, which is '
            "how it tells upstream pypcap from pcap-ct; see this module's docstring.\n\n"
            "#751's ruling was to try building it in CI rather than declining it forever "
            '-- "try to build and if the CI is not a good suit, then we ripe it" -- so '
            'the new pypcap-parity job now installs a toolchain plus libpcap headers and '
            'attempts it on the 3.10/3.11 legs the marker allows. integration and gate '
            'stay dark deliberately: the ruling on #751 was a dedicated job, not one '
            "more install line on either of those two. If pypcap-parity's build step "
            'turns out not to be a good fit for CI, the fix is deleting that job and '
            'widening this exclusion to name it too, with the failing run linked.'
        ),
    ),
    'HAS_PCAP_CT': Exclusion(
        dark={'test': ('pcap',), 'gate': ('pcap',)},
        reason=(
            'pcap-ct needs no toolchain, contrary to how #738 grouped it with pypcap: it '
            'and libpcap both publish py3-none-any wheels. Two other reasons stand, '
            'though. Both are published only as pre-releases, which is why '
            'pyproject.toml keeps them out of the all extra -- and its ctypes loader '
            'still calls find_library("pcap"), so a system libpcap has to be present on '
            'the runner at run time. A green install would therefore not imply the '
            'engine can start.\n\n'
            "#751's dedicated engine-tests job now takes this: it installs PCAP_CT and a "
            'system libpcap (apt-get libpcap0.8) across the full 3.10-3.14 matrix, kept '
            'in a venv of its own since pypcap and pcap-ct both install a top-level '
            '``pcap`` module and cannot coexist -- see '
            "pcapkit/foundation/engines/_pcap_backend.py's own docstring. test and gate "
            "stay dark on purpose, per #751's ruling that per-engine coverage gets its "
            'own job rather than one more install line on either.'
        ),
    ),
    'HAS_PYPCAPFILE': Exclusion(
        dark={'test': ('pcapfile',), 'integration': ('pcapfile',), 'gate': ('pcapfile',)},
        reason=(
            'Not, any longer, because the tests fail: the two bugs that made installing '
            'the extra turn 7 skips into 7 failures are fixed (#747 in the toolkit, #748 '
            'in the engine), which is what #745 excluded this flag "pending". The '
            'remaining obstacle is the marker. PyPCAPFile is declared '
            "\"pypcapfile; python_version < '3.12'\", because released 0.12.0 imports the "
            'imp module that 3.12 removed, so the extra resolves to nothing on three of '
            'the five matrix legs. Adding it would satisfy this guard -- which does not '
            'model markers -- while 3.12, 3.13 and 3.14 went on skipping: two legs of '
            'real coverage bought with exactly the false confidence #745 exists to '
            "remove.\n\n"
            "#751's ruling was to take that trade: engine-tests now installs PyPCAPFile "
            "across the full 3.10-3.14 matrix, covering the 9 HAS_PYPCAPFILE methods in "
            'test_pypcapfile_unit.py on the 3.10/3.11 legs where the marker lets it '
            'resolve, and pypcap-parity does the same for the other 6 in '
            'test_new_engine_parity_runtime.py. This guard still cannot see that only '
            'two of five legs run for real -- it does not evaluate markers, by this '
            "module's own docstring -- so that partial coverage is recorded here in "
            'prose rather than modelled: the alternative, teaching this guard markers, '
            'is out of scope for a workflow-only change. test, integration and gate stay '
            "dark on purpose, per #751's ruling that per-engine coverage gets its own "
            'job rather than one more install line on any of the three.'
        ),
    ),
    'HAS_VENDOR_DEPS': Exclusion(
        dark={'test': ('html5lib',), 'gate': ('html5lib',)},
        reason=(
            "Ruled onto a non-blocking leg by #738's option (b), on the premise that the "
            'crawlers fetch from IANA and Wikipedia and #518 records four Wikipedia 403s '
            'and a dead IETF URL -- so a blocking leg would go red on upstream '
            'availability rather than on this code. Note what is actually missing, which '
            "#738's own inventory gets wrong: requests and bs4 have shipped in the test "
            'extra since #507 and are installed on every job, so these classes are one '
            '*requirement extra* short -- html5lib, which only beautifulsoup4[html5lib] '
            'provides, i.e. the vendor and all extras.\n\n'
            'engine-tests (#751) is that leg. It already mirrors test\'s ignore-shape '
            'exactly (same --ignore flags), so it already reached these unit-tier '
            'HAS_VENDOR_DEPS gates; adding vendor to its install line is what closes '
            'them, and #738\'s own precedent for a job that "exists and reports" without '
            "gating a merge -- 3.15 in python-compatibility.yml (b7f51401b) -- already "
            'describes this job: "Engines Python X" has never been one of ruleset '
            "23497679's 15 required checks, so it was already the non-blocking leg the "
            'ruling asked for, and no new job was needed to get one. It is also the only '
            '*per-pull-request* job with that property: gate reaches these gates too but '
            "never runs on a pull request at all (only via a release's "
            "gate-only: true call), and integration's fixture-tier selection never "
            'reaches tests/vendor/ in the first place -- so engine-tests was the forced '
            'choice, not merely a convenient one.\n\n'
            'test and gate stay dark for different reasons, not the same one. test '
            'declines html5lib per the non-blocking-leg ruling itself -- that is the '
            'whole reason it is dark. gate is not part of the blocking matrix at all -- '
            "it only runs on the release path (workflow_call's gate-only: true), never "
            'on a pull request -- so the ruling does not require it dark; nothing about '
            '"non-blocking" would stop vendor being added there too. It stays dark on a '
            'separate, substantive ground instead: by the time a commit reaches the '
            'release path it has already run test, integration and engine-tests, and '
            'engine-tests already carries vendor, so gate would be re-verifying coverage '
            'that already ran rather than adding any. Gaining a network-and-parser '
            'extra on the one job that gates an actual release, for coverage the release '
            'path already has by the time it runs, is not worth the footprint.\n\n'
            'Worth recording since it bears on the ruling itself, though this exclusion '
            'is not the place to relitigate it: none of the 41 methods this closes make '
            'a live network call, though not for one reason across all four files. '
            'test_user_agent_unit.py (11 methods) and test_request_prompt_unit.py (16) '
            'gate on HAS_VENDOR_DEPS only because the pcapkit.vendor package import '
            'chain needs requests/bs4/html5lib importable -- html5lib itself is never '
            "used by either file's test bodies, both of which replace requests.get with "
            "a recorder for the whole of every case (each file's own module docstring "
            'says so in its own words, not a shared one). test_ipx_packet_unit.py (9 '
            'methods) is a regression suite for a *retired* scrape -- Packet.LINK is '
            'None, so _request() short-circuits before ever calling requests.get, and '
            'test_request_makes_no_network_call asserts exactly that by making '
            'requests.get and requests.Session.request raise if reached at all; '
            'html5lib is an import precondition there too, nothing in the file uses it. '
            'test_ftp_return_code_unit.py (5 methods) is not retired -- '
            'pcapkit.vendor.ftp.return_code.ReturnCode.LINK is a live Wikipedia URL -- '
            'and is the one file where html5lib is a *functional* dependency rather '
            'than an import precondition: its tests build the HTML fixture inline and '
            "hand it straight to ReturnCode.request(), which is "
            "bs4.BeautifulSoup(text, 'html5lib'); what keeps it off the network is the "
            'fixture being inline, not an absence of html5lib use. '
            "#518's flakiness is real for HAS_CRAWLER_DEPS's live crawlers, which run "
            'unconditionally since #507; it does not describe any of the above. '
            'pypcap-parity does not appear here even though it also declines html5lib, '
            'because its fixture-tier selection never reaches '
            'tests/vendor/test_ipx_packet_unit.py or its three siblings in the first '
            'place -- same shape as integration above it, which is why integration is '
            'not listed either.'
        ),
    ),
    'HAS_SCAPY': Exclusion(
        dark={'test': ('scapy',)},
        reason=(
            'Known, not new: #738 set it aside precisely because Scapy is installed on '
            'the integration and gate legs, so "they are dark only on the test leg". The '
            'test job declines Scapy on cost grounds -- its own install-step comment '
            'contrasts DPKT, which "costs nothing per leg", with Scapy. What was never '
            'written down is the consequence: the 10 methods it darkens '
            '(test_scapy_unit.py 5, test_scapy_engine.py 2, and one each in '
            'test_core.py, test_misc.py and test_sctp_unit.py) are all unit-tier, so the '
            'integration job never reaches them either. The gate job does, but it runs '
            "only where a caller passes gate-only: true -- the three Saturday schedules "
            '(deploy-pages, cron-vendor, cron-conda) and a v* release tag -- never on a '
            'pull request or a push to main. So no per-PR leg runs them at all.\n\n'
            "#751's engine-tests job now installs Scapy across the full 3.10-3.14 "
            'matrix, closing the "no per-PR leg" problem this exclusion used to '
            'describe -- it reaches 10 of this guard\'s 14 HAS_SCAPY methods, the same '
            'unit-tier subset #738 counted; the other 4 live in tests/integration/ or '
            "match the *_runtime.py ignore-glob, already covered by Scapy on the "
            "integration and gate jobs. test stays dark on purpose: the ruling on #751 "
            'was a dedicated job precisely so test would not have to reconsider the '
            'cost question it already answered.'
        ),
    ),
    'HAS_PYSHARK': Exclusion(
        dark={'test': ('pyshark',), 'integration': ('pyshark',), 'gate': ('pyshark',)},
        reason=(
            'One of #738\'s seven, left out of #740\'s "cheap, uncontroversial subset" '
            'and never since installed, so its 4 gated methods run nowhere. Three of them '
            'assert what PyShark.unsupported_reason says on an interpreter where the '
            'engine cannot work, so they need the distribution importable to have '
            'anything to ask.\n\n'
            "#751's later ruling asked to try a tshark binary the same way it asked to "
            'try building pypcap: "try to build and if the CI is not a good suit, then '
            'we ripe it… same for HAS_PYSHARK on tshark dependency." '
            'test_the_reason_tracks_the_running_interpreter used to call '
            'PyShark.unsupported_reason() unpatched and hard-assert the reason names '
            '"tshark" on every version below the asyncio ceiling -- true only while '
            'tshark stayed absent, and it would have turned that assertion from a pass '
            'into a failure the moment tshark was installed. Fixed by probing the same '
            'way PyShark.unsupported_reason() itself does -- pyshark\'s own '
            "get_process_path(), not shutil.which(), which its own config.ini "
            'precedence can make disagree with -- matching what its sibling '
            'test_this_host_really_has_no_tshark_so_the_check_is_not_vacuous already '
            'used, so the file no longer disagrees with itself about whether tshark may '
            'be present. engine-tests now installs both the distribution and tshark '
            '(apt-get, with a debconf pre-seed so the postinst prompt does not block) '
            'across the full 3.10-3.14 matrix, closing the test-job gap this exclusion '
            "used to describe. integration and gate stay dark on purpose, per #751's "
            'ruling that per-engine coverage gets its own job.'
        ),
    ),
    'HAS_RUNTIME': Exclusion(
        dark={'test': ('pyshark', 'scapy'), 'gate': ('pyshark',)},
        reason=(
            "Absent from #738's inventory of seven, and the one gap this guard found "
            "that no earlier pass did. Every other module's HAS_RUNTIME asks only for "
            'the four core dependencies, which pip install -e . always provides; '
            'tests/foundation/engines/test_runtime_engines.py reuses the name for those '
            'four plus dpkt, scapy and pyshark, so its two classes (5 methods) skip '
            'wherever any of the three is absent. It is unit-tier despite the name, '
            'because the ignore-glob is *_runtime.py and the file is '
            'test_runtime_engines.py, so the test job is what reaches it. The narrow '
            'fix -- giving that flag a name of its own, so the skip reason says which '
            'dependency was missing -- is left for a follow-up: it touches a test '
            "module #751 did not otherwise need to change, and this guard does not "
            'care what a flag is named, only whether the job that reaches it installs '
            'what it asks for.\n\n'
            "#751's engine-tests job installs DPKT, Scapy and PyShark together, closing "
            "this gap as a side effect of the per-engine extras rather than a separate "
            'install line: all 5 methods run wherever engine-tests does. test and gate '
            'stay dark on purpose, for the same reason HAS_SCAPY and HAS_PYSHARK above '
            'do.'
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
    """A job of :data:`WORKFLOW` that runs :program:`pytest`."""

    #: Job name as the workflow spells it.
    name: 'str'
    #: Extras of its ``pip install -e '.[...]'`` line, in declaration order.
    extras: 'tuple[str, ...]'
    #: How the job selects tests: ``'fixture-tier'`` when it asks
    #: :func:`~tests._tiers.fixture_tier_paths` for the selection,
    #: ``'ignore'`` when it subtracts ``--ignore`` flags from the whole suite,
    #: ``'whole-suite'`` when it passes no selection at all.
    selection: 'str'


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

    Deliberately not a PEP 508 parser: it handles the four things the extras in
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
    satisfies, from ``HAS_VENDOR_DEPS``, which it does not.

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

    A targeted scan rather than :mod:`tomllib`, which is 3.11+ while the
    ``test`` job's matrix floor is 3.10 -- and a guard that skips on one leg of
    five is the shape of invisibility this whole module exists to remove.
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


def module_providers(module: 'str') -> 'frozenset[str]':
    """Every distribution (or :data:`CORE`) :data:`MODULE_PROVIDERS` says could ship ``module``.

    Unlike :func:`extras_providing`, which this deliberately does not touch,
    keyed on the dotted path *exactly as given* when :data:`MODULE_PROVIDERS`
    has a dedicated entry for it -- ``pcap._pcap`` resolves to ``('pcap-ct',)``
    alone rather than falling back to plain ``pcap``'s two-wide entry. Falls
    back to the top-level package otherwise, the same rule
    :func:`extras_providing` always uses, which is what makes an unmapped
    module a failure there rather than a silent pass here too (the fallback
    can raise :exc:`KeyError` exactly as that function's own lookup does).

    :func:`ambiguous_satisfactions` is the reason this exists: it needs the
    narrower, exact-path answer to tell a distribution that genuinely,
    uniquely ships a submodule apart from the wider set that merely ships its
    top-level package -- see that function's own docstring.

    """
    return frozenset(MODULE_PROVIDERS.get(module, MODULE_PROVIDERS[module.partition('.')[0]]))


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

    Raises :exc:`KeyError` for a module with no :data:`MODULE_PROVIDERS` entry,
    which is what makes a newly gated dependency a failure rather than a pass.

    """
    providers = MODULE_PROVIDERS[module.partition('.')[0]]
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

    ``want_negated`` picks which side this call collects: :data:`False` (the
    default, and every call site before :func:`module_flag_exclusions` existed)
    yields the positively-required modules, as before. :data:`True` yields the
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
    time, rather than against whichever of them the suite happens to use today.

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

    Resolved per file rather than per flag name, which matters for exactly one
    flag and matters a lot: ``HAS_RUNTIME`` names the four core dependencies in
    every module but one, and in
    :file:`tests/foundation/engines/test_runtime_engines.py` it names those four
    plus ``dpkt``, ``scapy`` and ``pyshark``. Keyed on the name alone, that one
    module's requirements would be demanded of the 130 others, or the 130 would
    excuse it.

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
    ``HAS_DPKT`` reaches 20 methods through 6 class decorators and 8 through a
    method decorator -- counted by exact-match AST identifiers the way this
    function itself matches them, not by a substring search, which would
    (elsewhere) fold ``HAS_PYPCAP`` together with ``HAS_PYPCAPFILE``.

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


def pytest_jobs(workflow: 'Optional[pathlib.Path]' = None) -> 'tuple[Job, ...]':
    """The jobs of ``workflow`` that run :program:`pytest`.

    Keyed on running the suite, not on holding an install line: seven other
    workflows install ``.[all]`` -- which does carry ``pypcapfile`` -- and never
    invoke :program:`pytest`, so a guard that looked at install lines anywhere
    would pass vacuously. Within this workflow the ``changelog`` job is
    excluded by the same rule; it installs nothing and runs a generator.

    The ``workflow`` argument exists so the guard can be pointed at a doctored
    copy and shown to fail; see
    :meth:`~tests.test_tier_guard.DependencyGateFalsifiabilityTests\
.test_removing_crypto_from_the_test_job_is_caught`.

    """
    text = (workflow or WORKFLOW).read_text(encoding='utf-8')
    jobs = []  # type: list[Job]
    for name, section in job_sections(text).items():
        if 'python -m pytest' not in section:
            continue

        installs = re.findall(r"pip install -e '\.\[([^]]*)\]'", section)
        if len(installs) != 1:
            raise AssertionError(
                f'the {name!r} job runs pytest but has {len(installs)} '
                f"\"pip install -e '.[...]'\" lines, and this guard cannot tell which "
                f'extras the run would have'
            )

        # Scoped to the step that runs pytest, not to the job, and found by what
        # the step does rather than by what it is called. Both matter: the
        # `gate` job's *comment* says "no --ignore, no tier selection" and the
        # `integration` job's names `fixture_tier_paths()`, so classifying on
        # the whole job section reads `gate` as an ignore-selection job and
        # credits it with reaching only the unit tier. Matching on the step name
        # would work today and break the day a step is renamed.
        steps = re.findall(r'(?ms)^      - name: [^\n]*\n(.*?)(?=^      - name:|\Z)', section)
        running = [step for step in steps if 'python -m pytest' in step]
        if len(running) != 1:
            raise AssertionError(
                f'the {name!r} job runs pytest in {len(running)} of its steps, and this '
                f'guard reads the selection off exactly one of them'
            )

        run_block = running[0]
        if 'fixture_tier_paths' in run_block:
            selection = 'fixture-tier'
        elif '--ignore' in run_block:
            selection = 'ignore'
        else:
            selection = 'whole-suite'

        jobs.append(Job(name, tuple(extra.strip() for extra in installs[0].split(',')),
                        selection))
    return tuple(jobs)


def job_reaches(job: 'Job', gate: 'Gate') -> 'bool':
    """Whether ``job``'s selection would collect the tests ``gate`` guards.

    The three selection shapes are answered three ways, and none of them
    reimplements the workflow's own list:

    * ``'whole-suite'`` reaches everything under :file:`tests/`.
    * ``'ignore'`` is the unit tier, so :func:`~tests._tiers.is_unit_tier`
      answers it -- and
      :meth:`~tests.test_tier_guard.WorkflowAgreementTests\
.test_ignore_flags_match_the_fixture_tier_constants`
      is what keeps that equivalence true.
    * ``'fixture-tier'`` is whatever
      :func:`~tests._tiers.fixture_tier_paths` returns, which is what the job
      itself runs. Its node-ID entries are honoured at method granularity: a
      selection naming one method of a module does not reach a gate on a
      *different* method of it.

    "Reaches" means the job runs **at least one** test the gate guards, which is
    the question the guard is asking -- one missing extra makes every test under
    that gate skip, so one selected test is enough for the install line to
    matter. A node ID naming one method of a class therefore does reach a
    class-level gate on that class, even though the class's other methods run
    elsewhere; :data:`Gap` counts gate decorators rather than methods, so nothing
    is double-counted by that. The strict reading -- "every test the gate guards"
    -- would be the unsafe one, because it would let a job that runs one gated
    test out of three off the hook entirely.

    """
    if job.selection == 'whole-suite':
        return True
    if job.selection == 'ignore':
        return _tiers.is_unit_tier(gate.module)

    for entry in _tiers.fixture_tier_paths():
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
    job reaches 14 ``HAS_CRYPTO`` methods and installs no ``cryptography``",
    not fourteen copies of it.

    """
    requirements = flag_requirements()
    gaps = {}  # type: dict[tuple[str, str], tuple[set[str], list[Gate]]]

    for job in pytest_jobs(workflow):
        available = frozenset(job.extras) | {CORE}
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
    requirement string for for. ``html5lib`` also has two entries there, and
    is not this: both name the same one distribution reached two ways, not two
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
                # a contested name must never pay for that -- see this
                # function's own history (#762 round 3).
                excluded_modules = exclusions.get((gate.module, gate.flag), frozenset())
                disqualified = _disqualified_providers(excluded_modules)

                providers = MODULE_PROVIDERS[module.partition('.')[0]]
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
