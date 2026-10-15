GitHub Actions Workflows
========================

.. important::

   The thirteen workflows under :file:`.github/workflows/` trigger each other, and
   the chain that results is not visible from any single file -- reading one
   ``on:`` block never shows what a *different* workflow's completion goes on
   to start. This page is the repository-wide graph. The release *pipeline*
   itself, job by job from a version bump to a published package, is on
   :doc:`releasing`.

At a Glance
-----------

.. list-table::
   :header-rows: 1

   * - Workflow
     - File
     - ``push``
     - ``pull_request``
     - ``schedule``
     - ``workflow_run`` (from)
     - other
   * - CodeQL
     - :file:`codeql-analysis.yml`
     - ``main``
     - ``main``
     - Sat 02:00
     - --
     - --
   * - Unit Tests
     - :file:`unit-tests.yml`
     - ``main``
     - ``main``
     - --
     - --
     - ``workflow_call`` (reusable)
   * - Experimental Tests
     - :file:`experimental.yml`
     - ``main``
     - ``main``
     - --
     - --
     - --
   * - Python Compatibility
     - :file:`python-compatibility.yml`
     - ``main``
     - ``main``
     - Sat 04:00
     - --
     - --
   * - Lint
     - :file:`lint.yml`
     - --
     - ``main``
     - Sat 06:00
     - --
     - ``workflow_dispatch``
   * - Vendor Update
     - :file:`cron-vendor.yml`
     - --
     - --
     - Sat 10:00
     - **Unit Tests**
     - --
   * - Conda Update
     - :file:`cron-conda.yml`
     - --
     - --
     - Sat 10:00
     - **Unit Tests**
     - --
   * - GitHub Pages
     - :file:`deploy-pages.yml`
     - --
     - ``main``
     - Sat 02:00
     - **Unit Tests**
     - --
   * - Create Release
     - :file:`create-release.yml`
     - tags ``v*``
     - --
     - --
     - **Vendor Update**
     - --
   * - Project Status
     - :file:`project-status.yml`
     - --
     - --
     - daily 00:37
     - --
     - ``issues``, ``pull_request_target``, ``workflow_dispatch``
   * - Coverage Comment
     - :file:`coverage-comment.yml`
     - --
     - --
     - --
     - **Unit Tests**
     - --
   * - CI Timing
     - :file:`ci-timing.yml`
     - --
     - --
     - Mon 07:23
     - --
     - ``workflow_dispatch``
   * - Python Versions
     - :file:`cron-python-versions.yml`
     - --
     - --
     - Mon 05:41
     - --
     - ``workflow_dispatch``

.. note::

   Only Coverage Comment fires *exclusively* on ``workflow_run``: it has
   nothing to do without a completed Unit Tests run. Each of the other four
   that carry one pairs it with a direct trigger of its own -- a Saturday
   ``schedule`` for Vendor Update, Conda Update and GitHub Pages, a ``v*`` tag
   push for Create Release -- for the path where no upstream run exists yet to
   chain from.

The Graph
---------

Solid arrows are direct triggers (``push``, ``pull_request``, ``schedule``,
``workflow_dispatch``). Thick arrows are ``workflow_run`` edges -- a
*separate* run, started only after the upstream workflow's run has fully
completed. Dotted arrows are ``uses:`` edges -- a reusable-workflow call that
runs synchronously *inside* the caller's own run, sharing its run id rather
than starting a new one.

.. mermaid::

   flowchart TD
       PUSH["push: main"]
       PR["pull_request: main"]
       TAG["push: tags v*"]
       SCHED["schedule (Saturday, Monday, or daily)"]
       ISSUES["issues"]
       PRT["pull_request_target"]
       DISPATCH["workflow_dispatch"]

       CQ["CodeQL<br/>codeql-analysis.yml"]
       UT["Unit Tests<br/>unit-tests.yml"]
       EX["Experimental Tests<br/>experimental.yml"]
       PC["Python Compatibility<br/>python-compatibility.yml"]
       LT["Lint<br/>lint.yml"]
       VU["Vendor Update<br/>cron-vendor.yml"]
       CU["Conda Update<br/>cron-conda.yml"]
       GP["GitHub Pages<br/>deploy-pages.yml"]
       CR["Create Release<br/>create-release.yml"]
       PS["Project Status<br/>project-status.yml"]
       CC["Coverage Comment<br/>coverage-comment.yml"]
       CT["CI Timing<br/>ci-timing.yml"]
       PV["Python Versions<br/>cron-python-versions.yml"]

       PUSH --> CQ
       PR --> CQ
       SCHED -->|02:00| CQ

       PUSH --> UT
       PR --> UT

       PUSH --> EX
       PR --> EX

       PUSH --> PC
       PR --> PC
       SCHED -->|04:00| PC

       PR --> LT
       SCHED -->|06:00| LT
       DISPATCH --> LT

       PR --> GP
       SCHED -->|02:00| GP

       SCHED -->|10:00| VU
       SCHED -->|10:00| CU

       TAG --> CR

       ISSUES --> PS
       PRT --> PS
       SCHED -->|daily 00:37| PS
       DISPATCH --> PS

       SCHED -->|Mon 07:23| CT
       DISPATCH --> CT

       SCHED -->|Mon 05:41| PV
       DISPATCH --> PV

       UT ==>|workflow_run: completed| VU
       UT ==>|workflow_run: completed| CU
       UT ==>|workflow_run: completed| GP
       VU ==>|workflow_run: completed| CR
       UT ==>|workflow_run: completed| CC

       VU -.->|uses: gate-only| UT
       CU -.->|uses: gate-only| UT
       GP -.->|uses: gate-only| UT
       CR -.->|uses: gate-only| UT

       classDef trig fill:none,stroke-dasharray:2 2
       class PUSH,PR,TAG,SCHED,DISPATCH,ISSUES,PRT trig

The double relationship between **Unit Tests** and the four dependants that
also call it is the
part that reading a single file cannot show, and it is deliberate rather than
redundant: each of the four calls ``unit-tests.yml`` with ``gate-only: true``
itself (dotted, above) **only when its own trigger is not** ``workflow_run``
(their gate jobs' ``if:`` guards this explicitly) -- i.e. only on the
Saturday ``schedule`` path, where no completed Unit Tests run exists yet to
read a verdict from. On the ``workflow_run`` path (thick arrows), each reads
the verdict Unit Tests already reached instead of re-running the gate a second
time. Vendor Update, Conda Update and GitHub Pages act on it only once their
``verdict`` job, described under the edge list below, says it is a verdict on
the commit they build.

``workflow_run`` Edges
----------------------

Five in total, found by grepping every ``on:`` block rather than trusting a
hand-maintained list:

* ``.github/workflows/cron-vendor.yml:14-16`` -- **Vendor Update** fires on
  completion of **Unit Tests**.
* ``.github/workflows/cron-conda.yml:17-19`` -- **Conda Update** fires on
  completion of **Unit Tests**.
* ``.github/workflows/deploy-pages.yml:12-14`` -- **GitHub Pages** fires on
  completion of **Unit Tests**.
* ``.github/workflows/create-release.yml:6-9`` -- **Create Release** fires on
  completion of **Vendor Update**.
* ``.github/workflows/coverage-comment.yml:21-23`` -- **Coverage Comment** fires
  on completion of **Unit Tests**.

``workflow_run`` fires for *every* completion of the named workflow --
success, failure, or skipped -- and regardless of what triggered it,
including a pull request's own run of Unit Tests. Every one of the five
downstream workflows therefore re-checks ``github.event.workflow_run.event``
and ``.head_branch`` (or, for Create Release and Coverage Comment, ``.conclusion``) itself before
doing anything with an outward effect; none of the filtering happens in the
``on:`` block.

Those checks say nothing about *which* commit was verified. A ``workflow_run``
checks out ``github.sha``, ``main``'s tip when the event is raised, not
``github.event.workflow_run.head_sha``, the commit the completed run tested, and
in a merge wave the two differ: Conda Update 38325136710 bumped 2e941bbb7 under
the verdict for 9083163f5 (`#1643 <https://github.com/JarryShaw/PyPCAPKit/issues/1643>`__).
So Vendor Update, Conda Update and GitHub Pages each run a ``verdict`` job first,
and act only when the tip is the verified commit, or that commit plus bot commits
to ``conda/build`` and ``conda/requirements.txt`` alone; otherwise they skip, and
the tip's own Unit Tests run raises them again. Vendor Update's run still
concludes ``success`` then, since ``verdict`` ran, so Create Release reads its
``vendor-update`` job to tell it from a real one
(`#1748 <https://github.com/JarryShaw/PyPCAPKit/issues/1748>`__). The rule and its evidence are in
``util/verdict_covers_checkout.py``. Conda Update also writes after the
checkout, so it applies the same rule a second time: its push rebases onto
``main``'s tip only when the commits that brings in pass it, and otherwise
pushes nothing, and Conda Tag tags the commit that push landed rather than the
tip (`#1632 <https://github.com/JarryShaw/PyPCAPKit/issues/1632>`__).

Vendor Update's own commit raises it again: the push gets a Unit Tests run, whose
completion starts another crawl. The commit bumps the version only when the crawl
changed code. If every change is to comments or docstrings, the commit is "Updated
vendor documentation without a version bump", and the Create Release run that
follows sees the same version, so it has nothing new to publish
(`#1674 <https://github.com/JarryShaw/PyPCAPKit/issues/1674>`__). A crawl raised by
such a commit's own Unit Tests run does not commit comment changes on top of it,
so documentation commits cannot chain. The rule is in
``util/vendor_code_changed.py``. A bump commit carries every module the crawl
wrote, a new one included, so the crawl it raises does not find one untracked
and bump again (`#1685 <https://github.com/JarryShaw/PyPCAPKit/issues/1685>`__).

Reusable-Workflow Calls (``uses:``)
-----------------------------------

A ``uses:`` call is a different relationship from triggering: it runs inside
the caller's own workflow run, as one of the caller's own jobs, rather than
starting an independent run after the caller finishes. All four calls in this
repository target the same reusable workflow, with the same input:

* ``.github/workflows/create-release.yml:593`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/cron-conda.yml:50`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/cron-vendor.yml:56`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/deploy-pages.yml:55`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.

``gate-only: true`` selects **three** of ``unit-tests.yml``'s **fourteen** jobs,
not one: ``gate`` (the full suite, on ``latest``), ``changelog``
(checks ``CHANGELOG.md`` against its source entry) and ``python-versions``,
which reads ``gate``'s version (see `Python Versions`_ below). It skips the other
**eleven** -- the eight matrix jobs, ``test`` (five Python legs), ``test-ktlo``
(four), ``integration`` (five), ``integration-ktlo`` (four),
``engine-tests`` (one job for each of five engines, each looping over six
Python versions), ``pypcap-parity`` (one), ``pypcap-parity-ktlo`` (one) and
``unittest-ordering`` (eleven matrix cells), each of which has already run once for this commit
from Unit Tests' own ``push`` trigger (and, all but ``unittest-ordering``,
which runs on ``main`` pushes only, from its ``pull_request`` trigger), so
running any of them again per caller would
test the same commit several times over -- the docs-only path's ``changes``
and ``project-tests``, and ``required-checks`` (see `Required Status
Checks`_ below), gated out by their own ``if:`` rather than by having
already run. ``changelog`` carries no
``if:`` at all and runs on every path regardless -- deliberately, per its own
comment (``unit-tests.yml:1612-1618``): ``create-release.yml`` feeds
``CHANGELOG.md`` to the GitHub Release body, so the release path is exactly
where a drifted file must not go unchecked. Confirmed on run `36210743295
<https://github.com/JarryShaw/PyPCAPKit/actions/runs/36210743295>`__ (a
schedule-triggered GitHub Pages run): both ``Changelog drift`` and ``Gate
(full suite, Python 3.14)`` succeeded, with the four matrix jobs that
existed then -- ``Python ${{ matrix.python-version }}``, ``Integration
Python …``, ``Engines Python …`` and ``PyPCAP/PyPCAPFile parity Python
…`` -- all reporting ``skipped``.

The Skip Cascade (`#888 <https://github.com/JarryShaw/PyPCAPKit/issues/888>`__)
-------------------------------------------------------------------------------

The two relationships above compose into a failure mode worth seeing on its
own graph. Create Release's ``version_check`` -- ahead of the ``uses:`` call
above -- carries:

.. code-block:: yaml

   if: >-
     ${{ !cancelled() &&
     (github.event_name != 'workflow_run' || github.event.workflow_run.conclusion == 'success') &&
     !(github.event_name == 'push' && github.actor_id == vars.RELEASE_APP_BOT_ID) &&
     needs.vendor_update.outputs.updated != 'false' }}

(``create-release.yml:290-294``). Its third clause skips the tag-push run that
the release App's own tag starts (:doc:`releasing`, "The Release App"). On the
``workflow_run`` path, this evaluates **false**, and the job is skipped
outright, whenever the upstream Vendor Update run's own conclusion was
anything other than ``success`` -- including
``skipped``, which is exactly what Vendor Update's *own* jobs report when
*their* ``workflow_run``-path guards decline (see ``cron-vendor.yml``'s
``vendor-update`` job). Since
`#1748 <https://github.com/JarryShaw/PyPCAPKit/issues/1748>`__ it is also false
for a Vendor Update that concluded ``success`` with ``vendor-update`` skipped --
its ``verdict`` job found the Unit Tests verdict was for another commit -- which
the ``vendor_update`` job reads from that run's jobs first, as run 38650191283
was. ``!cancelled()`` keeps a skipped ``vendor_update``, on a push, from
skipping it. ``unit-tests`` then depends on that job with
``needs: [ version_check ]`` (``create-release.yml:581``) and an ``if:`` that
calls no status-check function, so a skipped dependency skips it too -- and
every job past it is gated the same way: ``github`` needs ``[ unit-tests,
version_check ]`` (``:619``), ``tag`` needs ``[ github, unit-tests,
version_check ]`` (``:806``), ``pypi`` needs ``[ github, unit-tests,
version_check ]`` (``:972``), and ``conda`` needs ``[ tag, github,
unit-tests, version_check ]`` (``:1208``).

.. mermaid::

   flowchart TD
       WR["Vendor Update completed<br/>conclusion != success,<br/>or vendor-update skipped"]
       VC["version_check<br/>SKIPPED"]
       UTX["unit-tests (uses: unit-tests.yml)<br/>SKIPPED"]
       GH["github (GitHub Release)<br/>SKIPPED"]
       TAGJ["tag (Conda Tag)<br/>SKIPPED"]
       PY["pypi (PyPI distribution)<br/>SKIPPED"]
       CD["conda<br/>SKIPPED"]

       WR -->|if: false| VC
       VC -->|needs| UTX
       UTX -->|needs| GH
       GH -->|needs| TAGJ
       GH -->|needs| PY
       GH -->|needs| CD
       TAGJ -->|needs| CD

       classDef skipped fill:#fdecea,stroke:#c0392b,stroke-dasharray:4 2
       class UTX,VC,GH,TAGJ,PY,CD skipped

This is a transitive reduction, as in :doc:`releasing`: ``version_check`` and
``unit-tests`` are also direct ``needs:`` of ``tag`` and ``pypi``
(``create-release.yml:806,972``) and of ``conda`` (``:1208``), but ``github``
already implies those edges, since it depends on both itself. Drawing them
would add lines without changing which job can start before which, or which
job a skip in ``version_check`` reaches.

The whole run then reports **skipped**, not failed -- there is no red X to
notice. Observed in production on runs `36511610205
<https://github.com/JarryShaw/PyPCAPKit/actions/runs/36511610205>`__ and
`36510774776
<https://github.com/JarryShaw/PyPCAPKit/actions/runs/36510774776>`__, both
``workflow_run``-triggered **Create Release** runs on ``main`` that concluded
``skipped`` with every one of their six jobs -- ``Release test gate``,
``Check Version``, ``GitHub Release``, ``Conda Tag (release)``, ``PyPI
distribution for Python …`` and ``Conda deployment (release) …`` -- reporting
``skipped`` in turn.

This is a distinct mechanism from the ``PCAPKIT_TAG_EXISTS`` skip
:doc:`releasing` already documents under "Precautions" (a *later* run
skipping because the tag a *previous* run already created still exists): this
one can skip the very first attempt, before any tag is ever created, purely
because the upstream Vendor Update run did not itself conclude ``success``.

Such a run is also kept out of the release's concurrency group
(``create-release.yml:30-32``,
`#1705 <https://github.com/JarryShaw/PyPCAPKit/issues/1705>`__). It is keyed on
its own ``github.run_id`` rather than on the ref, so it cannot cancel a run
waiting there with release work. Keyed on the ref, run 38499295798 joined at
02:06:32Z on 2026-10-14, and the pending 38499150441, whose Vendor Update had
succeeded, was cancelled a second later. A run whose Vendor Update concluded
``success`` with ``vendor-update`` skipped (#1748) is still keyed on the ref:
the group reads only the event, which does not say which jobs ran. It can still
displace a run pending there, and now releases nothing in its place, so that
release waits for the next Vendor Update on ``main``.

``pull_request_target``
-----------------------

**Project Status** is the only workflow on ``pull_request_target``, and the only one
that runs with a secret on an event a fork can cause: it writes the project board's
*Status* field with ``PROJECT_TOKEN``, which a fork's ``pull_request`` run would not
receive. It therefore never checks out the repository and has no ``uses:`` step. It
fetches :file:`util/project_status.py` through the API at ``github.sha`` -- the base
branch's tip under that event -- and takes only the item number from the payload.
``tests/project/test_project_status.py`` asserts this over the file. Without the
secret it skips with a ``::notice::``. The Status mapping it applies is documented in
:doc:`conventions/process`.

Coverage (`#1063 <https://github.com/JarryShaw/PyPCAPKit/issues/1063>`__)
-------------------------------------------------------------------------

Coverage is measured inside an existing leg rather than by a workflow of its
own: the ``Python 3.15`` leg of ``test`` (matrix key ``coverage: true``) runs
its unchanged pytest selection under ``coverage run
--rcfile=.github/coverage.toml``. That rcfile repeats
:file:`pyproject.toml`'s ``[tool.coverage.*]`` settings
(``tests/project/test_coverage_rcfile.py`` asserts it) and adds ``parallel``
and ``patch = ["subprocess"]``, without which only the xdist controller is
measured, not its workers, plus ``core = "ctrace"``: with the suite purging
and re-importing pcapkit, one module's peak RSS was 4.17 GiB under the default
``sys.monitoring`` core against 0.41 GiB under ``ctrace``, and that growth
killed the runner. ``sigterm = true`` and a ``pytest_sessionfinish`` hook in
:file:`tests/conftest.py` that saves each xdist worker's data early keep a
worker that dies during shutdown from losing its file
(`#1423 <https://github.com/JarryShaw/PyPCAPKit/issues/1423>`__). The leg then
writes the total and a per-package table to the job summary and uploads the HTML
report as the ``coverage-html`` artifact (30 days), with the bare numbers as the
``coverage-summary`` artifact and the per-process debug log as
``coverage-processes-log``.

The PR comment comes from **Coverage Comment** (:file:`coverage-comment.yml`),
not from ``unit-tests.yml``. That file is also a reusable workflow, a called
workflow can only narrow the token its caller passes, and all four callers grant
``contents: read``, so a ``pull-requests: write`` job there would break them.
Coverage Comment runs no tests. On ``workflow_run`` it uses the default
branch's file and its own token, so fork pull requests get a comment too. It
treats the artifact as untrusted: it never checks out pull-request code. It
takes the PR number from the API, as the open PR whose head is the run's head
sha, and renders its own Markdown from validated numbers. It edits one comment,
found by a hidden marker, on each push. The first line says when the tests
failed. Neither workflow's coverage step is a required check.

CI Timing Review (`#1538 <https://github.com/JarryShaw/PyPCAPKit/issues/1538>`__)
---------------------------------------------------------------------------------

**CI Timing** (:file:`ci-timing.yml`) runs :file:`util/ci_timing.py` every Monday,
or on dispatch with a ``days`` window and an optional ``concurrency_hours`` runner-pool
measurement. Through the API it lists every completed run in the window of Unit Tests,
Python Compatibility, Lint, CodeQL, GitHub Pages and Experimental Tests (#1732, so
its two-hour legs stay measured), a day per query because a filtered listing stops
at 1,000 runs (Pages completed 1,154 in the week to 2026-10-09). It then reads the
jobs of an evenly spaced sample -- 150 push and 150 pull-request runs of Unit Tests,
60 runs of each other workflow -- and the summary says how many runs each sample
holds and which span they cover. That is about 690 calls (estimate: 63 listing
pages, one per workflow per day and one more per further 100 runs, by the week to
2026-10-09's run counts with Experimental Tests taken as Unit Tests' 10, since it
runs on the same events; at most 300 + 300 job reads; 15 for the JUnit artifacts;
up to 12 workflow-file reads) of ``GITHUB_TOKEN``'s 1,000 an hour, on a read-only token
(``actions: read``, ``contents: read``). A job is measured by its own outcome: one
cancelled at 95% of its cap or later timed out and counts, even in a run that reads
``cancelled`` for that reason; one cancelled earlier was superseded and does not. A
step cap written as an expression differs by leg and reads as none.
The report goes to the job summary and to the ``ci-timing-report`` artifact (90
days), and the newest earlier report is the next run's baseline. It is not a
``workflow_run`` on Unit Tests, which would add a job per run to a runner pool
measured saturated at 20 concurrent jobs.

Per-test timings come from the ``test`` and ``integration`` legs, and from
:file:`experimental.yml`'s, which run pytest with ``--durations=30
--durations-min=1.0`` and ``--junitxml`` and upload the file as
``junit-unit-<version>``, ``junit-integration-<version>`` or
``junit-experimental-<version>`` (14 days). Each upload step is ``continue-on-error``,
so an artifact-service outage cannot fail a leg. pytest writes one ``<testcase>`` per test however
many subtests it runs -- about 0.6 MB per unit leg (estimate) -- but the suite's
``tests=`` count includes subtests, so the review reads each testcase's ``time``. The
ordering, ``gate``, ``engine-tests`` and ``pypcap-parity`` legs write no file, and nor
does a leg killed at its cap, since pytest writes it at session end.

A HARD threshold fails the run with status 1, and GitHub emails a scheduled
workflow's failure to whoever last edited its cron line; a WARN is an annotation. A
run that cannot read the API ends with 2 and one that crashes with 3, each with an
annotation saying no threshold was evaluated. Each threshold is anchored to a figure
measured on the issue:

.. list-table::
   :header-rows: 1
   :widths: 8 64 28

   * - ID
     - Fires when
     - Measured
   * - ``H1``
     - a job's p90 reaches 50% of its ``timeout-minutes``
     - ``Python 3.14``: 12.1 of 45 min
   * - ``H2``
     - a step with a cap of its own reaches 50% of it at p90 (the ordering cells' 20)
     - ``protocols (rest)``: 319 s
   * - ``H3``
     - ``W9``'s p90 is at or over 30 min and 25% or more above the baseline's (needs a
       baseline)
     - --
   * - ``H4``
     - a job's or capped step's linear fit reaches its cap within 14 days
     - --
   * - ``W1``
     - a job's median rises 20% on the baseline, with 20 samples each side
     - --
   * - ``W2``
     - pull-request time to mergeable passes 18 min at the median
     - 14.4 min
   * - ``W3``
     - the coverage leg's tests step passes 1.8 times its paired legs' (median)
     - 1.57
   * - ``W4``
     - ms per test on 3.13 rises 15% on the baseline
     - 110.8 ms
   * - ``W5``
     - run queue p90 passes 5 min on pull requests or 15 min on pushes
     - 3.1 and 9.6 min
   * - ``W6``
     - more than 35% of pull-request runs are cancelled, i.e. superseded
     - 29%
   * - ``W7``
     - a module passes 30 s summed or a test 10 s on 3.13, a module enters the top
       10, or a class's every test costs about what its first does
     - --
   * - ``W8``
     - a different job finishes last before ``Required checks passed``
     - ``Python 3.14``
   * - ``W9``
     - pull-request time to ``Required checks passed`` reaches 30 min at p90
     - 19.6 min; 36.7 in the two days to 2026-10-10

The cap line sits at 50% because at the fastest growth measured, +1.27 min/day on
``Python 3.14``, crossing it leaves 12-18 days before the cap: one review and one
fixing pull request. Time to ``Required checks passed`` is HARD only as a regression
because its p90 measures runner-queue load as much as test time: it was 19.6 min when
the line was set and 36.7 min in the two days to 2026-10-10 with the pool saturated,
so an absolute HARD line would email about the queue every week. The 25% rise is an
initial value, to tune once weekly reports exist. ``W9`` is therefore expected to fire
while the pool stays saturated, and the first runs with JUnit will show whether
``W7``'s 10-second test line needs raising. What to do when one fires is on
:doc:`conventions/process`.

``H1``, ``H2`` and ``H4`` on a non-blocking job are warnings, not HARD, so they do
not fail the run (#1732): on every job of :file:`experimental.yml`, which no
required context names, on every KTLO leg, a job whose name ends in ``(KTLO)``
(#1633), and on a job whose name ends in ``(experimental)`` in any workflow. That
last covers the experimental legs that ran in :file:`unit-tests.yml` under
``test``'s 45-minute cap before the split, whose runs stay in the 7-day window for a
week after it. The finding keeps its ``H`` id and says it is non-blocking. A
KTLO leg past its job's ``timeout-minutes`` is still cancelled, and its check run
reads red, though since #1738 nothing gating waits on it, so that warning is worth
acting on before the cap.

Work Kept Off the Pull-Request Queue (`#1538 <https://github.com/JarryShaw/PyPCAPKit/issues/1538>`__)
-----------------------------------------------------------------------------------------------------

Two cuts in :file:`unit-tests.yml` keep work that cannot gate a merge from competing
with pull-request jobs for the 20-runner pool. None touches a required check or adds a
permission to the reusable workflow.

* ``unittest-ordering`` runs on ``main`` pushes only, per `#1052
  <https://github.com/JarryShaw/PyPCAPKit/issues/1052>`__ item H, and has
  ``needs: [test]``, so its eleven cells join the queue once ``test`` finishes rather
  than when the push run is created, ahead of that run's own ``Python`` legs and of
  pull-request jobs created later in a merge wave. Its ``if:`` opens with
  ``!cancelled()``, so the cells still run when ``test`` fails, and a red cell still
  fails the push run that GitHub Pages, Conda Update and Vendor Update (and so Create
  Release) wait on. The cost is wall time: the push run, and those workflows, finish
  about one slowest cell later, about 6 min before any queue wait (estimate).
* ``engine-tests`` has no ``DPKT`` cell. Its only path was
  :file:`tests/toolkit/test_dpkt_unit.py`, which ``test`` runs with ``DPKT`` installed
  on every leg. Dropped with it: that file in a venv holding only ``test`` and ``DPKT``.

A third cut, running the then-prerelease 3.15 engine cell on ``main`` pushes only,
ended with `#1633 <https://github.com/JarryShaw/PyPCAPKit/issues/1633>`__: 3.15 is
supported now, so its cells block on every run.

Required Status Checks
----------------------

Ruleset ``23497679`` on ``main`` requires six contexts, with
``strict_required_status_checks_policy: true`` (a branch must be up to date
with ``main`` before it can merge, not merely green). Each was found by
grepping every workflow file for its name:

.. list-table::
   :header-rows: 1

   * - Required context
     - Emitted by
     - Where
   * - ``Required checks passed``
     - job ``required-checks``
     - ``unit-tests.yml:1937``
   * - ``Compat Python 3.11``
     - job ``compatibility``, matrix leg ``3.11``
     - ``python-compatibility.yml:60``, ``.github/python-versions.toml:20``
   * - ``Compat Python 3.12``
     - job ``compatibility``, matrix leg ``3.12``
     - ``python-compatibility.yml:60``, ``.github/python-versions.toml:21``
   * - ``Compat Python 3.13``
     - job ``compatibility``, matrix leg ``3.13``
     - ``python-compatibility.yml:60``, ``.github/python-versions.toml:22``
   * - ``Compat Python 3.14``
     - job ``compatibility``, matrix leg ``3.14``
     - ``python-compatibility.yml:60``, ``.github/python-versions.toml:23``
   * - ``Compat Python 3.15``
     - job ``compatibility``, matrix leg ``3.15``
     - ``python-compatibility.yml:60``, ``.github/python-versions.toml:24``

That is the list after `#1633 <https://github.com/JarryShaw/PyPCAPKit/issues/1633>`__,
which added ``Compat Python 3.15`` and removed ``Compat Python 3.10``. Moving a version
between the tiers below means editing the ruleset in the same change.

``Required checks passed`` is defined by exactly one job
(``unit-tests.yml:1937``). ``Compat Python`` is defined by one, the
``compatibility`` job in ``python-compatibility.yml`` (``:60``), whose matrix
(``:74``) comes from :file:`.github/python-versions.toml`: the five required legs
are its supported tier (``python-versions.toml:20-24``), and its four KTLO legs
(``python-versions.toml:16-19``) have names ending in ``(KTLO)``, so no required
context matches one. A comment at
``unit-tests.yml:1849`` mentions the string without defining it.

``Required checks passed`` is an aggregate, not a single check run. The ruleset
requires it and the five ``Compat Python 3.11``-``3.15`` legs, nothing else, as
``unit-tests.yml``'s own comment (``unit-tests.yml:1848-1858``) records. It
``needs:`` the gating jobs of ``unit-tests.yml`` -- ``test``, ``integration``,
``engine-tests`` and ``pypcap-parity``, plus ``changes`` and ``project-tests``
for the docs-only path -- and checks each result explicitly
(``unit-tests.yml:1936-1990``). Rulesets match check names literally, with no
wildcard, so requiring the matrix cells one by one would mean editing the
ruleset whenever a matrix changes; the aggregate keeps the required list fixed.
It accepts the four legs as ``skipped`` only on a docs-only pull request, where
``project-tests`` -- every test that reads ``docs/`` or Markdown -- must pass
instead. The ``Compat`` legs stay required separately because they come from
``python-compatibility.yml``, and a job cannot ``needs:`` a job in another
workflow file. This job runs on Unit Tests' own ``push``/``pull_request``
triggers; the ``gate-only: true`` reusable calls documented above skip it via
``if: ${{ always() && inputs.gate-only != true }}`` (``unit-tests.yml:1939``),
so it is never produced -- and never expected -- on those paths.

Python versions come in two tiers (#1633), and an experimental one (#1660,
below), declared in :file:`.github/python-versions.toml` (see `Python Versions`_).
The **supported** tier, 3.11-3.15, blocks: a failed leg fails ``Required checks passed`` or its own
required ``Compat`` context. The **KTLO** tier -- end-of-life 3.7-3.10, still built and
tested -- never blocks, is never a required context, and never shows a commit or a
pull request red (#1672). In ``unit-tests.yml`` the KTLO legs are jobs of their own
since `#1738 <https://github.com/JarryShaw/PyPCAPKit/issues/1738>`__: ``test-ktlo``,
``integration-ktlo`` and ``pypcap-parity-ktlo``, which neither ``required-checks``
nor ``unittest-ordering`` ``needs:``, so not even a failure no step can contain, such
as a lost runner or the job cap, reaches a gate. Each runs its gating twin's steps,
by YAML alias (`Reusing workflow configurations
<https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#yaml-anchors-and-aliases>`__),
and keeps its legs' check names, ``Python 3.10 (KTLO)`` and so on. In
``python-compatibility.yml`` and ``create-release.yml`` a KTLO leg shares its job
with supported legs. Every job holding KTLO legs works the same way:

* Every step that can fail on a KTLO leg has an ``id`` and
  ``continue-on-error: ${{ matrix.ktlo == true }}`` (``unit-tests.yml:406-423``),
  unless it is masked on every leg, as the timings uploads are. Its ``outcome`` is
  then ``failure`` but its ``conclusion`` ``success``, so the job, its check run
  and ``required-checks`` read ``success``. A step that needs an earlier one's work
  waits on that step's ``outcome``: a leg that cannot install stops there, and a
  ``pypi`` leg stops at its first failure.
* The last step, ``KTLO summary``, runs on KTLO legs only and reports each failed
  ``outcome`` as a warning and a job-summary line. A step's own annotations take
  ``ANNOTATION_LEVEL``: ``warning`` on a KTLO leg, ``error`` on a supported one.
  ``engine-tests``' KTLO cells, a step of their own with ``continue-on-error: true``,
  report the same way.
* Never job-level ``continue-on-error`` alone: it passes the *run*, but the leg's
  check run still concludes ``failure``, which showed every commit red while
  ``Compat Python 3.7 (KTLO)`` carried it. ``unit-tests.yml``'s three KTLO jobs
  carry it on top of the step-level guards, as a backstop for the failures no step
  contains, as ``experimental.yml``'s job does; it "prevents a workflow run from
  failing when a job fails" (`Workflow syntax
  <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idcontinue-on-error>`__),
  so the Unit Tests run its ``workflow_run`` consumers read stays green.

Two errors remain on a failed KTLO step, neither changing a conclusion: the
runner's ``Process completed with exit code N.`` for a ``run:`` step, and an
action's own. And #1634's tag check still blocks the ``pypi`` KTLO legs: it fails
every leg alike, and masked, the leg would go on to publish.

3.7 can neither install the ``test`` extra nor import the package, so each 3.7 leg
fails one step, with a warning saying why -- ``test`` and ``integration`` at the
install step, the ``Compat`` leg at ``Verify package`` -- and concludes
``success``. They run on ``ubuntu-22.04``, which retires on 2027-04-17 after
brownouts from 2027-03-23 (actions/runner-images#14254). A brownout fails a
``test-ktlo`` or ``integration-ktlo`` leg before any step runs, where no step-level
``continue-on-error`` reaches; since #1738 that fails nothing gating, but the leg's
check run reads red, so they must still go before then (#1660). 3.6 is
in no matrix: setup-python builds it only for retired Ubuntu images. Nor are
3.7-3.9 in ``engine-tests``, which installs every interpreter on
``ubuntu-latest``, where setup-python has no Ubuntu 26.04 build of any of them. Nor
are they in ``pypcap-parity``, which also runs on ``ubuntu-latest``; none of them
was measured on that job.

The **experimental** tier is free-threaded CPython and GraalPy, spelt as
setup-python reads them (``3.14t``, ``graalpy-25.4``). Each runs one leg of
``experimental`` (two), the one matrix job of :file:`.github/workflows/experimental.yml`
("Experimental Tests"), named ``Python <version> (experimental)``, and nothing
else: no ``integration``, ``Compat``, wheel or conda leg, so never a required
context. They were legs of ``test`` until `#1732
<https://github.com/JarryShaw/PyPCAPKit/issues/1732>`__, which moved them to a
workflow of their own, by the owner's ruling that nothing waits on them. **That
workflow reports separately and holds up nothing**: a job cannot ``needs:`` one in
another workflow, nothing calls it, and no ``workflow_run`` names it, so the Unit
Tests run completes without it, and with it ``Required checks passed``,
``unittest-ordering`` and the four workflows that wait on Unit Tests completing
(``coverage-comment.yml``, ``deploy-pages.yml``, ``cron-vendor.yml`` and
``cron-conda.yml``). It runs on Unit Tests' ``push`` and ``pull_request`` events,
skips a docs-only pull request by the same ``changes`` script, and cancels a
pull request's superseded run. The legs never
block, by the KTLO mechanics above: every step that can fail has
``continue-on-error: true``, their annotations are warnings, and ``Experimental
summary``, the job's last step, reports each failed step. A failure no step
contains, such as a lost runner, fails the job, and the job's own
``continue-on-error: true`` keeps it from failing the run: it "prevents a workflow
run from failing when a job fails" (`Workflow syntax
<https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idcontinue-on-error>`__),
though the leg's check run still reads ``failure``. A job past its
``timeout-minutes`` is cancelled, and that page does not say whether the job-level
guard covers a cancellation. So setup-python, the install and the tests have caps
of their own, of 5, 10 and 120 minutes, under the job's 140: a step at its cap
fails rather than cancels, and the guard holds (actions/runner
``src/Runner.Worker/StepsRunner.cs:322-353``). The runner's ``has timed out`` error
stays, changing no conclusion, as ``Process completed with exit code N.`` does.
Everything but the install and the tests took under 20 seconds on every uncovered
leg of runs 38569321543-38569522442. ``test``'s caps are main's: 45 minutes for the
job, and none on a step. Promoting one whose leg stays green is a hand edit, which
:file:`util/python_versions.py` refuses until the build has a wheel, a conda build
and a ``Compat`` leg.

The tests' 120 minutes are sized for GraalPy, the slower of the two legs that share
them: its leg reached 26% of the unit tier in 25 minutes (job 115915976024), where
3.14t's ran the whole tier in 5.8 (run 38581834697). By the owner's ruling the
round-trip sweeps run on ``latest`` alone: every leg but ``latest`` adds
``--ignore-glob='*roundtrip*'``, which leaves out each unit-tier module whose path
holds ``roundtrip`` (``ROUNDTRIP_SWEEP_GLOB`` in :file:`tests/_tiers.py`), and
``latest``, the coverage leg, runs them as before. The subset covers
``integration`` too: off ``latest`` its legs leave out the three
``*roundtrip*_runtime.py`` modules (``ROUNDTRIP_RUNTIME_GLOB``), dropping them from
``fixture_tier_paths()``'s selection and adding the glob as an ``--ignore-glob``,
since pytest applies no ignore to a path it was handed. On 2026-10-14 they were 41 modules
and 8% of the unit tier's time in a serial 3.14 run (86 of 1,031 s), and 10-11% on the
3.14, 3.15 and 3.14t legs of run 38581834697, so the rest should take GraalPy 88-113
minutes (estimate).

Python Versions
---------------

Since `#1660 <https://github.com/JarryShaw/PyPCAPKit/issues/1660>`__,
:file:`.github/python-versions.toml` declares every Python version CI runs: one
line per version, with its tier -- ``supported``, ``ktlo``, ``experimental``, or
``pre-release``, which none is today -- and, where ``ubuntu-latest`` cannot
provide it, the ``runner`` it needs. ``latest`` names the newest supported CPython, which every
job on one interpreter runs. :file:`util/python_versions.py` reads the file with
the runner's own ``python3`` -- its ``tomllib`` needs 3.11, and every image that
runs it has 3.12 or newer -- and writes each matrix as JSON: a ``python-versions``
job in ``unit-tests.yml`` and ``python-compatibility.yml``, ``version_check`` in
``create-release.yml`` and ``conda-update`` in ``cron-conda.yml`` hand theirs on
through ``fromJSON``, and each single-interpreter job reads ``latest``.

**A tier change is a one-line edit to that file, plus the matching edit to ruleset
23497679's ``Compat`` contexts.** The file's ``exemptions`` list each pin kept
off ``latest``, with its reason in the comment above it, such as the conda
jobs' ``!= '3.15'``. ``tests/project/test_python_versions_1660.py`` fails on a
pin the file does not list, on an exemption with no comment, and on a
classifier, doc or comment that no longer matches the file -- the coverage
leg's version, the release checks' counts. Its tests, and the other tests that
read the file, skip on the KTLO interpreters, which have no ``tomllib``. Two
edits it names rather than makes: a new ``pypi`` KTLO leg needs its own
``ktlo_*`` output for ``release_status``, and a pre-release leg needs
non-blocking mechanics no workflow has yet, so the script refuses one.

**Python Versions** (:file:`cron-python-versions.yml`) proposes those edits.
Every Monday, or on dispatch, its ``detect`` job runs
:file:`util/update_python_versions.py` with no secret: it reads python.org's
release cycle, PyPy's releases, setup-python's ``versions-manifest.json`` and
the runner-images README, recomputes the tiers by the rules in that script's
docstring, rewrites the file and the prose these tests pin to it, and runs the
three audit modules on the result. Only when that changes something does ``pr``
enter ``github-release``, so the owner approves only those runs. It mints a
release App token (:doc:`releasing`, "The Release App") with contents and pull
requests write, force-pushes ``bot/python-versions`` and opens or updates its
one pull request, whose body lists each move and why, the ``Compat`` contexts to
change in the ruleset by hand, and every renamed check run. It never pushes
``main``, edits the ruleset or writes a workflow file, which that token cannot
push, so workflow comments name the tiers rather than restate them. While the
branch's pull request is open, it does not re-push tiers a commit on the branch
already proposes, hand edits or merges of ``main`` on top or not, nor overwrite
commits it did not make: when the branch holds some and proposes other tiers,
``detect`` fails before asking for the approval. Once that pull request is
merged or closed, the next run with something to propose recreates the branch
from ``main``, a closed proposal's tiers included. It reports a pre-release
instead of writing it. The experimental entries are hand-maintained: no source it
reads rates them, so every run keeps their lines as written, and a hand edit to
one changes no proposal.

Deployment ``environment:``
----------------------------

Five jobs declare a deployment ``environment:`` and can therefore pause for an
approval, four in ``create-release.yml`` and one in ``cron-python-versions.yml``:

* ``github`` -- ``environment: github-release`` (``create-release.yml:616``)
* ``tag`` -- ``environment: conda-tag`` (``create-release.yml:804``)
* ``pypi`` -- ``environment: pypi`` (``create-release.yml:967``)
* ``conda`` -- ``environment: anaconda`` (``create-release.yml:1205``)
* ``pr`` -- ``environment: github-release``, for the release App's key (see
  `Python Versions`_)

No other workflow in scope here declares one -- including
``deploy-pages.yml``, whose ``deploy-pages`` job pushes straight to the
``gh-pages`` branch via ``JamesIves/github-pages-deploy-action`` rather than
through an ``environment:``-gated deployment. Of the four environments, only
``github-release`` carries a required reviewer; :doc:`releasing`
covers why one approval on that single environment is enough to gate the
whole release graph, and is the page to read for the reasoning rather than
repeating it here.
