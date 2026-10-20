GitHub Actions Workflows
========================

.. important::

   The workflows under :file:`.github/workflows/` trigger each other, and
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
   nothing to do without a completed Unit Tests run. Each of the others
   that carry one pairs it with a direct trigger of its own -- a Saturday
   ``schedule`` for Vendor Update, Conda Update and GitHub Pages, a ``v*`` tag
   push for Create Release -- for the path where no upstream run exists yet to
   chain from.

The Graph
---------

Solid arrows are direct triggers (``push``, ``pull_request``, ``schedule``,
``workflow_dispatch``, ``issues``, ``pull_request_target``), drawn in the first
graph with a node for each schedule day. The second graph is the edges from one
workflow to another. Thick arrows are ``workflow_run`` edges -- a
*separate* run, started only after the upstream workflow's run has fully
completed. Dotted arrows are ``uses:`` edges -- a reusable-workflow call that
runs synchronously *inside* the caller's own run, sharing its run id rather
than starting a new one.

.. mermaid::

   flowchart LR
       PUSH["push: main"]
       PR["pull_request: main"]
       SAT["schedule: Saturday"]
       MON["schedule: Monday"]
       DISPATCH["workflow_dispatch"]
       DAILY["schedule: daily"]
       ISSUES["issues"]
       PRT["pull_request_target"]
       TAG["push: tags v*"]

       UT["Unit Tests<br/>unit-tests.yml"]
       EX["Experimental Tests<br/>experimental.yml"]
       PC["Python Compatibility<br/>python-compatibility.yml"]
       CQ["CodeQL<br/>codeql-analysis.yml"]
       GP["GitHub Pages<br/>deploy-pages.yml"]
       CU["Conda Update<br/>cron-conda.yml"]
       LT["Lint<br/>lint.yml"]
       VU["Vendor Update<br/>cron-vendor.yml"]
       PV["Python Versions<br/>cron-python-versions.yml"]
       CT["CI Timing<br/>ci-timing.yml"]
       PS["Project Status<br/>project-status.yml"]
       CR["Create Release<br/>create-release.yml"]

       PUSH --> UT
       PR --> UT

       PUSH --> EX
       PR --> EX

       PUSH --> PC
       PR --> PC
       SAT -->|04:00| PC

       PUSH --> CQ
       PR --> CQ
       SAT -->|02:00| CQ

       PR --> GP
       SAT -->|02:00| GP

       SAT -->|10:00| CU

       PR --> LT
       SAT -->|06:00| LT
       DISPATCH --> LT

       SAT -->|10:00| VU

       MON -->|05:41| PV
       DISPATCH --> PV

       MON -->|07:23| CT
       DISPATCH --> CT

       DISPATCH --> PS
       DAILY -->|00:37| PS
       ISSUES --> PS
       PRT --> PS

       TAG --> CR

       classDef trig fill:none,stroke-dasharray:2 2
       class PUSH,PR,SAT,MON,DISPATCH,DAILY,ISSUES,PRT,TAG trig

.. mermaid::

   flowchart LR
       UT["Unit Tests<br/>unit-tests.yml"]
       VU["Vendor Update<br/>cron-vendor.yml"]
       CU["Conda Update<br/>cron-conda.yml"]
       GP["GitHub Pages<br/>deploy-pages.yml"]
       CC["Coverage Comment<br/>coverage-comment.yml"]
       CR["Create Release<br/>create-release.yml"]

       UT ==>|workflow_run: completed| VU
       UT ==>|workflow_run: completed| CU
       UT ==>|workflow_run: completed| GP
       VU ==>|workflow_run: completed| CR
       UT ==>|workflow_run: completed| CC

       VU -.-> UT
       CU -.-> UT
       GP -.-> UT
       CR -.-> UT

The double relationship between **Unit Tests** and the dependants that also
call it is the part that reading a single file cannot show, and it is
deliberate rather than redundant. Vendor Update, Conda Update and GitHub Pages
call ``unit-tests.yml`` with ``gate-only: true`` themselves (dotted, above)
**only when their own trigger is** ``schedule`` -- their gate jobs' ``if:``
skips ``workflow_run``, and GitHub Pages' skips ``pull_request`` as well -- so
only on the Saturday path, where no completed Unit Tests run exists yet to read
a verdict from. On the ``workflow_run`` path (thick arrows), each reads the
verdict Unit Tests already reached instead of re-running the gate a second
time, and acts on it only once its ``verdict`` job, described under the edge
list below, says it is a verdict on the commit it builds. Create Release has
no ``schedule``, and its gate job's ``if:`` reads ``version_check``'s evidence
rather than the event, so its gate can run whichever way the run was raised, once
``version_check`` itself has passed: on a ``v*`` tag push, and on a
``workflow_run`` from Vendor Update when some target is not yet published
(:doc:`releasing` gives the conditions).

``workflow_run`` Edges
----------------------

Each edge cites the ``on:`` block it comes from, so grepping those blocks
re-derives the list:

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
including a pull request's own run of Unit Tests. Every
downstream workflow therefore re-checks ``github.event.workflow_run.event``
and ``.head_branch`` (or, for Create Release and Coverage Comment,
``.conclusion``) itself before doing anything with an outward effect; none of
the filtering happens in the ``on:`` block.

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
starting an independent run after the caller finishes. Every call in this
repository targets the same reusable workflow, with the same input:

* ``.github/workflows/create-release.yml:595`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/cron-conda.yml:50`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/cron-vendor.yml:56`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/deploy-pages.yml:55`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.

``gate-only: true`` selects not only ``unit-tests.yml``'s ``gate`` (the full
suite, on ``latest``) but also ``changelog`` (checks ``CHANGELOG.md`` against its
source entry) and ``python-versions``, which reads ``gate``'s version (see
`Python Versions`_ below). It skips the rest -- the matrix jobs, ``test``,
``test-ktlo``, ``integration``, ``integration-ktlo``, ``engine-tests`` (a job per
engine, each looping over its Python versions), ``pypcap-parity``,
``pypcap-parity-ktlo`` and ``unittest-ordering``, each of which has already run
once for this commit from Unit Tests' own ``push`` trigger (and, all but
``unittest-ordering``, which runs on ``main`` pushes only, from its
``pull_request`` trigger), so running any of them again per caller would test
the same commit several times over. It also skips ``changes``,
``project-tests``, whose project pins ``gate``'s full suite runs too (see
`Project Pins`_ below), and ``required-checks`` (see `Required Status
Checks`_ below), which are gated out by their own ``if:`` rather than by having
already run. ``changelog`` carries no
``if:`` at all and runs on every path regardless -- deliberately, per its own
comment (``unit-tests.yml:1663-1669``): ``create-release.yml`` feeds
``CHANGELOG.md`` to the GitHub Release body, so the release path is exactly
where a drifted file must not go unchecked. Confirmed on run `36210743295
<https://github.com/JarryShaw/PyPCAPKit/actions/runs/36210743295>`__ (a
schedule-triggered GitHub Pages run): both ``Changelog drift`` and ``Gate
(full suite, Python 3.14)`` succeeded, with the matrix jobs that
existed then -- ``Python ${{ matrix.python-version }}``, ``Integration
Python …``, ``Engines Python …`` and ``PyPCAP/PyPCAPFile parity Python
…`` -- all reporting ``skipped``.

The Skip Cascade (`#888 <https://github.com/JarryShaw/PyPCAPKit/issues/888>`__)
-------------------------------------------------------------------------------

The relationships above compose into a failure mode worth seeing on its
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
the ``vendor_update`` job reads from that run's jobs first (observed on run
38650191283). ``!cancelled()`` keeps a skipped ``vendor_update``, on a push, from
skipping it. ``unit-tests`` then depends on that job with
``needs: [ version_check ]`` (``create-release.yml:583``) and an ``if:`` that
calls no status-check function, so a skipped dependency skips it too -- and
every job past it is gated the same way: ``github`` needs ``[ unit-tests,
version_check ]`` (``:621``), ``tag`` needs ``[ github, unit-tests,
version_check ]`` (``:808``), ``pypi`` needs ``[ github, unit-tests,
version_check ]`` (``:974``), and ``conda`` needs ``[ tag, github,
unit-tests, version_check ]`` (``:1210``).

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
(``create-release.yml:808,974``) and of ``conda`` (``:1210``), but ``github``
already implies those edges, since it depends on both itself. Drawing them
would add lines without changing which job can start before which, or which
job a skip in ``version_check`` reaches.

The whole run then reports **skipped**, not failed -- there is no red X to
notice. Observed in production on runs `36511610205
<https://github.com/JarryShaw/PyPCAPKit/actions/runs/36511610205>`__ and
`36510774776
<https://github.com/JarryShaw/PyPCAPKit/actions/runs/36510774776>`__, both
``workflow_run``-triggered **Create Release** runs on ``main`` that concluded
``skipped`` with every one of their jobs -- ``Release test gate``,
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
``success`` with ``vendor-update`` skipped (`#1748 <https://github.com/JarryShaw/PyPCAPKit/issues/1748>`__) is still keyed on the ref:
the group reads only the event, which does not say which jobs ran. It can still
displace a run pending there, and releases nothing in its place, so that
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
workflow can only narrow the token its caller passes, and every caller grants
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
Python Compatibility, Lint, CodeQL, GitHub Pages and Experimental Tests (`#1732 <https://github.com/JarryShaw/PyPCAPKit/issues/1732>`__, so
its two-hour legs stay measured), a day per query because a filtered listing stops
at 1,000 runs (Pages completed 1,154 in the week to 2026-10-09). It then reads the
jobs of an evenly spaced sample -- 150 push and 150 pull-request runs of Unit Tests,
60 runs of each other workflow -- and the summary says how many runs each sample
holds and which span they cover. For the week to 2026-10-19 that was 677 calls
(`#1930 <https://github.com/JarryShaw/PyPCAPKit/issues/1930>`__: 49 listing pages,
one per workflow per day and one more per further 100 runs; 601 job reads; 15 for
the JUnit artifacts; 12 workflow-file reads) of ``GITHUB_TOKEN``'s 1,000 an hour, on
a read-only token (``actions: read``, ``contents: read``). It took 16.6 minutes,
908 seconds of it on the job reads, which the API answers at up to 2.4 s each and
which are made one at a time. So they are read last, in an order every prefix of
which spans each sample, and stop at ``--budget-minutes`` (30): the report is then
written on the runs read, with a note saying so. The step's cap (35 minutes) and the
job's (40) sit above that budget, and the summary and upload steps run on
``always()``, so a report written before a cap stopped the job is still published.
Progress goes to the log as the script runs. A job is measured by its own outcome: one
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
so an absolute HARD line would email about the queue every week. The 25% rise is a
starting value, to be tuned against the weekly reports. ``W9`` is therefore expected to
fire while the pool stays saturated, and the JUnit timings are what show whether
``W7``'s 10-second test line needs raising. What to do when one fires is on
:doc:`conventions/process`.

``H1``, ``H2`` and ``H4`` on a non-blocking job are warnings, not HARD, so they do
not fail the run (`#1732 <https://github.com/JarryShaw/PyPCAPKit/issues/1732>`__): on every job of :file:`experimental.yml`, which no
required context names, on every :ref:`KTLO <ktlo-tier>` leg, a job whose name ends in ``(KTLO)``
(`#1633 <https://github.com/JarryShaw/PyPCAPKit/issues/1633>`__), and on a job whose name ends in ``(experimental)`` in any workflow. That
last covers the experimental legs that ran in :file:`unit-tests.yml` under
``test``'s 45-minute cap before the split. The finding keeps its ``H`` id and says it is non-blocking. A
KTLO leg past its job's ``timeout-minutes`` is still cancelled, and its check run
reads red, though since `#1738 <https://github.com/JarryShaw/PyPCAPKit/issues/1738>`__ nothing gating waits on it, so that warning is worth
acting on before the cap.

Work Kept Off the Pull-Request Queue (`#1538 <https://github.com/JarryShaw/PyPCAPKit/issues/1538>`__)
-----------------------------------------------------------------------------------------------------

Cuts in :file:`unit-tests.yml` keep work that cannot gate a merge from competing
with pull-request jobs for the 20-runner pool. None touches a required check or adds a
permission to the reusable workflow.

* ``unittest-ordering`` runs on ``main`` pushes only, per `#1052
  <https://github.com/JarryShaw/PyPCAPKit/issues/1052>`__ item H, and has
  ``needs: [test]``, so its cells join the queue once ``test`` finishes rather
  than when the push run is created, ahead of that run's own ``Python`` legs and of
  pull-request jobs created later in a merge wave. Its ``if:`` opens with
  ``!cancelled()``, so the cells still run when ``test`` fails, and a red cell still
  fails the push run that GitHub Pages, Conda Update and Vendor Update (and so Create
  Release) wait on. The cost is wall time: the push run, and those workflows, finish
  about one slowest cell later, about 6 min before any queue wait (estimate).
* ``engine-tests`` has no ``DPKT`` cell. Its only path was
  :file:`tests/toolkit/test_dpkt_unit.py`, which ``test`` runs with ``DPKT`` installed
  on every leg. Dropped with it: that file in a venv holding only ``test`` and ``DPKT``.

Another cut, running the then-prerelease 3.15 engine cell on ``main`` pushes only,
ended with `#1633 <https://github.com/JarryShaw/PyPCAPKit/issues/1633>`__: 3.15 is
in the supported tier, so its cells block on every run.

Required Status Checks
----------------------

Ruleset ``23497679`` on ``main`` requires the contexts below, with
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
     - ``unit-tests.yml:2037``
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
(``unit-tests.yml:2037``). ``Compat Python`` is defined by one, the
``compatibility`` job in ``python-compatibility.yml`` (``:60``), whose matrix
(``:74``) comes from :file:`.github/python-versions.toml`: the required legs
are its supported tier (``python-versions.toml:20-24``), and its KTLO legs
(``python-versions.toml:16-19``) have names ending in ``(KTLO)``, so no required
context matches one. A comment at
``unit-tests.yml:1949`` mentions the string without defining it.

``Required checks passed`` is an aggregate, not a single check run. The ruleset
requires it and the ``Compat Python 3.11``-``3.15`` legs, nothing else, as
``unit-tests.yml``'s own comment (``unit-tests.yml:1948-1958``) records. It
``needs:`` the gating jobs of ``unit-tests.yml`` -- ``test``, ``integration``,
``engine-tests`` and ``pypcap-parity``, plus ``project-tests``, the one run of
the project pins, and ``changes`` for the docs-only path -- and checks each
result explicitly
(``unit-tests.yml:2036-2092``). Rulesets match check names literally, with no
wildcard, so requiring the matrix cells one by one would mean editing the
ruleset whenever a matrix changes; the aggregate keeps the required list fixed.
It accepts the gating jobs as ``skipped`` only on a docs-only pull request, where
``project-tests`` runs every test that reads ``docs/`` or Markdown as well;
``project-tests`` must pass on every diff. The ``Compat`` legs stay required separately because they come from
``python-compatibility.yml``, and a job cannot ``needs:`` a job in another
workflow file. This job runs on Unit Tests' own ``push``/``pull_request``
triggers; the ``gate-only: true`` reusable calls documented above skip it via
``if: ${{ always() && inputs.gate-only != true }}`` (``unit-tests.yml:2039``),
so it is never produced -- and never expected -- on those paths.

.. _ktlo-tier:

Python versions are tiered -- supported and KTLO
(`#1633 <https://github.com/JarryShaw/PyPCAPKit/issues/1633>`__), and experimental
(`#1660 <https://github.com/JarryShaw/PyPCAPKit/issues/1660>`__, below) -- in
:file:`.github/python-versions.toml` (see `Python Versions`_).
The **supported** tier, 3.11-3.15, blocks: a failed leg fails ``Required checks passed`` or its own
required ``Compat`` context. The **KTLO** (*keep the lights on*) tier -- end-of-life 3.7-3.10, still built and
tested -- never blocks, is never a required context, and never shows a commit or a
pull request red (`#1672 <https://github.com/JarryShaw/PyPCAPKit/issues/1672>`__). In ``unit-tests.yml`` the KTLO legs are jobs of their own
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
  ``continue-on-error: ${{ matrix.ktlo == true }}`` (``unit-tests.yml:443-460``),
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
  ``Compat Python 3.7 (KTLO)`` carried it. ``unit-tests.yml``'s KTLO jobs
  carry it on top of the step-level guards, as a backstop for the failures no step
  contains, as ``experimental.yml``'s job does; it "prevents a workflow run from
  failing when a job fails" (`Workflow syntax
  <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idcontinue-on-error>`__),
  so the Unit Tests run its ``workflow_run`` consumers read stays green.

Errors remain on a failed KTLO step, though none changes a conclusion: the
runner's ``Process completed with exit code N.`` for a ``run:`` step, and an
action's own. And `#1634 <https://github.com/JarryShaw/PyPCAPKit/issues/1634>`__'s tag check still blocks the ``pypi`` KTLO legs: it fails
every leg alike, and masked, the leg would go on to publish.

3.7 can neither install the ``test`` extra nor import the package, so each 3.7 leg
fails one step, with a warning saying why -- ``test`` and ``integration`` at the
install step, the ``Compat`` leg at ``Verify package`` -- and concludes
``success``. They run on ``ubuntu-22.04``, which retires on 2027-04-17 after
brownouts from 2027-03-23 (actions/runner-images#14254). A brownout fails a
``test-ktlo`` or ``integration-ktlo`` leg before any step runs, where no step-level
``continue-on-error`` reaches; since `#1738 <https://github.com/JarryShaw/PyPCAPKit/issues/1738>`__ that fails nothing gating, but the leg's
check run reads red, so they must still go before then (`#1660 <https://github.com/JarryShaw/PyPCAPKit/issues/1660>`__). 3.6 is
in no matrix: setup-python builds it only for retired Ubuntu images. Nor are
3.7-3.9 in ``engine-tests``, which installs every interpreter on
``ubuntu-latest``, where setup-python has no Ubuntu 26.04 build of any of them. Nor
are they in ``pypcap-parity``, which also runs on ``ubuntu-latest``; none of them
was measured on that job.

The **experimental** tier is free-threaded CPython and GraalPy, spelt as
setup-python reads them (``3.14t``, ``graalpy-25.4``). Each runs a leg of
``experimental``, the matrix job of :file:`.github/workflows/experimental.yml`
("Experimental Tests"), named ``Python <version> (experimental)``, and nothing
else: no ``integration``, ``Compat``, wheel or conda leg, so never a required
context. They were legs of ``test`` until `#1732
<https://github.com/JarryShaw/PyPCAPKit/issues/1732>`__, which moved them to a
workflow of their own, by the owner's ruling that nothing waits on them. **That
workflow reports separately and holds up nothing**: a job cannot ``needs:`` one in
another workflow, nothing calls it, and no ``workflow_run`` names it, so the Unit
Tests run completes without it, and with it ``Required checks passed``,
``unittest-ordering`` and the workflows that wait on Unit Tests completing
(``coverage-comment.yml``, ``deploy-pages.yml``, ``cron-vendor.yml`` and
``cron-conda.yml``). It runs on Unit Tests' ``push`` and ``pull_request`` events,
skips a docs-only pull request by the same ``changes`` script, and lets a newer
commit supersede a run, a pull request's or, unlike Unit Tests, a push to ``main``'s
(`#1903 <https://github.com/JarryShaw/PyPCAPKit/issues/1903>`__): since nothing
waits on the legs, ``main``'s newest commit is the one worth testing, whereas Unit
Tests keeps a run per push for ``unittest-ordering``, which runs only there.

A superseded run is skipped or stopped, never cancelled (`#1938
<https://github.com/JarryShaw/PyPCAPKit/issues/1938>`__): GitHub counts a
``cancelled`` check against its commit, so a cancelled run marks the commit red.
The workflow has no ``concurrency`` group either, since a group cancels its pending
run once a newer one queues. Its first job, ``current`` ("Check the commit is still
current"), sets up ``latest`` and installs ``requests``, which the script fetches with,
then runs :file:`util/superseded.py`'s ``check``. A push's commit is current
while it is the head of ``main``; a pull request's while the pull request is open and
its head is still the event's ``pull_request.head.sha``; any other event's always.
Every other job needs ``current`` and skips where its output is ``false``, so a run
superseded before it starts ends with ``skipped`` checks and a ``Superseded`` notice.
Each of those ``if:`` conditions opens with ``!cancelled()``, which drops the implicit
``success()``, so a failed ``current`` step, which leaves the output empty, or a failed
``current`` job runs the rest; the legs still need ``changes`` and ``python-versions``
to succeed. ``Run unit tests`` runs its whole command -- the scope's ``sudo`` where
there is one, then ``prlimit``, ``timeout`` and pytest -- under the script's ``watch``,
outside the scope, which asks again every 60 seconds. The watcher runs on a CPython of
its own, ``latest`` from a second setup-python step, ``watcher-python``, with
``update-environment: false``, so the leg's ``PATH``, ``LD_LIBRARY_PATH`` and pip
cache are as its own setup-python left them, and ``requests`` goes into that
interpreter, never the leg's GraalPy or free-threaded build. The two steps are capped
at 1 minute each, and where either fails the tests run unwatched. Once the commit is superseded,
or the pull request merged or closed, it sends SIGTERM, then SIGKILL 30 seconds on:
to ``pcapkit-tests.scope`` by name (``sudo -n systemctl kill``) where the tests run
in it, since they run as the runner's user under a root-owned ``sudo`` and in
``timeout``'s own process group, and to the command's session otherwise. Ubuntu's
``/etc/sudoers`` sets ``use_pty``, which sudoers(5) says has no effect where ``sudo``
has no terminal, as in a step; the scope is reached by name either way. Once the
command exits, the watcher writes a ``Superseded`` notice and a job-summary line and
exits 0, so the leg ends green and frees its runner. Every wait is bounded: where the
command outlives SIGKILL by 15 seconds, it writes a ``Superseded run not stopped``
warning and exits 70, not 0, since the tests may run on, holding the step's output,
until ``timeout`` or the step's cap ends them, and the failed step is then a warning
like any other on these legs. Otherwise the step ends with the tests' own status. An
API the script cannot read counts as current, so it never stops the tests, and it
asks with ``If-None-Match``, as a ``304`` answer costs no rate limit.

The legs never block, by the KTLO mechanics above: every step that can fail has
``continue-on-error: true``, their annotations are warnings, and ``Experimental
summary``, the job's last step, reports each failed step. A failure no step
contains, such as a lost runner, fails the job, and the job's own
``continue-on-error: true`` keeps it from failing the run: it "prevents a workflow
run from failing when a job fails" (`Workflow syntax
<https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idcontinue-on-error>`__),
though the leg's check run still reads ``failure``. A job past its
``timeout-minutes`` is cancelled, and that page does not say whether the job-level
guard covers a cancellation. So setup-python, the install, the watcher's setup-python
and ``requests`` (`#1938 <https://github.com/JarryShaw/PyPCAPKit/issues/1938>`__,
below) and the tests have caps of their own, of 5, 10, 1, 1 and 120 minutes, under
the job's 140, which leaves 3 for the rest: a step at its cap
fails rather than cancels, and the guard holds (actions/runner
``src/Runner.Worker/StepsRunner.cs:322-353``). The runner's ``has timed out`` error
stays, changing no conclusion, as ``Process completed with exit code N.`` does.
Everything but the install and the tests took under 20 seconds on every uncovered
leg of runs 38569321543-38569522442. ``test``'s caps are main's: 45 minutes for the
job, and none on a step. Promoting one whose leg stays green is a hand edit, which
:file:`util/python_versions.py` refuses until the build has a wheel, a conda build
and a ``Compat`` leg.

The tests' 120 minutes are sized for GraalPy, the slowest of the legs that share
them: its leg reached 26% of the unit tier in 25 minutes (job 115915976024), where
3.14t's ran the whole tier in 5.8 (run 38581834697). The experimental legs run the
``ALL`` test tier alone, as every leg but ``latest`` does (see `Test Tiers`_ below):
``List the LATEST tier`` asks ``latest_tier_paths()`` on the runner's own ``python3``,
before setup-python, so GraalPy does not parse the tree, and ``Run unit tests``
passes each module it printed as an ``--ignore``. The
round-trip sweeps of `#1732 <https://github.com/JarryShaw/PyPCAPKit/issues/1732>`__
took 8% of the unit tier's time in a serial 3.14 run (86 of 1,031 s), and 10-11% on
the 3.14, 3.15 and 3.14t legs of run 38581834697, so the rest should take GraalPy
88-113 minutes (estimate).

GraalPy's leg still loses its runner 18-30 minutes into its tests, with ``The runner
has received a shutdown signal`` (`#1740 <https://github.com/JarryShaw/PyPCAPKit/issues/1740>`__),
so each experimental leg samples its runner while the tests run. ``Start the resource
monitor`` writes ``free -m``, ``df -h`` of ``/`` and the workspace's volume,
``/proc/loadavg`` and the five processes with the most RSS every 30 seconds, each
line led by ``[monitor]``, to ``$RUNNER_TEMP/resource-monitor.log``; ``Run unit
tests`` copies the file into its own log with ``tail -F``; ``Stop the resource
monitor`` ends the sampler, ``if: always()``. The file is uploaded as
``resource-monitor-<version>`` (14 days, ``if: always()``, ``continue-on-error``)
only where the runner survives the tests. `always()
<https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#always>`__
runs a step "even when canceled", and docs.github.com says nothing of a runner's
shutdown, after which the runner evaluates no later step's condition (actions/runner
``src/Runner.Worker/StepsRunner.cs:205-208``, at ``796cc18ff``). Job 116057255255
skipped every step after its tests, ``Post Run actions/checkout@v7`` too, whose
`post-if
<https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax#runspost-if>`__
"defaults to ``always()``". On a lost runner, then, the ``[monitor]`` lines in the
tests' log are the record. The monitor's steps -- start, stop and upload -- are each
``continue-on-error`` with no cap of their own, so the caps above and the check names
are as they were.

A lost runner fails the job, and so its check, whatever ``continue-on-error`` says,
so ``Run unit tests`` holds the tests to what leaves the runner alive, and a breach
fails the step, which ``Containment summary`` and ``Experimental summary`` report as
warnings:

* GraalPy alone gets ``GRAAL_PYTHON_VM_ARGS=--vm.Xmx2g --vm.XX:+ExitOnOutOfMemoryError``,
  a 2 GiB heap for every GraalPy process, xdist workers included, and ``-n 3``, a CPU
  of the runner's 4 left to the JIT and the runner; 3.14t keeps ``-n auto``. A
  worker's live heap grows with the tests it runs (`#1753
  <https://github.com/JarryShaw/PyPCAPKit/issues/1753>`__): in job 116172356218 all
  three reached 2.2-2.6 GB RSS in 16 minutes, and a ``MemoryError`` in pytest's own
  failure report ended the session, exit 3, with 7.9 GB free. So a worker whose heap
  is spent exits, xdist fails the test it ran as crashed and starts another, and
  ``--max-worker-restart=30`` allows 30 restarts in all, where three 16-minute heaps need
  about 21 in 110 minutes; xdist's default is 4 a worker, 12 at ``-n 3``.
* ``timeout --signal=INT --kill-after=3m 110m`` ends pytest under the step's 120-minute
  cap, so it still writes the junit XML, and exits 124; ``prlimit --fsize=2147483648``
  caps any file at 2 GiB.
* Where the scope starts ``true`` under a throwaway unit, ``pcapkit-probe-<pid>.scope``,
  with every flag the tests get (``sudo -n --preserve-env``, ``MemoryMax=12G``,
  ``MemorySwapMax=0``, ``CPUWeight=20``, ``--uid``, ``--gid``), the tests run in the
  transient scope ``pcapkit-tests.scope`` as the runner's own user; otherwise they run
  the same pytest command line uncapped, under a ``No memory cap`` warning. sudo
  resets ``PATH`` and drops ``LD_*``, where setup-python puts its ``lib/``, so ``env``
  sets them, and the heap, again. The sampler started a step earlier, outside the scope, so an OOM kill there
  leaves it running; each sample adds the kernel's ``oom_kill`` count and the scope's
  ``memory.current`` and ``memory.events``.

The step writes ``$RUNNER_TEMP/tests-status``: the exit status, the scope and the
probe's error, the seconds the tests took, the OOM kills while they ran
(``/proc/vmstat``), the lines in their output that report a raised ``MemoryError`` (#1962),
not those that mention one, such as a docstring a traceback prints, and xdist's ``node
down`` lines. From it and the monitor's last sample, ``Containment summary`` warns
``No memory cap``, ``tests lost a process to the OOM killer``, ``tests timed out at 110
minutes``, ``tests raised MemoryError`` or ``tests lost an xdist worker``, each a
warning of its own. A timeout is exit 124, or 137 with no OOM kill
after 110 minutes: ``--kill-after``'s SIGKILL to a teardown SIGINT did not end, where an
OOM kill of pytest exits 137 too. ``Experimental summary``, the job's last step and the
KTLO summary's script, still warns of every failed step, ``tests`` included. The 2 GiB,
``-n 3`` and 12G are estimates for a 16 GB, 4-CPU runner until a run shows them. At 3
workers rather than 4, GraalPy's tests should take about 117-151 minutes (an inference
from the 88-113 above, not measured), so its leg may end on the 110-minute timeout as a
warning: that is expected, blocks nothing, and leaves the caps as they are.

Test Tiers
----------

Every test module runs in one of two *test tiers* (`#1958
<https://github.com/JarryShaw/PyPCAPKit/issues/1958>`__): ``ALL``, which runs on every
leg, and ``LATEST``, which runs on ``latest`` alone. They are orthogonal to the unit
and fixture-dependent tiers, which decide what a module may read and so which job
collects it; a test tier decides on which of that job's legs it runs.

``module_tier()`` in :file:`tests/_tiers.py` decides, in one place, for every
``tests/**/test_*.py``. ``ALL`` is a curated, opt-in list (#1958, #1963): short enough
to save time on every leg, the same on every leg so QA stays consistent, and enough
on its own to validate a change on each interpreter, while ``latest`` runs the whole
suite as the gate.

* **The marker.** A module joins ``ALL`` with a module-level ``__tier__ = 'ALL'``,
  read by AST, under a ``#: Test tier (#1958): <reason>`` comment. It is a module
  constant rather than a pytest marker, so ``unittest-ordering``'s plain
  ``unittest`` runs read the same module. A value that is not ``'ALL'`` or
  ``'LATEST'``, or a marker assigned twice or anywhere but at the module's top
  level, fails the tier guard.
* **The default.** A module that states no tier is ``LATEST``, so a new module runs
  on ``latest`` until it says why every leg needs it. ``__tier__ = 'LATEST'`` is
  optional, and records why a module someone might expect on every leg is not; a
  module that compares ``sys.version_info``, ``sys.implementation`` or
  ``sys.maxsize``, reads
  ``sys.flags``, calls ``sysconfig.get_config_var()`` or probes :mod:`sys` with
  ``hasattr``/``getattr`` has to state its tier either way, so a version gate never
  lands on ``latest`` alone by omission. The check is syntactic and best-effort: an
  alias, a flag imported from ``pcapkit.utilities.compat`` or a gate in a helper is
  not seen, and such a module states its tier by hand.

A module opts in when it exercises behaviour that can differ between interpreters
or versions:

* compat shims and version or implementation gates;
* C-accelerated versus pure paths, and code sensitive to garbage collection, weak
  references or finalisation;
* ``int``, ``bytes`` and ``struct`` edge cases, and ``sys.maxsize`` or recursion
  limits;
* pickling and copying, metaclass and ABC machinery, and enum mechanics;
* stream and buffer semantics, threading and locking, and the warning and
  exception hooks;
* a third-party engine whose installable releases vary by interpreter, such as
  ``pypcap`` and ``pypcapfile``, which install below 3.12 only, and Scapy, which the
  ``integration`` and ``pypcap-parity`` legs install on every interpreter and a
  ``test`` leg off ``latest`` skips;
* the hand-picked round trips, whatever their names, and the #1202 edge-case
  tables, whose cases are each written out by hand, as the owner ruled on #1958;
  and
* the smoke slice: a representative module per protocol family and per package,
  so each leg still drives the main parse and build paths.

Everything else is ``LATEST``: the per-protocol field-by-field tests, whose
behaviour is interpreter-independent pure Python, each real sweep -- a round trip
over every class or registry entry a table enumerates, every offset of a packet or
every capture, as the owner ruled on #1732 and #1958 -- and the docs, project and
structure tests. The vendor extra is installed on ``latest`` alone and the crawlers
are pure Python, so the vendor modules are ``LATEST``, each saying so, but for the
file-restore and environment-variable tests, which stay on every leg. The tier guard itself is ``ALL``, since :file:`tests/conftest.py`
runs it at collection on every leg.

Which legs run which tier:

.. list-table::
   :header-rows: 1

   * - Leg
     - Tiers
   * - ``test`` on ``latest``, the coverage leg
     - ``ALL`` and ``LATEST``, less the project pins
   * - ``project-tests``
     - the project pins
   * - ``test`` off ``latest``, ``test-ktlo``, ``experimental``
     - ``ALL``
   * - ``integration`` on ``latest``
     - ``ALL`` and ``LATEST``
   * - ``integration`` off ``latest``, ``integration-ktlo``, ``pypcap-parity``,
       ``pypcap-parity-ktlo``
     - ``ALL``
   * - ``gate``, ``unittest-ordering``
     - ``ALL`` and ``LATEST``

Each leg asks :file:`tests/_tiers.py` at run time, so no workflow lists a tier: a
``test`` leg off ``latest`` passes each module ``latest_tier_paths()`` prints as an
``--ignore``, and an ``integration`` or ``pypcap-parity`` leg off ``latest`` runs
``fixture_tier_paths('ALL')``, which drops each ``LATEST`` path and node ID and
replaces a directory holding a ``LATEST`` module by its ``ALL`` ones, since pytest
applies no ignore to a path it was handed. :file:`tests/test_tier_guard.py` checks
that every module resolves to exactly one tier and runs the steps to check what each
does with the answer, and :file:`tests/project/test_sweeps_on_latest_only_1732.py`
does the same for every leg the tier file gives.

The project pins stay in a job of their own rather than joining the ``latest`` leg:
``project-tests`` runs in parallel with the coverage leg, the slowest of ``test``'s,
rather than lengthening it under coverage, and it is also the job that runs the docs
readers on a docs-only diff.

Latest CPython runs the whole suite, as the sanity check and the gate (the owner's
ruling on #1958), so it also installs what the whole suite gates on. In ``test`` and
``integration`` the step ``Install the whole suite's dependencies on latest`` runs on
the ``latest`` leg alone, after the install every leg runs, and adds the engines pip
can install there (``Scapy``, ``PyShark``), html5lib through ``vendor``, Sphinx and
the pinned sphinx-autodoc-typehints through ``docs``, and emoji through ``cli``.
``project-tests`` and ``gate``, which run on ``latest`` only, install the same set in
their ``Install package and test dependencies`` and ``Install package, test and
generator dependencies`` steps. The other legs keep their install lines and run the
``ALL`` tier with them, so a test gated on one of these extras skips there and runs on
``latest``. The other engines stay out: ``PCAP_CT`` needs a system libpcap, which
``engine-tests`` installs for its own cell, and the ``PyPCAP`` and ``PyPCAPFile``
markers resolve to nothing on ``latest``. :file:`tests/_dependency_gates.py` reads the
``latest`` step as that leg's extras, and
:file:`tests/project/test_whole_suite_on_latest_1958.py` pins the set and the gates it
closes.

Project Pins
------------

The *project pins* run once per push (`#1954
<https://github.com/JarryShaw/PyPCAPKit/issues/1954>`__): the modules under
:file:`tests/project` whose run does not vary by interpreter, as they read the
repository's text or drive a ``util/`` script. ``is_project_pin()`` in
:file:`tests/_tiers.py` decides, by the AST of each module and of the repository
code it runs: a module is a pin unless it, a module it takes names from, or a file
it runs by path imports ``pcapkit``, or compares ``sys.version_info`` or
``sys.implementation``. A computed import, or a ``.py`` name computed for a
loader or a child process, counts as importing it, and so does a file that does
not parse. Every pin is in the ``LATEST`` test tier (see `Test Tiers`_ above),
and a ``tests/project`` module marked ``__tier__ = 'ALL'`` is no pin. The modules
that import ``pcapkit`` are no pins either; those the tiers send to ``latest`` run
on ``test``'s ``latest`` leg, under coverage.

``project-tests`` runs the pins under pytest, with ``test``'s flags, on ``latest``,
on every pull request and every push to ``main``, and ``required-checks`` needs it.
Every ``test``, ``test-ktlo`` and ``experimental`` leg passes each pin as an
``--ignore``, ``latest``'s coverage leg included, which measures only ``pcapkit``.
``latest`` asks ``project_pin_paths()`` at run time, and every other leg
``latest_tier_paths()``, which holds each pin, as ``integration`` asks for its
selection, so no workflow lists the pins, and :file:`tests/test_tier_guard.py` runs
the steps to check what each does with the answer. Under ``gate-only``, ``gate``'s
full suite runs the pins with everything else. ``unittest-ordering``'s ``project``
cell keeps them, as it asks how a module runs in one interpreter, in file order and
without xdist, which is a question about the module rather than the Python version.

A pin's skip where ``tomllib`` is missing, before 3.11, runs on no leg: the scripts
those pins drive read the tier file on the runner's own ``python3``, and
:file:`tests/project/test_python_versions_1660.py` checks those skips in a child
interpreter that cannot import ``tomllib``.

File Size Caps (`#1969 <https://github.com/JarryShaw/PyPCAPKit/issues/1969>`__)
-------------------------------------------------------------------------------

A test that writes without bound fills the runner's disk rather than failing: `#1372
<https://github.com/JarryShaw/PyPCAPKit/issues/1372>`__'s ``out.json`` grew to
several gigabytes on every run. So every pytest and unittest command in
:file:`.github/workflows/unit-tests.yml` runs as ``python util/cap_file_size.py
python -m ...``: ``test``'s ``Run unit tests``; ``integration``'s,
``pypcap-parity``'s and ``gate``'s ``Run full test suite``; the KTLO twins of
``test``, ``integration`` and ``pypcap-parity``, which share their steps; the
engine cells that ``engine-tests``' ``Write the per-cell script`` writes;
``unittest-ordering``'s cells; and each run step of ``project-tests``.

``util/cap_file_size.py`` sets ``RLIMIT_FSIZE``, soft and hard, to 2 GiB, or keeps
a lower hard limit, and execs the command, so the step's exit status and
``continue-on-error`` behave as before and every process the command starts
inherits the cap. A write past it raises ``OSError: [Errno 27] File too large`` in
Python, since CPython ignores ``SIGXFSZ``, so the test errors; any other program is
killed by the signal, whose default action the script restores before it execs.
``experimental.yml``'s legs get the same 2 GiB through ``prlimit --fsize`` (see
above).

:file:`tests/project/test_file_size_caps_1969.py` fails when a command in
``unit-tests.yml`` runs pytest, unittest or :file:`util/run_unittest_leg.py`
without the script, and runs the script against a small limit.

Action Pins (`#1968 <https://github.com/JarryShaw/PyPCAPKit/issues/1968>`__)
----------------------------------------------------------------------------

A tag or a branch is a reference its owner can move, so every ``uses:`` of an
action outside this repository names a full commit, with the release that commit
is as a trailing comment::

   - uses: actions/checkout@<40-hex commit> # v7.0.1

A step's ``uses`` is therefore the commit alone, as the YAML reads it; the comment
is what Dependabot rewrites with the commit on a bump. A local ``./`` workflow call
stays as it is. :file:`.github/dependabot.yml` watches the ``github-actions``
ecosystem from the repository root beside ``pip``, on the same weekly schedule, so a
new release reaches the workflows as a Dependabot pull request rather than by a tag
moving under a run.

:file:`tests/project/test_actions_pinned_1968.py` fails on a ``uses:`` under
:file:`.github` that names a tag, a branch or a commit without its version comment,
and when :file:`.github/dependabot.yml` drops the ``github-actions`` ecosystem.
``pinned()`` and ``versions()`` in :file:`tests/_workflows.py` read a pin, for a test
that names a particular action.

Python Versions
---------------

Since `#1660 <https://github.com/JarryShaw/PyPCAPKit/issues/1660>`__,
:file:`.github/python-versions.toml` declares every Python version CI runs: one
line per version, with its tier -- ``supported``, ``ktlo``, ``experimental``, or
``pre-release``, which no version carries -- and, where ``ubuntu-latest`` cannot
provide it, the ``runner`` it needs. ``latest`` names the newest supported CPython, which every
job on one interpreter runs. :file:`util/python_versions.py` reads the file with
the runner's own ``python3`` -- its ``tomllib`` needs 3.11, and every image that
runs it has 3.12 or newer -- and writes each matrix as JSON: a ``python-versions``
job in ``unit-tests.yml`` and ``python-compatibility.yml``, ``version_check`` in
``create-release.yml`` and ``conda-update`` in ``cron-conda.yml`` hand theirs on
through ``fromJSON``, and each single-interpreter job reads ``latest``.

**A tier change is a one-line edit to that file, plus the matching edit to ruleset
23497679's** ``Compat`` **contexts.** The file's ``exemptions`` list each pin kept
off ``latest``, with its reason in the comment above it, such as the conda
jobs' ``!= '3.15'``. ``tests/project/test_python_versions_1660.py`` fails on a
pin the file does not list, on an exemption with no comment, and on a
classifier, doc or comment that no longer matches the file -- a tier range,
the coverage leg's version. Its tests, and the other tests that
read the file, skip on the KTLO interpreters, which have no ``tomllib``. Some
edits it names rather than makes: a new ``pypi`` KTLO leg needs its own
``ktlo_*`` output for ``release_status``, and a pre-release leg needs
non-blocking mechanics no workflow has yet, so the script refuses one.

**Python Versions** (:file:`cron-python-versions.yml`) proposes those edits.
Every Monday, or on dispatch, its ``detect`` job runs
:file:`util/update_python_versions.py` with no secret: it reads python.org's
release cycle, PyPy's releases, setup-python's ``versions-manifest.json`` and
the runner-images README, recomputes the tiers by the rules in that script's
docstring, rewrites the file and the prose these tests pin to it, and runs the
audit modules on the result. Only when that changes something does ``pr``
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
instead of writing it. Nor does it retire a job (`#1747
<https://github.com/JarryShaw/PyPCAPKit/issues/1747>`__): when the tiers leave
a matrix job with no leg, as 3.11 reaching end of life leaves
``pypcap-parity``, it writes them as computed, warns, and puts the job first in
the body as a manual step: retire or remove it, and the ``needs:`` that list it,
such as the one in ``required-checks``, before merging. A proposal is still
identified by its tiers alone, so retiring the job on ``main`` does not propose
them again. The
experimental entries are hand-maintained: no source it reads rates them, so
every run keeps their lines as written, and a hand edit to one changes no
proposal.

Deployment ``environment:``
----------------------------

These jobs declare a deployment ``environment:`` and can therefore pause for an
approval, in ``create-release.yml`` and ``cron-python-versions.yml``:

* ``github`` -- ``environment: github-release`` (``create-release.yml:618``)
* ``tag`` -- ``environment: conda-tag`` (``create-release.yml:806``)
* ``pypi`` -- ``environment: pypi`` (``create-release.yml:969``)
* ``conda`` -- ``environment: anaconda`` (``create-release.yml:1207``)
* ``pr`` -- ``environment: github-release``, for the release App's key (see
  `Python Versions`_)

No other workflow in scope here declares one -- including
``deploy-pages.yml``, whose ``publish-pages`` job pushes straight to the
``gh-pages`` branch via ``JamesIves/github-pages-deploy-action`` rather than
through an ``environment:``-gated deployment. Its ``deploy-pages`` job builds
the site, a pull request's included, with ``contents: read``, and uploads it
for ``publish-pages``, which alone holds ``contents: write`` and never runs on
a pull request. Its ``Check gh-pages holds no newer build`` step skips the
deploy when ``gh-pages`` already holds the build of a commit this run's commit
is behind, so a build that finishes late cannot replace newer documentation
(`#1968 <https://github.com/JarryShaw/PyPCAPKit/issues/1968>`__). Of these environments, only
``github-release`` carries a required reviewer; :doc:`releasing`
covers why one approval on that single environment is enough to gate the
whole release graph, and is the page to read for the reasoning rather than
repeating it here.
