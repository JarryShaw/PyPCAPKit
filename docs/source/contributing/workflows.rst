GitHub Actions Workflows
========================

.. important::

   The ten workflows under :file:`.github/workflows/` trigger each other, and
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
       SCHED["schedule (Saturday, or daily)"]
       ISSUES["issues"]
       PRT["pull_request_target"]
       DISPATCH["workflow_dispatch"]

       CQ["CodeQL<br/>codeql-analysis.yml"]
       UT["Unit Tests<br/>unit-tests.yml"]
       PC["Python Compatibility<br/>python-compatibility.yml"]
       LT["Lint<br/>lint.yml"]
       VU["Vendor Update<br/>cron-vendor.yml"]
       CU["Conda Update<br/>cron-conda.yml"]
       GP["GitHub Pages<br/>deploy-pages.yml"]
       CR["Create Release<br/>create-release.yml"]
       PS["Project Status<br/>project-status.yml"]
       CC["Coverage Comment<br/>coverage-comment.yml"]

       PUSH --> CQ
       PR --> CQ
       SCHED -->|02:00| CQ

       PUSH --> UT
       PR --> UT

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
the verdict Unit Tests already reached for that same commit instead of
re-running the gate a second time.

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

Reusable-Workflow Calls (``uses:``)
-----------------------------------

A ``uses:`` call is a different relationship from triggering: it runs inside
the caller's own workflow run, as one of the caller's own jobs, rather than
starting an independent run after the caller finishes. All four calls in this
repository target the same reusable workflow, with the same input:

* ``.github/workflows/create-release.yml:374`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/cron-conda.yml:43`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/cron-vendor.yml:49`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/deploy-pages.yml:47`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.

``gate-only: true`` selects **two** of ``unit-tests.yml``'s **ten** jobs,
not one: ``gate`` (the full suite, one Python version) and ``changelog``
(checks ``CHANGELOG.md`` against its source entry). It skips the other
**eight** -- the five matrix jobs, ``test`` (five Python legs),
``integration`` (five), ``engine-tests`` (one job per engine, each looping
over six Python versions), ``pypcap-parity`` (two) and ``unittest-ordering``
(eleven matrix cells), each of which has already run once for this commit
from Unit Tests' own ``push`` trigger (and, all but ``unittest-ordering``,
which runs on ``main`` pushes only, from its ``pull_request`` trigger), so
running any of them again per caller would
test the same commit several times over -- the docs-only path's ``changes``
and ``project-tests``, and ``required-checks`` (see `Required Status
Checks`_ below), gated out by their own ``if:`` rather than by having
already run. ``changelog`` carries no
``if:`` at all and runs on every path regardless -- deliberately, per its own
comment (``unit-tests.yml:1011-1017``): ``create-release.yml`` feeds
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
own graph. Create Release's first job, ``version_check`` -- ahead of the
``uses:`` call above -- carries:

.. code-block:: yaml

   if: ${{ github.event_name != 'workflow_run' || github.event.workflow_run.conclusion == 'success' }}

(``create-release.yml:179``). On the ``workflow_run`` path, this evaluates
**false**, and the job is skipped outright, whenever the upstream Vendor
Update run's own conclusion was anything other than ``success`` -- including
``skipped``, which is exactly what Vendor Update's *own* jobs report when
*their* ``workflow_run``-path guards decline (see ``cron-vendor.yml``'s
``vendor-update`` job). ``unit-tests`` then depends on that job with
``needs: [ version_check ]`` (``create-release.yml:364``) and an ``if:`` that
calls no status-check function, so a skipped dependency skips it too -- and
every job past it is gated the same way: ``github`` needs ``[ unit-tests,
version_check ]`` (``:392``), ``tag`` needs ``[ github, unit-tests,
version_check ]`` (``:493``), ``pypi`` needs ``[ github, unit-tests,
version_check ]`` (``:573``), and ``conda`` needs ``[ tag, github,
unit-tests, version_check ]`` (``:674``).

.. mermaid::

   flowchart TD
       WR["Vendor Update completed<br/>conclusion != success"]
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
(``create-release.yml:493,573``) and of ``conda`` (``:674``), but ``github``
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
own: the ``Python 3.14`` leg of ``test`` (matrix key ``coverage: true``) runs
its unchanged pytest selection under ``coverage run
--rcfile=.github/coverage.toml``. That rcfile repeats
:file:`pyproject.toml`'s ``[tool.coverage.*]`` settings
(``tests/project/test_coverage_rcfile.py`` asserts it) and adds ``parallel``
and ``patch = ["subprocess"]``, without which only the xdist controller is
measured, not its workers, plus ``core = "ctrace"``: with the suite purging
and re-importing pcapkit, one module's peak RSS was 4.17 GiB under the default
``sys.monitoring`` core against 0.41 GiB under ``ctrace``, and that growth
killed the runner. The leg then writes the total and a per-package table to the
job summary and uploads the HTML report as the ``coverage-html``
artifact (30 days), with the bare numbers as the ``coverage-summary`` artifact.

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
     - ``unit-tests.yml:1320``
   * - ``Compat Python 3.10``
     - job ``compatibility``, matrix leg ``3.10``
     - ``python-compatibility.yml:31,41``
   * - ``Compat Python 3.11``
     - job ``compatibility``, matrix leg ``3.11``
     - ``python-compatibility.yml:31,42``
   * - ``Compat Python 3.12``
     - job ``compatibility``, matrix leg ``3.12``
     - ``python-compatibility.yml:31,43``
   * - ``Compat Python 3.13``
     - job ``compatibility``, matrix leg ``3.13``
     - ``python-compatibility.yml:31,44``
   * - ``Compat Python 3.14``
     - job ``compatibility``, matrix leg ``3.14``
     - ``python-compatibility.yml:31,45``

``Required checks passed`` is defined by exactly one job
(``unit-tests.yml:1320``). ``Compat Python`` is defined by two in
``python-compatibility.yml``: the required ``compatibility`` job (``:31``,
``Compat Python ${{ matrix.python-version }}``, expanding to the five required
legs at ``:41-45``) and the non-required ``compatibility-nightly`` job (``:69``,
``Compat Python 3.15 (scheduled)``, see below). A comment at
``unit-tests.yml:1235`` mentions the string without defining it.

``Required checks passed`` is an aggregate, not a single check run. The ruleset
requires it and the five ``Compat Python 3.10``-``3.14`` legs, nothing else, as
``unit-tests.yml``'s own comment (``unit-tests.yml:1234-1244``) records. It
``needs:`` the gating jobs of ``unit-tests.yml`` -- ``test``, ``integration``,
``engine-tests`` and ``pypcap-parity``, plus ``changes`` and ``project-tests``
for the docs-only path -- and checks each result explicitly
(``unit-tests.yml:1319-1373``). Rulesets match check names literally, with no
wildcard, so requiring the matrix cells one by one would mean editing the
ruleset whenever a matrix changes; the aggregate keeps the required list fixed.
It accepts the four legs as ``skipped`` only on a docs-only pull request, where
``project-tests`` -- every test that reads ``docs/`` or Markdown -- must pass
instead. The ``Compat`` legs stay required separately because they come from
``python-compatibility.yml``, and a job cannot ``needs:`` a job in another
workflow file. This job runs on Unit Tests' own ``push``/``pull_request``
triggers; the ``gate-only: true`` reusable calls documented above skip it via
``if: ${{ always() && inputs.gate-only != true }}`` (``unit-tests.yml:1322``),
so it is never produced -- and never expected -- on those paths.

``Compat Python 3.10``-``3.14`` are five ordinary matrix legs, not an
aggregate: ``python-compatibility.yml``'s own comment (``:37-40``) and
``unit-tests.yml``'s matching one for its own, differently-matrixed
``test``/``integration`` jobs (``unit-tests.yml:59-62``, ``unit-tests.yml:230``) both say why 3.15 is
excluded from every *required* matrix in this repository -- the ruleset's
required-checks list stops at 3.14, so a 3.15 leg cannot gate a merge and is
kept advisory (``continue-on-error: true`` in ``python-compatibility.yml``'s
``compatibility-nightly`` job, ``:72``) rather than required.

Deployment ``environment:``
----------------------------

Four jobs, all in ``create-release.yml``, declare a deployment
``environment:`` and can therefore pause for an approval:

* ``github`` -- ``environment: github-release`` (``create-release.yml:389``)
* ``tag`` -- ``environment: conda-tag`` (``create-release.yml:491``)
* ``pypi`` -- ``environment: pypi`` (``create-release.yml:568``)
* ``conda`` -- ``environment: anaconda`` (``create-release.yml:671``)

No other workflow in scope here declares one -- including
``deploy-pages.yml``, whose ``deploy-pages`` job pushes straight to the
``gh-pages`` branch via ``JamesIves/github-pages-deploy-action`` rather than
through an ``environment:``-gated deployment. Of the four above, only
``github-release`` carries a required reviewer; :doc:`releasing`
covers why one approval on that single environment is enough to gate the
whole release graph, and is the page to read for the reasoning rather than
repeating it here.
