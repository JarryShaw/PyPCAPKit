GitHub Actions Workflows
========================

.. important::

   The nine workflows under :file:`.github/workflows/` trigger each other, and
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

.. note::

   No workflow here fires *exclusively* on ``workflow_run``. Each of the four
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

       VU -.->|uses: gate-only| UT
       CU -.->|uses: gate-only| UT
       GP -.->|uses: gate-only| UT
       CR -.->|uses: gate-only| UT

       classDef trig fill:none,stroke-dasharray:2 2
       class PUSH,PR,TAG,SCHED,DISPATCH,ISSUES,PRT trig

The double relationship between **Unit Tests** and its four dependants is the
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

Four in total, found by grepping every ``on:`` block rather than trusting a
hand-maintained list:

* ``.github/workflows/cron-vendor.yml:14-16`` -- **Vendor Update** fires on
  completion of **Unit Tests**.
* ``.github/workflows/cron-conda.yml:17-19`` -- **Conda Update** fires on
  completion of **Unit Tests**.
* ``.github/workflows/deploy-pages.yml:12-14`` -- **GitHub Pages** fires on
  completion of **Unit Tests**.
* ``.github/workflows/create-release.yml:6-9`` -- **Create Release** fires on
  completion of **Vendor Update**.

``workflow_run`` fires for *every* completion of the named workflow --
success, failure, or skipped -- and regardless of what triggered it,
including a pull request's own run of Unit Tests. Every one of the four
downstream workflows therefore re-checks ``github.event.workflow_run.event``
and ``.head_branch`` (or, for Create Release, ``.conclusion``) itself before
doing anything with an outward effect; none of the filtering happens in the
``on:`` block.

Reusable-Workflow Calls (``uses:``)
-----------------------------------

A ``uses:`` call is a different relationship from triggering: it runs inside
the caller's own workflow run, as one of the caller's own jobs, rather than
starting an independent run after the caller finishes. All four calls in this
repository target the same reusable workflow, with the same input:

* ``.github/workflows/create-release.yml:153`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/cron-conda.yml:43`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/cron-vendor.yml:49`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.
* ``.github/workflows/deploy-pages.yml:47`` -- job ``unit-tests`` calls
  ``./.github/workflows/unit-tests.yml`` with ``gate-only: true``.

``gate-only: true`` selects **two** of ``unit-tests.yml``'s **eight** jobs,
not one: ``gate`` (the full suite, one Python version) and ``changelog``
(checks ``CHANGELOG.md`` against its source entry). It skips the other
**six** -- the five matrix jobs, ``test`` (five Python legs),
``integration`` (five), ``engine-tests`` (a Python x engine matrix),
``pypcap-parity`` (two) and ``unittest-ordering`` (eleven matrix cells),
each of which has already run once for this commit from Unit Tests' own
``push``/``pull_request`` triggers, so running any of them again per caller
would test the same commit several times over -- and
``required-checks`` (see `Required Status Checks`_ below), gated out by its
own ``if:`` rather than by having already run. ``changelog`` carries no
``if:`` at all and runs on every path regardless -- deliberately, per its own
comment (``unit-tests.yml:950-956``): ``create-release.yml`` feeds
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
own graph. Create Release's ``unit-tests`` job -- the ``uses:`` call above --
carries:

.. code-block:: yaml

   if: ${{ github.event_name != 'workflow_run' || github.event.workflow_run.conclusion == 'success' }}

(``create-release.yml:150``). On the ``workflow_run`` path, this evaluates
**false**, and the job is skipped outright, whenever the upstream Vendor
Update run's own conclusion was anything other than ``success`` -- including
``skipped``, which is exactly what Vendor Update's *own* jobs report when
*their* ``workflow_run``-path guards decline (see ``cron-vendor.yml``'s
``vendor-update`` job). ``version_check`` then depends on that job with a
plain ``needs: [ unit-tests ]`` (``create-release.yml:160``) and no
``always()`` override, so a skipped dependency skips it too -- and every job
past it is gated the same way: ``github`` needs ``[ version_check ]``
(``:348``), ``tag`` needs ``[ github, version_check ]`` (``:449``), ``pypi``
needs ``[ github, version_check ]`` (``:527``), and ``conda`` needs
``[ tag, github, version_check ]`` (``:626``).

.. mermaid::

   flowchart TD
       WR["Vendor Update completed<br/>conclusion != success"]
       UTX["unit-tests (uses: unit-tests.yml)<br/>SKIPPED"]
       VC["version_check<br/>SKIPPED"]
       GH["github (GitHub Release)<br/>SKIPPED"]
       TAGJ["tag (Conda Tag)<br/>SKIPPED"]
       PY["pypi (PyPI distribution)<br/>SKIPPED"]
       CD["conda<br/>SKIPPED"]

       WR -->|if: false| UTX
       UTX -->|needs| VC
       VC -->|needs| GH
       GH -->|needs| TAGJ
       GH -->|needs| PY
       GH -->|needs| CD
       TAGJ -->|needs| CD

       classDef skipped fill:#fdecea,stroke:#c0392b,stroke-dasharray:4 2
       class UTX,VC,GH,TAGJ,PY,CD skipped

This is a transitive reduction, as in :doc:`releasing`: ``version_check`` is
also a direct ``needs:`` of ``tag`` and ``pypi`` (``create-release.yml:449,527``)
and of ``conda`` (``:626``), but ``github`` already implies those edges, since
it depends on ``version_check`` itself. Drawing them would add lines without
changing which job can start before which, or which job a skip in
``version_check`` reaches.

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
     - ``unit-tests.yml:1200``
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
(``unit-tests.yml:1200``). ``Compat Python`` is defined by two in
``python-compatibility.yml``: the required ``compatibility`` job (``:31``,
``Compat Python ${{ matrix.python-version }}``, expanding to the five required
legs at ``:41-45``) and the non-required ``compatibility-nightly`` job (``:69``,
``Compat Python 3.15 (scheduled)``, see below). A comment in
``unit-tests.yml`` (``:1061``) mentions the string without defining it.

``Required checks passed`` is itself an aggregate, not a single check run --
but it stands in for **17** of the ruleset's originally-named 22 contexts,
not all 22. ``unit-tests.yml``'s own comment (``:1060-1081``) accounts for the
22: five each for ``test`` and ``integration``, five for the live ``Compat
Python 3.10``-``3.14`` contexts (emitted by ``python-compatibility.yml``, a
*different* workflow file -- nothing in ``unit-tests.yml`` could ever stand
in for them, since a job cannot depend on a job living elsewhere), five for
the now-dead single-cell ``Engines Python <version>`` name ``engine-tests``
stopped producing once it became a Python x engine matrix, and two for
``pypcap-parity``. ``Required checks passed`` replaces only the
``test``/``integration``/dead-``Engines``/``pypcap-parity`` slots -- 5 + 5 +
5 + 2 = 17 -- via its own ``needs: [test, integration, engine-tests,
pypcap-parity]`` plus an explicit per-dependency check
(``unit-tests.yml:1199-1225``). The five ``Compat`` contexts stay required
exactly as they are and are listed separately in the table above. This job
runs on Unit Tests' own ``push``/``pull_request`` triggers; the
``gate-only: true`` reusable calls documented above skip it via
``if: ${{ always() && inputs.gate-only != true }}`` (``:1202``), so it is never
produced -- and never expected -- on those paths.

``Compat Python 3.10``-``3.14`` are five ordinary matrix legs, not an
aggregate: ``python-compatibility.yml``'s own comment (``:37-40``) and
``unit-tests.yml``'s matching one for its own, differently-matrixed
``test``/``integration`` jobs (``:58-61``, ``:138``) both say why 3.15 is
excluded from every *required* matrix in this repository -- the ruleset's
required-checks list stops at 3.14, so a 3.15 leg cannot gate a merge and is
kept advisory (``continue-on-error: true`` in ``python-compatibility.yml``'s
``compatibility-nightly`` job, ``:72``) rather than required.

Deployment ``environment:``
----------------------------

Four jobs, all in ``create-release.yml``, declare a deployment
``environment:`` and can therefore pause for an approval:

* ``github`` -- ``environment: github-release`` (``create-release.yml:345``)
* ``tag`` -- ``environment: conda-tag`` (``create-release.yml:447``)
* ``pypi`` -- ``environment: pypi`` (``create-release.yml:522``)
* ``conda`` -- ``environment: anaconda`` (``create-release.yml:623``)

No other workflow in scope here declares one -- including
``deploy-pages.yml``, whose ``deploy-pages`` job pushes straight to the
``gh-pages`` branch via ``JamesIves/github-pages-deploy-action`` rather than
through an ``environment:``-gated deployment. Of the four above, only
``github-release`` carries a required reviewer; :doc:`releasing`
covers why one approval on that single environment is enough to gate the
whole release graph, and is the page to read for the reasoning rather than
repeating it here.
