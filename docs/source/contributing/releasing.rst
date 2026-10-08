Release Process
================

.. important::

   This page records the **operational contract** for cutting a release --
   what a maintainer is expected to touch by hand, what the workflow is
   expected to do unattended, and the precautions that follow from the two
   being different.

   The short version: **the only manual edit is bumping**
   ``pcapkit.__version__``. Everything else -- the ``v*`` tag, the GitHub
   Release, the PyPI and Anaconda uploads, the ``conda-*`` tag and its commit
   to ``main`` -- is produced by
   ``.github/workflows/create-release.yml`` and is never hand-made.

The One Manual Step
-------------------

Bumping ``pcapkit.__version__`` is done by :file:`util/bump_version.py`, whose
own docstring is the authority on what it does; summarised here rather than
duplicated. Given the current version, it works out the next one under
:pep:`440` -- a ``devN`` counter, a pre-release counter, a post-release
counter, or a fresh ``.post1`` for a final release -- and then:

* rewrites the ``__version__`` assignment in ``pcapkit/__init__.py``;
* moves :file:`CITATION.cff`'s ``version`` and ``date-released`` fields to
  match, line-oriented so the file's own quoting and comments survive;
* resets :file:`conda/build` to ``0``.

Its one scheduled caller is the ``Bump Version`` step of
``.github/workflows/cron-vendor.yml``, and only when a weekly registry crawl
actually changed something (``steps.verify-changed-files.outputs.files_changed
== 'true'``) -- a crawl that finds nothing does not bump. That commit is what
starts the automated path described below.

The same script is also the manual entry point: run
``python util/bump_version.py`` and commit the result to ``main`` for a
release that is not a vendor-registry refresh -- a feature or a fix that has
landed and is ready to go out.

Editing ``__version__`` by hand without also moving :file:`CITATION.cff`'s
``version`` field to match is **not** a safe shortcut: it blocks the release.
``tests/project/test_bump_version.py``'s
``RepositoryCitationTests.test_the_citation_file_names_the_packaged_version``
(``:494-514``) asserts the two agree, and ``create-release.yml``'s
``unit-tests`` job (``:362-376``) calls ``unit-tests.yml`` with
``gate-only: true``, which runs the **full** suite rather than the tiered
subset an ordinary push runs (its ``gate`` job, ``unit-tests.yml:1214-1283``).
That gate runs whenever a release will -- a moved ``__version__`` is exactly
what makes ``version_check``'s evidence read "not yet published" -- and every
publishing job requires it to have succeeded (``:392,493,573,674``), so a
citation left behind fails the gate well before any approval is requested.
Either run the script, or move both fields by hand in the same commit.

This is the **only** edit a person makes to get a release started -- the tag,
the Release, and every upload are the workflow's job from here. Two other
checks run unconditionally on the same path, though neither is a step in *this*
process: the ``changelog`` job (``unit-tests.yml:1074-1095``) fails outright if
``CHANGELOG.md`` has drifted from its source entry under
:file:`docs/source/changelog/`, and the release-body step warns, without
failing, if that entry's heading still reads "unreleased"
(``create-release.yml:446-447``). Both enforce what the changelog convention
already asks for.

Two Ways to Start a Release
---------------------------

``create-release.yml`` has two triggers
(``.github/workflows/create-release.yml:2-9``), and both are first-class --
neither is a workaround for the other:

``push: tags: ['v*']``
   Pushing a tag matching ``v*`` yourself. This chooses **which commit** to
   release, not which version: ``version_check``'s checkout
   (``:183-186``) carries no explicit ``ref:``, so it checks out whatever
   commit the pushed tag points at, and reads ``pcapkit.__version__`` out of
   *that* tree (``:203``). Every downstream tag and release name is built
   from that output -- ``tag_name: "v${{ needs.version_check.outputs.PCAPKIT_VERSION }}"``
   appears at ``:469``, ``:650`` and ``:892``, always from
   ``PCAPKIT_VERSION``, never from ``github.ref_name`` -- so the version
   actually released is whatever ``__version__`` says on the tagged commit,
   not the name of the tag that was pushed. The two agree only if the tag
   was named to match. Push ``v1.6.0`` at a commit whose ``__version__`` is
   still ``1.5.0b5`` and ``softprops/action-gh-release`` creates a *new*
   ``v1.5.0b5`` tag and names the Release after it; the ``v1.6.0`` tag that
   was actually pushed is left dangling, attached to nothing.
   :doc:`pep` calls this workflow "version-driven rather than tag-driven"
   for the same reason -- name the tag to match the version you intend, and
   the two conveniently coincide, but nothing enforces that they do.

``workflow_run`` after **Vendor Update** completes
   The path a version bump on ``main`` takes without anyone pushing a tag:
   a push to ``main`` completes **Unit Tests**, whose completion triggers
   **Vendor Update** (``cron-vendor.yml``), whose completion -- bump step run
   or not -- triggers this workflow. A ``workflow_run``-triggered run always
   evaluates the tip of the default branch (documented GitHub Actions
   behaviour, not measured here), so ``github.ref_name`` reads ``main``,
   never a tag.

Both paths converge on the same job graph from ``version_check`` onward; only
the trigger and ``github.ref_name`` differ, which is what the guards below
read. A ``v*`` ref always runs the release test gate; on ``main`` it runs only
when some target's evidence is not yet ``'true'``
(`#1052 <https://github.com/JarryShaw/PyPCAPKit/issues/1052>`__), so the
common Vendor Update run that bumped nothing costs a minute, not a full-suite
run.

Per-Job Evidence, Not a Shared Proxy
------------------------------------

Until `#888 <https://github.com/JarryShaw/PyPCAPKit/issues/888>`__, every job
past ``version_check`` shared one guard:

.. code-block:: yaml

   if: ${{ startsWith(github.ref_name, 'v') || needs.version_check.outputs.PCAPKIT_TAG_EXISTS == 'false' }}

using "the ``v*`` tag exists" as a proxy for "this version was already
published". Those diverge exactly when a release half-completes -- ``github``
tags, a later job fails or is rejected, and the tag is left behind with the
publish incomplete -- which is the whole subject of `Precautions`_ below.
``github`` still uses that guard for its own artefact, since the tag it
checks *is* the one it is about to create:

.. code-block:: yaml

   if: ${{ startsWith(github.ref_name, 'v') || needs.version_check.outputs.PCAPKIT_TAG_EXISTS == 'false' }}

``tag``, ``pypi`` and ``conda`` each read their own evidence instead:

* ``tag`` checks whether ``conda-<version>+0``, the tag *it* creates, already
  exists.
* ``pypi`` compares PyPI's file count for the version against the 8 expected
  -- 7 matrix legs plus the sdist kept only on the 3.14 leg. This job is
  already idempotent (``skip-existing: true`` on both upload steps), so the
  check exists only to save the cost of the build matrix, not for correctness.
* ``conda`` compares Anaconda's aggregate count against the 10 expected (2 OS
  x 5 Python versions) as the same kind of job-level cost saver, and *also*
  checks, per matrix leg, whether that leg's own platform/Python distribution
  is already there -- this second check is the actual correctness fix, because
  ``anaconda/actions/upload-package`` has no ``skip-existing`` equivalent, only
  ``force:`` (never set), so re-uploading a file it already has fails outright
  rather than being absorbed.

All three evidence checks run inside ``version_check``, curling PyPI's and
Anaconda's public, unauthenticated JSON APIs; the per-leg check runs inside
``conda`` itself, once per matrix leg, against the same Anaconda endpoint.

On the tag-push path ``startsWith(github.ref_name, 'v')`` bypasses the
evidence check unconditionally; on the ``workflow_run`` path it falls through
to whichever evidence that job owns.

The Skip-Cascade Guard
----------------------

``tag``, ``pypi`` and ``conda`` each depend on ``github`` (and ``conda`` also
on ``tag``), and GitHub Actions skips a job whose ``needs:`` included a job
that itself skipped -- *before* that job's own ``if:`` is even evaluated --
unless the ``if:`` calls a status-check function itself. ``github``
legitimately skips whenever its own tag already exists, which is exactly the
retry case this fix is for. Left alone, that skip would cascade: ``pypi``'s
own evidence might correctly say "not yet on PyPI, please run", but the
default status check GitHub Actions prepends to an ``if:`` that does not
itself call a status-check function -- effectively ``success()`` over
``needs:`` -- would still skip it, because ``github`` did not *succeed* in
this run, it *skipped*.

``tag``, ``pypi`` and ``conda`` all guard against this the same way
``unit-tests``'s other callers already do for the identical problem --
``cron-vendor.yml``, ``deploy-pages.yml`` and ``cron-conda.yml`` each open
with ``!cancelled() && needs.unit-tests.result != 'failure'`` so that a
skipped gate does not cascade-skip them, while an outright failure or a
genuine run cancellation still does. The three jobs here are stricter about
their *publishing* predecessors -- ``github``, and for ``conda`` also ``tag``:
``!cancelled() && (needs.<job>.result == 'success' || needs.<job>.result ==
'skipped')``, not ``!= 'failure'``. The two spellings differ only when a
predecessor's own result is ``cancelled``, which ``!= 'failure'`` still admits
and the equality pair does not. Concretely: if ``tag`` is cancelled while the
run itself is not, ``!= 'failure'`` would let ``conda`` proceed into its
``actions/checkout`` with ``ref: conda-<version>+0``, a tag ``tag`` never
pushed, trading a clean skip for a checkout failure; the equality pair skips
``conda`` outright instead.

``version_check`` is the exception, and deliberately so: all three require
``needs.version_check.result == 'success'`` with no ``|| 'skipped'``. It
produces the evidence the gates read, so a skipped or cancelled
``version_check`` leaves them nothing to decide on. ``unit-tests`` is held to
the same bar for a different reason: it is the release test gate, and it skips
when nothing is publishable
(`#1052 <https://github.com/JarryShaw/PyPCAPKit/issues/1052>`__), so accepting
``skipped`` there would publish untested. ``github`` names it in ``needs:`` instead and relies on the implicit
``success()``. The gate's own ``if:`` is the union of the four publishers'
conditions, with ``!= 'true'`` so unknown evidence runs it; should the two
ever drift apart, the failure is a release that did not happen, which
``release_status`` reports loudly, never one that went out untested.

The Release Pipeline
--------------------

.. mermaid::

   flowchart TD
       T1["push: tags v*<br/>ref_name starts with v"] --> VC
       T2["workflow_run: Vendor Update completed<br/>ref_name = main"] --> VC
       VC["version_check -- reads pcapkit.__version__<br/>computes each job's own evidence<br/>no gate, read-only"]
       VC --> UT
       UT["unit-tests -- Release test gate<br/>skipped when nothing is publishable"] --> GH
       GH["github -- GitHub Release<br/>creates/attaches the v* tag<br/>THE ONLY APPROVAL"]
       GH --> TG["tag -- Conda Tag<br/>commit to main + conda-&lt;version&gt;+0 tag"]
       GH --> PY["pypi -- build + publish<br/>OIDC trusted publishing"]
       TG --> CD["conda -- build + upload<br/>matrix: 2 OS, per-leg evidence"]
       GH --> CD
       UT --> RS
       VC --> RS
       GH --> RS
       TG --> RS
       PY --> RS
       CD --> RS
       RS["release_status -- always runs<br/>reports why nothing released, or that it did"]
       classDef gate stroke-dasharray:6 3,stroke-width:2px
       class GH gate

A transitive reduction: ``version_check`` and ``unit-tests`` are also direct
``needs:`` of ``tag``, ``pypi`` and ``conda`` in the file, but ``github``
already implies them (``github`` itself depends on both), so drawing them would
add six lines without changing which job can start before which. ``release_status``'s
edges are drawn in full, since it depends directly on *every* job precisely so
that it can run regardless of which of them skipped.

Only ``github-release`` carries a required reviewer; ``conda-tag``,
``pypi`` and ``anaconda`` kept their environments but had their reviewers
removed on `#887 <https://github.com/JarryShaw/PyPCAPKit/issues/887>`__.
What still makes one approval mean *the whole release* is the ``needs:``
graph: ``tag`` and ``pypi`` both depend on ``github``
(``.github/workflows/create-release.yml:493,573``), and ``conda`` depends on
``tag`` and ``github`` (``:674``) -- so nothing downstream of ``github`` can
start before it is approved, and rejecting it leaves nothing tagged and
nothing published. Before this change ``tag`` depended on ``version_check``
alone, so removing its reviewer without moving this dependency would have let
it push a commit to ``main`` and cut a ``conda-*`` tag *ahead of* the
approval it was supposed to wait for.

Precautions
-----------

.. warning::

   **Do not gate a release job on whether the ``v*`` tag exists.** ``github``
   creates the tag before ``pypi`` and ``conda`` upload, so a tag proves nothing
   about whether the upload finished. A job keyed on ``PCAPKIT_TAG_EXISTS``
   skips itself on a retry after a partial release, and the run finishes green
   because skipped is not failed -- so nothing in the UI says the release did
   not happen.

   `Per-Job Evidence, Not a Shared Proxy`_
   above is what prevents it: ``tag``, ``pypi`` and ``conda`` each check whether
   *their own* artefact is missing rather than whether the ``v*`` tag exists, so an
   incomplete release runs the jobs that did not finish instead of skipping them.
   A half-finished release self-heals on the next ``workflow_run``-triggered
   attempt, or on re-running the workflow by hand -- see `Recovery`_ below.
   ``release_status`` is the other half: it runs unconditionally and reports,
   with a ``::notice``, a ``::warning`` or a failing ``::error``, why a run
   released nothing or that it released something, so a stranded release is
   never only a green checkmark, even if the evidence checks disagree with
   reality.

**Do not hand-make a tag to route around a stuck release.** This is narrower
than "never tag by hand": pushing a *fresh* ``v<version>`` tag to start a
release, as in `Two Ways to Start a Release`_, is fine. What is not sanctioned
is deleting and re-pushing a tag that a stuck run already created, to force a
retry. A ``git push`` of a tag ref that already points at the same commit
produces no new event (documented GitHub Actions behaviour, not measured
here), so the push only fires again after the tag is deleted -- which touches a
ref the release automation owns, and lands the retry back on the tag-push path,
where every job's guard is bypassed regardless of what has already gone out.
Neither is worth the risk of a double upload to an index that cannot take one
back, and neither is needed, since a plain re-run self-heals; see
`Recovery`_ below.

**``environment: pypi`` stays even though its reviewer is gone.** ``pypi``
publishes through PyPI's OIDC trusted publishing (``environment: pypi`` at
``:568``, ``id-token: write`` at ``:572``), and PyPI's trusted-publisher
configuration can be scoped to a GitHub Actions environment name. If this
project's publisher on PyPI is scoped that way, removing the ``pypi`` name
-- not just its reviewer -- would break the upload with a claim mismatch;
this is standard OIDC trusted-publishing behaviour, not something the
publisher's actual PyPI-side configuration was read to confirm here. Keep
the name regardless, since there is no upside to removing it.

**``conda-tag`` writes to ``main``, so a release is not read-only on the
branch.** The ``tag`` job resets :file:`conda/build` to ``0``, commits that,
and pushes straight to ``main``
(``.github/workflows/create-release.yml:512-532``) before cutting the
``conda-<version>+0`` tag. Approving ``github-release`` therefore also
approves a commit landing on the default branch, not only the artefacts that
sound like they are the point.

Recovery
--------

The sanctioned recovery from a failed or partial release run is re-running
the workflow, not re-tagging by hand, for the reasons above. This is the
actual fix rather than a best-effort suggestion: `Per-Job Evidence, Not a
Shared Proxy`_ above means ``tag``, ``pypi`` and ``conda`` each check whether
*their own* artefact is missing, so a re-run finishes whichever jobs did not
complete last time instead of skipping them on the ``v*`` tag's mere
existence. ``pypi`` is safe to re-run (``skip-existing: true``), and so is
``conda``, because each matrix leg checks Anaconda for its own
platform/Python distribution before uploading and skips only that leg's
upload if it is already there.

**A re-run does not need to be verified by hand against the PyPI and Anaconda
listings, because ``release_status`` does it.** That job runs on every
``Create Release`` attempt regardless of what else skipped, and reconciles
each of ``github``/``tag``/``pypi``/``conda`` *against its own evidence*
rather than demanding the same outcome from all four -- a target counts as
reconciled if it succeeded, or if it skipped *because* its own evidence
already said it was done. That is what makes a self-heal reportable: a retry
after a partial release legitimately produces a **mixed** result
(``github``/``tag`` skipping because their artefacts exist while
``pypi``/``conda`` finish the rest), and a check demanding uniformity would
read that mix as the failure it exists to detect.

With that reconciliation, ``release_status`` reports exactly one of: nothing
to release because the trigger had nothing to do (quiet ``::notice``),
nothing to release because every target was already reconciled by skipping,
i.e. the version was already fully out before this run started (quiet
``::notice``), the release is now fully out because every target reconciled
-- whether by a fresh full run, or by the mixed self-heal above (quiet
``::notice`` either way), a release job failed or was cancelled outright
(``::warning``, already visible as a red job elsewhere), or -- the shape
`#888 <https://github.com/JarryShaw/PyPCAPKit/issues/888>`__ was actually
about -- at least one target skipped despite its own evidence saying it is
still incomplete, and nothing else failed to explain that (``::error``, and
the job itself fails). That last case should be unreachable given the
evidence-based guards above, since a target's own incomplete evidence is
what makes its job run rather than skip; reaching it anyway is a signal that
those checks themselves need attention, not that the release needs a
hand-rolled recovery.
