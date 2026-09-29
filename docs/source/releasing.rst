Release Process
================

.. important::

   This page records the **operational contract** for cutting a release --
   what a maintainer is expected to touch by hand, what the workflow is
   expected to do unattended, and the precautions that follow from the two
   being different. Settled on
   `#887 <https://github.com/JarryShaw/PyPCAPKit/issues/887>`__, which also
   collapsed what used to be four separate approvals into one.

   The short version: **the only manual edit is bumping**
   ``pcapkit.__version__``. Everything else -- the ``v*`` tag, the GitHub
   Release, the PyPI and Anaconda uploads, the ``conda-*`` tag and its commit
   to ``main`` -- is produced by
   ``.github/workflows/create-release.yml`` and is never hand-made.

The one manual step
--------------------

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

Editing ``__version__`` by hand instead, without also moving
:file:`CITATION.cff`'s ``version`` field to match, is **not** a safe
shortcut -- it does not drift through silently, it blocks the release.
``tests/project/test_bump_version.py``'s
``RepositoryCitationTests.test_the_citation_file_names_the_packaged_version``
(``:493-513``) asserts the two agree, and that assertion is not optional on
the release path: ``create-release.yml``'s ``unit-tests`` job
(``:96-103``) calls ``unit-tests.yml`` with ``gate-only: true``, which runs
the **full** suite rather than the tiered subset an ordinary push runs
(its ``gate`` job, ``unit-tests.yml:734-803``). ``version_check`` itself
depends on that job (``needs: [ unit-tests ]``, ``:108``), so a citation left
behind fails the gate before ``version_check`` ever runs, and well before any
approval is requested. Either run the script, or move both fields by hand in
the same commit.

This is the **only** edit a person makes to get a release started -- the tag,
the Release, and every upload are the workflow's job from here. Two other
checks run unconditionally on the same path and are worth knowing about
rather than being surprised by, though neither is a step in *this* process:
the ``changelog`` job (``unit-tests.yml:707-728``) fails outright if
``CHANGELOG.md`` has drifted from its source entry under
:file:`docs/source/changelog/`, and the release-body step warns, without
failing, if that entry's heading still reads "unreleased"
(``create-release.yml:210-211``). Both are enforcing work the changelog
convention already asks for, not extra work this process adds.

Two ways to start a release
----------------------------

``create-release.yml`` has two triggers
(``.github/workflows/create-release.yml:2-9``), and both are first-class --
neither is a workaround for the other:

``push: tags: ['v*']``
   Pushing a tag matching ``v*`` yourself. This chooses **which commit** to
   release, not which version: ``version_check``'s checkout
   (``:112-115``) carries no explicit ``ref:``, so it checks out whatever
   commit the pushed tag points at, and reads ``pcapkit.__version__`` out of
   *that* tree (``:132``). Every downstream tag and release name is built
   from that output -- ``tag_name: "v${{ needs.version_check.outputs.PCAPKIT_VERSION }}"``
   appears at ``:233``, ``:392`` and ``:549``, always from
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

Both paths converge on the same job graph from ``unit-tests`` onward; only
the trigger and ``github.ref_name`` differ, which is what the guard below
reads.

Every job past ``version_check`` shares:

.. code-block:: yaml

   if: ${{ startsWith(github.ref_name, 'v') || needs.version_check.outputs.PCAPKIT_TAG_EXISTS == 'false' }}

and the two triggers hit it differently:

* On the tag-push path ``github.ref_name`` already starts with ``v``, so the
  guard is **unconditionally bypassed** -- its second half, the actual check
  against ``PCAPKIT_TAG_EXISTS``, can never carry the run, because
  ``startsWith`` alone already satisfied the ``||``. Nothing here checks
  whether the version read out of the tagged commit was already published,
  and pushing a tag is also a ref **update**, not only a creation, so a tag
  force-moved onto a new commit takes this same path with the same bypass.
  The protection on this path is the operator's deliberate act of choosing
  what to tag, not an absence of risk -- see `Precautions`_ below for what
  that risk actually is.
* On the ``workflow_run`` path ``github.ref_name`` is ``main``, so the guard
  falls through to ``PCAPKIT_TAG_EXISTS``, and *that* is what stops the same
  version being published twice, including the sibling race described in the
  comment above ``concurrency:`` where two Vendor Update completions land
  close together.

The pipeline, and why one approval is enough
----------------------------------------------

.. mermaid::

   flowchart TD
       T1["push: tags v*<br/>ref_name starts with v"] --> UT
       T2["workflow_run: Vendor Update completed<br/>ref_name = main"] --> UT
       UT["unit-tests -- Release test gate"] --> VC
       VC["version_check -- reads pcapkit.__version__<br/>checks whether v&lt;version&gt; already exists<br/>no gate, read-only"]
       VC --> GH
       GH["github -- GitHub Release<br/>creates/attaches the v* tag<br/>THE ONLY APPROVAL"]
       GH --> TG["tag -- Conda Tag<br/>commit to main + conda-&lt;version&gt;+0 tag"]
       GH --> PY["pypi -- build + publish<br/>OIDC trusted publishing"]
       TG --> CD["conda -- build + upload<br/>matrix: 2 OS"]
       GH --> CD
       classDef gate stroke-dasharray:6 3,stroke-width:2px
       class GH gate

A transitive reduction: ``version_check`` is also a direct ``needs:`` of
``tag``, ``pypi`` and ``conda`` in the file itself, alongside the edges drawn
above -- omitted here because ``github`` already implies it (``github``
itself depends on ``version_check``), and drawing it would add three more
lines without changing which job can start before which.

Only ``github-release`` carries a required reviewer today; ``conda-tag``,
``pypi`` and ``anaconda`` kept their environments but had their reviewers
removed on `#887 <https://github.com/JarryShaw/PyPCAPKit/issues/887>`__.
What still makes one approval mean *the whole release* is the ``needs:``
graph: ``tag`` and ``pypi`` both depend on ``github``
(``.github/workflows/create-release.yml:251,319``), and ``conda`` depends on
``tag`` and ``github`` (``:406``) -- so nothing downstream of ``github`` can
start before it is approved, and rejecting it leaves nothing tagged and
nothing published. Before this change ``tag`` depended on ``version_check``
alone, so removing its reviewer without moving this dependency would have let
it push a commit to ``main`` and cut a ``conda-*`` tag *ahead of* the
approval it was supposed to wait for.

Precautions
-----------

.. warning::

   **A half-finished release leaves a ``v*`` tag that makes every retry skip
   silently.** ``github`` creates the tag; if ``pypi`` or ``conda`` then fails
   (or is rejected), the tag now exists with the upload incomplete. The next
   ``workflow_run``-triggered attempt reads ``PCAPKIT_TAG_EXISTS=true`` with
   ``ref_name=main``, so the shared guard evaluates false and **every release
   job is skipped** -- the run finishes green, because skipped is not failed,
   and nothing in the UI says a release did not happen. This is
   `#888 <https://github.com/JarryShaw/PyPCAPKit/issues/888>`__, open at the
   time of writing. Recognise it by a green **Create Release** run that
   published nothing, rather than trusting the checkmark.

**Do not hand-make a tag to route around a stuck release.** This is a
narrower rule than "never tag by hand" -- pushing a *fresh* ``v<version>``
tag to start a release, as in `Two ways to start a release`_ above, is fine
and unchanged by any of this. What is not sanctioned is deleting and
re-pushing a tag that a stuck run already created, to force a retry. A
``git push`` of a tag ref that already points at the same commit produces no
new event (documented GitHub Actions behaviour, not measured here), so the
only way to make that push fire again is to delete the tag first -- which
both touches a ref the release automation owns, and lands the retry back on
the tag-push path, where the guard is unconditionally bypassed (see
`Two ways to start a release`_ above) regardless of what has already gone
out. Neither is worth the risk of a double upload to an index that cannot
take one back.

**``environment: pypi`` stays even though its reviewer is gone.** ``pypi``
publishes through PyPI's OIDC trusted publishing (``environment: pypi`` at
``:314``, ``id-token: write`` at ``:318``), and PyPI's trusted-publisher
configuration can be scoped to a GitHub Actions environment name. If this
project's publisher on PyPI is scoped that way, removing the ``pypi`` name
-- not just its reviewer -- would break the upload with a claim mismatch;
this is standard OIDC trusted-publishing behaviour, not something the
publisher's actual PyPI-side configuration was read to confirm here. Keep
the name regardless, since there is no upside to removing it.

**``conda-tag`` writes to ``main``, so a release is not read-only on the
branch.** The ``tag`` job resets :file:`conda/build` to ``0``, commits that,
and pushes straight to ``main``
(``.github/workflows/create-release.yml:266-286``) before cutting the
``conda-<version>+0`` tag. Approving ``github-release`` therefore also
approves a commit landing on the default branch, not only the artefacts that
sound like they are the point.

Recovery
--------

The sanctioned recovery from a failed or partial release run is re-running
the workflow -- nothing more elaborate, and specifically not re-tagging by
hand, for the reasons above. Be aware it can be a **silent no-op** on the
``workflow_run`` path, exactly as
`#888 <https://github.com/JarryShaw/PyPCAPKit/issues/888>`__ describes: a
green re-run is not evidence that anything was actually published, so check
the PyPI and Anaconda listings themselves rather than the checkmark.

Beyond that: there is currently **no sanctioned manual recovery** for a
release that is already stranded -- a ``v*`` tag created with the publish
incomplete. That gap is
`#888 <https://github.com/JarryShaw/PyPCAPKit/issues/888>`__, and it stays
open rather than being papered over here with a procedure that does not
actually work; the previous suggestion of pushing the tag by hand does not
apply once the tag already exists -- see `Precautions`_ above.
