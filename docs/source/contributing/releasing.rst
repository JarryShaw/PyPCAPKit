Release Process
================

.. important::

   This page records the **operational contract** for cutting a release --
   what a maintainer is expected to touch by hand, what the workflow is
   expected to do unattended, and the precautions that follow from the two
   being different.

   The short version: **the only manual edit is bumping**
   :data:`pcapkit.__version__`. Everything else -- the ``v*`` tag, the GitHub
   Release, the PyPI and Anaconda uploads, the ``conda-*`` tag and its commit
   to ``main`` -- is produced by
   ``.github/workflows/create-release.yml`` and is never hand-made.

The One Manual Step
-------------------

Bumping :data:`pcapkit.__version__` is done by :file:`util/bump_version.py`, whose
own docstring is the authority on what it does; summarised here rather than
duplicated. Given the current version, it works out the next one under
:pep:`440` -- a ``devN`` counter, a pre-release counter, a post-release
counter, or a fresh ``.post1`` for a final release -- and then:

* rewrites the ``__version__`` assignment in ``pcapkit/__init__.py``;
* moves :file:`CITATION.cff`'s ``version`` and ``date-released`` fields to
  match, line-oriented so the file's own quoting and comments survive;
* resets :file:`conda/build` to ``0``.

Its one scheduled caller is the ``Bump Version`` step of
``.github/workflows/cron-vendor.yml``, and only when a registry crawl changed
code. ``util/vendor_code_changed.py`` compares each changed file with ``HEAD``;
a crawl whose changes are all to comments or docstrings is committed as
"Updated vendor documentation without a version bump" instead, so it reaches
``main`` without starting a release
(`#1674 <https://github.com/JarryShaw/PyPCAPKit/issues/1674>`__). A crawl that
finds nothing commits nothing. The bump commit carries every module the crawl
wrote under ``pcapkit/const/``, new and deleted ones included
(`#1685 <https://github.com/JarryShaw/PyPCAPKit/issues/1685>`__), and is what
starts the automated path described below.

The same script is also the manual entry point: run
``python util/bump_version.py`` and commit the result to ``main`` for a
release that is not a vendor-registry refresh -- a feature or a fix that has
landed and is ready to go out.

Editing ``__version__`` by hand without also moving :file:`CITATION.cff`'s
``version`` field to match is **not** a safe shortcut: it blocks the release.
``tests/project/test_bump_version.py``'s
``RepositoryCitationTests.test_the_citation_file_names_the_packaged_version``
asserts the two agree, and ``create-release.yml``'s ``unit-tests`` job calls
``unit-tests.yml`` with
``gate-only: true``, which runs the **full** suite rather than the tiered
subset an ordinary push runs (its ``gate`` job).
That gate runs whenever a release will -- a moved ``__version__`` is exactly
what makes ``version_check``'s evidence read "not yet published" -- and every
publishing job's ``needs:`` requires it to have succeeded, so a
citation left behind fails the gate well before any approval is requested.
Either run the script, or move both fields by hand in the same commit.

This is the **only** edit a person makes to get a release started -- the tag,
the Release, and every upload are the workflow's job from here. Other
checks run unconditionally on the same path, though none is a step in *this*
process: the ``changelog`` job's "Check CHANGELOG.md is in step with its source
entry" step fails outright if ``CHANGELOG.md`` has drifted from its source entry under
:file:`docs/source/changelog/`, and ``github``'s "Select release body" step
warns, without failing, if that entry's heading still reads "unreleased". Each
enforces what the changelog convention
already asks for.

Ways to Start a Release
-----------------------

``create-release.yml``'s ``on:`` triggers are all first-class -- none is a
workaround for another:

``push: tags: ['v*']``
   Pushing a tag matching ``v*`` yourself. This chooses **which commit** to
   release, not which version: ``version_check``'s "Checkout code" step pins
   ``ref: ${{ github.sha }}``, which on this trigger is the commit the pushed
   tag points at, and its "Get Version" step reads :data:`pcapkit.__version__`
   out of *that* tree. Every downstream tag and release name is built
   from that output -- ``v${{ needs.version_check.outputs.PCAPKIT_VERSION }}``
   is the ``tag_name`` of ``github``'s "Create Release" step and the release
   ``pypi`` and ``conda`` upload to, always from
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
   or not -- triggers this workflow. A ``workflow_run``-triggered run
   evaluates the tip of the default branch as it was when the run was
   *created*: ``github.ref_name`` reads ``main``, never a tag, and
   ``github.sha`` is that tip, fixed for the life of the run. On run
   38008819343 it was ``b6b95bc8e``, the bump Vendor Update had just pushed,
   while ``github.event.workflow_run.head_sha`` -- the commit Vendor Update
   ran *on* -- was the bump's parent, ``945c3c3d8``.

The paths converge on the same job graph from ``version_check`` onward; only
the trigger and ``github.ref_name`` differ, which is what the guards below
read. The release test gate runs only once ``version_check`` has passed, and
``version_check`` itself skips the release App's own tag push and a Vendor
Update that did not conclude ``success`` or skipped ``vendor-update`` (below).
Past it, a ``v*`` ref always runs the gate; on ``main`` it
runs only when the version is not tagged at another commit and some target's
evidence is not yet ``'true'``
(`#1052 <https://github.com/JarryShaw/PyPCAPKit/issues/1052>`__), so the
common Vendor Update run that bumped nothing costs a minute, not a full-suite
run.

A run that may release waits for the one ahead of it on the same ref and never
cancels it (the ``concurrency`` block), since two Vendor Update runs
completing close together raise two runs on the same tip. A group holds one
pending run, which a newer one cancels, so a run whose Vendor Update did not
conclude ``success`` is keyed on its own ``github.run_id`` instead
(`#1705 <https://github.com/JarryShaw/PyPCAPKit/issues/1705>`__). It releases
nothing, so it neither waits behind a release nor displaces a run waiting
there; only a newer run that may release, reading ``main``'s newer tip, can.
A Vendor Update that concluded ``success`` with ``vendor-update`` skipped --
its Unit Tests verdict was for another commit -- releases nothing either since
`#1748 <https://github.com/JarryShaw/PyPCAPKit/issues/1748>`__: the
``vendor_update`` job reads that run's jobs, and
``version_check`` skips. The group cannot see that, so such a run still joins
the ref's group; if it displaces a pending run, that release waits for the
next Vendor Update on ``main``.

One Commit per Release
----------------------

Every job that checks out, tags, builds or publishes pins ``github.sha``
(`#1634 <https://github.com/JarryShaw/PyPCAPKit/issues/1634>`__), so a run
releases the commit it was created for however long it waits on approval.
Before that, run 38008819343 was created for ``b6b95bc8e``, approved three
days later, and tagged ``main``'s tip ``2c0008c3c`` as both ``v1.5.0b9`` and
``conda-1.5.0b9+0``: ``action-gh-release`` defaulted ``target_commitish`` to
the default branch, and ``tag`` pulled ``main`` before tagging.

* On ``workflow_run``, where ``github`` creates the ``v*`` tag, it passes
  ``target_commitish`` ``github.sha``; on a ``v*`` push the tag
  already exists and it passes none. Either way it then checks that the tag
  names that commit.
* ``tag``'s "Create Tag" step cuts ``conda-<version>+0`` at that commit before
  it reads ``main`` at all; the :file:`conda/build` reset, "Reset Build
  Number", is a separate commit on top of ``main``, described under
  `Precautions`_.
* ``pypi`` and ``conda`` check out that commit and, before building, check
  that every tag they publish under names it, as ``tag`` does for the ``v*``
  tag. A run created for a *later* commit of the same version therefore never
  publishes a second tree under that version. ``version_check`` resolves the
  ``v*`` tag the same way first, in "Check which commit the version's tag
  names", and off a ``v*`` ref a tag naming another commit skips the gate and every publisher
  (`#1748 <https://github.com/JarryShaw/PyPCAPKit/issues/1748>`__):
  ``Release status`` posts a ``::notice`` if that release is complete, or a
  ``::warning`` naming both commits and what is missing, and the run stays
  green. A ``v*`` push of such a version still fails with the
  check's ``::error``. A partial release is finished by re-running the run that
  tagged it.
* ``pypi`` and ``conda`` attach their files with ``gh release upload``, in
  their "Upload package to GitHub Release" steps, not ``action-gh-release``,
  which calls Update a release before every upload (3.0.2's ``src/github.ts:631-683``). A file
  the release already has is left alone
  (`#1640 <https://github.com/JarryShaw/PyPCAPKit/issues/1640>`__): the action
  deleted and re-uploaded it, and a rebuild against live PyPI is not
  byte-identical to the published copy. Only an asset in state ``uploaded``
  counts: `Upload a release asset
  <https://docs.github.com/en/rest/releases/assets#upload-a-release-asset>`__
  says a ``502`` "may leave an empty asset with a state of starter. It can be
  safely deleted.", so an asset in any other state is deleted and uploaded
  again (``--clobber``). ``conda``'s upload is not gated on ``check_leg``, so a
  leg whose Anaconda upload landed but whose GitHub upload failed still gets
  its asset on a re-run.
* ``gh release upload`` also fails, deliberately, where the action did not.
  With no release for the tag, the upload fails with ``gh``'s
  "release not found", where the action made one, with no notes and
  ``target_commitish`` unset (``src/github.ts:617-628,1026``), which Create a
  release defaults to "the repository's default branch"; the release is
  ``github``'s to make, at the run's commit. A file pattern matching nothing
  exits 1 with ``::error title=Nothing to upload``, where the action,
  ``fail_on_unmatched_files`` unset, only warned (``src/run.ts:15-20``) and
  published the release without that file.

Pinning the target may have a cost, and GitHub documents the rule two ways.
Its REST docs for `Create a release
<https://docs.github.com/en/rest/releases/releases#create-a-release>`__ say
that if "the commit identified by target_commitish (or, when target_commitish
is omitted, the latest commit on the default branch) adds or modifies any file
under .github/workflows/ relative to the repository's default branch", the
token must be authorized to modify workflows, and "The GITHUB_TOKEN available
to GitHub Actions cannot be authorized for this"; the call fails with ``404
Not Found``, or on some paths ``403 Resource not accessible by integration``.
`Update a release
<https://docs.github.com/en/rest/releases/releases#update-a-release>`__
applies it to "the new value of target_commitish if you are changing it,
otherwise the existing target"; `Upload a release asset
<https://docs.github.com/en/rest/releases/assets#upload-a-release-asset>`__
states no such rule. GitHub's `2023-11-02 changelog
<https://github.blog/changelog/2023-11-02-github-actions-enforcing-workflow-scope-when-creating-a-release/>`__
instead requires that authorization for a ``target_commitish`` "that modifies
an Actions workflow file and that SHA does not have an existing ref (branch
head or tag)".

The two readings disagree on run 38008819343. Against the default branch,
``b6b95bc8e..2c0008c3c`` changed ``ci-timing.yml`` and ``unit-tests.yml``, so
its ``github`` would have failed at Create Release. As the commit's own
change, ``b6b95bc8e`` touches no workflow file -- its diff against its parent
is :file:`CITATION.cff`, :file:`conda/build`, :file:`pcapkit/__init__.py` and
``apptype`` modules -- so it would not. Which reading GitHub enforces is
not measured here. `softprops/action-gh-release#411
<https://github.com/softprops/action-gh-release/issues/411>`__ was closed with
"The latest repro still hits ``403 Resource not accessible by integration``
when ``github.token`` is used to create a release/tag against an older
commit. …", but the thread does not say whether that commit touched a
workflow file, so it fits both readings.

Under the first, once ``main`` changes a workflow file after a run's commit,
Create Release refuses that run's ``GITHUB_TOKEN``, which is why ``github``
spends a GitHub App's token instead (`The Release App`_). After ``github``,
nothing in this workflow calls Update a release, so by the docs nothing
re-checks the target (unmeasured).
``cron-conda.yml``'s ``conda-dist`` does: it attaches packages with
``ncipollo/release-action`` v1.21.0, pinned to its commit, and
``allowUpdates: true``, which updates the release before uploading
(``src/Action.ts:53-66,107-120``). It therefore
names the default branch -- ``github.ref_name`` whichever trigger raised it -- as
``commit``, which that update sends as ``target_commitish``
(``src/Releases.ts:150-174``), so the rule checks ``main`` itself; the tag
stays put, as Update a release calls the target "Unused if the Git tag already
exists". It also uploads only to a published release, read first with ``gh
release view``. With none, the action would create one, and its tag, at
``commit`` (``src/Action.ts:72-92``). Conda Update bumped 1.5.0b9's build
three times while that run waited on approval; once ``conda-dist`` runs on
every bump (`#1632 <https://github.com/JarryShaw/PyPCAPKit/issues/1632>`__),
that would tag the pending version at ``main``'s tip and fail Create Release's
tag check. The action would also retarget a draft at ``commit``
(``src/Action.ts:85-92,107-120``), which ``omitDraftDuringUpdate`` keeps a
draft, but Create Release's ``workflow_run`` run finds the draft and resets
its target to the run's sha (``action-gh-release`` 3.0.2's
``src/github.ts:636-646,832-866``), so skipping a draft is a precaution
against retargeting a release Create Release owns.
Either way the build goes to anaconda.org only, with a ``::notice``. The
update also sends the release's name, notes and ``prerelease`` and ``draft``
flags, which unset inputs make the tag, ``""`` and ``false``
(``src/Inputs.ts:70-92,128-135,210-240``), so the step sets the
``omit*DuringUpdate`` inputs that leave them out (`#1657
<https://github.com/JarryShaw/PyPCAPKit/issues/1657>`__).

The Release App
---------------

The owner's choice on `#1634
<https://github.com/JarryShaw/PyPCAPKit/issues/1634>`__: ``github`` creates
the release with a GitHub App installation token, which Create a release
accepts for a target that changes a workflow file when it has the "Workflows"
repository permission (write). "Mint the release App's token" runs
``actions/create-github-app-token`` v3.3.0, pinned to its commit, with
``permission-contents: write`` and ``permission-workflows: write`` and no
``owner`` or ``repositories``, so the token is "scoped to only the current
repository" and revoked in the action's ``post`` step (v3.3.0's README). Only
Create Release spends it.
While ``vars.RELEASE_APP_CLIENT_ID`` is unset, which reads as "an empty
string", the step skips and Create Release spends ``GITHUB_TOKEN``, so the
workflow keeps working, refusals included, until the App exists. A PAT would
work too, but its tag push is attributed to a person, so no guard could tell
it from a tag pushed by hand.

One-time setup:

1. Register a GitHub App with the **Contents** and **Workflows** repository
   permissions at read and write, and install it on this repository only. Add
   **Pull requests** at read and write too, and accept it on the installation:
   the Python Versions workflow's ``pr`` job opens its pull request with a token
   of this App, with contents and pull requests write only (`#1660
   <https://github.com/JarryShaw/PyPCAPKit/issues/1660>`__, :doc:`workflows`).
2. Add repository variables ``RELEASE_APP_CLIENT_ID``, the App's Client ID, and
   ``RELEASE_APP_BOT_ID``, its bot's user id (``gh api
   "/users/<app-slug>[bot]" --jq .id``, as the action's README reads it).
3. Store the App's private key as ``RELEASE_APP_PRIVATE_KEY``, a secret of the
   ``github-release`` environment rather than of the repository: "If the
   environment requires approval, a job cannot access environment secrets
   until one of the required reviewers approves it". ``github`` and Python
   Versions' ``pr`` are the only jobs that name the environment or read the
   secret.

Unlike ``GITHUB_TOKEN``'s, the App's tag starts a tag-push run. It would rerun
the release test gate, ask for a second approval and race the first run's
uploads from another concurrency group, so ``version_check``'s ``if:`` skips a
``push`` whose ``github.actor_id`` is ``vars.RELEASE_APP_BOT_ID``, and
``release_status`` reports it with ``::notice title=Nothing to release``. A
tag pushed by a person runs as before. Whether a tag made
through the Releases API fires ``push``, and with the bot as actor, is
unmeasured; if not, the guard never matches and the cost is one approval to
reject.

A refused Create Release (404, or 403 "Resource not accessible by
integration") is explained by "Explain a refused release tag"
according to the token spent: with ``GITHUB_TOKEN`` it lists the setup above;
with the App's, it points at the App's permissions and installation. For a
final release, first delete any draft ``v<version>`` the refused run left:
``action-gh-release`` creates a non-prerelease as a draft and publishes it
with Update a release in the same step (``src/github.ts:1025``), and the next
run would reuse that draft and its target (``:631-647`` there). Then re-run
the job; that a re-run reads variables and secrets set since is unmeasured.

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
* ``pypi`` compares PyPI's file count for the version against the expected one
  -- a wheel per supported leg plus the sdist kept only on the 3.15 leg; the
  :ref:`KTLO <ktlo-tier>` legs' wheels (`#1633 <https://github.com/JarryShaw/PyPCAPKit/issues/1633>`__) are not counted. This job is
  already idempotent (``skip-existing: true`` on every upload step), so the
  check exists only to save the cost of the build matrix, not for correctness.
* ``conda`` compares Anaconda's aggregate count against the expected one (the
  ``linux-64``, ``osx-64`` and ``osx-arm64`` files for each Python version of
  its matrix, one platform per ``os`` leg,
  `#1922 <https://github.com/JarryShaw/PyPCAPKit/issues/1922>`__) as the same
  kind of job-level cost saver, and *also*
  checks, per matrix leg, whether that leg's own platform/Python distribution
  is already there -- this second check is the actual correctness fix, because
  ``anaconda/actions/upload-package`` has no ``skip-existing`` equivalent, only
  ``force:`` (never set), so re-uploading a file it already has fails outright
  rather than being absorbed.

These evidence checks all run inside ``version_check``, curling PyPI's and
Anaconda's public, unauthenticated JSON APIs; the per-leg check runs inside
``conda`` itself, once per matrix leg, against the same Anaconda endpoint.

The PyPI and Anaconda counts are of the tiers the version was released with.
Until its ``v*`` tag exists, that is this run's
:file:`.github/python-versions.toml`; once it does, ``version_check`` reads the
file at the tag's commit with that commit's ``util/python_versions.py``. A
supported version added since (`#1660
<https://github.com/JarryShaw/PyPCAPKit/issues/1660>`__) was never built for the
release, and counting it would read a finished release as incomplete, run the
gate and ``pypi``, and fail `One Commit per Release`_'s tag check on every run
until the next release. A tag older than the file, as ``v1.5.0b12`` is, counts
the tiers the file was added with, which the change for `#1660 <https://github.com/JarryShaw/PyPCAPKit/issues/1660>`__ copied unchanged from the
workflows of the time.

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

``tag``, ``pypi`` and ``conda`` all guard against this the same way the
other workflows gated on a test run already do for the identical problem --
``cron-vendor.yml``, ``deploy-pages.yml`` and ``cron-conda.yml`` each open
with ``!cancelled() && needs.head.result != 'failure'``, ``head`` being their
call to ``cron-head.yml``, so that a skipped gate does not cascade-skip them,
while an outright failure or a genuine run cancellation still does. ``tag``, ``pypi`` and ``conda`` are
stricter about their *publishing* predecessors -- ``github``, and for
``conda`` also ``tag``: ``!cancelled() && (needs.<job>.result == 'success' ||
needs.<job>.result == 'skipped')``, not ``!= 'failure'``. The two spellings
differ only when a predecessor's own result is ``cancelled``, which
``!= 'failure'`` still admits and the equality pair does not. Concretely: if
``tag`` is cancelled while the run itself is not, ``!= 'failure'`` would let
``conda`` proceed into its check that ``conda-<version>+0`` names this run's
commit, a tag ``tag`` never pushed, trading a clean skip for a failed step; the
equality pair skips ``conda`` outright instead.

``version_check`` is the exception, and deliberately so: ``tag``, ``pypi`` and
``conda`` each require ``needs.version_check.result == 'success'`` with no
``|| 'skipped'``. It produces the evidence the gates read, so a skipped or
cancelled ``version_check`` leaves them nothing to decide on. ``unit-tests`` is
held to the same bar for a different reason: it is the release test gate, and
it skips when nothing is publishable
(`#1052 <https://github.com/JarryShaw/PyPCAPKit/issues/1052>`__), so accepting
``skipped`` there would publish untested. ``github`` names it in ``needs:`` instead and relies on the implicit
``success()``. The gate's own ``if:`` is the union of the publishers'
conditions, with ``!= 'true'`` so unknown evidence runs it; should the two
ever drift apart, the failure is a release that did not happen, which
``release_status`` reports loudly, never one that went out untested.

The Release Pipeline
--------------------

.. mermaid::

   flowchart TD
       T1["push: tags v*<br/>ref_name starts with v"] --> VC
       T2["workflow_run: Vendor Update completed<br/>ref_name = main"] --> VC
       VC["version_check -- reads pcapkit.\_\_version\_\_<br/>computes each job's own evidence<br/>no gate, read-only"]
       VC --> UT
       UT["unit-tests -- Release test gate<br/>skipped when nothing is publishable"] --> GH
       GH["github -- GitHub Release<br/>creates/attaches the v* tag<br/>THE ONLY APPROVAL"]
       GH --> TG["tag -- Conda Tag<br/>conda-&lt;version&gt;+0 tag at github.sha<br/>then conda/build reset on main"]
       GH --> PY["pypi -- build + publish<br/>OIDC trusted publishing"]
       TG --> CD["conda -- build + upload<br/>matrix: OS x Python, per-leg evidence"]
       GH --> CD
       VC --> RS
       UT --> RS
       GH --> RS
       TG --> RS
       CD --> RS
       PY --> RS
       RS["release_status -- always runs<br/>reports why nothing released, or that it did"]
       classDef gate stroke-dasharray:6 3,stroke-width:2px
       class GH gate

A transitive reduction: ``version_check`` and ``unit-tests`` are also direct
``needs:`` of ``tag``, ``pypi`` and ``conda`` in the file, but ``github``
already implies them (``github`` itself depends on both), so drawing them would
add edges without changing which job can start before which. ``release_status``'s
edges are drawn in full, since it depends directly on *every* job precisely so
that it can run regardless of which of them skipped.

Only ``github-release`` carries a required reviewer; ``conda-tag``,
``pypi`` and ``anaconda`` kept their environments but had their reviewers
removed on `#887 <https://github.com/JarryShaw/PyPCAPKit/issues/887>`__.
What still makes one approval mean *the whole release* is the ``needs:``
graph: ``tag`` and ``pypi`` both depend on ``github``, and ``conda`` depends on
``tag`` and ``github`` -- so nothing downstream of ``github`` can
start before it is approved, and rejecting it leaves nothing tagged and
nothing published. Before that removal ``tag`` depended on ``version_check``
alone, so removing its reviewer without moving this dependency would have let
it push a commit to ``main`` and cut a ``conda-*`` tag *ahead of* the
approval it was supposed to wait for.

Precautions
-----------

.. warning::

   **Do not gate a release job on whether the** ``v*`` **tag exists.** ``github``
   creates the tag before ``pypi`` and ``conda`` upload, so a tag proves nothing
   about whether the upload finished. A job keyed on ``PCAPKIT_TAG_EXISTS``
   skips itself on a retry after a partial release, and the run finishes green
   because skipped is not failed -- so nothing in the UI says the release did
   not happen.

   `Per-Job Evidence, Not a Shared Proxy`_
   above is what prevents it: ``tag``, ``pypi`` and ``conda`` each check whether
   *their own* artefact is missing rather than whether the ``v*`` tag exists, so an
   incomplete release runs the jobs that did not finish instead of skipping them.
   A half-finished release self-heals on re-running the run that tagged it
   -- see `Recovery`_ below; a run created for a later commit releases nothing
   instead, with a warning that names what is missing (`One Commit per Release`_).
   ``release_status`` is the other half: it runs unconditionally and reports,
   with a ``::notice``, a ``::warning`` or a failing ``::error``, why a run
   released nothing or that it released something, so a stranded release is
   never only a green checkmark, even if the evidence checks disagree with
   reality.

**Do not hand-make a tag to route around a stuck release.** This is narrower
than "never tag by hand": pushing a *fresh* ``v<version>`` tag to start a
release, as in `Ways to Start a Release`_, is fine. What is not sanctioned
is deleting and re-pushing a tag that a stuck run already created, to force a
retry. A ``git push`` of a tag ref that already points at the same commit
produces no new event (documented GitHub Actions behaviour, not measured
here), so the push only fires again after the tag is deleted -- which touches a
ref the release automation owns, and lands the retry back on the tag-push path,
where every job's guard is bypassed regardless of what has already gone out.
Neither is worth the risk of a double upload to an index that cannot take one
back, and neither is needed, since a plain re-run self-heals; see
`Recovery`_ below.

``environment: pypi`` **stays even though its reviewer is gone.** ``pypi``
publishes through PyPI's OIDC trusted publishing (the job's
``environment: pypi`` and ``id-token: write``), and PyPI's trusted-publisher
configuration can be scoped to a GitHub Actions environment name. If this
project's publisher on PyPI is scoped that way, removing the ``pypi`` name
-- not just its reviewer -- would break the upload with a claim mismatch;
this is standard OIDC trusted-publishing behaviour, not something the
publisher's actual PyPI-side configuration was read to confirm here. Keep
the name regardless, since there is no upside to removing it.

``conda-tag`` **writes to** ``main``\ **, so a release is not read-only on the
branch.** After cutting ``conda-<version>+0`` at the run's commit, the
``tag`` job pushes a commit setting :file:`conda/build` to ``0`` on top of
``main`` (its "Reset Build Number" step) -- a plain
fast-forward push, never a rewrite -- so the next Conda Update bump of that
version is ``+1``. There is none when the run's commit is not on ``main``, nor
when ``main``'s tip already says ``0`` (the usual case, since
:file:`util/bump_version.py` writes ``0``) or carries another ``__version__``,
nor when origin already has a ``conda-<version>+N`` tag other than ``+0``,
since rewinding the counter would then reuse a tagged build number; the first
and last warn. `#1634 <https://github.com/JarryShaw/PyPCAPKit/issues/1634>`__'s own shape -- three Conda Update bumps that `#1632
<https://github.com/JarryShaw/PyPCAPKit/issues/1632>`__ left untagged -- gets
the reset: ``main``'s 3 becomes 0. A rejected push is retried from a fresh
fetch, three times at most. Approving ``github-release`` therefore also
approves a commit landing on the default branch, not only the artefacts that
sound like they are the point.

Recovery
--------

The sanctioned recovery from a failed or partial release run is re-running
that run (**Re-run failed jobs**), not deleting and re-pushing a tag by hand,
for the reasons above; a run created for a later commit will not finish it
(`One Commit per Release`_). A run whose ``github`` was refused created no
tag, so re-running it once the App is set up (`The Release App`_) starts its
release rather than re-tagging it. This is the actual fix rather than a
best-effort suggestion: `Per-Job Evidence, Not a Shared Proxy`_ above means ``tag``, ``pypi`` and ``conda`` each check whether
*their own* artefact is missing, so a re-run finishes whichever jobs did not
complete last time instead of skipping them on the ``v*`` tag's mere
existence. ``pypi`` is safe to re-run (``skip-existing: true``), and so is
``conda``, because each matrix leg checks Anaconda for its own
platform/Python distribution before uploading and skips only that leg's
upload if it is already there. Neither replaces a file the GitHub Release
already has (`#1640 <https://github.com/JarryShaw/PyPCAPKit/issues/1640>`__).

**A re-run does not need to be verified by hand against the PyPI and Anaconda
listings, because** ``release_status`` **does it.** That job runs on every
``Create Release`` attempt regardless of what else skipped, and reconciles
each of ``github``/``tag``/``pypi``/``conda`` *against its own evidence*
rather than demanding the same outcome from all of them -- a target counts as
reconciled if it succeeded, or if it skipped *because* its own evidence
already said it was done. That is what makes a self-heal reportable: a retry
after a partial release legitimately produces a **mixed** result
(``github``/``tag`` skipping because their artefacts exist while
``pypi``/``conda`` finish the rest), and a check demanding uniformity would
read that mix as the failure it exists to detect.

With that reconciliation, ``release_status`` reports exactly one of:

* nothing to release, because the trigger had nothing to do (quiet
  ``::notice``);
* nothing to release, because every target was already reconciled by skipping,
  i.e. the version was already fully out before this run started (quiet
  ``::notice``);
* the release is fully out, because every target reconciled, whether by a fresh
  full run or by the mixed self-heal above (quiet ``::notice`` either way);
* a release job failed or was cancelled outright (``::warning``, already
  visible as a red job elsewhere);
* at least one target skipped despite its own evidence saying it is still
  incomplete, and nothing else failed to explain that (``::error``, and the job
  itself fails) -- the shape
  `#888 <https://github.com/JarryShaw/PyPCAPKit/issues/888>`__ was actually
  about.

That last case should be unreachable given the
evidence-based guards above, since a target's own incomplete evidence is
what makes its job run rather than skip; reaching it anyway is a signal that
those checks themselves need attention, not that the release needs a
hand-rolled recovery.
