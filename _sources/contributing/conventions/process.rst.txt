.. _process:

Running the Repository
----------------------

The four pages before this one are about writing library code. The rulings here are
about running the repository -- what an install carries, what a changelog entry is,
and what the issue and pull request labels mean. None of them is derivable from a
module, and none fits a code-convention page, so the owner ruled on
`#918 <https://github.com/JarryShaw/PyPCAPKit/issues/918>`__ that they get a page of
their own rather than being left in their threads. Each ruling below is **paraphrased
rather than quoted**, also on the owner's standing instruction there; the issue named
beside it is where the original wording is.

The ``all`` Extra
~~~~~~~~~~~~~~~~~

``all`` means **core addons only** -- the things that let the library itself run at
full functionality -- rather than everything a user might conceivably want. The owner
settled that on `#910 <https://github.com/JarryShaw/PyPCAPKit/issues/910>`__ and named
the three that qualify to date: the CLI addon, the crypto addon, and ``pycrate``.

On the tree, in :file:`pyproject.toml`:

.. code-block:: toml

   cli    = [ "emoji" ]
   crypto = [ "cryptography>=3.4" ]
   NGAP   = [ "pycrate" ]

   all    = [ "emoji", "cryptography>=3.4", "pycrate" ]

So ``all`` is exactly the union of those three extras, written out as literals rather
than referenced.

Two groups stay out, and the reasons are **different** rather than two versions of
one reason. Keeping them apart is what stops the list drifting the way it already did
once:

*  **The third-party capture engines are excluded by kind.** ``DPKT``, ``Scapy``,
   ``PyShark``, ``PyPCAPFile``, ``PyPCAP`` and ``PCAP_CT`` are not core addons, so
   they are on demand -- one extra at a time, ``pip install pypcapkit[Scapy]`` and so
   on. This holds however easy they are to install, and it is what the ruling
   changed: four of them used to be in ``all``.
*  **``PyPCAP`` and ``PCAP_CT`` were already excluded for installability**, which the
   ruling leaves untouched. ``pypcap`` is an sdist-only C extension needing a
   compiler and the libpcap development files; ``pcap-ct`` and ``libpcap`` are
   published only as pre-releases, and ``all`` should not be how somebody acquires a
   beta they did not ask for.

``vendor`` is the crawler dependency set and is not for end users, so it is out on the
same audience grounds. Narrowing ``all`` costs a user nothing at run time:
:meth:`Extractor.run <pcapkit.foundation.extraction.Extractor.run>` warns and falls
back to the default engine rather than raising when a requested engine is absent.

.. note::

   The ``dev`` extra exists **because** of this narrowing, and is not a second
   catch-all. pylint, mypy and autodoc all resolve imports against what is installed,
   so the four engines leaving ``all`` would have made them newly unresolvable to the
   toolchain. ``dev`` is defined by what the toolchain must be able to *see*, and the
   workflows that need full resolution install ``.[all,dev]``. Do not add
   ``pypcap``/``pcap-ct`` to it to silence a lint finding; :file:`.github/workflows/lint.yml`
   carries a tracked ``import-error`` count that is deliberate rather than accidental.

Changelog Entry Granularity
~~~~~~~~~~~~~~~~~~~~~~~~~~~

An entry is **not one line per commit**. Group the changes by topic, and give concise
detail of what actually changed in that version bump. Ruled on
`#918 <https://github.com/JarryShaw/PyPCAPKit/issues/918>`__.

Two different things get confused here, so they are named apart:

*  **A pull request's commits.** The shared changelog for the 1.5.0 cycle is a
   long-lived pull request of its own, carrying roughly one commit per code pull
   request, deliberately unsquashed so that what is and is not accounted for stays
   readable in its log. That is a property of *the pull request*, and it is not what
   the ruling is about.
*  **A changelog file's entries.** :file:`docs/source/changelog/1.5.0.rst` groups its
   entries under a section per top-level module, with ``Added``, ``Changed`` and
   ``Fixed`` nested inside each, and a single entry routinely cites several changes at
   once -- the completed Mobility Header registry is one bullet, not two. That is a
   property of *the file*, and it is the axis the ruling governs.

Both are measurable rather than matters of memory, which is the point of writing the
commands down instead of a figure that will be stale by the next merge:

.. code-block:: shell

   # entries in the file, and the module sections they group under
   grep -cE '^\* ' docs/source/changelog/1.5.0.rst
   grep -B1 -E '^-{3,}$' docs/source/changelog/1.5.0.rst | grep -vE '^-{3,}$|^--$'

   # commits on the shared changelog pull request -- a different number, about a
   # different thing
   gh pr list -R JarryShaw/PyPCAPKit --state all \
       --search 'shared 1.5.0 changelog in:title' \
       --json commits -q '.[].commits|length'

The grouping scheme was settled on #918: **a section per top-level module, with**
``Added``/``Changed``/``Fixed`` **nested inside each** -- module granularity, not
per-file and not per-subpackage. The file carries **9** module-level sections holding
155 entries, and no entry carries an inline kind label::

   $ grep -cE '^\* \*\*(Added|Changed|Fixed)\*\*' docs/source/changelog/1.5.0.rst
   0

Eight of those nine name a module; the ninth, *Project infrastructure*, is for what
belongs to none. Nor is the map one-to-one with the package list below --
:mod:`pcapkit.interface` has no 1.5.0 entry, so it has no section of its own:

.. code-block:: shell

   ls -d pcapkit/*/ | sed 's|pcapkit/||;s|/||'   # const corekit dumpkit foundation
                                                 # interface protocols toolkit
                                                 # utilities vendor

.. note::

   One case the rule does not settle by itself: an entry whose change spans modules --
   the reassembly and extraction ones touch :mod:`pcapkit.foundation` and
   :mod:`pcapkit.protocols` together. Ruled on
   `#952 <https://github.com/JarryShaw/PyPCAPKit/issues/952>`__: file it under the
   module the change is *about*, name the others in the entry's own text, and do
   **not** duplicate the entry into each section. A reader scanning one module's
   section wants that module's changes; the same prose appearing twice reads as two
   separate changes. Raised originally on #918.

   The restructure itself belongs to the shared changelog's own pull request, which
   owns the file and merges last; doing it earlier would conflict with every open
   change that touches an entry.

Issue and Pull Request Labels
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The owner asked on `#918 <https://github.com/JarryShaw/PyPCAPKit/issues/918>`__ for
this to be written down alongside ``breaking``, since ``breaking``'s meaning only
makes sense against the scheme it sits in.

**Almost every label is applied by hand, by the owner** -- so a label is generally a
statement someone made rather than a value derived from the change. That matters most
for the ``review:`` family below: such a label is not evidence of the state it names,
it is a record that the owner asserted it.

Two paths are automated, and both are worth knowing about because a label they set has
had no human judgement behind it:

*  **dependabot** puts ``dependencies`` and ``python`` on its own pull requests, and
   only those two: :file:`.github/dependabot.yml` configures a single ecosystem,
   ``pip``, so it never opens a workflow bump here. ``github_actions`` exists as a
   label but is **hand-applied like the rest** -- naming it as dependabot's would tell
   a reader the opposite of this section's point.
*  **The issue templates** apply an issue-kind label from their front matter, before
   anyone reads the issue -- :file:`.github/ISSUE_TEMPLATE/bug_report.md` carries
   ``labels: bug`` and :file:`.github/ISSUE_TEMPLATE/feature_request.md` carries
   ``labels: enhancement``. So ``bug`` and ``enhancement`` on a template-opened issue
   are defaults rather than assessments.

Nothing else automates a label. :file:`.github/release.yml` only *reads* existing
labels to bucket release notes, and the ``PCAPKIT_CONDA_LABEL`` in the release
workflows is a conda channel label, unrelated to these.

The ones that carry meaning here fall into five groups, which stack rather than
compete: a pull request normally carries one from the first group and as many of the
rest as apply. **The five groups are not the whole label set** -- the repository also
has GitHub's own defaults, of which ``wontfix``, ``invalid``, ``help wanted`` and
``duplicate`` are all in live use and only ``good first issue`` has never been applied.
Those are documented by GitHub rather than here, and are counted rather than listed so
this page does not go stale every time one is added::

   $ gh label list -R JarryShaw/PyPCAPKit --limit 100 --json name -q '.[].name' | wc -l
   29

One of those defaults carries a local ruling worth knowing: an issue closed as
unnecessary takes ``invalid`` (or the nearest applicable) rather than ``bug``, since
the issue was not a defect. `#275
<https://github.com/JarryShaw/PyPCAPKit/issues/275>`__ is where it was applied --
``bug`` removed and ``invalid`` added in the same second -- and `#707
<https://github.com/JarryShaw/PyPCAPKit/issues/707>`__ is the worked example, closed
as invalid because it was filed against ``main`` rather than against the pull
request's diff.

**Type -- what kind of change it is.** Each corresponds to the subject prefix of the
commit, so the label and the message agree by construction:

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Label
     - Applies to
   * - ``feat``
     - a new capability
   * - ``fix``
     - a defect repaired
   * - ``refactor``
     - restructuring for its own sake -- neither a fix nor a new capability
   * - ``perf``
     - a performance improvement
   * - ``docs``
     - documentation only
   * - ``test``
     - tests added or corrected
   * - ``ci``
     - CI or workflow configuration
   * - ``chore``
     - tooling and repository hygiene, with no library behaviour change
   * - ``release``
     - version bumps and distribution rollups
   * - ``const``
     - regenerated IANA or vendor constant tables, members keeping their numeric
       values

**Issue kind**, for issues rather than pull requests: ``design`` marks a pattern being
decided rather than a defect or a request, and a majority of the rulings on these pages
were filed under it -- though not all, several having been settled on a ``bug`` or
``enhancement`` thread instead. Alongside ``bug``, ``enhancement`` and ``question``.

**State -- what is happening to it now.** An open issue is meant to carry one of
these, so that its status is readable without opening it:

*  ``wip`` -- in flight: a covering pull request is open, or an agent is on it.
*  ``blocked`` -- deferred behind other work or a decision, with the last comment
   saying what unblocks it. The condition is meant to be *checkable* rather than
   remembered -- a command someone else can run and get an answer from.
*  ``needs: decision`` -- waiting on the owner, and on nothing else.

Two things the board shows rather than the rule: ``wip`` and ``needs: decision``
legitimately **co-occur**, when the bulk of an issue is being worked and one
sub-question is held for the owner -- #918 itself was labelled that way while this
page was being written. And an open issue with no state label at all is a gap rather
than a category, which is worth checking for rather than assuming away:

.. code-block:: shell

   gh issue list -R JarryShaw/PyPCAPKit --state open --limit 100 \
       --json number,labels -q '.[]|"#\(.number) \(.labels|map(.name)|join(","))"'

**Review -- the cross-review verdict, at the current head.** Separate from CI, which
has a status of its own: ``review: pending`` means no verdict for this head,
either never reviewed or the head moved since; ``review: good-to-go`` and
``review: needs-changes`` are the two verdicts. Because they are keyed on the head
rather than on the pull request, a new push invalidates the label -- a verdict that
outlives the commit it was given on is worse than none.

**Scope.** ``dependencies`` and ``python`` are dependabot's, per above.
``github_actions`` is the same kind of label -- it scopes a change to the workflows --
but nothing applies it automatically, because dependabot is not configured for that
ecosystem here.

The ``breaking`` Label
~~~~~~~~~~~~~~~~~~~~~~

``breaking`` is **additive** -- it goes on alongside the type label, never instead of
it. Its own description in the label set says so, and defines it as breaking
public-facing behaviour or API.

So the question it answers is not "how big is this change" but **"can a caller
observe the difference without changing their code"**. On the tree, the changes
carrying it are that kind:

*  an exception type a caller catches --
   `#805 <https://github.com/JarryShaw/PyPCAPKit/issues/805>`__ raising
   :exc:`~pcapkit.utilities.exceptions.ProtocolError` where a bare
   :exc:`struct.error` used to escape, and
   `#759 <https://github.com/JarryShaw/PyPCAPKit/issues/759>`__ raising one where a
   single-bit lookup used to return a member;
*  a public attribute's meaning --
   `#618 <https://github.com/JarryShaw/PyPCAPKit/issues/618>`__ swapping ``Frame.len``
   and ``Frame.cap_len`` between the PCAP and PCAP-NG readers;
*  a signature or a name a caller writes --
   `#806 <https://github.com/JarryShaw/PyPCAPKit/issues/806>`__ retyping
   ``AppType.proto`` and giving ``register_apptype`` varargs,
   `#778 <https://github.com/JarryShaw/PyPCAPKit/issues/778>`__ enforcing ``@final``
   at runtime;
*  a path a caller or a script depends on -- the change that named the examples
   directories apart.

.. warning::

   **A pull request's prose and its label can disagree, and the label is not
   automatically right.** Both directions have happened here. The ``#759`` and
   ``#805`` changes carry the label while their changelog bullets never said so, which
   a review round on the shared changelog caught and corrected. The
   `#844 <https://github.com/JarryShaw/PyPCAPKit/issues/844>`__ change carries it too,
   and its own pull request argues at length that the change is *not* breaking -- a
   review round checked that argument and found it right on the facts, so there the
   label is the half that overstates. So when the two conflict, settle it on what a
   caller can observe, and fix whichever of the two is wrong rather than letting the
   pair stand.

.. note::

   **The label is not applied uniformly across the repository's history, and a census
   that assumes it is will be wrong.** It is dense on pull requests from the
   examples-directory change above onward and effectively absent below it: the only
   earlier carriers are seven pre-``0.15`` pull requests, clustered at the very start
   of the numbering, with nothing labelled at all between them and that change. Three
   of those seven are distribution rollups, each also carrying ``release``; the other
   four are early ``refactor``/``feat`` work from before the project stabilised. On
   issues it is sparser still, appearing only from ``#775`` up. So ``breaking``'s
   absence on an old pull request is weak evidence at best. The current figures, rather
   than these:

   .. code-block:: shell

      gh pr list -R JarryShaw/PyPCAPKit --state all --label breaking --limit 200 \
          --json number -q '[.[].number]|sort|@json'
      gh issue list -R JarryShaw/PyPCAPKit --state all --label breaking --limit 100 \
          --json number -q '[.[].number]|sort|@json'
