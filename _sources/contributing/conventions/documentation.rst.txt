.. _documentation:

Writing the Documentation
-------------------------

Rules for the documentation itself: the reStructuredText under :file:`docs/source/`
and the :mod:`pcapkit` docstrings the API reference renders from. Most were settled on
:issue:`719`, the prose sweep. As on :ref:`process`, every ruling is **paraphrased
rather than quoted**; the issue named beside a rule holds the original wording.

Concision
~~~~~~~~~

**Every page, docstring and comment is as short as it can be while staying
accurate.** Cut restatement, hedging, narration, and any sentence that would survive
deletion unnoticed; keep the specific fact, name and reference. Where the content is
structure or a run of parallel items, a diagram (`Mermaid for Flows`_) or a table says
it in less. This reaches the Markdown documents and every code comment too. Ruled on
:issue:`719` and reaffirmed by the owner in session, recorded on :issue:`2787`.

**Cut timed context** -- when a thing changed and what it used to do -- everywhere but
version-bounded prose: changelog entries, breaking-change and deprecation notes, and the
version directives. **Keep a design decision**: where a reader would otherwise undo a
deliberate choice, its reason is tightened rather than removed. Ruled on :issue:`719`.

Heading Case and Shape
~~~~~~~~~~~~~~~~~~~~~~

**Title Case, and short.** Sentence case is only for a heading that genuinely is a
sentence, such as a how-to question, and that was ruled rare: a sentence should
generally not be a title at all. Settled on :issue:`719`.

Title Case is the conventional kind, not every-word capitalisation: ``a``, ``an``,
``the``, ``and``, ``or``, ``of``, ``in``, ``for`` and ``to`` stay lowercase unless they
lead. That reading was put to the owner on :issue:`719` and left standing; *The*
``all`` *Extra* and *Issue and Pull Request Labels* on :ref:`process` follow it.

**Casing is the easy half.** A correctly cased heading still breaks the rule if it is a
clause: *What a Failed Lookup Raises* became *Failed-Lookup Exceptions*. A **finite
verb** makes a heading a sentence and earns a rewrite; a gerund or infinitive phrase is
a noun phrase and needs only re-casing, so *Running the tests* becomes *Running the
Tests*.

.. note::

   A heading must also describe its section; check that on any rewrite. *One Approval,
   Whole Release* became *The Release Pipeline* because the section opens on a Mermaid
   flowchart, and the approval prose it was named for sat well below it.

**A module docstring's** ``=`` **title underline runs six past the title.** The title
is measured as written, inline markup included, as the crawler templates under
:mod:`pcapkit.vendor` compute it. Ruled on
:issue:`2718`; :file:`tests/project/test_docs_module_title_underline_2718_unit.py`
fails on an underline of any other length.

.. code-block:: python

   """Some Module
   =================

   """

Renaming a Heading
~~~~~~~~~~~~~~~~~~

Each of these traps has been hit.

**Re-measure the underline against the new text.** A case flip usually keeps the
length; a rewrite rarely does, and docutils only warns on a short underline, which the
build does not fail on.

**A heading is a link target, so a rename is a repository-wide sweep**, not a
:file:`docs/source/` one: ``.rst`` prose, ``:ref:`` and ``:doc:`` link text, toctree
entries, implicit ``` `Text`_ ``` references, :mod:`pcapkit` docstrings and
:file:`tests/`. One rename left stale references in
:file:`pcapkit/corekit/sentinels.py` (a shipped docstring the API reference renders),
:file:`tests/corekit/test_sentinel_exports_unit.py` and
:file:`tests/project/test_conventions_doc_claims.py`.

.. warning::

   **Derive the old headings from the pre-change file, not from the diff**, which drops
   any heading whose underline is outside the hunk. Search every tracked file,
   whitespace-flattened, for each pre-change heading string.

Nothing in CI catches a reference a rename left behind: :file:`docs/source/conf.py`
sets no ``nitpicky`` and :file:`docs/Makefile` leaves ``SPHINXOPTS`` empty, so the
build runs without ``-n`` or ``-W`` and a dead reference renders as plain text.
:issue:`934` found a batch that way.

No tool checks the prose around a renamed heading either: making one plural left a
following *"it"* on :ref:`registry-protocol` without its antecedent.

Mermaid for Flows
~~~~~~~~~~~~~~~~~

**Draw the structure, and keep the prose beside it short.** A pipeline, a hierarchy, a
dispatch chain, a lifecycle or a decision procedure gets a Mermaid graph rather than an
ASCII diagram, even where its paragraph reads well, since a graph reads faster.
:issue:`719` asked for graphs where necessary and helpful; the owner widened that in
session, recorded on :issue:`2787`, keeping :issue:`719`'s bounds and adding the last
of these:

*  **A short sequence does not earn a graph.** Two steps read well as a sentence.
*  **A rationale stays prose.** A diagram carries structure and sequence, not *why* a
   choice was made, which :issue:`719` protects rather than compresses.
*  **Do not redraw a graph another page already has.** Approving the navigation work
   on :issue:`719`, the owner required that nothing duplicate information already
   shown.
*  **Every node and edge traces to the code or to the page**, so `Accuracy`_ applies
   to each.

**Every diagram is vertical**, because a horizontal one renders too small to read. Ruled
by the owner in session and recorded on :issue:`2787`:

*  A flowchart is ``flowchart TD`` or ``flowchart TB``, and a subgraph inside one
   stacks too, so it sets no horizontal ``direction`` of its own.
*  A state diagram is ``stateDiagram-v2`` with ``direction TB``.
*  A sequence diagram is allowed only while its participants are few, since they lay
   out side by side; ``wrap: true``, ``width`` and ``actorMargin`` in its front matter
   wrap its messages between narrow participants.

Vertical is judged on the render, which must come out taller than wide. A diagram is
``TD`` or ``TB`` unless an ``LR`` layout measures both taller than wide and larger than
every ``TD`` attempt, as the workflow trigger map and the field and protocol
hierarchies do.

Where a vertical layout runs wide or piles up its labels, stack siblings with an
invisible link (``A ~~~ B``), group nodes in subgraphs, break a long label with
``<br/>``, lower ``nodeSpacing`` in the front matter, or split it -- never turn it on
its side.

For the mechanics, follow the diagrams in the tree: each builds and is a bare
``.. mermaid::`` with no directive options. This page names the directive in its prose,
so the listing excludes it:

.. code-block:: shell

   grep -rn 'mermaid::' docs/source --include='*.rst' \
        --exclude='documentation.rst' | wc -l   # directives
   grep -rl 'mermaid::' docs/source --include='*.rst' \
        --exclude='documentation.rst' | wc -l   # pages carrying one

*  **Quote a node label whose text Mermaid would otherwise parse**, and leave a bare
   identifier bare. A graph whose labels are prose quotes all of them. A type hierarchy
   keeps the bare ``A{{Meta}}``, ``B(Base)``, ``D([user customisation ...])`` and
   ``subgraph name [Title]`` forms, and quotes only where the text forces it --
   ``h1["HTTP/1.*"]`` in :file:`docs/source/pcapkit/protocols/index.rst` -- and on
   ``click`` targets.
*  **Write a** ``click`` **target relative to its page** -- ``protocol.html#...``,
   ``../../ext.html#...``. The site is served under ``/PyPCAPKit/``, so a target
   starting with ``/`` resolves outside it and 404s.
*  **Edge labels follow no rule.** The exemplars quote some and leave others bare, such
   as ``|workflow_run: completed|`` and ``|02:00|``, which Mermaid accepts; match the
   graph being edited.
*  **Inside a quoted label**, ``<br/>`` breaks the line and a literal ``<`` or ``>`` is
   ``&lt;`` or ``&gt;``. Mermaid reads label text as Markdown, so an underscore that
   opens or closes a name is ``\_`` -- ``\_missing\_``, ``pcapkit.\_\_version\_\_``
   -- or the name renders as emphasis. Mermaid's ``#95;`` escape is no substitute: in a
   label with a ``<br/>`` it is decoded before the Markdown pass.
*  **Where a steep edge runs under a neighbouring edge label**, ``curve: monotoneX`` in
   the front matter keeps it clear, as the mint criterion's decision graph does.
*  **Leave the sizing to** :file:`docs/source/conf.py`. Its ``mermaid_init_config``
   turns ``useMaxWidth`` off for flowchart, state and sequence diagrams, each of which
   reads its own copy, so a diagram renders at its own size; a new diagram type needs
   its own entry there.

:doc:`The release pipeline </contributing/releasing>` is the example of a vertical
pipeline, :doc:`the engine hierarchy </pcapkit/foundation/engines/index>` of a vertical
type hierarchy, and :doc:`/contributing/maintenance` of the state and sequence diagrams.

Toctree Captions
~~~~~~~~~~~~~~~~

**A caption renders wherever its own toctree renders**, and that differs by toctree.
Measured on a built tree:

*  A toctree in the **root** document renders into the global sidebar, so its caption
   is visible from every page in the build.
*  A **nested** toctree renders only in its own page's body, so its caption is visible
   on that page alone.
*  ``:hidden:`` suppresses the body rendering. On a root toctree the sidebar copy
   survives and the caption is still everywhere; on a nested one nothing is left, and
   the caption renders nowhere.

So the per-package toctrees are deliberately bare: a caption on a package index would
show on that page alone. The root ones in :file:`docs/source/index.rst` carry captions,
and ``Subpackages`` in :file:`docs/source/pcapkit/index.rst` is the only nested one. A
built tree confirms it (this page names the captions, so it is excluded):

.. code-block:: shell

   grep -rl 'API Reference' --include='*.html' --exclude='documentation.html' \
        docs/build/html | wc -l   # every other page
   grep -rl 'Subpackages'   --include='*.html' --exclude='documentation.html' \
        docs/build/html | wc -l   # the pcapkit index page alone

The root toctrees are ``:hidden:`` because otherwise each caption renders twice on the
root page, in the body and in the sidebar: the duplication the owner ruled out on
:issue:`719`.

.. note::

   For the same reason, add no inline ``.. contents::``: ``furo`` already renders a
   sticky page-local table of contents on every page. The one in
   :file:`docs/source/index.rst` is commented out and stays so.

   ``toc_object_entries`` in :file:`docs/source/conf.py` was set by measurement, and
   the comment beside it records the figures so nobody reopens it blind. That is worth
   copying for the next measured setting; it is a precedent, not a ruling.

Paraphrasing a Ruling
~~~~~~~~~~~~~~~~~~~~~

Write a ruling in your own words. **Do not quote the owner verbatim** -- a standing
instruction on :issue:`719`, which every page here follows (:issue:`949` converted the
earlier ones).

The cost is not style. A quotation is pinned to the moment it was said, so it cannot
be corrected when its subject moves, and a test asserting on it fails when the wording
is tidied rather than when the claim stops being true; such tests derive the claim from
the tree instead. :ref:`process` and :ref:`mint-criterion` show the form: say what was
ruled and where, and leave the wording there.

**Name the issue, not the pull request.** A pull request describes the day it merged,
and a later change can make the citation wrong without touching it. The issue, where
the ruling was asked for and given, outlives the work. So cite the issue a rule was
settled on, and describe a change by what it did rather than by its number. Ruled on
:issue:`719`.

**Cite a ruling given in a pull request's review by the issue that pull request
closes**, as ``ruled in review of <PR> (:issue:`N`)``. Where it closes none, cite the
pull request with ``:pr:`` and say that no issue holds the ruling. Ruled in review of
:pr:`2599` (:issue:`2557`).

**The changelog and** :file:`tests/` **are exempt.** A changelog entry exists so a
reader can find the change, and the pull-request number *is* that pointer --
:file:`docs/source/changelog/1.5.0.rst` cites pull requests by design. Many pull
requests cited under :file:`tests/` close no issue, and where one exists it often lacks
the cited fact, which lives in the pull request's body or review. Ruled on
:issue:`719`.

Nothing else is exempt: a sibling page here that cites a pull request is unconverted,
not a third exemption.

Accuracy
~~~~~~~~

**Verify a claim against the code it describes, never against another document.** Where
prose and code disagree the code wins and the prose is fixed -- :issue:`719`'s own
charter. Docstrings have outlived what they described here before.

**State no count.** A count of things in the codebase or the documentation drifts as
soon as what it counts changes, so living prose words the claim without one -- *every
registered option*, *the remaining entries* -- and drops a count that was the only
content. Protocol and specification quantities, code constants, versions and issue
numbers are not counts, and a measurement that justifies a design choice stays, stated
as a measurement. Ruled on :issue:`1103`; the released changelogs are a frozen record
and keep theirs.

A keyword search is not a sweep. Take every cited repository path in each form it is
written in -- slash path, dotted module, bare filename, elided spellings -- intersect
them with the diff since the merge base, and re-measure the intersection. A
tense-keyword grep misses a claim phrased as a fraction of a total.

**Treat** ``every``, ``all``, ``each`` **and** ``none`` **as a claim about members, and
check the members one at a time.** Several of :issue:`719`'s findings had that shape:

*  A sweep asserted every ``.. module::`` target resolved. The RARP page declared
   ``pcapkit.protocols.data.link.rarp``, which never existed, since RARP and DRARP reuse
   ARP's data class. Fixed in ``68fbccd90``.
*  :issue:`911`'s ruling -- export the sentinel objects, not their types -- was read as
   describing every module then holding a sentinel. :mod:`pcapkit.corekit.fields.field`
   exported neither, so applying it there meant *adding* a name.

**Know which claims are pinned.** :file:`tests/project/test_conventions_doc_claims.py`
checks several pages against the tree by name rather than by figure -- the
extension-header table against the classes it classifies, :ref:`process`'s changelog
grouping against the entries, :ref:`registry-protocol`'s helpers against the code -- so
a stale claim there goes red. A page's entry in that module's ``ANCHORS`` fixes only
its existence, anchor and toctree position; the rest is pinned only where a test reads
it. The same module checks what neither a reader nor Sphinx would notice: in a
``` `#NNN <.../NNN>`__ ``` link the displayed number must match its URL's, since a
review round once corrupted a run of well-formed ones.

Resolvable Targets
~~~~~~~~~~~~~~~~~~

**A** ``.. module::`` **target must name a file on disk.** A dangling one is worse than
none: it adds a module-index entry for a module that does not exist and a
cross-reference target that resolves to nothing. Settled on :issue:`719`; the check:

.. code-block:: shell

   grep -rhE '^\.\. +(py:)?(module|currentmodule):: ' docs/source --include='*.rst' \
        --exclude='documentation.rst' |
       awk '{print $NF}' | sort -u | tr '.' '/' |
       while read -r path; do
           [ -f "$path.py" ] || [ -f "$path/__init__.py" ] || echo "dangling: $path"
       done

**Under a** ``.. module::``, **a hand-written** ``.. data::`` **or** ``.. function::``
**takes the bare name.** The module directive supplies the prefix, so
``.. data:: pcapkit.x._T`` under ``.. module:: pcapkit.x`` registers
``pcapkit.x.pcapkit.x._T``, which no reference resolves to exactly. An object in
another module takes a ``:module:`` option, as the ``LINKTYPE`` entry on
:doc:`/pcapkit/protocols/link/index` does. :issue:`1775` found long-form directives
that left TypeVar references ambiguous;
:file:`tests/project/test_docs_ambiguous_xrefs_1775_unit.py` fails on the next one.

**Every importable shipped module is documented, with one deliberate exception**: the
modules under :file:`pcapkit/protocols/*/NotImplemented/`, placeholders for unwritten
dissectors with no class a reader could use. Packaging does not force this -- measured
on ``1.5.0b8``, each is in the source distribution *and* the wheel and imports as a
namespace-package submodule. None of those directories has an :file:`__init__.py`, so
``find_packages`` omits them. :file:`tests/project/test_docs_module_pages_2559_unit.py`
fails on a module with no ``module``, ``currentmodule`` or ``automodule`` directive,
and on a placeholder that gains one.

When something is removed, its documentation entry goes too: with a deprecation note
where a user could have depended on it, deleted outright where it never shipped, as the
``rarp`` entry was. Ruled on :issue:`719`.

Version Directives
~~~~~~~~~~~~~~~~~~

**One** ``versionadded`` **per version in a docstring or prose block**; same-version
directives merge. **A body that only names the thing added and cites its issue or pull
request is dropped**, leaving the bare tag, since the summary already names it. A body
with content of its own stays, such as a move (*Moved here from* ...), a rename or a
takeover. Ruled on :issue:`2530`.

Format and Mechanics
~~~~~~~~~~~~~~~~~~~~

*  **reStructuredText under** :file:`docs/source/`, **Markdown outside it**, the READMEs
   included. Ruled by the owner on :issue:`719`, correcting a blanket *always* ``.rst``;
   ``CONTRIBUTING.md``'s *Documentation* section records the same split. The
   ``global-include`` in :file:`MANIFEST.in` does not reach Markdown, so the READMEs
   under :file:`examples/` ship through ``recursive-include examples *.md``, and any
   other Markdown file ships only if setuptools or an ``include`` line adds it.
*  **Cite an issue or a pull request by role wherever Sphinx renders the text.** In an
   ``.rst`` page, a docstring or a ``#:`` doc-comment an issue is ``:issue:`NNN``` and
   a pull request ``:pr:`NNN```, by what the number is rather than what a URL says: a
   bare ``#NNN`` renders as plain text there, and a hand-written tracker link hides
   which of the two it names. A plain ``#`` comment, a workflow's YAML comment,
   :file:`tests/` and any other unrendered file keep ``#NNN``, which GitHub links. A
   link into another repository or to a Discussion keeps its URL, and ``GH-NNN`` is a
   deliberate issue form. Ruled on :issue:`1103`.
   :file:`tests/project/test_docs_issue_pr_roles_1103_unit.py` fails on a bare number,
   a hand-written link or a role of the wrong kind in rendered text, and
   :file:`tests/project/test_issue_refs_in_comments.py` on a role in a plain comment.
   Each number's kind comes from
   :file:`tests/project/issue_pr_roles_fixtures/kinds.json`, which
   ``python util/issue_pr_kinds.py`` regenerates from the tracker and the scheduled
   Issue and PR Kinds workflow proposes refreshing (:doc:`/contributing/workflows`).
   The test skips a number above the file's highest until a refresh, and fails on a
   lower one the file lacks, such as a Discussion's. Its ``ALLOWED`` set exempts the
   hand-written links and the bare ``#1962`` on :doc:`/contributing/workflows`, which
   other tests pin in that form, so converting one changes its pin in the same commit.
*  **Prose names the real defining module, not a re-export**, a strand of the
   consistency sweep on :doc:`the roadmap </contributing/pep>`. Every sentinel is
   defined in :mod:`pcapkit.corekit.sentinels`, and :ref:`sentinel-convention`'s table
   names it rather than the modules that use them, which do not re-export them
   (:issue:`1744`).
*  **A verbatim upstream port is exempt from these conventions.**
   :ref:`sentinel-convention` gives the reason: a vendored copy's value is that it can
   still be diffed against upstream, which a house-style rewrite destroys.
