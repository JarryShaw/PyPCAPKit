.. _documentation:

Writing the Documentation
-------------------------

The pages before this one rule on library code and on running the repository. This
one rules on the documentation itself -- how a page is titled, when a diagram beats a
paragraph, and what a sentence on it is allowed to claim. It governs the
reStructuredText under :file:`docs/source/` and the :mod:`pcapkit` docstrings the API
reference renders from, since the owner named both when settling the first of these.

Nearly all of it was settled on
:issue:`719`, the prose sweep, whose
thread was the only place most of it lived. As on :ref:`process`, every ruling here is
**paraphrased rather than quoted**, on the owner's standing instruction there; the
issue named beside a rule is where the original wording is.

Heading Case and Shape
~~~~~~~~~~~~~~~~~~~~~~

**Title Case, and short.** Sentence case belongs only to a heading that genuinely is a
sentence -- a how-to question is the example the owner gave -- and that was ruled rare:
a sentence should generally not be used as a title at all. Settled on :issue:`719`.

Title Case here is the conventional kind rather than every-word capitalisation. The
short function words ``a``, ``an``, ``the``, ``and``, ``or``, ``of``, ``in``, ``for``
and ``to`` stay lowercase unless they lead, which was the reading put to the owner on
:issue:`719` and left standing. It is also what the tree does: *The* ``all`` *Extra* and
*Issue and Pull Request Labels* on :ref:`process` are both in it.

**The casing is the easy half.** A heading can be in Title Case already and still
break the rule by being a clause rather than a title: *What a Failed Lookup Raises* was
correctly cased and was renamed *Failed-Lookup Exceptions*.

The line to draw: a **finite verb** makes a heading a sentence and earns a rewrite,
while a gerund or infinitive phrase is a noun phrase and needs only re-casing -- so
*Running the tests* becomes *Running the Tests* rather than being reworded.

.. note::

   A heading also has to describe the section beneath it, and a rewrite is the moment
   to check that. *One Approval, Whole Release* was renamed *The Release Pipeline*
   because the section opens on a Mermaid flowchart while the approval prose it had
   been named for sat well below, leaving the page's most navigable artefact
   unfindable from the table of contents.

Renaming a Heading
~~~~~~~~~~~~~~~~~~

Mechanical traps, each of which has bitten rather than being hypothetical.

**Re-measure the underline against the new text.** A case flip usually keeps the
length; a rewrite almost never does, and docutils reports an underline shorter than
its heading in a build that does not fail on warnings. Re-check every heading.

**A heading is a link target, so a rename is a repository-wide sweep** rather than a
:file:`docs/source/` one. In scope: ``.rst`` prose, ``:ref:`` and ``:doc:`` link text,
toctree entries, implicit ``` `Text`_ ``` references, **and** :mod:`pcapkit` docstrings
and the files under :file:`tests/`. A heading rename once left stale
references spread across :file:`pcapkit/corekit/sentinels.py`,
:file:`tests/corekit/test_sentinel_exports_unit.py` and
:file:`tests/project/test_conventions_doc_claims.py`. The first of those is a shipped
module docstring that renders into the API reference, so a reader following it searches
the page for a string no longer on it.

.. warning::

   **Derive the list of old headings from the pre-change file, not from the diff.** A
   diff-derived list silently drops any heading whose underline is not adjacent in the
   hunk. A whitespace-flattened search for every pre-change heading string across
   every tracked file is what works.

Nothing in CI catches a reference a rename left behind. :file:`docs/source/conf.py`
sets no ``nitpicky`` and :file:`docs/Makefile` leaves ``SPHINXOPTS`` empty, so the
build runs with neither ``-n`` nor ``-W``: a dead reference renders as the plain text
it used to be, and the build still succeeds. :issue:`934` found a batch of them at once
that way.

One thing a rename breaks that no tool checks at all is the prose around it. Turning a
singular heading plural cost :ref:`registry-protocol` the antecedent of a following
*"it"*, caught in the same review.

Mermaid for Flows
~~~~~~~~~~~~~~~~~

Where the subject is a flow, prefer a Mermaid graph to the paragraph or the ASCII
diagram that would otherwise carry it -- a graph is read faster than its own
description. The owner ruled this on :issue:`719`, asking for it where it is necessary and
helpful, which bounds it:

*  **A short sequence does not earn a graph.** Two steps read perfectly well as a
   sentence, and a diagram of them costs a reader a context switch for nothing.
*  **A rationale stays prose.** A diagram carries structure and sequence; it cannot
   carry *why* a choice was made, and that reasoning is what :issue:`719` protects rather
   than compresses.
*  **Do not redraw a graph another page already has.** The owner's condition when
   approving the navigation work on :issue:`719` was that nothing duplicate information
   already shown, and a second copy of a flow is exactly that.

The style model is the set already in the tree, every one of which builds. The sweep
excludes this page, which names the directive in its own prose and would otherwise
count itself:

.. code-block:: shell

   grep -rn 'mermaid::' docs/source --include='*.rst' \
        --exclude='documentation.rst' | wc -l   # directives
   grep -rl 'mermaid::' docs/source --include='*.rst' \
        --exclude='documentation.rst' | wc -l   # pages carrying one

Every one is a bare ``.. mermaid::`` carrying no directive options, and every one is a
``flowchart``: ``LR`` for a type hierarchy, and for a graph whose ``TD`` layout would run
wider than the page or pile its edge labels on top of each other -- a decision with many
outcomes, a trigger map -- and ``TD`` for the other sequences and decisions. **Quote a
node label whose text Mermaid would otherwise try to parse**, and leave a bare identifier
bare. That is what the exemplars do with *node* labels, and it follows the subject rather
than the direction: every node label in the sequence, decision and trigger graphs is
quoted, since every one of them is prose; the type hierarchies quote only where the text
forces it, which is ``h1["HTTP/1.*"]`` and ``h2["HTTP/2"]`` in
:file:`docs/source/pcapkit/protocols/index.rst` and nowhere else. Everything else there
uses the bare ``A{{Meta}}``, ``B(Base)``, ``D([user customisation ...])`` and
``subgraph name [Title]`` forms, and spends its quotes on ``click`` targets instead.
**Write a** ``click`` **target relative to the page it is on** -- ``protocol.html#...``,
``../../ext.html#...`` -- never from the site root: the published site is served under
``/PyPCAPKit/``, so a target starting with ``/`` resolves outside it and 404s.
**Edge labels follow no rule at all.** The exemplars quote some and leave others bare,
including ``|workflow_run: completed|`` and ``|02:00|``, which the reason above would
have quoted and which Mermaid accepts anyway -- so match the graph being edited rather
than this paragraph. Inside a quoted label, ``<br/>`` breaks the text across lines and a
literal ``<`` or ``>`` is written ``&lt;`` or ``&gt;``. Mermaid also reads label text as
Markdown, so an underscore that opens or closes a name is written ``\_`` --
``\_missing\_``, ``pcapkit.\_\_version\_\_`` -- or the name renders as emphasis. Its
own ``#95;`` escape is no substitute: in a label that carries a ``<br/>`` it is decoded
before the Markdown pass, and the emphasis comes back. Where a steep edge runs under
a neighbouring edge label, ``curve: monotoneX`` in the graph's front matter keeps it
clear, as the mint criterion's decision graph does.
:doc:`The release pipeline </contributing/releasing>` is the ``TD`` example and
:doc:`the field hierarchy </pcapkit/corekit/fields/index>` the ``LR`` one.

Toctree Captions
~~~~~~~~~~~~~~~~

**A caption renders wherever its own toctree renders, which is not the same place for
every toctree.** Measured against a built tree rather than assumed:

*  A toctree in the **root** document renders into the global sidebar, so its caption
   is visible from every page in the build.
*  A **nested** toctree renders only in its own page's body, so its caption is visible
   on that page alone.
*  ``:hidden:`` suppresses the body rendering. On a root toctree the sidebar copy
   survives and the caption is still everywhere; on a nested one nothing is left, and
   the caption renders nowhere.

That is why most of the per-package toctrees are deliberately bare -- a caption on a
package index would be invisible on every page but one. The root ones in
:file:`docs/source/index.rst` carry captions, and ``Subpackages`` in
:file:`docs/source/pcapkit/index.rst` is the only nested one. A built tree says so --
excluding this page, which names these captions in its own prose and would otherwise
count itself:

.. code-block:: shell

   grep -rl 'API Reference' --include='*.html' --exclude='documentation.html' \
        docs/build/html | wc -l   # every other page
   grep -rl 'Subpackages'   --include='*.html' --exclude='documentation.html' \
        docs/build/html | wc -l   # the pcapkit index page alone

Those root toctrees are ``:hidden:`` because, without it, each of their captions
rendered twice on the root page -- once inline in the body, once in the sidebar -- which
is the duplication the owner ruled out on :issue:`719`.

.. note::

   For the same reason, do not add an inline ``.. contents::`` to a page. The ``furo``
   theme already renders a sticky page-local table of contents on every page, so an
   inline directive is a second copy of it; the one in :file:`docs/source/index.rst`
   is commented out and should stay that way.

   One setting there was decided by measurement rather than by preference:
   ``toc_object_entries`` carries, in a comment beside it, the figures that settled it,
   so that nobody reopens the question blind. That is worth copying the next time a
   setting is chosen that way, but it is a single precedent and not a rule the owner
   has ruled on.

Paraphrasing a Ruling
~~~~~~~~~~~~~~~~~~~~~

Write a ruling down in your own words. **Do not quote the owner verbatim** -- a
standing instruction on :issue:`719`, and the one every page in this directory follows.
:issue:`949` went back over the pages that then existed and replaced their quoted
rulings with paraphrase.

What a quotation costs is not style. A quoted sentence is pinned to the moment it was
said, so it cannot be corrected when the thing it describes moves; and a test that
asserts on the quotation fails when the wording is tidied rather than when the claim
stops being true. That change rewrote those tests alongside the prose, so that each
derives its claim from the tree instead. :ref:`process` and :ref:`mint-criterion` show
the form: say what was ruled, name where it was ruled, and leave the wording there.

**Name the issue, not the pull request.** A pull request is a point in time: it
describes what was true on the day it merged, and the next change past it can make the
citation wrong without touching it. The issue is the durable half -- where the ruling
was asked for and given -- and it survives the work that implemented it. So cite the
issue a rule was settled on, and describe a change by what it did rather than by its
number. Ruled on :issue:`719`.

**The changelog and** :file:`tests/` **are both exempt, for related reasons.** A
changelog entry exists so a reader can find the change, and the pull-request number *is*
that pointer; converting it would delete the thing the entry is for --
:file:`docs/source/changelog/1.5.0.rst` is dense with pull-request citations by design.
A substantial share of the pull requests cited under :file:`tests/` close no issue at
all -- one credits a proposal to an external contributor and closes nothing -- and where
an issue does exist beside a citation, it frequently lacks the fact being cited, which
lives in the pull request's own body or review thread instead. Ruled on :issue:`719`.

The rule reaches the rest of this directory as well: a sibling page that cites a pull
request is unconverted, not a third exemption. The changelog and :file:`tests/` are the
whole exempt set -- nothing else is.

Accuracy
~~~~~~~~

**Verify a claim against the code it describes, never against another document.** Where
prose and code disagree the code wins and the prose is what gets fixed -- :issue:`719`'s
own charter -- and a docstring outliving the thing it described is a demonstrated failure
mode here rather than a hypothetical one.

**State no count.** A count of things in the codebase or the documentation drifts as
soon as what it counts changes, and keeping it in step by hand does not scale, so
living prose words the claim without one -- *every registered option*, *the remaining
entries* -- and drops a count that was the only content. Protocol and specification
quantities, code constants, versions and issue numbers are not counts, and a
measurement that justifies a design choice stays, stated as a measurement. Ruled on
:issue:`1103`; the released changelogs are a frozen record and keep theirs.

A keyword search is not a sweep: the reliable method takes every cited
repository path in each of the forms it gets written in -- slash path, dotted module,
bare filename, and the elided spellings -- intersects them with the diff since the
merge base, and re-measures the intersection. A tense-keyword grep misses a claim
phrased as a fraction of a total.

**Treat** ``every``, ``all``, ``each`` **and** ``none`` **as a claim about members, and
check the members one at a time.** Several of :issue:`719`'s findings were of exactly that
shape:

*  A sweep asserted that every ``.. module::`` target in the documentation resolved.
   One did not: the RARP page declared ``pcapkit.protocols.data.link.rarp``, which has
   never existed, because RARP and DRARP reuse ARP's data class. Fixed in ``68fbccd90``.
*  :issue:`911`'s ruling -- export the sentinel objects and leave their types out -- was
   read as describing every module that then held a sentinel. One ran the other
   way: :mod:`pcapkit.corekit.fields.field` exported neither, so applying the rule
   there meant *adding* a name rather than removing one.

**Some claims on these pages are pinned, and knowing which is part of writing one.**
:file:`tests/project/test_conventions_doc_claims.py` checks what several pages assert
against the tree by name rather than by figure -- the extension-header table against
the classes it classifies, :ref:`process`'s changelog grouping against the entries,
:ref:`registry-protocol`'s helpers against the code -- so a stale claim there goes red
instead of quiet. A page's entry in that module's ``ANCHORS`` fixes only its existence,
anchor and toctree position; what the page goes on to say is pinned by nothing unless a
test reads it. The same module checks something a reader cannot see and Sphinx cannot
warn about: in a ``` `#NNN <.../NNN>`__ ``` link the displayed number has to match the
number in its own URL. A review round once corrupted a run of them and nothing caught
it, because both halves were well-formed.

Resolvable Targets
~~~~~~~~~~~~~~~~~~

**A** ``.. module::`` **target must name a file on disk.** A dangling one is worse than
no directive at all: it registers a module-index entry for a module that does not
exist, and gives cross-references a target that resolves to nothing. The sweep that
settled this on :issue:`719` found exactly one, and repeating it is cheap:

.. code-block:: shell

   grep -rhE '^\.\. +(py:)?(module|currentmodule):: ' docs/source --include='*.rst' \
        --exclude='documentation.rst' |
       awk '{print $NF}' | sort -u | tr '.' '/' |
       while read -r path; do
           [ -f "$path.py" ] || [ -f "$path/__init__.py" ] || echo "dangling: $path"
       done

**Under a** ``.. module::``, **a hand-written** ``.. data::`` **or** ``.. function::``
**takes the bare name.** The module directive already supplies the prefix, so
``.. data:: pcapkit.x._T`` under ``.. module:: pcapkit.x`` registers
``pcapkit.x.pcapkit.x._T``, which no reference resolves to exactly. Where the object
lives in a module other than the current one, a ``:module:`` option names it, as the
``LINKTYPE`` entry on :doc:`/pcapkit/protocols/link/index` does. :issue:`1775` found
directives spelled the long way, which left TypeVar references ambiguous;
:file:`tests/project/test_docs_ambiguous_xrefs_1775_unit.py` fails on the next one.

**Every importable shipped module is documented, with one deliberate exception.** The
modules under :file:`pcapkit/protocols/*/NotImplemented/` are the set with no entry:
placeholder sources for dissectors nobody has written yet, carrying no class a reader
could use. The exception is a choice rather than a consequence of packaging, which is
worth stating because the opposite is easy to assume -- measured on ``1.5.0b8``, every one
is in the source distribution *and* in the wheel, and each imports as a
namespace-package submodule. What they are not is a *package*: none of those
directories carries an :file:`__init__.py`, so ``find_packages`` omits all of them.

When something is removed, its documentation entry goes with it -- carrying a
deprecation note where a user could have depended on the thing, and deleted outright
where it never shipped. The ``rarp`` entry above needed no note for that second reason.
Asked and ruled on :issue:`719`.

Version Directives
~~~~~~~~~~~~~~~~~~

**One** ``versionadded`` **per version in a docstring or prose block.** Directives of
the same version there merge into one. **A body that only names the thing added and
cites its issue or pull request is dropped**, leaving the bare tag: the summary above
already names the thing, so the body adds nothing. A body with content of its own
stays, such as a move (*Moved here from* ...), a rename or a takeover. Ruled on
:issue:`2530`.

Format and Mechanics
~~~~~~~~~~~~~~~~~~~~

*  **reStructuredText under** :file:`docs/source/`, **Markdown outside it.** The owner
   ruled this on :issue:`719`, correcting a blanket *always* ``.rst`` that had been in
   circulation: the Sphinx documentation is reST, and the other documents --
   the READMEs included -- are Markdown where that applies. ``CONTRIBUTING.md``'s own
   *Documentation* section records the same split. The ``global-include`` in
   :file:`MANIFEST.in` does not reach Markdown, so the READMEs under :file:`examples/`
   ship through ``recursive-include examples *.md``, and any other Markdown file
   ships only if setuptools or an ``include`` line adds it.
*  **Cite an issue or a pull request by role wherever Sphinx renders the text.** In an
   ``.rst`` page, a docstring or a ``#:`` doc-comment an issue is ``:issue:`NNN``` and
   a pull request ``:pr:`NNN```, by what the number is rather than what a URL says: a
   bare ``#NNN`` there renders as plain text, and a hand-written link to the tracker
   hides which of the two it names. A plain ``#`` comment, a workflow's YAML comment,
   :file:`tests/` and any other file nothing renders keep ``#NNN``, which GitHub links
   itself. A link into another repository or to a Discussion keeps its URL, and
   ``GH-NNN`` is a deliberate issue form. Ruled on :issue:`1103`;
   :file:`tests/project/test_docs_issue_pr_roles_1103_unit.py` fails on a bare number
   or a hand-written link in rendered text, and
   :file:`tests/project/test_issue_refs_in_comments.py` on a role in a plain comment.
*  **Prose names the real defining module, not a re-export.** One strand of the
   consistency sweep on :doc:`the roadmap </contributing/pep>`. The sentinels are the
   worked example: every one is defined in :mod:`pcapkit.corekit.sentinels`, and
   :ref:`sentinel-convention`'s table names it rather than any of the modules that
   use them, which do not re-export them (:issue:`1744`).
*  **A verbatim upstream port is exempt from these conventions.**
   :ref:`sentinel-convention` carries the reason: the value of a
   vendored copy is that it can still be diffed against upstream, and a house-style
   rewrite destroys that in exchange for nothing a reader ever sees.
