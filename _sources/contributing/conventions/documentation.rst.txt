.. _documentation:

Writing the Documentation
-------------------------

The pages before this one rule on library code and on running the repository. This
one rules on the documentation itself -- how a page is titled, when a diagram beats a
paragraph, and what a sentence on it is allowed to claim. It governs the
reStructuredText under :file:`docs/source/` and the :mod:`pcapkit` docstrings the API
reference renders from, since the owner named both when settling the first of these.

Nearly all of it was settled on
`#719 <https://github.com/JarryShaw/PyPCAPKit/issues/719>`__, the prose sweep, whose
thread was the only place most of it lived. As on :ref:`process`, every ruling here is
**paraphrased rather than quoted**, on the owner's standing instruction there; the
issue named beside a rule is where the original wording is.

Heading Case and Shape
~~~~~~~~~~~~~~~~~~~~~~

**Title Case, and short.** Sentence case belongs only to a heading that genuinely is a
sentence -- a how-to question is the example the owner gave -- and that was ruled rare:
a sentence should generally not be used as a title at all. Settled on #719.

Title Case here is the conventional kind rather than every-word capitalisation. The
short function words ``a``, ``an``, ``the``, ``and``, ``or``, ``of``, ``in``, ``for``
and ``to`` stay lowercase unless they lead, which was the reading put to the owner on
#719 and left standing. It is also what the tree does: *The* ``all`` *Extra* and
*Issue and Pull Request Labels* on :ref:`process` are both in it.

**The casing is the easy half.** A heading can be in Title Case already and still
break the rule by being a clause rather than a title. The sweep of
:file:`docs/source/contributing/` under this ruling found, of 62 headings, 24 already
right, 16 needing only re-casing, and **22 to be rewritten**. *What a Failed Lookup
Raises* was correctly cased and is now *Failed-Lookup Exceptions*.

The line that sweep drew, and the one to keep drawing: a **finite verb** makes
a heading a sentence and earns a rewrite, while a gerund or infinitive phrase is a
noun phrase and needs only re-casing -- so *Running the tests* became *Running the
Tests* rather than being reworded.

.. note::

   A heading also has to describe the section beneath it, and a rewrite is the moment
   to check that. Two of that sweep's own new titles were renamed again in review for
   failing it. *One Approval, Whole Release* became *The Release Pipeline* because the
   section opens on a Mermaid flowchart while the approval prose it had been named for
   sat well below, leaving the page's most navigable artefact unfindable from the table
   of contents.

Renaming a Heading
~~~~~~~~~~~~~~~~~~

Two mechanical traps, both of which bit on that sweep rather than being hypothetical.

**Re-measure the underline against the new text.** A case flip usually keeps the
length; a rewrite almost never does, and docutils reports an underline shorter than
its heading in a build that does not fail on warnings. The sweep re-checked all 62 and
found none short, which is the standard to hold.

**A heading is a link target, so a rename is a repository-wide sweep** rather than a
:file:`docs/source/` one. In scope: ``.rst`` prose, ``:ref:`` and ``:doc:`` link text,
toctree entries, implicit ``` `Text`_ ``` references, **and** :mod:`pcapkit`
docstrings and the files under :file:`tests/`. The first pass reported one
surviving stale reference; review found **five**, spread across
:file:`pcapkit/corekit/sentinels.py`,
:file:`tests/corekit/test_sentinel_exports_unit.py` and
:file:`tests/project/test_conventions_doc_claims.py`. The first of those is a shipped
module docstring that renders into the API reference, so a reader following it
searches the page for a string no longer on it.

.. warning::

   **Derive the list of old headings from the pre-change file, not from the diff.** A
   diff-derived list silently drops any heading whose underline is not adjacent in the
   hunk, which is why the second pass undercounted as well as the first. What
   worked was a whitespace-flattened search for every pre-change heading string across
   every tracked file.

Nothing in CI catches a reference a rename left behind. :file:`docs/source/conf.py`
sets no ``nitpicky`` and :file:`docs/Makefile` leaves ``SPHINXOPTS`` empty, so the
build runs with neither ``-n`` nor ``-W``: a dead reference renders as the plain text
it used to be, and the build still succeeds. ``#934`` found sixteen of them at once
that way.

One thing a rename breaks that no tool checks at all is the prose around it. Turning a
singular heading plural cost :ref:`registry-protocol` the antecedent of a following
*"it"*, caught in the same review.

Mermaid for Flows
~~~~~~~~~~~~~~~~~

Where the subject is a flow, prefer a Mermaid graph to the paragraph or the ASCII
diagram that would otherwise carry it -- a graph is read faster than its own
description. The owner ruled this on #719, asking for it where it is necessary and
helpful, which bounds it in three directions:

*  **A short sequence does not earn a graph.** Two steps read perfectly well as a
   sentence, and a diagram of them costs a reader a context switch for nothing.
*  **A rationale stays prose.** A diagram carries structure and sequence; it cannot
   carry *why* a choice was made, and that reasoning is what #719 protects rather than
   compresses.
*  **Do not redraw a graph another page already has.** The owner's condition when
   approving the navigation work on #719 was that nothing duplicate information already
   shown, and a second copy of a flow is exactly that.

The style model is the set already in the tree, every one of which builds. The sweep
excludes this page, which writes the directive name three times in its own prose and
would otherwise inflate both counts:

.. code-block:: shell

   grep -rn 'mermaid::' docs/source --include='*.rst' \
        --exclude='documentation.rst' | wc -l   # 12 directives
   grep -rl 'mermaid::' docs/source --include='*.rst' \
        --exclude='documentation.rst' | wc -l   # on 11 pages

All twelve are a bare ``.. mermaid::`` carrying no directive options, and all twelve
are a ``flowchart``: ``TD`` where the subject is a sequence or a decision, ``LR`` for a
type hierarchy. **Quote a node label whose text Mermaid would otherwise try to parse**,
and leave a bare identifier bare. That is what the exemplars do with *node* labels, and
it falls close to the ``TD``/``LR`` line without following it: every node label in the
six ``TD`` graphs is quoted, since every one of them is prose; the ``LR`` graphs quote
only where the text forces it, which today is ``h1["HTTP/1.*"]`` and ``h2["HTTP/2"]`` in
:file:`docs/source/pcapkit/protocols/index.rst` and nowhere else. Everything else there
uses the bare ``A{{Meta}}``, ``B(Base)``, ``D([user customisation ...])`` and
``subgraph name [Title]`` forms, and spends its quotes on ``click`` targets instead.
**Edge labels follow no rule at all.** The exemplars quote some and leave others bare,
including ``|workflow_run: completed|`` and ``|02:00|``, which the reason above would
have quoted and which Mermaid accepts anyway -- so match the graph being edited rather
than this paragraph. Inside a quoted label, ``<br/>`` breaks the text across lines and a
literal ``<`` or ``>`` is written ``&lt;`` or ``&gt;``.
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
package index would be invisible on every page but one. The three in
:file:`docs/source/index.rst` carry captions, and ``Subpackages`` in
:file:`docs/source/pcapkit/index.rst` is the single nested one. A built tree says so --
excluding this page, which names both captions in its own prose and would otherwise
count itself:

.. code-block:: shell

   grep -rl 'API Reference' --include='*.html' --exclude='documentation.html' \
        docs/build/html | wc -l   # every other page
   grep -rl 'Subpackages'   --include='*.html' --exclude='documentation.html' \
        docs/build/html | wc -l   # exactly one

That is why those root toctrees are ``:hidden:``. Without it each of the three
captions rendered twice on the root page -- once inline in the body, once in the
sidebar -- which is the duplication the owner ruled out on #719.

.. note::

   For the same reason, do not add an inline ``.. contents::`` to a page. The ``furo``
   theme already renders a sticky page-local table of contents on every page, so an
   inline directive is a second copy of it; the one in :file:`docs/source/index.rst`
   has been commented out since 2023 and should stay that way.

   One setting there was decided by measurement rather than by preference:
   ``toc_object_entries`` carries, in a comment beside it, the figures that settled it,
   so that nobody reopens the question blind. That is worth copying the
   next time a setting is chosen that way, but it is a single precedent and not yet a
   rule the owner has ruled on.

Paraphrasing a Ruling
~~~~~~~~~~~~~~~~~~~~~

Write a ruling down in your own words. **Do not quote the owner verbatim** -- a
standing instruction on #719, and the one every page in this directory follows.
``#949`` went back over the five pages that then existed and replaced their quoted
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
number. Ruled on #719, and the reason every citation on this page is an issue.

Accuracy
~~~~~~~~

**Verify a claim against the code it describes, never against another document.** Where
prose and code disagree the code wins and the prose is what gets fixed -- #719's own
charter -- and a docstring outliving the thing it described is a demonstrated failure
mode here rather than a hypothetical one.

**Re-derive a count; do not copy one.** Better still, write down the command that
produces it, as :ref:`process` does, so the figure can be rechecked rather than
trusted. A keyword search is not a sweep: the method the changelog review settled takes
every cited repository path in each of the forms it gets written in -- slash path,
dotted module, bare filename, and the elided spellings -- intersects them with the
diff since the merge base, and re-measures the intersection. A tense-keyword grep
misses a claim phrased as a fraction of a total.

**Treat** ``every``, ``all``, ``each`` **and** ``none`` **as a claim about members, and
check the members one at a time.** Several of #719's findings were of exactly that
shape:

*  A sweep asserted that every ``.. module::`` target in the documentation resolved.
   One did not: :file:`docs/source/pcapkit/protocols/link/rarp.rst` declared
   ``pcapkit.protocols.data.link.rarp``, which has never existed, because RARP and
   DRARP reuse ARP's data class. Fixed in ``68fbccd90``.
*  ``#911``'s ruling -- export the sentinel objects and leave their types out -- was
   read as describing all three modules that then held a sentinel. One ran the other
   way: :mod:`pcapkit.corekit.fields.field` exported neither, so applying the rule
   there meant *adding* a name rather than removing one.

**Some numbers on these pages are pinned, and knowing which is part of writing one.**
:file:`tests/project/test_conventions_doc_claims.py` re-derives figures for the three
pages that have a figure test of their own -- ``extension-header-subclassing``,
``process`` and ``registry-protocol``, the last most heavily of all, down to both halves
of an *N of M* -- so a stale count there goes red instead of quiet. Every other figure,
this page's included, is pinned by nothing: the entry it adds to that module's
``ANCHORS`` fixes the page's existence, anchor and toctree position, not its arithmetic.
Re-derive before trusting, and do not read a number as load-bearing just because it is
written down. The same module checks something a reader cannot see and Sphinx cannot
warn about: in a ``` `#NNN <.../NNN>`__ ``` link the displayed number has to match the
number in its own URL. A review round once corrupted roughly thirty of them across two
pages and nothing caught it, because both halves were well-formed.

Resolvable Targets
~~~~~~~~~~~~~~~~~~

**A** ``.. module::`` **target must name a file on disk.** A dangling one is worse than
no directive at all: it registers a module-index entry for a module that does not
exist, and gives cross-references a target that resolves to nothing. The sweep that
settled this on #719 found exactly one, and repeating it is cheap:

.. code-block:: shell

   grep -rhE '^\.\. +(py:)?(module|currentmodule):: ' docs/source --include='*.rst' \
        --exclude='documentation.rst' |
       awk '{print $NF}' | sort -u | tr '.' '/' |
       while read -r path; do
           [ -f "$path.py" ] || [ -f "$path/__init__.py" ] || echo "dangling: $path"
       done

**Every importable shipped module is documented, with one deliberate exception.** The 33
modules under :file:`pcapkit/protocols/*/NotImplemented/` are the set with no entry:
placeholder sources for dissectors nobody has written yet, carrying no class a reader
could use. The exception is a choice rather than a consequence of packaging, which is
worth stating because the opposite is easy to assume -- measured on ``1.5.0b8``, all 33
are in the source distribution *and* in the wheel, and each imports as a
namespace-package submodule. What they are not is a *package*: none of the four
directories carries an :file:`__init__.py`, so ``find_packages`` returns 73 here and
omits all of them.

When something is removed, its documentation entry goes with it -- carrying a
deprecation note where a user could have depended on the thing, and deleted outright
where it never shipped. The ``rarp`` entry above needed no note for that second reason.
Asked and ruled on #719.

Format and Mechanics
~~~~~~~~~~~~~~~~~~~~

*  **reStructuredText under** :file:`docs/source/`, **Markdown outside it.** The owner
   ruled this on #719, correcting a blanket *always* ``.rst`` that had been in
   circulation until then: the Sphinx documentation is reST, and the other documents --
   the READMEs included -- are Markdown where that applies. ``CONTRIBUTING.md``'s own
   *Documentation* section records the same split. One trap arrived with the ruling:
   :file:`MANIFEST.in` reaches the two READMEs under :file:`examples/` through
   ``global-include *.rst`` and has no ``*.md`` equivalent, so renaming one without
   adding coverage drops it from every source distribution.
*  **Prose names the real defining module, not a re-export.** One strand of the
   consistency sweep on :doc:`the roadmap </contributing/pep>`. The sentinels are the
   worked example: all four are defined in :mod:`pcapkit.corekit.sentinels` and
   re-exported by the modules that use them, and :ref:`sentinel-convention`'s table
   names the defining module rather than any of the re-exports.
*  **A verbatim upstream port is exempt from these conventions.**
   :ref:`sentinel-convention` already carries the case that settled it, the
   ``cached_property`` backport in :file:`pcapkit/utilities/compat.py`: the value of a
   vendored copy is that it can still be diffed against upstream, and a house-style
   rewrite destroys that in exchange for nothing a reader ever sees.
