.. _maintenance-workflow:

Maintenance Workflow
====================

.. important::

   Between releases the repository is maintained by a **coordinator** session: it
   watches the board on a schedule, dispatches agents to do the work, verifies what
   they return, and is the only thing that writes to GitHub. This page is that loop
   written down -- as a brief another agent can take over, and as a record of what
   the owner has established. What the labels mean is on :ref:`process`, how CI is
   wired on :doc:`workflows`, and the release itself on :doc:`releasing`; this page
   links to them rather than restating them.

Actors and Roles
----------------

.. mermaid::

   ---
   config:
     flowchart:
       curve: monotoneX
       nodeSpacing: 10
       wrappingWidth: 150
   ---
   flowchart TD
       OWNER["Owner<br/>rules and merges"]
       GH["GitHub<br/>issues, pull requests, labels"]
       COORD["Coordinator<br/>main thread"]
       WORKER["Worker<br/>one issue, one worktree"]
       REVIEW["Reviewer<br/>another model, read-only"]
       CI["GitHub Actions"]
       NOTES["Private notes store"]

       OWNER -->|"comments, merges"| GH
       GH -->|"every channel, every tick"| COORD
       COORD -->|"brief"| WORKER
       WORKER -->|"one local commit, report"| COORD
       COORD -->|"head sha, claims to test"| REVIEW
       REVIEW -->|"verdict"| COORD
       COORD -->|"push, pull request, comments, labels"| GH
       GH -->|"push and pull request events"| CI
       CI -->|"check runs, reports"| GH
       COORD -->|"checkpoint"| NOTES
       CI ~~~ COORD
       WORKER ~~~ NOTES

.. list-table::
   :header-rows: 1
   :widths: 14 46 40

   * - Actor
     - Responsible for
     - Never
   * - Owner
     - Rulings and merges, given in GitHub comments on the issue or pull request.
       Merges, tags and releases are the owner's alone.
     - Asked to decide in the session: a question goes on the item it concerns.
   * - Coordinator
     - The session's main thread. Runs the loops below, dispatches, verifies every
       agent claim before it goes public, and **alone** commits, pushes, opens pull
       requests, posts comments and sets labels.
     - Does the hands-on work itself -- edits, test runs and investigations go to
       agents -- or merges, tags or releases.
   * - Worker
     - One issue, in its own isolated worktree, ending in one local commit and a
       report.
     - Pushes, posts, labels, writes to the notes store, edits the changelog, or
       spawns agents of its own.
   * - Reviewer
     - A cross-review of one head on a model other than the author's, read-only,
       inside a time budget, returning a verdict.
     - Edits, commits or posts.
   * - CI
     - The workflows on :doc:`workflows`, read at job level.
     - Settles readiness by itself: green is necessary, not sufficient.

**One GitHub account posts everything.** The coordinator posts under the owner's
login, so a comment from that account may be the coordinator's rather than the
owner's, and an agent reading a thread cannot tell them apart. Every brief says so,
and says that the coordinator sets the labels by hand, so that no agent reads them as
automation. The coordinator itself tells the two apart by the ids of its own posts,
which the post gate records (`Helper Scripts`_).

The Recurring Loops
-------------------

Each loop is a scheduled prompt that only points at a policy file, so the file is what
gets edited. The scheduler expires a recurring job after seven days without notice,
which once left the owner's answers unread; the sweep therefore checks that every loop
is scheduled and re-creates a missing one from its file.

.. list-table::
   :header-rows: 1
   :widths: 14 9 33 20 24

   * - Loop
     - Cadence
     - Reads
     - Gated by
     - Writes
   * - Decision watch
     - 3 min
     - comments past the watermark; the last human comment of every open
       ``needs: decision`` item and pull request; inline review comments and review
       bodies
     - the post gate
     - reconciliation comments, state-label swaps, dispatches
   * - Board sweep
     - 13 min
     - the same channels, then every open and closed item's labels, heads,
       mergeability, file lists and check runs; ``main``'s CI; the CI reports; the
       Actions queue; host load
     - the post gate, the queue thresholds, the host guard
     - pushes, pull requests, labels, verdicts, rebase notes, dispatches, cancelled
       runs, pruned worktrees
   * - Notes checkpoint
     - 17 min
     - what changed since the last checkpoint
     - nothing new, nothing written
     - one append to a private notes store

.. mermaid::

   ---
   config:
     sequence:
       wrap: true
       width: 110
       actorMargin: 15
   ---
   sequenceDiagram
       participant S as Scheduler
       participant C as Coordinator
       participant G as GitHub
       participant A as Agents
       participant N as Notes store
       par Decision watch, every 3 min
           S->>C: tick
           C->>G: read past the watermark, and every open decision item
           G-->>C: rulings, questions, or nothing
           C->>G: gated reconciliation and label swap
           C->>A: dispatch what a ruling unblocks
       and Board sweep, every 13 min
           S->>C: tick
           C->>G: enumerate items, check runs, queue depth
           A-->>C: finished commits and verdicts
           C->>G: push, open, label, post verdicts within the thresholds
           C->>A: a worker per idle issue, a reviewer per unreviewed head
       and Notes checkpoint, every 17 min
           S->>C: tick
           C->>N: append what changed, or write nothing
       end

**Every tick runs its reads before it reports.** A report of *nothing changed* is
honest only once that tick's enumeration has returned; ticks answered from memory once
hid a run of merges and a conflicting pull request until the owner asked. A tick never
says it *will* dispatch: it dispatches, or says it did not.

Decision Watch
~~~~~~~~~~~~~~

#. **Read past the watermark**, which is a comment id rather than a timestamp: comment
   timestamps went non-monotonic across a daylight-saving change, and a time cutoff
   hid new comments. The watermark only ever advances to the highest id a *read*
   returned, never to the id of a post just made, since a ruling can land between the
   read and the post.
#. **Read every open** ``needs: decision`` **item and every open pull request by
   number**, taking its last human comment, whatever the watermark says. A repo-wide
   newest-first read is buried by the coordinator's own bursts of posts; this read is
   what caught a ruling the watermark missed.
#. **Read the other channels.** Inline review comments and review bodies have their
   own endpoints, and a comment in an unsubmitted review is visible only through
   GraphQL. Read each inline comment's body, not its count, including on a pull
   request merged since the last tick. A comment from GitHub's Copilot bot, or the
   owner asking it for something, is a channel event too.
#. **On a ruling or a new question**, run `The Decision Loop`_. If nothing arrived,
   change nothing and say which items are still waiting.

Board Sweep
~~~~~~~~~~~

#. **Read every channel first**, as the decision watch does.
#. **Enumerate, never remember.** List the open issues and pull requests every tick,
   with ``state`` and ``mergedAt`` -- the mergeability fields never say *merged* -- even
   while one pull request is absorbing the attention; a remembered list once reported
   merged pull requests as open for hours.
#. **Labels.** Every open issue carries one state label (:ref:`process`); an issue
   with none is a gap to close. Re-check each ``blocked`` issue's condition, and on the
   tick it clears swap the label and dispatch. Strip state and ``review:`` labels from
   closed items, issues and pull requests both, by name -- a bare label ``DELETE``
   removes every label -- reading them back from the item rather than from the search
   index, which lags. Milestones are left to their automation, never set by hand.
#. **Prune spent worktrees** (`Worktree Cleanup`_).
#. **Lead the report with what is ready to merge**: ``review: good-to-go`` at the
   current head, every required check run completed, none failed. Experimental legs
   count against neither condition; a :ref:`KTLO <ktlo-tier>` leg is left out of the
   tally, but its failing test ids are diffed against ``main``'s, because the leg can
   read green while its tests fail. Re-read the checks once they complete: a verdict
   given while CI ran says nothing about how it ended.
#. **Dispatch to fill every gap**: a reviewer for each pull request at
   ``review: pending`` on its head, a worker for each ``pending`` issue, with the
   label moved in the same pass, and a fix worker for each ``review: good-to-go`` pull
   request whose required check went red. Holds: `Throttles and Guards`_.
#. **Run every failed check down to its root cause**, from the job's log and its
   failing step, never reporting a bare red mark. A timeout kill and a lost runner
   both read *the operation was canceled*; compare the job's duration against its cap
   across several runs before deciding which.
#. **Watch** ``main`` (`The Post-Merge Routine and the Main-CI Watch`_).
#. **Keep the loops scheduled**, re-creating any that expired.
#. **Rebase every conflicting pull request unasked**, and post a rebase note: old and
   new heads, whether the patch id is unchanged, the CI tally on the old head, and the
   verdict -- which stands when the patch is unchanged and is reset to
   ``review: pending``, with a re-review dispatched, when it is not. A stacked child
   moves with ``git rebase --onto <new-parent> <old-parent-sha>``, checked with
   ``git patch-id --stable`` and ``git range-diff``. ``UNKNOWN`` mergeability is not
   an answer; query again until it settles.
#. **Keep the changelog central**: a pull request whose file list touches the
   changelog gets a strip commit, and the text moves to the central changelog pull
   request.
#. **Read the CI reports** (:ref:`CI Reports`): each warning or failure there is a
   possible defect, root-caused and filed like a red check.

Notes Checkpoint
~~~~~~~~~~~~~~~~

The coordinator is the store's only writer; no agent touches it. A checkpoint records
what is expensive to rediscover -- pull requests with their head shas, rulings
paraphrased, every refuted claim including the coordinator's own, and the open threads
with what each live agent is doing -- not a transcript. It makes at most one append per
tick. A failed append goes to a local backlog and bumps a failure streak; after ten
failures in a row the coordinator opens a continuation note and repoints the loop at
it. A write that errors may still have committed, so the note is searched for the
heading just written before anything is retried.

Label State Machines
--------------------

The meanings, and the one legal pair of state labels, are on :ref:`process`; these
are the moves the loops make.

.. mermaid::

   stateDiagram-v2
       direction TB
       state "pending" as P
       state "wip" as W
       state "blocked" as B
       state "needs: decision" as D
       [*] --> P : filed, nothing blocks it
       [*] --> B : filed behind other work
       P --> W : worker dispatched
       W --> P : work abandoned, issue open
       P --> B : deferred behind a checkable condition
       B --> W : condition cleared, worker dispatched
       B --> P : condition cleared, nobody dispatched
       P --> D : question posted for the owner
       D --> W : ruled, work dispatched
       D --> P : ruled, accepted, unstarted
       D --> B : ruled, deferred
       W --> [*] : covering pull request merged, issue closed

A merged pull request closes only the issue its own ``Closes`` keyword names, one
keyword per issue, so every ``wip`` issue is checked against its pull request's state
and closed by hand where the keyword did not.

``review: good-to-go`` goes on when the verdict lands; the CI gate belongs to
reporting the pull request as ready.

.. mermaid::

   stateDiagram-v2
       direction TB
       state "review: pending" as RP
       state "review: running" as RR
       state "review: good-to-go" as RG
       state "review: needs-changes" as RN
       [*] --> RR : opened with its review dispatched
       [*] --> RP : opened without one
       RP --> RR : reviewer dispatched on this head
       RR --> RG : GOOD TO GO
       RR --> RN : NEEDS CHANGES
       RR --> RP : head moved mid-review
       RN --> RP : fix round pushed
       RG --> RP : new head, patch changed
       RG --> [*] : owner merges

The Pull Request Lifecycle
--------------------------

.. mermaid::

   flowchart TD
       I["Issue labelled pending"] --> D["Dispatch a worker<br/>issue becomes wip"]
       D --> W["Worker: one commit in its own worktree,<br/>new tests, a report"]
       W --> V{"Coordinator verifies the diff and the tests;<br/>do the new tests fail with pcapkit/ reverted?"}
       V -->|no| W
       V -->|yes| K{"Pure tests or docs,<br/>no call for the owner's eyes?"}
       K -->|yes| MAIN["Push straight to main,<br/>close the issue"]
       K -->|no| Q{"Actions queue under 20?"}
       Q -->|no| H["Hold, and say so on the issue"] --> Q
       Q -->|yes| P["Push and open the pull request:<br/>repository template, type label, Closes keyword"]
       P --> R["Cross-review on another model<br/>review: running"]
       P --> CI["CI runs"]
       R --> VD{"Verdict"}
       VD -->|NEEDS CHANGES| NC["One-line verdict, review: needs-changes,<br/>the pull request's CI runs cancelled"]
       NC --> FX["The original worker amends<br/>in its kept worktree"]
       FX --> PU["Verified, then pushed at queue under 40<br/>review: pending"]
       PU --> R
       VD -->|GOOD TO GO| GG["One-line verdict<br/>review: good-to-go"]
       GG --> RDY{"Required checks completed green,<br/>no test failing that main passes?"}
       CI --> RDY
       RDY -->|no| FX
       RDY -->|yes| M["Reported ready; the owner merges"]
       M --> PM["Post-merge routine"]

The steps that the graph compresses:

*  **Verifying a worker** means reading its diff with three dots against the merge
   base, re-running its tests from inside its tree, and taking the fix out of
   :file:`pcapkit/` to watch the new tests fail, as :ref:`test-coverage` asks. The
   coordinator commits from a tree of its own, never inside a live agent's worktree.
*  **The pull request** follows :file:`.github/PULL_REQUEST_TEMPLATE.md`, ticking only
   what holds: the changelog box is left unticked with a note that the changelog is
   central. It carries its type label from creation (:ref:`process`). Comments of 8
   lines or fewer and bodies of 15 or fewer are recommendations, not hard limits.
*  **A push to an existing branch** uses
   ``--force-with-lease=<branch>:<last-pushed-sha>``.
*  **The verdict** is posted as its own one-line comment -- the verdict, the head sha
   it covers, the one thing most worth knowing -- with the review's detail as an
   appendix. A verdict superseded by a new head is said to be, so a stale one never
   reads as current. A reviewer's correction of an earlier number is itself a claim,
   re-derived before it is relayed.
*  **A green, conflict-free pull request can still break** ``main``: after a merge
   wave, merge it into the current ``main`` in a scratch tree and run the affected
   tests before calling it ready.
*  **Findings on an unmerged pull request go back to its original worker**, which
   still holds the context, rather than to a new issue; a separate issue is for a
   pull request already merged or a concern genuinely apart from it.

The Decision Loop
-----------------

**The loop never blocks on the owner.** A question is posted on the issue or pull
request it concerns -- never asked in the session -- and the work that does not depend
on it carries on.

.. mermaid::

   ---
   config:
     sequence:
       wrap: true
       width: 110
       actorMargin: 15
   ---
   sequenceDiagram
       participant C as Coordinator
       participant G as Issue or pull request
       participant O as Owner
       participant A as Agents
       C->>G: what needs deciding, one line per option, a recommendation and its reason
       C->>G: label needs: decision
       Note over C,A: work that does not wait on the answer carries on
       O->>G: ruling, often one line
       loop every decision watch tick
           C->>G: read past the watermark, and this item's last human comment
       end
       G-->>C: a human comment newer than the coordinator's last reply
       C->>G: re-read the channels and abort on anything new
       C->>G: paraphrase the ruling and reconcile it against the current state
       C->>G: swap the label for pending, wip or blocked
       C->>A: dispatch the work

*  **The question stands alone**: what needs deciding, the options, and the
   recommendation, on the same item that carries the label -- a question posted on a
   pull request while its issue holds the label once left the owner asking what was
   wanted.
*  **A one-line ruling is not tentative.** It is unambiguous only when one proposal is
   in play, though; with two, name both, recommend one and ask which.
*  **Re-read the channels in the same call as any post**, and abort the post on
   anything new. The gap between reading and posting is where the coordinator posted
   over the owner's fresh comment, more than once; the post gate closes it in code
   rather than by care.
*  **Record a ruling paraphrased, never quoted** -- the rule on
   :ref:`documentation` -- and reconcile it on the item: what it answers, what it
   leaves open, what it changes. A partial answer gets the open part restated with
   its options.
*  **A ruling given in the session is recorded in the same turn**: in the loop's policy
   file, in the notes, in the standing rules when it is one, and on the item it
   concerns, with the work dispatched. Acknowledging it in chat does none of these. A
   ruling that settles a convention is written onto its conventions page in the same
   change that implements it.

The Post-Merge Routine and the Main-CI Watch
--------------------------------------------

After every merge the sweep runs, in order:

#. **Labels**: strip the merged pull request's labels and settle its issues' -- close
   any its keyword did not, unblock any whose condition was this merge.
#. **Superseded runs on** ``main``: cancel the queued and running push runs of Unit
   Tests, Python Compatibility, CodeQL and Experimental Tests on every ``main`` sha
   older than the head, whose results the head makes moot. The head is read afresh
   inside the cancelling script -- a stale local ``origin/main`` once cancelled the
   real head's runs -- and when the head is docs-only, the newest code-changing
   commit keeps its runs. **Never cancelled**: Create Release, Project Status,
   Milestone, CI Reports, any scheduled run, and the head's own runs.
#. **The latest-tier sweeps, locally**: the project modules that only CI's
   ``latest`` leg runs (Test Tiers on :doc:`workflows`) are run on a scratch tree of
   the new ``main``, because a merge wave supersedes ``main``'s runs before they
   finish.
#. **Rebases**: a pull request the merge made conflicting is rebased and noted, as in
   the sweep. One that is only behind is left alone: ``main``'s ruleset requires
   branches to be up to date, every push to ``main`` puts every open pull request
   behind, and the owner merges through the bypass.
#. **The changelog fold**: feature pull requests carry no changelog edits, and their
   entries are written centrally (:issue:`2449`), into the changelog pull request --
   the only stream that edits those files, which merges last in the cycle.
#. **Worktrees**: the merged pull request's worktrees become prunable.

On a pull request no run is cancelled: a cancelled run leaves a red mark on its
commit that reads as a failure, which is why the owner ruled out cancelling
superseded runs on :issue:`2243`. A ``review: needs-changes`` head is the exception --
every run on it is cancelled except the board-sync ones, Project Status and Milestone,
since that head is going to be replaced. Experimental Tests lets a newer commit
supersede its run, which it skips or stops rather than cancels (:doc:`workflows`).

.. mermaid::

   flowchart TD
       S["Each sweep and each merge:<br/>main's push runs, read per job"] --> F{"A check run on main<br/>ended other than success?"}
       F -->|no| OK["Nothing to do"]
       F -->|yes| X{"Only cancelled runs<br/>of superseded commits?"}
       X -->|yes| OK
       X -->|no| RC["Root-cause it this tick"]
       RC --> T["Fix verified: the failing module passes locally"]
       T --> FIX["Pushed straight to main,<br/>with no queue threshold"]

**Read** ``main`` **at job level.** A run stays queued while one job waits, even with a
job already failed. A non-blocking leg's red check is a defect as well: such a leg may
only warn and end green, so a step that can lose its runner is contained -- capped,
bounded, timed out -- rather than excused.

**What may go straight to** ``main``. A fix for a red ``main``, whatever it touches. A
change that is purely tests or docs, unless it needs the owner's eyes -- a
conventions-page rule, the changelog, or a page that codifies process, like this one,
goes through a pull request. Code always gets a pull request. Before a direct push,
check that no open pull request edits the same hunk.

Throttles and Guards
--------------------

.. list-table::
   :header-rows: 1
   :widths: 22 30 48

   * - Guard
     - Threshold
     - Applies to
   * - Actions queue
     - queued runs < 20
     - opening a new pull request; finishing the open ones comes first
   * -
     - queued runs < 40
     - a push to an existing pull request -- a fix round, a rebase, a changelog fold --
       and filing issues, in batches of about ten, since each issue starts board and
       milestone runs
   * -
     - none
     - a fix for a red ``main``
   * - Host load
     - OK, TIGHT or CRITICAL, from load against cores, free memory and disk
     - TIGHT staggers or shrinks a dispatch wave; CRITICAL holds it
   * - Review budget
     - about 25 min
     - a reviewer: at the budget it is asked for its verdict at once, and an unfinished
       check comes back ``UNVERIFIED``
   * - File size
     - ``RLIMIT_FSIZE`` of about 2 GiB, soft only (hard limit unlimited)
     - every local test run -- some project modules raise the limit themselves, which
       a hard cap breaks. CI has its own (File Size Caps on :doc:`workflows`)
   * - Probe memory
     - ``RLIMIT_AS`` of 6 GiB
     - an ad hoc probe script, whose every loop over layers or payloads is bounded
   * - Test scope
     - one module per process
     - every local run, never the whole suite (:ref:`test-coverage`)
   * - Processes
     - a known pid only
     - never kill by pattern

**A held push or dispatch is commented on the item it concerns**, and retried first on
the next tick rather than dropped.

Worktree Cleanup
~~~~~~~~~~~~~~~~

Worktrees accumulate fast, and a wrong prune destroys work silently, so the prune is
conservative:

*  **Scope**: only the directory agent worktrees live in -- never the scratch trees
   elsewhere, which hold reviewers' baselines and the coordinator's landing trees.
*  **Keep** a locked tree; a live agent's; one touched in the last 3 hours; one on an
   open pull request's branch, so its agent can be resumed for the next round; one
   with uncommitted tracked edits not already on ``main``; one with commits no merged
   pull request carries.
*  **Remove** a clean tree whose head is, or is an earlier round of, a merged pull
   request's head, and a tree whose every commit is upstream. Save its diff first, and
   never force past a lock: the lock is the signal.
*  **Never commit inside a live agent's worktree**; copy its diff out to a tree of your
   own. A state change the agent did not make looks to it like a fault.

Briefs
------

**A worker brief carries**:

*  the conventions pages to read first, to follow over its own inference and to cite
   by name, with unsettled questions brought back as options and a recommendation;
*  an explicit base sha to branch from -- never ``origin/main`` by name, which sibling
   worktrees move -- and a sample regeneration in the fresh tree;
*  the issue, read in full and read-only;
*  the test recipe: one module per process, run from inside the worktree with
   ``pcapkit.__file__`` asserted to resolve there -- an editable install of the shared
   checkout otherwise wins -- under the soft file-size cap, plus the standing guard
   modules and a scratch revert of :file:`pcapkit/` proving each new test fails;
*  the rules: one local commit, its conventional subject ending ``(#N)``; no push,
   post, label, notes store or changelog edit; no sub-agents; no kill by pattern;
   labels are set by hand, and one login posts everything;
*  the parallel streams and the files each owns, which are off limits;
*  the prose budget -- the documentation rules apply to code comments too;
*  what to report: the sha, what changed and why, the tests that fail on the base,
   anything of doubtful scope, and every ``UNVERIFIED`` item.

**A reviewer brief carries**: the head sha and the tree to read, read-only; a model
other than the author's -- a worker run without a model override inherits the
coordinator's, so its reviewer names another; the load-bearing claims, ranked, with an
instruction to falsify rather than bless; the pull request's own diff as the thing
under review, not ``main``; the time budget; and a report that opens and closes with
``GOOD TO GO`` or ``NEEDS CHANGES`` at the sha, with each claim marked confirmed,
refuted or ``UNVERIFIED``.

**Treat an agent's report of an action as a finding.** Workers have posted, filed
issues and spawned agents despite their briefs; what such a worker did is verified and
owned by the coordinator, and the next brief repeats the rule.

Helper Scripts
--------------

These live on the coordinator's host, outside the repository. Each is small enough to
rebuild from its description.

Decision Watch Reader
~~~~~~~~~~~~~~~~~~~~~

*  **Input**: the watermark, a comment id.
*  Reads the repository's issue comments newest-first, a page of a hundred, and keeps
   those past the watermark. Each is tagged ``MINE`` if its id is in the own-post
   file, ``BOT`` if a bot or Copilot wrote it, and ``NEW`` otherwise.
*  Lists the open pull requests and the open ``needs: decision`` issues, and for each
   prints any comment past the watermark that is neither the coordinator's nor a bot's.
*  **Independently of the watermark**, prints ``NEW DECISION-OPEN`` for every decision
   item whose newest human comment is not the coordinator's.
*  Prints every open pull request's inline comments and non-empty review bodies.
*  **Output** ends with the highest comment id it read.

Post Gate
~~~~~~~~~

*  **Input**: the item number, a body file, and optionally the ids of comments already
   read and handled.
*  Runs the reader against the stored watermark in the same invocation, and **aborts
   with a non-zero exit** on any ``NEW`` line not acknowledged -- which includes
   ``NEW DECISION-OPEN``.
*  Otherwise posts the body from the file, appends the new comment's id to the
   own-post file, and moves the watermark to the highest id the *pre-post* read saw,
   never to its own post.
*  Every comment goes through it; nothing posts around it.

Sweep Enumerator
~~~~~~~~~~~~~~~~

One GraphQL query over the open pull requests -- number, head, mergeability, labels,
files, and the head's check runs -- and per pull request it prints:

*  ``fail``, the check runs that failed, timed out, were cancelled or failed at startup,
   and ``inc``, the ones not completed, both excluding experimental and KTLO-suffixed
   names; plus the ``Required checks passed`` conclusion;
*  any changelog path in its files, outside the central changelog pull request.

It counts only ``CheckRun`` contexts, since a status context can sit pending forever,
and keys ``inc`` on the status, since a running check reports an empty conclusion
rather than a null one. It goes on to list the inline comments, flag every open issue
whose state labels are not a single one or the legal pair, print the last comment of
every ``blocked``, ``needs: decision`` and ``pending`` issue, list closed items still
carrying state or ``review:`` labels, and print the queued and in-progress run counts.

Post-Merge Sweep Runner
~~~~~~~~~~~~~~~~~~~~~~~

*  **Input**: a scratch tree of the new ``main``.
*  Regenerates the sample captures if the tree lacks them, then runs a fixed list of
   latest-tier modules -- the RFC-constants, protocol-package, public-API, dead-helper,
   member-order, doc-claims, const-export and shared-context-variable guards, the
   schema and short-read round trips, and the dispatch registry and reachability
   checks -- each in its own process with a time limit and the file-size cap.
*  Asserts in each process that :mod:`pcapkit` imports from the scratch tree, and
   prints each module's summary line with its exit code. A red one is fixed and
   pushed straight to ``main``.

Worktree Pruner
~~~~~~~~~~~~~~~

*  Applies `Worktree Cleanup`_. Its inputs are the ids of live agents, the open pull
   requests' branches, and a map from every sha a merged pull request ever had -- its
   heads, its commits, both sides of each force-push -- to that pull request, since
   squash merges and amended heads leave an agent's own shas off ``main``.
*  A tree's commits count as landed when ``git cherry`` shows them upstream, or when
   every one maps to a merged pull request; its uncommitted edits count as landed when
   their diff reverse-applies to ``main``'s index.
*  Has a dry run that only classifies. A real run saves each tree's diff before the
   removal, never forces past a lock, runs ``git worktree prune``, and prints what it
   removed and what it kept, with the reason for each.

Bootstrapping a New Coordinator
-------------------------------

#. **Read** :doc:`conventions/index` and its pages, then :ref:`process`,
   :ref:`documentation`, :ref:`test-coverage`, :doc:`workflows`, :doc:`releasing`
   and this page.
#. **Tooling**: an authenticated ``gh`` with write access; the repository's virtual
   environment for tests, never installed into while agents use it; a separate one
   built from :file:`docs/requirements.txt` for any docs build; a scratch directory
   outside the repository.
#. **State**: initialise the watermark to the newest comment id, and an empty
   own-post file.
#. **Helpers**: write the scripts above, and dry-run the pruner.
#. **Policy files**: one per loop, plus the worker and reviewer brief templates, with
   the list of parallel streams in the worker's.
#. **Notes**: find the thread's note in the private store before opening a new one.
#. **Schedule** the loops at their cadences, note when each was created, and renew
   them before the seven days run out.
#. **Run the first sweep by hand**: enumerate, close the label gaps, give every open
   pull request a ``review:`` state, then dispatch in waves the queue and the host can
   take.
#. **From then on**, every in-session ruling is recorded in the same turn, and the goal
   of every tick is an empty issue board with every open pull request at
   ``review: good-to-go``.

Failure Modes and Their Guards
------------------------------

.. list-table::
   :header-rows: 1
   :widths: 55 45

   * - Failure
     - Guard
   * - Ticks answered from memory hid merges
     - reads first (`The Recurring Loops`_)
   * - A ruling sat under the coordinator's own posts
     - per-item read (`Decision Watch`_)
   * - A timestamp cutoff dropped comments
     - id watermark (`Decision Watch`_)
   * - A post landed over the owner's fresh comment
     - `Post Gate`_
   * - A remembered list kept merged pull requests open
     - enumeration (`Board Sweep`_)
   * - The loops expired silently
     - schedule check (`Board Sweep`_)
   * - A mid-CI verdict hid a red required leg
     - re-read completed checks (`Board Sweep`_)
   * - A KTLO leg read green over new failures
     - failing-id diff (`Board Sweep`_)
   * - A bare label ``DELETE`` removed every label
     - removal by name (`Board Sweep`_)
   * - ``Closes #a, #b`` closed one issue
     - one keyword per issue (`Label State Machines`_)
   * - A green pull request failed against the current ``main``
     - scratch merge (`The Pull Request Lifecycle`_)
   * - Cancelled board-sync runs left the board stale
     - never-cancelled list (`The Post-Merge Routine and the Main-CI Watch`_)
   * - A test filled the disk
     - file-size cap (`Throttles and Guards`_)
   * - Bulk issue filing flooded the Actions queue
     - queue thresholds (`Throttles and Guards`_)
   * - A held dispatch was dropped
     - commented holds (`Throttles and Guards`_)
   * - A prune selected live agents' trees
     - keep rules (`Worktree Cleanup`_)
   * - A measurement read the shared checkout
     - ``pcapkit.__file__`` assert (`Briefs`_)
   * - A cross-review likely ran on the author's model
     - another model (`Briefs`_)
   * - A worker posted and spawned on its own
     - the worker rules (`Briefs`_)
