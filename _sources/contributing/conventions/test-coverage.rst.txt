.. _test-coverage:

Testing a Change
----------------

The pages before this one rule on the library, the repository and the prose. This one
rules on what the test suite has to prove, and what a change has to bring to it. The
owner set the direction on :issue:`1203`, paraphrased here as on the other pages: every
round trip the library offers must pass and match exactly, the tests must cover all of
them, and the rules belong on a page rather than in review threads. :issue:`1202` tracks
extending round-trip coverage to the paths that do not have it yet.

Round-Trip Invariants
~~~~~~~~~~~~~~~~~~~~~

**A round trip either reproduces its input exactly or is a recorded defect.** There is
no tolerance in between: a cycle that comes back with different octets is a bug, even
when both halves are internally consistent.

Coverage is **enumerated from the registries rather than hand-picked**, so a code
registered tomorrow gets a case tomorrow. The two registry-driven suites that carry a
known-failure table keep their cases in a generator, beside the captures it also writes:

.. list-table::
   :header-rows: 1
   :widths: 34 30 36

   * - Suite
     - Cases from
     - Asserts
   * - :file:`tests/protocols/test_option_roundtrip_unit.py`
     - :file:`examples/generators/options.py`
     - every option, chunk, parameter, message, frame and block code survives construct
       -> parse -> construct with identical octets; known failures in
       ``EXPECTED_FAILURES``
   * - :file:`tests/protocols/test_dispatch_registry_unit.py`
     - :file:`examples/generators/dispatch.py`
     - every ``__proto__`` entry dispatches to the class ``PINNED_TARGETS`` names;
       known failures in ``KNOWN_DEGRADED`` (:issue:`496`)

The rules those tables carry:

*  **Every registered code has a case.** ``test_every_registered_code_has_a_case``
   fails otherwise. The option suite's ``SKIP`` table is the only exit, and each of its
   five entries states why a case would assert nothing: TCP's ``End_of_Option_List``
   and ``No_Operation`` are padding that ``_make_tcp_options`` drops, ``Multipath_TCP``
   is the envelope of the ``tcp-mptcp`` family and would duplicate one of its subtypes,
   and ``PadN`` under HOPOPT and IPv6-Opts emits the same option-less header as
   ``Pad1``. A code that fails is never skipped.
*  **A failing case is an entry, never a changed argument.** An ``EXPECTED_FAILURES``
   entry records the status, a failure-detail fragment narrow enough to match one
   site, and the defect: the ``file:line`` that causes it and the issue that tracks it.
   Routing a case around a defect hides it: the generator's ``HIP_COPIES`` once put two
   parameters in every HIP packet, so the unrepresentable length of a lone one
   (:issue:`651`) was never constructed. Entries older than this page name the
   ``file:line`` alone, and :issue:`1202` is where they gain their issue.
   ``KNOWN_DEGRADED`` entries have a different shape -- a fragment and a reason -- and
   its two record why the probe's placeholder payload cannot reach the target, not a
   defect to fix, so the ``file:line``-and-issue rule does not apply to them.
*  **A regression is fixed; a pre-existing defect is recorded.** A case that a change
   breaks -- including a code it registers that does not close -- is fixed in that
   change, not added to a table. A newly found defect that predates the change gets an
   entry naming the ``file:line`` that causes it, as the failure message asks, and an
   issue.
*  **The tables are checked in both directions.** In the option suite, an entry whose
   case starts passing turns ``test_round_trip_is_identity_or_a_recorded_gap`` red, and
   one naming a case that no longer exists fails
   ``test_expected_failures_name_real_cases``; the dispatch suite has the same pair. So
   a fix deletes its entry in the same change.
*  **The harness guards its own shape.** ``test_recorded_gaps_are_a_minority`` fails
   once recorded failures reach half the option cases (the dispatch suite's
   ``test_degraded_cases_are_a_small_minority`` draws the line at a quarter), since
   that points at the harness rather than the library. Each case runs under
   ``CASE_TIMEOUT``, 30 seconds in both suites, so a case that never finishes fails by
   name instead of hanging the run.
*  **A closed cycle is not proof of correctness.** A writer and a reader that share an
   error round-trip perfectly: HIP's parameter padding (:issue:`651`) and IPv4's ``SID``
   width (:issue:`534`) both closed the cycle while wrong. So a round trip is paired with
   an assertion against the specification -- the RFC's own lengths, or a known-good
   packet's field values.

A lossless path that is not registry-shaped gets a capture-driven case instead:
rebuild each layer with ``from_data`` and require the original octets back, as
:file:`tests/protocols/test_declared_length_roundtrip_runtime.py` does for the
declared lengths of a truncated capture.

Raising Coverage
~~~~~~~~~~~~~~~~

**Every change raises coverage, and each new test is shown to fail without its fix.**
A test that also passes on the unfixed tree cannot tell the fix from its absence, so it
pins nothing. Before opening the pull request, take the fix out, run the new test, put
the fix back, and say in the pull request that you did:

.. code-block:: shell

   git diff origin/main -- pcapkit/ > /tmp/fix.diff
   git apply -R /tmp/fix.diff
   python -m pytest tests/<path>/test_<name>_unit.py -q    # must fail
   git apply /tmp/fix.diff
   python -m pytest tests/<path>/test_<name>_unit.py -q    # must pass

CI measures one leg, the ``test`` job's Python 3.14 cell in
:file:`.github/workflows/unit-tests.yml`, with branch coverage over :mod:`pcapkit`
configured by :file:`.github/coverage.toml`; :file:`.github/workflows/coverage-comment.yml`
posts the totals on the pull request. Locally, measure with ``coverage run`` rather than
a pytest plugin, which this project does not install, and narrow at report time --
``[tool.coverage.run]``'s ``source`` in :file:`pyproject.toml` takes precedence over
``--include`` at run time:

.. code-block:: shell

   python -m coverage run -m pytest tests/<path>/test_<name>_unit.py -q
   python -m coverage report --include='pcapkit/<path>/<name>.py'

Running the Tests
~~~~~~~~~~~~~~~~~

*  **One module per process, never the whole suite.** Check a change by running the
   modules it touches, each as its own ``python -m pytest <module> -q``, and leave the
   whole tier to CI, which spreads it over workers with ``-n auto --dist load``. Every
   purge-then-import leaves the previous generation of :mod:`pcapkit` behind as
   garbage, and the whole suite in one plain-unittest process runs out of memory --
   :file:`util/run_unittest_leg.py` records the measurement.
*  **Read the summary line, not the exit code.** pytest's last line
   (``N passed, M failed``) and unittest's ``OK`` or ``FAILED (...)`` are the result;
   an exit code read through a pipe or a wrapper is the pipe's or the wrapper's.
*  **Keep to the tiers.** The unit tier must pass on a fresh clone with no generated
   captures, installed as CI's ``test`` and ``unittest-ordering`` jobs install it,
   ``pip install -e '.[test,DPKT,crypto,NGAP]'``; :file:`tests/integration/`, :file:`*_runtime.py` and
   :file:`*_regression.py` are the fixture-dependent tier, run after ``make samples``.
   A unit-tier module builds its own octets and never reads a generated capture --
   :file:`tests/_tiers.py` enforces that at collection and on every ``sample_path``
   call.
*  **Import once per class.** A test class that needs a fresh :mod:`pcapkit` calls
   ``reimport_once_per_class(self)`` from ``setUp``, in place of a per-test
   ``purge_modules``, which re-imported the package before every test and dominated
   the suite's time (:issue:`1065`). Both live in :file:`tests/_support.py`; pass
   ``restore=True`` when the class must leave :data:`sys.modules` as it found it.
*  **Check ordering under plain unittest.** :file:`tests/conftest.py` heals cross-module
   import pollution after every test, so pytest alone cannot see it (:issue:`981`).
   :file:`util/run_unittest_leg.py` runs one :file:`tests/` subdirectory, then the
   root-level modules, in one plain-unittest process, which is what CI's
   ``unittest-ordering`` job does per leg. Run it on the directory a change touches
   when the change moves imports or module state:

   .. code-block:: shell

      python util/run_unittest_leg.py protocols/internet
      python util/run_unittest_leg.py protocols --exclude protocols/internet

   The leg list lives in the workflow, not the script; :file:`tests/corekit/` and
   :file:`tests/integration/` are deliberately not legs, for the reasons recorded
   there.

Adding a Protocol, Option or Dumper
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

What each must bring in tests before it merges, on top of the fail-without-fix proof
above:

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - Adding
     - Must bring
   * - an option-like code
     - Registering it gives it a case automatically. Add arguments to the generator's
       tables in :file:`examples/generators/options.py` where the ``_make_*`` defaults
       are degenerate, and a ``Family`` to ``FAMILIES`` for a new registry. Its cycle
       closes before it merges.
   * - a protocol
     - A unit-tier :file:`tests/protocols/<layer>/test_<name>_unit.py` that builds its
       own octets, asserts construct -> parse -> construct identity, and checks a parse
       against the specification's field values. A ``__proto__`` registration also
       needs its ``PINNED_TARGETS`` entry in :file:`examples/generators/dispatch.py`,
       which ``test_every_case_has_a_pinned_target`` enforces.
   * - a dumper
     - Unit tests under :file:`tests/dumpkit/` asserting the output exactly, and a case
       in :file:`tests/integration/test_output_formats.py` for the file that lands on
       disk. That a format :mod:`pcapkit` also reads, such as PCAP, reproduces its
       input byte for byte is the target :issue:`1202` tracks; nothing asserts it
       yet.
