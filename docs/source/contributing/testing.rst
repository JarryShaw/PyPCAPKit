Testing
=======

.. note::

   This page came out of the project README when that was trimmed down to a
   landing page. It is the only prose copy of the fixture story, so it lives here
   rather than nowhere.

Running the tests
-----------------

The unit tests need nothing beyond the package itself and the sample captures
tracked in the repository:

.. code-block:: shell

   make test

The runtime, regression and integration tests additionally read sample captures
that are **not** tracked (see :file:`.gitignore`);
:file:`examples/generators/make_samples.py` reconstructs them into
:file:`examples/captures/`, and ``make test-all`` regenerates them before running
the whole suite:

.. code-block:: shell

   make samples     # write examples/captures/*.pcap and *.pcapng
   make test-all    # regenerate the fixtures, then run every test

The same fixtures back the demonstration scripts in
:file:`examples/legacy_smoke/`, which read them as ``../captures/…``.

Continuous integration runs the ``make test`` selection, since the fixtures are
not in the repository. Wireshark's ``tshark`` is only required to exercise the
:class:`PyShark <pcapkit.foundation.engines.pyshark.PyShark>` engine, and is not
needed by the test suite.

The option round-trip generator
-------------------------------

One of the generators works differently from the rest and is worth knowing about.
:file:`examples/generators/options.py` does not describe packets it wants; it asks
the library which option, chunk, parameter, message, frame and block codes it
registers, and then constructs one of each through the public construction API,
parses it back, and constructs it again from what was parsed. The
:file:`options-*.pcap` captures are the cases that survive that round trip, so
they record what this version of :mod:`pcapkit` builds rather than what a
third-party tool builds.

:file:`tests/protocols/test_option_roundtrip_unit.py` runs the same cases without
needing a fixture at all, and carries a table of the ones that do not yet close
the cycle, each named against the defect that stops it.
