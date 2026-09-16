=====================
Demonstration Scripts
=====================

A tour of ``pcapkit`` by example: each script here does one thing and prints or dumps
the result, so you can get a thorough view of the library either on how to use it or
on what it can do. They are demos rather than tests -- ``pytest`` does not collect
this directory (``testpaths = ["tests"]``) and nothing in CI runs them, so they are
also where API drift goes unnoticed the longest. Run them after changing anything
public.

Running them
------------

Every script reads its capture with a path relative to its own directory, so **run
them from inside** ``examples/legacy_smoke/``, not from the repository root:

.. code-block:: shell

   cd examples/legacy_smoke
   python test_basic.py

The captures live in ``../captures/``. Only ``in.pcap`` and ``dhcp.pcapng`` are
committed; the rest are generated, so build them once before running anything else:

.. code-block:: shell

   python ../generators/make_samples.py     # or: make samples, from the repository root

The scripts
-----------

.. list-table::
   :header-rows: 1

   * - Script
     - What it demonstrates
   * - `test_basic <test_basic.py>`_
     - the smallest useful call -- extract ``in.pcap`` to a tree-view text file
   * - `test_extractor <test_extractor.py>`_
     - ``pcapkit.extract`` dumping the same capture as plist, JSON and tree
   * - `test_file <test_file.py>`_
     - reading from an already-open binary file object rather than a path
   * - `test_api <test_api.py>`_
     - most of the keyword surface at once: per-frame files, reassembly and flow
       tracing
   * - `test_tcp <test_tcp.py>`_
     - extraction of TCP packets
   * - `test_ipv6 <test_ipv6.py>`_
     - extraction of IPv6 packets, one output file per frame
   * - `test_pcapng <test_pcapng.py>`_
     - extraction of a PCAP-NG capture, which uses a different engine
   * - `test_http <test_http.py>`_
     - iterating frames manually and testing ``pcapkit.HTTP in frame``
   * - `test_reassembly <test_reassembly.py>`_
     - TCP payload reassembly, writing the reassembled datagrams out
   * - `test_ip_reasm <test_ip_reasm.py>`_
     - IPv4 fragment reassembly
   * - `test_ipv6_reasm <test_ipv6_reasm.py>`_
     - IPv6 fragment reassembly
   * - `test_analyse <test_analyse.py>`_
     - analysis of the application layer *after* reassembly, printing the recovered
       HTTP messages
   * - `test_trace <test_trace.py>`_
     - tracing TCP flows and dumping the flow index
   * - `test_engine <test_engine.py>`_
     - the same capture through each extraction engine, side by side
   * - `test_time <test_time.py>`_
     - timing each engine, reported as milliseconds per packet
   * - `test_profile <test_profile.py>`_
     - cProfile stats for one extraction; ``make profile`` renders the call graph
   * - `test_perf <test_perf.py>`_
     - the same comparison under the ``pyperf`` benchmark harness
   * - `test_stream <test_stream.py>`_
     - extracting a live capture streamed from ``tcpdump`` on stdin
   * - `test_stream_askpass <test_stream_askpass.py>`_
     - the same, with ``sudo -A`` for a non-interactive password

``_engine_support.py`` is not a demo -- it is the shared helper the engine demos use
to work out whether an engine can run on this host.

What needs more than pcapkit
----------------------------

Most of these run with nothing but ``pcapkit``. These do not:

- **test_engine, test_time, test_perf** exercise the ``dpkt``, ``scapy`` and
  ``pyshark`` engines. Those are optional packages, and ``pyshark`` additionally
  drives Wireshark's ``tshark`` binary. An engine that is missing is reported as
  skipped, with the reason, and the rest still run -- see ``_engine_support.py``. Two
  things worth knowing:

  - ``pyshark`` 0.6 does not work on Python 3.14 at all. It asks
    ``asyncio.get_event_loop_policy().get_event_loop()`` for a loop on a thread that
    has none, which 3.14 no longer creates implicitly, so every extraction through it
    raises ``RuntimeError: There is no current event loop in thread 'MainThread'``
    before ``tshark`` is even reached. That is a pyshark bug, not a pcapkit one, and
    there is nothing to configure around it.
  - When an engine's *package* is missing, ``pcapkit.extract`` does not fail. It warns
    and falls back to pcapkit's own parser, so the extraction succeeds under the wrong
    engine. The demos name the driver that actually ran, so a fallback is visible
    rather than being reported as a healthy result.

- **test_perf** needs the ``pyperf`` harness, which ``pcapkit`` does not depend on:
  ``python -m pip install pyperf``. Without it the script says so and stops.
  ``test_time.py`` does the same comparison with no extra dependency.
- **test_profile**'s ``make profile`` target needs ``gprof2dot``, ``graphviz`` and
  ``snakeviz`` to render the call graph. The script itself only needs ``pcapkit``.
- **test_stream, test_stream_askpass** run ``sudo tcpdump`` against a live interface,
  so they need root and cannot run unattended. ``INTERFACE`` at the top of each is
  ``en0`` (macOS); on Linux it is usually ``eth0`` or ``wlan0``. They buffer the live
  capture into a temporary file -- never into ``../captures/``, which holds generated
  captures the test suite pins.

Regenerating the committed fixtures
-----------------------------------

Four files in ``../captures/`` are committed outputs rather than inputs, and they are
produced by two of the scripts here. To refresh them after a change to how
``pcapkit`` renders a capture:

.. code-block:: shell

   cd examples/legacy_smoke && make fixtures

That is the whole recipe. It runs, equivalently:

.. code-block:: shell

   TZ=UTC python test_extractor.py     # ../captures/out.json, out.plist, out.txt  <- in.pcap
   TZ=UTC python test_pcapng.py        # ../captures/pcapng.txt                    <- dhcp.pcapng

Both inputs are committed, so this works on a fresh clone with no ``make samples``
first. Use ``make fixtures PYTHON=../../.venv/bin/python`` to pick a specific
interpreter.

``TZ=UTC`` **is not decoration.** ``pcapkit`` renders frame timestamps in the host's
local zone, so an unpinned run rewrites every timestamp line in all four files with
wherever it happened to be run -- which is how these fixtures came to disagree with
each other, the PCAP three having been generated at UTC-05:00 and ``pcapng.txt`` at
UTC+08:00. Pinning UTC makes the output reproducible on any host. It also happens to
be the only zone in which PCAP-NG's ``timestamp_epoch`` is the true UNIX epoch:
``PCAPNG._read_timestamp`` adds the zone's UTC offset to the value it returns, so a
fixture generated anywhere else bakes in that offset.
