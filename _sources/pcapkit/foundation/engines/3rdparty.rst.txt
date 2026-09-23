=================
3rd-Party Engines
=================

Scapy Support
=============

.. module:: pcapkit.foundation.engines.scapy

This module contains the implementation for `Scapy`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _Scapy: https://scapy.net

.. note::

   Constructing this engine imports :mod:`scapy.all`, which is what populates
   `Scapy`_'s layer registries -- ``conf.l2types`` and the ``bind_layers``
   payload table, both of which exist only as import side effects of the layer
   modules. Importing a narrower submodule leaves them empty, and
   :class:`~scapy.utils.PcapReader` then returns every frame as one opaque
   :class:`~scapy.packet.Raw` layer without raising, so the engine dissected
   nothing at all and said so only on :data:`sys.stderr`. See
   :meth:`Scapy.__init__` for why naming the layer modules individually is not a
   cheaper route to the same place.

   One side effect is worth knowing about in advance: :mod:`scapy.all` loads
   :mod:`scapy.layers.dcerpc`, which reaches `Scapy`_'s TLS layer and there
   triggers a ``CryptographyDeprecationWarning`` from :mod:`cryptography` about
   finite-field Diffie-Hellman. It concerns a key-exchange code path
   :mod:`pcapkit` never executes, but it subclasses :exc:`UserWarning` rather
   than :exc:`DeprecationWarning`, so Python's default filters show it.

   :mod:`pcapkit` deliberately does not filter it away -- it is `Scapy`_'s to
   emit and the consumer's to silence, on the same footing as every other
   category (see :mod:`pcapkit.utilities.warnings`)::

      import warnings

      from cryptography.utils import CryptographyDeprecationWarning

      warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

.. autoclass:: pcapkit.foundation.engines.scapy.Scapy
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__

   .. automethod:: __init__
   .. automethod:: run
   .. automethod:: read_frame

   .. autoattribute:: _expkg
   .. autoattribute:: _extmp

DPKT Support
============

.. module:: pcapkit.foundation.engines.dpkt

This module contains the implementation for `DPKT`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _DPKT: https://dpkt.readthedocs.io

.. autoclass:: pcapkit.foundation.engines.dpkt.DPKT
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__

   .. automethod:: run
   .. automethod:: read_frame

   .. autoattribute:: _expkg
   .. autoattribute:: _extmp

PyShark Support
===============

.. module:: pcapkit.foundation.engines.pyshark

This module contains the implementation for `PyShark`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyShark: https://kiminewt.github.io/pyshark

.. important::

   `PyShark`_ has **two** requirements beyond installing it, and neither is
   visible to an import -- the package imports cleanly and then fails when used,
   which is why
   :meth:`~pcapkit.foundation.engines.pyshark.PyShark.unsupported_reason` checks
   both up front.

   **Python 3.13 or older.** ``pyshark`` 0.6 builds its event loop with
   ``asyncio.get_event_loop_policy().get_event_loop()``. Measured in a fresh
   interpreter with no running loop: 3.10 and 3.11 return a loop silently, 3.12
   returns one with a :exc:`DeprecationWarning`, and **3.14 raises**
   ``RuntimeError: There is no current event loop in thread 'MainThread'``. Python
   3.13 was not available to measure and is expected to work, being on the
   deprecated-but-functional side of that change.

   **Wireshark's** :program:`tshark` **binary.** ``pyshark`` shells out to it and
   parses nothing itself. It need not be on :envvar:`PATH`: ``pyshark`` consults
   ``tshark_path`` in its :file:`config.ini` first, then :envvar:`PATH` on POSIX,
   both Program Files directories on Windows, and
   :file:`/Applications/Wireshark.app` on macOS. The check delegates to
   ``pyshark``'s own resolver for exactly that reason, so a correctly configured
   install off :envvar:`PATH` is not refused.

.. autoclass:: pcapkit.foundation.engines.pyshark.PyShark
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__
   .. autoattribute:: PYTHON_CEILING

   .. automethod:: unsupported_reason

   .. automethod:: run
   .. automethod:: read_frame
   .. automethod:: close

   .. autoattribute:: _expkg
   .. autoattribute:: _extmp

PyPCAP Support
==============

.. module:: pcapkit.foundation.engines.pypcap

This module contains the implementation for `PyPCAP`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyPCAP: https://github.com/pynetwork/pypcap

.. important::

   `PyPCAP`_ publishes no wheels, so installing it compiles a C extension and
   needs both the :manpage:`libpcap(3)` headers and its shared library on the
   system -- a header alone is not enough. It is therefore **not** part of the
   ``all`` extra, and is installed on its own once libpcap is available:

   .. code-block:: shell

      pip install pypcapkit[PyPCAP]

   **On Python 3.12 and newer it cannot be installed at all**, which is why the
   extra carries a ``python_version < '3.12'`` marker. `PyPCAP`_ 1.3.0 ships a
   ``pcap.c`` pre-generated by Cython 0.29.32 and never runs Cython at build
   time, and that generated C does not compile against the 3.12+ C API. Measured
   on four interpreters with libpcap present and found:

   ===============  ===============================================================
   Python           ``pip install pypcap``
   ===============  ===============================================================
   3.10             builds, imports
   3.11             builds, imports
   3.12             **fails** -- ``ob_digit``, ``curexc_traceback``
   3.14             **fails** -- those, plus ``ma_version_tag`` and the
                    ``_PyLong_AsByteArray`` arity
   ===============  ===============================================================

   Upstream is unmaintained -- one doc-only commit since 1.3.0, and its Python
   3.12 issue (`pynetwork/pypcap#116
   <https://github.com/pynetwork/pypcap/issues/116>`_) has been open and
   uncommented since May 2024 -- so the cap is not expected to lift. Use
   :class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT` on 3.12 and newer.

.. important::

   `pcap-ct`_ installs the same top-level :mod:`pcap` module as `PyPCAP`_. This
   engine therefore checks which of the two it got and raises
   :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` when it is `pcap-ct`_,
   naming ``engine='pcap_ct'`` in the message. Running `pcap-ct`_ under the
   ``PyPCAP`` name would report an engine that is not the one in use, and the two
   have different install requirements and different version coverage to report.

.. important::

   `PyPCAP`_ is a :manpage:`libpcap(3)` binding aimed primarily at live capture.
   Offline it performs **no protocol dissection**: each frame is the
   ``(timestamp, bytes)`` pair that :c:func:`pcap_next_ex` produced. Reassembly
   and flow tracing are therefore unavailable and are disabled -- with an
   :class:`~pcapkit.utilities.warnings.AttributeWarning` -- when requested.

   The engine also reads PCAP savefiles only, and only from a file on disk.
   PCAP-NG is rejected with a
   :exc:`~pcapkit.utilities.exceptions.FormatError`, because
   :manpage:`libpcap(3)` opens such a file without complaint and then yields no
   frames at all; and a non-file input is rejected with an
   :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`, because
   :c:func:`pcap_open_offline` opens a savefile by *name*.

.. autoclass:: pcapkit.foundation.engines.pypcap.PyPCAP
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__
   .. autoattribute:: __engine_distribution__

   .. automethod:: unsupported_reason

   .. autoproperty:: dlink
   .. autoproperty:: backend

   .. automethod:: run
   .. automethod:: read_frame
   .. automethod:: close

   .. autoattribute:: _expkg
   .. autoattribute:: _extmp
   .. autoattribute:: _backend
   .. autoattribute:: _dlink
   .. autoattribute:: _closed

pcap-ct Support
===============

.. module:: pcapkit.foundation.engines.pcap_ct

This module contains the implementation for `pcap-ct`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _pcap-ct: https://pypi.org/project/pcap-ct/
.. _libpcap: https://pypi.org/project/libpcap/

.. important::

   `pcap-ct`_ is an independent :mod:`ctypes` reimplementation of the `PyPCAP`_
   interface, by a different author, on top of the `libpcap`_ distribution. It is
   a **separate engine** rather than a second backend for
   :class:`~pcapkit.foundation.engines.pypcap.PyPCAP`: select it with
   ``engine='pcap_ct'``.

   Its reason for existing is coverage. Upstream `PyPCAP`_ stops at Python 3.11
   (see the note under `PyPCAP Support`_ above); `pcap-ct`_ and `libpcap`_ both
   publish ``py3-none-any`` wheels, so **installing** this engine needs no
   compiler and no ``pcap.h``:

   .. code-block:: shell

      pip install pypcapkit[PCAP_CT]

   Verified end to end on Python **3.10.20** and **3.14.7**: both read
   :file:`examples/captures/in.pcap` through ``engine='pcap_ct'`` and return the
   same six frames with identical timestamps. So the two engines together cover
   every interpreter the project supports, and ``PCAP_CT`` covers all of it on
   its own:

   =========================================================================  ==================
   Engine                                                                     Python
   =========================================================================  ==================
   :class:`~pcapkit.foundation.engines.pypcap.PyPCAP` (``pypcap``)             3.10, 3.11
   :class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT` (``pcap-ct``)          3.10 and newer
   =========================================================================  ==================

.. warning::

   **A system** :manpage:`libpcap(3)` **is still required at run time**, and this
   is the easiest thing to get wrong about `pcap-ct`_. `libpcap`_ ships a vendored
   :file:`libpcap.so` under ``_platform/{linux,macos,windows}/`` but does **not**
   use it by default: its :file:`libpcap.cfg` reads ``LIBPCAP = None`` as
   published, which sends the loader to :func:`ctypes.util.find_library`, so what
   gets mapped is the host's ``libpcap.so.1``.

   Measured, not assumed: the same ``libpcap`` 1.11.0b29 wheel loaded
   :file:`/usr/lib64/libpcap.so.1.5.3` under one interpreter on this host and
   linuxbrew's 1.11.0 under another, purely because their loader search paths
   differ. Setting ``LIBPCAP = tcpdump`` in :file:`libpcap.cfg` selects the
   vendored copy instead, which reports libpcap 1.10.6.

   With no system :manpage:`libpcap(3)` at all, ``import pcap`` raises
   :exc:`OSError` rather than :exc:`ImportError`, which would escape
   :meth:`Extractor.import_test
   <pcapkit.foundation.extraction.Extractor.import_test>` and abort the
   extraction. :meth:`PCAP_CT.unsupported_reason
   <pcapkit.foundation.engines.pcap_ct.PCAP_CT.unsupported_reason>` detects it and
   reports it as an ordinary "engine unavailable", so the extraction falls back to
   the default engine with a warning naming the missing library.

.. warning::

   **Both distributions are pre-releases.** ``pcap-ct`` 1.3.0b3 and ``libpcap``
   1.11.0b29 are the newest published versions, and neither project has ever
   published a stable release -- which is also why ``pip install`` resolves them
   without ``--pre``. ``pcap-ct`` further documents itself as tracking the
   `PyPCAP`_ **1.2.3** interface rather than 1.3.0.

   Every attribute this engine touches -- the ``pcap.pcap(name=..., promisc=...)``
   constructor, :meth:`~pcap.pcap.datalink`, ``snaplen``, iteration yielding
   ``(timestamp, bytes)``, and :meth:`~pcap.pcap.close` -- is present on both and
   was measured to behave identically, byte for byte and timestamp for timestamp,
   on ``pcap-ct`` 1.3.0b3 against ``pypcap`` 1.3.0. That is a statement about the
   versions tested, not a guarantee from upstream. ``PCAP_CT`` is therefore not
   included in the ``all`` extra: a beta should be asked for by name.

.. important::

   Being the same interface, `pcap-ct`_ has the same limits. It performs **no
   protocol dissection**: each frame is the ``(timestamp, bytes)`` pair that
   :c:func:`pcap_next_ex` produced. Reassembly and flow tracing are therefore
   unavailable regardless of which backend is installed, and are disabled -- with
   an :class:`~pcapkit.utilities.warnings.AttributeWarning` -- when requested;
   the adapters in :mod:`pcapkit.toolkit.pcap_ct` raise
   :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` rather than fail
   obscurely. It also reads from a file on disk only, because
   :c:func:`pcap_open_offline` opens a savefile by *name*; a non-file input is
   rejected with an :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`.

   The timestamp is seconds since the epoch as a :class:`float`. `pcap-ct`_ opens
   savefiles asking for nanosecond precision via
   :c:func:`pcap_open_offline_with_tstamp_precision`, so a microsecond-resolution
   savefile is scaled up by :manpage:`libpcap(3)` rather than truncated; for
   :file:`examples/captures/in.pcap` the result matches each record header's
   ``ts_sec + ts_usec * 1e-6`` exactly.

.. note::

   PCAP-NG is rejected with a
   :exc:`~pcapkit.utilities.exceptions.FormatError`, for both engines, and the
   reason is that accepting it would be *unpredictable* rather than merely
   limited. :manpage:`libpcap(3)` can read a PCAP-NG savefile, but how well
   depends on the version the host provides -- which, per the warning above, the
   `libpcap`_ wheel does not pin. Both measured on
   :file:`examples/captures/dhcp.pcapng`:

   ================  ===========================================================
   System libpcap    Result
   ================  ===========================================================
   1.11.0            correct -- the same four frames and the same sub-second
                     timestamps as
                     :class:`~pcapkit.foundation.engines.pcapng.PCAPNG`
   1.5.3             four frames, but nonsense sub-second timestamps
                     (``1102274184.0000002`` and the like), silently and with no
                     error
   ================  ===========================================================

   Even on a good version, :c:func:`pcap_datalink` reports a single link type for
   the whole file, so a capture whose interfaces differ would have one interface's
   link type applied to every frame.
   :class:`~pcapkit.foundation.engines.pcapng.PCAPNG` reads the per-interface
   blocks properly and does not depend on the host's library at all, so PCAP-NG is
   routed there rather than read approximately -- or wrongly -- here.

.. autoclass:: pcapkit.foundation.engines.pcap_ct.PCAP_CT
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__
   .. autoattribute:: __engine_distribution__

   .. automethod:: unsupported_reason

   .. autoproperty:: dlink
   .. autoproperty:: backend

   .. automethod:: __init__
   .. automethod:: run
   .. automethod:: read_frame
   .. automethod:: close

   .. autoattribute:: _expkg
   .. autoattribute:: _handle
   .. autoattribute:: _extmp
   .. autoattribute:: _backend
   .. autoattribute:: _dlink
   .. autoattribute:: _closed

PyPCAPFile Support
==================

.. module:: pcapkit.foundation.engines.pypcapfile

This module contains the implementation for `PyPCAPFile`_ engine
support, as is used by :class:`pcapkit.foundation.extraction.Extractor`.

.. _PyPCAPFile: https://github.com/kisom/pypcapfile

.. important::

   `PyPCAPFile`_ is a pure Python savefile reader that decodes Ethernet, IPv4,
   TCP and UDP and nothing else. IPv6 reassembly is therefore unavailable and is
   disabled -- with an :class:`~pcapkit.utilities.warnings.AttributeWarning` --
   when requested; IPv4 and TCP reassembly and TCP flow tracing remain
   available. PCAP-NG is rejected with a
   :exc:`~pcapkit.utilities.exceptions.FormatError`.

.. autoclass:: pcapkit.foundation.engines.pypcapfile.PyPCAPFile
   :no-members:
   :show-inheritance:

   .. autoattribute:: __engine_name__
   .. autoattribute:: __engine_module__
   .. autoattribute:: LAYERS
   .. autoattribute:: PYTHON_CEILING

   .. automethod:: unsupported_reason

   .. autoproperty:: dlink

   .. automethod:: run
   .. automethod:: read_frame

   .. autoattribute:: _expkg
   .. autoattribute:: _extmp
   .. autoattribute:: _dlink
   .. autoattribute:: _declf

Internal Definitions
--------------------

.. automethod:: pcapkit.foundation.engines.pypcapfile.PyPCAPFile._get_decoder
.. automethod:: pcapkit.foundation.engines.pypcapfile.PyPCAPFile._decode

Backend Detection
=================

.. module:: pcapkit.foundation.engines._pcap_backend

Two unrelated PyPI distributions install a top-level module named :mod:`pcap` --
`PyPCAP`_, a Cython binding shipped as a single extension module, and `pcap-ct`_,
a :mod:`ctypes` reimplementation shipped as a package. They therefore collide,
and ``import pcap`` resolves to whichever the import system finds first.
:class:`~pcapkit.foundation.engines.pypcap.PyPCAP` and
:class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT` each have to know which one
they actually got rather than assume, and this module is the one place that
answers it -- deliberately shared, since the two engines must agree and two
copies of the detection would be two chances to disagree. It is *only* detection,
and it imports nothing from :mod:`pcapkit`, so it cannot introduce an import
cycle.

.. autodata:: pcapkit.foundation.engines._pcap_backend.PYPCAP

.. autodata:: pcapkit.foundation.engines._pcap_backend.PCAP_CT

.. autodata:: pcapkit.foundation.engines._pcap_backend.DISTRIBUTIONS

.. autodata:: pcapkit.foundation.engines._pcap_backend.ENGINE_NAMES

.. autoclass:: pcapkit.foundation.engines._pcap_backend.Probe
   :no-members:
   :show-inheritance:

   .. note::

      This is an :class:`~pcapkit.corekit.infoclass.Info` subclass, so it is a
      :class:`~collections.abc.Mapping` rather than a :class:`tuple`: its fields
      are reached by name, not by position, and it cannot be unpacked as a
      sequence.

   .. autoattribute:: name
   .. autoattribute:: version
   .. autoattribute:: origin
   .. autoattribute:: failure
   .. autoattribute:: missing
   .. autoattribute:: installed

   .. automethod:: describe

.. autofunction:: pcapkit.foundation.engines._pcap_backend.probe

.. autofunction:: pcapkit.foundation.engines._pcap_backend.identify

.. autofunction:: pcapkit.foundation.engines._pcap_backend.installed_distributions

.. autofunction:: pcapkit.foundation.engines._pcap_backend.wrong_backend_reason

.. autofunction:: pcapkit.foundation.engines._pcap_backend.collision_reason

Internal Definitions
--------------------

.. autofunction:: pcapkit.foundation.engines._pcap_backend._purge
