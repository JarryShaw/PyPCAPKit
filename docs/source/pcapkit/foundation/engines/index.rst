Engine Support
==============

.. module:: pcapkit.foundation.engines

:mod:`pcapkit.foundation.engines` is a collection of engines
support for :mod:`pcapkit`, including but not limited to the
built-in PCAP and `PCAP-NG`_ file support, `Scapy`_, `PyShark`_,
`DPKT`_, `PyPCAP`_, `pcap-ct`_ and `PyPCAPFile`_ 3rd party engine
support.

.. seealso::

   For more information on customisation and extension, please
   refer to :doc:`../../../ext`.

.. toctree::
   :maxdepth: 2

   engine
   builtin
   3rdparty

All engines are implemented as :class:`~pcapkit.foundation.engines.engine.EngineBase`
subclasses, which are responsible for parsing the input files and extracting
the network packets for further processing. Below is a brief diagram of the
class hierarchy of :mod:`pcapkit.foundation.engines`:

.. mermaid::

   flowchart LR
       A{{EngineMeta}} -.->|metaclass| B(EngineBase)

       subgraph built-in [Built-in Engines]
           %% direction TD

           PCAP
           PCAPNG
       end
       B --> built-in

       subgraph third-party [3rd Party Engines]
           %% direction TD

           Scapy
           DPKT
           PyShark
           PyPCAP
           PCAP_CT
           PyPCAPFile
       end
       B --> third-party

       B --> C(Engine)
       C --> D([user customisation ...])

       click A "/pcapkit/foundation/engines/engine.html#pcapkit.foundation.engines.engine.EngineMeta"
       click B "/pcapkit/foundation/engines/engine.html#pcapkit.foundation.engines.engine.EngineBase"
       click C "/pcapkit/foundation/engines/engine.html#pcapkit.foundation.engines.engine.Engine"
       click D "/ext.html#extractor-engines"

       click PCAP "/pcapkit/foundation/engines/builtin.html#pcapkit.foundation.engines.pcap.PCAP"
       click PCAPNG "/pcapkit/foundation/engines/builtin.html#pcapkit.foundation.engines.pcapng.PCAPNG"

       click Scapy "/pcapkit/foundation/engines/3rdparty.html#pcapkit.foundation.engines.scapy.Scapy"
       click DPKT "/pcapkit/foundation/engines/3rdparty.html#pcapkit.foundation.engines.dpkt.DPKT"
       click PyShark "/pcapkit/foundation/engines/3rdparty.html#pcapkit.foundation.engines.pyshark.PyShark"
       click PyPCAP "/pcapkit/foundation/engines/3rdparty.html#pcapkit.foundation.engines.pypcap.PyPCAP"
       click PCAP_CT "/pcapkit/foundation/engines/3rdparty.html#pcapkit.foundation.engines.pcap_ct.PCAP_CT"
       click PyPCAPFile "/pcapkit/foundation/engines/3rdparty.html#pcapkit.foundation.engines.pypcapfile.PyPCAPFile"

Not every engine can do everything :class:`~pcapkit.foundation.extraction.Extractor`
offers, and the ones that cannot say so rather than quietly doing less:

+-----------------------------------------------------------------+---------------------------------------------------------------+
| Engine                                                          | Gap, and how it is surfaced                                   |
+=================================================================+===============================================================+
| :class:`~pcapkit.foundation.engines.pyshark.PyShark`            | no reassembly -- disabled with an                             |
|                                                                 | :class:`~pcapkit.utilities.warnings.AttributeWarning`, and    |
|                                                                 | :program:`tshark`'s own IP reassembly is turned off, so a     |
|                                                                 | fragmented datagram is read frame by frame, as the built-in   |
|                                                                 | engine reads it                                               |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pypcap.PyPCAP`              | no protocol dissection at all, hence no reassembly and no     |
|                                                                 | flow tracing -- both disabled with an                         |
|                                                                 | :class:`~pcapkit.utilities.warnings.AttributeWarning`; PCAP   |
|                                                                 | savefiles on disk only, otherwise                             |
|                                                                 | :exc:`~pcapkit.utilities.exceptions.FormatError` /            |
|                                                                 | :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`          |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT`            | the same gaps as ``PyPCAP`` above -- it reads the same        |
|                                                                 | interface, so no dissection, no reassembly and no flow        |
|                                                                 | tracing, and PCAP savefiles on disk only                      |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile`      | no IPv6 decoder, hence no IPv6 reassembly -- disabled with an |
|                                                                 | :class:`~pcapkit.utilities.warnings.AttributeWarning`, and    |
|                                                                 | :func:`~pcapkit.toolkit.pypcapfile.ipv6_reassembly` raises;   |
|                                                                 | TCP over IPv6, tunnelled in IP (e.g. 6in4) or not, is left    |
|                                                                 | out of TCP reassembly and flow tracing, with an               |
|                                                                 | :class:`~pcapkit.utilities.warnings.AttributeWarning` once    |
|                                                                 | per capture; IPv4 behind 802.1Q/802.1ad VLAN tags is read as  |
|                                                                 | it is untagged; PCAP savefiles only, otherwise                |
|                                                                 | :exc:`~pcapkit.utilities.exceptions.FormatError`              |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.dpkt.DPKT`,                 | no PCAP output, since each frame reaches the writer as a      |
| :class:`~pcapkit.foundation.engines.scapy.Scapy`,               | plain :obj:`dict` -- ``json`` is written instead, with a      |
| :class:`~pcapkit.foundation.engines.pyshark.PyShark`,           | :class:`~pcapkit.utilities.warnings.FormatWarning`            |
| :class:`~pcapkit.foundation.engines.pypcap.PyPCAP`,             |                                                               |
| :class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT` and        |                                                               |
| :class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile`      |                                                               |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pcapng.PCAPNG`              | no PCAP output for a PCAP-NG input, which declares its link   |
|                                                                 | type and timestamp resolution per interface --                |
|                                                                 | :exc:`~pcapkit.utilities.exceptions.FormatError`              |
+-----------------------------------------------------------------+---------------------------------------------------------------+

Availability
------------

A third-party engine is usable only where its backing package is, and three are
harder to obtain than a plain :program:`pip install` suggests. A missing package
is not fatal -- :mod:`pcapkit` emits an
:class:`~pcapkit.utilities.warnings.EngineWarning` and falls back to its own
parser -- but the extraction then does not use the engine requested.

+-----------------------------------------------------------------+---------------------------------------------------------------+
| Engine                                                          | What it needs beyond ``pip install``                          |
+=================================================================+===============================================================+
| :class:`~pcapkit.foundation.engines.pcap.PCAP`,                 | nothing -- built in                                           |
| :class:`~pcapkit.foundation.engines.pcapng.PCAPNG`              |                                                               |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.dpkt.DPKT`,                 | nothing -- both are pure Python, and neither                  |
| :class:`~pcapkit.foundation.engines.scapy.Scapy`                | overrides ``unsupported_reason()``                            |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pyshark.PyShark`            | Wireshark's :program:`tshark` binary -- on :envvar:`PATH`, or |
|                                                                 | wherever ``pyshark``'s :file:`config.ini` points -- **and**   |
|                                                                 | Python **3.13 or older**: ``pyshark`` 0.6 builds its event    |
|                                                                 | loop with :func:`asyncio.get_event_loop`, which raises from   |
|                                                                 | 3.14                                                          |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pypcap.PyPCAP`              | :manpage:`libpcap(3)` headers and library, a C compiler, and  |
|                                                                 | Python **3.11 or older** -- ``pypcap`` 1.3.0 publishes no     |
|                                                                 | wheel and its pre-generated :file:`pcap.c` does not compile   |
|                                                                 | on 3.12+                                                      |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT`            | a system ``libpcap.so.1`` at *run* time -- nothing to build,  |
|                                                                 | since ``pcap-ct`` and ``libpcap`` ship pure-Python wheels,    |
|                                                                 | but see the warning below: the vendored library those wheels  |
|                                                                 | carry is not what gets loaded by default                      |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile`      | Python **3.11 or older** -- ``pypcapfile`` 0.12.0 imports the |
|                                                                 | ``imp`` module, removed in Python 3.12                        |
+-----------------------------------------------------------------+---------------------------------------------------------------+

A constraint that an import cannot reveal is enforced by overriding
:meth:`~pcapkit.foundation.engines.engine.EngineBase.unsupported_reason`, which
:meth:`Extractor.run <pcapkit.foundation.extraction.Extractor.run>` consults
*before* the import test, so asking for an engine that cannot run here produces
one warning naming the actual cause and a fall back to the built-in parser.
``PyShark`` checks its Python ceiling and for ``tshark``, ``PyPCAPFile`` its
Python ceiling, ``PCAP_CT`` for a system ``libpcap``, and ``PyPCAP`` and
``PCAP_CT`` which distribution owns ``pcap``. ``PyPCAP`` deliberately has no
Python ceiling check, even though upstream cannot be installed on 3.12 or newer:
what matters is which distribution is present, and a version check would refuse
a working build.

.. seealso::

   :doc:`../../../index` covers the installation prerequisites in full,
   including how ``pypcap``'s :file:`setup.py` looks for :file:`pcap.h` and why
   a Homebrew ``libpcap`` is not always found.

Choosing Between PyPCAP and PCAP_CT
-----------------------------------

:class:`~pcapkit.foundation.engines.pypcap.PyPCAP` and
:class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT` read the same
:manpage:`libpcap(3)` interface from two independent distributions, both of which
install a top-level :mod:`pcap` module. They are separate engines because they
are separate projects, with different authors, different install requirements
and different interpreter coverage:

+---------------------------------------------------------------+---------------------+-------------------+---------------------------------------------------+
| Engine (``engine=``)                                          | Distribution        | Python            | What it needs                                     |
+===============================================================+=====================+===================+===================================================+
| :class:`~pcapkit.foundation.engines.pypcap.PyPCAP`            | `PyPCAP`_ 1.3.0     | 3.10, 3.11 only   | to build: a C compiler, ``pcap.h`` and a system   |
| (``'pypcap'``)                                                | (stable)            |                   | libpcap -- no wheels are published                |
+---------------------------------------------------------------+---------------------+-------------------+---------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pcap_ct.PCAP_CT`          | `pcap-ct`_ 1.3.0b3  | 3.10 and newer    | to install: nothing -- ``py3-none-any`` wheels.   |
| (``'pcap_ct'``)                                               | + `libpcap`_        |                   | At run time: a system ``libpcap.so.1`` all the    |
|                                                               | 1.11.0b29 (**beta**)|                   | same -- see the warning below                     |
+---------------------------------------------------------------+---------------------+-------------------+---------------------------------------------------+

Neither engine dissects anything, so the capability gaps in the table above are
identical for both and are a property of :manpage:`libpcap(3)`, not of the
distribution: **reassembly and flow tracing are unavailable whichever one is
installed.** Pick on availability, not on features.

.. warning::

   ``PCAP_CT`` needs no toolchain to *install*, but it does need a system
   :manpage:`libpcap(3)` to *run*. `libpcap`_ ships a vendored
   :file:`libpcap.so` and, as published, does not use it: its
   :file:`libpcap.cfg` says ``LIBPCAP = None``, which sends the loader to
   :func:`ctypes.util.find_library`. With no system library at all
   ``import pcap`` raises :exc:`OSError` rather than :exc:`ImportError`;
   :meth:`PCAP_CT.unsupported_reason
   <pcapkit.foundation.engines.pcap_ct.PCAP_CT.unsupported_reason>` catches that
   and turns it into an ordinary fall back to the default engine, instead of the
   hard error it would otherwise be.

**The two distributions collide, so install exactly one.** Both own the top-level
:mod:`pcap` module, and pip will happily install both -- on Python 3.10,
the ``pcap-ct`` package then wins the import and upstream's extension module is
shadowed and unreachable. Each engine therefore detects which distribution it
actually got, via
:func:`pcapkit.foundation.engines._pcap_backend.probe`, and:

* reports it -- :attr:`PyPCAP.backend
  <pcapkit.foundation.engines.pypcap.PyPCAP.backend>` and
  :attr:`PCAP_CT.backend <pcapkit.foundation.engines.pcap_ct.PCAP_CT.backend>`
  name the distribution, version and file actually in use, so a bug report about
  "the pypcap engine" says which one ran;
* declines to run on the other one, through ``unsupported_reason()``, with a
  message naming the ``engine=`` string that does want it; and
* warns with an :class:`~pcapkit.utilities.warnings.EngineWarning` when it finds
  both installed, since that state makes one of the two engines permanently
  unselectable and nothing else would explain why.

.. _PCAP-NG: https://wiki.wireshark.org/Development/PcapNg
.. _libpcap: https://pypi.org/project/libpcap/

.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark
.. _PyPCAP: https://github.com/pynetwork/pypcap
.. _pcap-ct: https://pypi.org/project/pcap-ct/
.. _PyPCAPFile: https://github.com/kisom/pypcapfile
