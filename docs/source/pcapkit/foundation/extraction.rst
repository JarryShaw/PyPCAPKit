File Extractor
==============

.. module:: pcapkit.foundation.extraction

:mod:`pcapkit.foundation.extraction` contains
:class:`~pcapkit.foundation.extraction.Extractor` only,
which synthesises file I/O and protocol analysis,
coordinates information exchange in all network layers,
and extracts parameters from a PCAP file.

.. seealso::

   |pypcap|_, |pcap-ct|_ and |pypcapfile|_ are supported by
   :class:`pcapkit.foundation.engines.pypcap.PyPCAP` (``engine='pypcap'``),
   :class:`pcapkit.foundation.engines.pcap_ct.PCAP_CT` (``engine='pcap_ct'``)
   and :class:`pcapkit.foundation.engines.pypcapfile.PyPCAPFile`
   (``engine='pypcapfile'``). Each supports less than the
   :term:`default engine` does; :doc:`engines/index` tabulates the gaps, and
   :ref:`engine-prerequisites` gives what each needs installed.

An extraction runs in this order; a third-party engine implements its own
:meth:`~pcapkit.foundation.engines.engine.EngineBase.read_frame`:

.. mermaid::

   flowchart TD
       INIT["Extractor(...)"]
       SEL["settle the engine<br/>see the selection graph"]
       NAME["make\_name(): input, output and format<br/>FormatError for a format with no dumper"]
       MAGIC["peek the input's magic number"]
       RUN["run(): the chosen engine,<br/>or the built-in one the magic number names"]
       HDR["engine.run(): read the file header"]
       OPEN["\_open\_output(): open the output writer"]
       A{"auto?"}
       LOOP["record\_frames(): read\_frame() until EOF"]
       MAN["the caller drives it<br/>next(extractor) or extractor()"]
       RF["engine.read\_frame()"]
       EOF{"no\_eof, and the input<br/>still producing?"}
       CLEAN["\_cleanup(): TCP flow tracing finished,<br/>the input closed if this class opened it,<br/>the engine closed"]
       FAIL["\_cleanup(failed=True), then re-raised<br/>input and engine released,<br/>tracing not finished"]
       NEXT["the frame: read on under auto,<br/>else returned to the caller"]

       subgraph frame ["Per frame, in the built-in engines"]
           direction TB
           F1["parse the next frame, under layer= and protocol="]
           F2["count it, then the verbose callback"]
           F3{"nofile?"}
           F3W["write it: a file per frame under files=,<br/>else the one output"]
           F4{"reassembly?"}
           F4R["toolkit extractors feed the IPv4, IPv6,<br/>TCP and DTLS reassemblers switched on"]
           F5{"trace, and tcp?"}
           F5T["toolkit tcp\_traceflow feeds<br/>the TCP flow tracer"]
           F6{"store?"}
           F6S["kept in .frame"]
           F1 --> F2 --> F3
           F3 -->|no| F3W --> F4
           F3 -->|yes| F4
           F4 -->|yes| F4R --> F5
           F4 -->|no| F5
           F5 -->|yes| F5T --> F6
           F5 -->|no| F6
           F6 -->|yes| F6S
       end

       INIT --> SEL --> NAME --> MAGIC --> RUN --> HDR --> OPEN --> A
       A -->|yes| LOOP --> RF
       A -->|no| MAN --> RF
       RF -->|"a frame"| F1
       F6S --> NEXT
       F6 -->|no| NEXT
       RF -->|"EOFError or StopIteration<br/>ExtractionWarning: EOF reached"| EOF
       EOF -->|yes| RF
       EOF -->|no| CLEAN
       RUN -.->|"raises"| FAIL

       click SEL "engines/index.html#engine-selection"
       click NAME "extraction.html#pcapkit.foundation.extraction.Extractor.make_name"
       click RUN "extraction.html#pcapkit.foundation.extraction.Extractor.run"
       click OPEN "extraction.html#pcapkit.foundation.extraction.Extractor._open_output"
       click LOOP "extraction.html#pcapkit.foundation.extraction.Extractor.record_frames"
       click RF "engines/builtin.html#pcapkit.foundation.engines.pcap.PCAP.read_frame"
       click CLEAN "extraction.html#pcapkit.foundation.extraction.Extractor._cleanup"
       click FAIL "extraction.html#pcapkit.foundation.extraction.Extractor._cleanup"

.. autoclass:: pcapkit.foundation.extraction.Extractor
   :no-members:
   :show-inheritance:

   .. automethod:: __init__

   .. autoproperty:: length
   .. autoproperty:: format
   .. autoproperty:: input
   .. autoproperty:: output
   .. autoproperty:: frame
   .. autoproperty:: reassembly
   .. autoproperty:: trace
   .. autoproperty:: engine
   .. autoproperty:: magic_number

   .. automethod:: register_dumper
   .. automethod:: register_engine
   .. automethod:: register_reassembly
   .. automethod:: register_traceflow

   .. automethod:: run

   .. automethod:: import_test
   .. automethod:: make_name

   .. automethod:: record_header
   .. automethod:: _open_output
   .. automethod:: record_frames

   .. autoattribute:: __output__
      :no-value:
   .. autoattribute:: __engine__
      :no-value:
   .. autoattribute:: __reassembly__
      :no-value:
   .. autoattribute:: __traceflow__
      :no-value:

   .. automethod:: _cleanup
   .. automethod:: _release

   .. autoattribute:: _flag_a
   .. autoattribute:: _flag_d
   .. autoattribute:: _flag_e
   .. autoattribute:: _flag_f
   .. autoattribute:: _flag_q
   .. autoattribute:: _flag_o
   .. autoattribute:: _flag_r
   .. autoattribute:: _flag_t
   .. autoattribute:: _flag_v
   .. autoattribute:: _flag_n
   .. autoattribute:: _flag_s

   .. autoattribute:: _ifile
   .. autoattribute:: _finalizer
   .. autoattribute:: _ofile
   .. autoattribute:: _ifnm
   .. autoattribute:: _ofnm
   .. autoattribute:: _fext
   .. autoattribute:: _offmt
   .. autoattribute:: _magic

   .. autoattribute:: _frnum
   .. autoattribute:: _frame
   .. autoattribute:: _reasm
   .. autoattribute:: _trace
   .. autoattribute:: _ipv4
   .. autoattribute:: _ipv6
   .. autoattribute:: _tcp

   .. autoattribute:: _eof_mark
   .. autoattribute:: _vfunc
   .. autoattribute:: _vfunc_default

   .. autoattribute:: _exnam
   .. autoattribute:: _exeng

   .. autoattribute:: _exlyr
   .. autoattribute:: _exptl
   .. autoattribute:: _exctx

   .. automethod:: __iter__
   .. automethod:: __next__
   .. automethod:: __call__

   .. automethod:: __enter__
   .. automethod:: __exit__
   .. automethod:: __del__
   .. automethod:: _register_internal_engine
   .. automethod:: _owns_input
   .. automethod:: _note_eof_progress

Type Variables
--------------

.. data:: _P
   :type: typing.Any

   Frame type the extractor yields, as read by its engine.
