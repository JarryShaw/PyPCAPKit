Extractor for PCAP Files
========================

.. module:: pcapkit.foundation.extraction

:mod:`pcapkit.foundation.extraction` contains
:class:`~pcapkit.foundation.extraction.Extractor` only,
which synthesises file I/O and protocol analysis,
coordinates information exchange in all network layers,
extracts parametres from a PCAP file.

.. todo::

   Implement engine support for |pypcap|_ & |pycapfile|_.

.. autoclass:: pcapkit.foundation.extraction.Extractor
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

   .. attribute:: _ifnm
      :type: str

      Input file name.

   .. attribute:: _ofnm
      :type: str

      Output file name.

   .. attribute:: _fext
      :type: str

      Output file extension.

   .. attribute:: _flag_a
      :type: bool

      Auto extraction flag (as the ``auto`` parameter).

   .. attribute:: _flag_d
      :type: bool

      Data storing flag (as the ``store`` parameter).

   .. attribute:: _flag_e
      :type: bool

      EOF flag.

   .. attribute:: _flag_f
      :type: bool

      Split output into files flag (as the ``files`` parameter).

   .. attribute:: _flag_m
      :type: bool

      Multiprocessing engine flag.

   .. attribute:: _flag_q
      :type: bool

      No output flag (as the ``nofile`` parameter).

   .. attribute:: _flag_t
      :type: bool

      TCP flow tracing flag (as the ``trace`` parameter).

   .. attribute:: _flag_v
      :type: Union[bool, Callable[[pcapkit.foundation.extraction.Extractor, pcapkit.protocols.pcap.frame.Frame]]]

      A :obj:`bool` value or a function takes the :class:`Extract` instance and current parsed frame (depends on
      the engine selected) as parameters to print verbose output information (as the ``verbose`` parameter).

   .. attribute:: _vfunc
      :type: Union[NotImplemented, Callable[[pcapkit.foundation.extraction.Extractor, pcapkit.protocols.pcap.frame.Frame]]]

      If the ``verbose`` parameter is a callable, then it will be assigned as :attr:`self._vfunc <Extractor._vfunc>`;
      otherwise, it keeps :obj:`NotImplemented` as a placeholder and has specific function for each engine.

   .. attribute:: _frnum
      :type: int

      Current frame number.

   .. attribute:: _frame
      :type: List[pcapkit.protocols.pcap.frame.Frame]

      Frame records storage.

   .. attribute:: _proto
      :type: pcapkit.corekit.protochain.ProtoChain

      Current frame's protocol chain.

   .. attribute:: _reasm
      :type: List[Optiona[pcapkit.reassembly.ipv4.IPv4_Reassembly],
                  Optiona[pcapkit.reassembly.ipv6.IPv6_Reassembly],
                  Optiona[pcapkit.reassembly.tcp.TCP_Reassembly]]

      Reassembly buffers.

   .. attribute:: _trace
      :type: Optional[pcapkit.foundation.traceflow.TraceFlow]

      TCP flow tracer.

   .. attribute:: _ipv4
      :type: bool

      IPv4 reassembly flag (as the ``ipv4`` and/or ``ip`` flag).

   .. attribute:: _ipv6
      :type: bool

      IPv6 reassembly flag (as the ``ipv6`` and/or ``ip`` flag).

   .. attribute:: _tcp
      :type: bool

      TCP reassembly flag (as the ``tcp`` parameter).

   .. attribute:: _exptl
      :type: str

      Extract til protocol flag (as the ``protocol`` parameter).

   .. attribute:: _exlyr
      :type: str

      Extract til layer flag (as the ``layer`` parameter).

   .. attribute:: _exeng
      :type: str

      Extration engine (as the ``engine`` parameter).

   .. attribute:: _ifile
      :type: io.BufferedReader

      Source PCAP file (opened in binary mode).

   .. attribute:: _ofile
      :type: Optional[Union[dictdumper.dumper.Dumper, Type[dictdumper.dumper.Dumper]]]

      Output dumper. If :attr:`self._flag_f <Extractor._flag_f>` is :data:`True`,
      it is the :class:`~dictdumper.dumper.Dumper` object, otherwise it is an
      initialised :class:`~dictdumper.dumper.Dumper` instance.

      .. note::

         We customised the :meth:`~dictumpder.dumper.Dumper.object_hook` method to
         provide generic support of :class:`enum.Enum`, :class:`ipaddress.IPv4Address`,
         :class:`ipaddress.IPv6Address` and :class:`~pcapkit.corekit.infoclass.Info`.

      .. seealso::

         When the output format is unsupported, we uses :class:`~pcapkit.dumpkit.NotImplementedIO`
         as a fallback solution.

   .. attribute::  _gbhdr
      :type: pcapkit.protocols.pcap.header.Header

      Parsed PCAP global header instance.

   .. attribute:: _vinfo
      :type: pcapkit.corekit.version.VersionInfo

      The version info of the PCAP file (as the
      :attr:`self._gbhdr.version <pcapkit.protocols.pcap.header.Header.version>` property).

   .. attribute:: _dlink
      :type: pcapkit.const.reg.linktype.LinkType

      Protocol type of data link layer (as the
      :attr:`self._gbhdr.protocol <pcapkit.protocols.pcap.header.Header.protocol>` property).

   .. attribute:: _nnsec
      :type: bool

      Nanosecond PCAP file flag (as the
      :attr:`self._gbhdr.nanosecond <pcapkit.protocols.pcap.header.Header.nanosecond>` property).

   .. attribute:: _type
      :type: str

      Output format (as the :attr:`self._ofile.kind <dictdumper.dumper.Dumper.kind>` property).

   .. attribute:: _expkg
      :type: types.ModuleType

      Extraction engine module.

   .. attribute:: _extmp
      :type: Iterator[Any]

      Temporary storage for frame parsing iterator.

   .. attribute:: _mpprc
      :type: List[multiprocessing.Process]

      List of active child processes.

   .. attribute:: _mpfdp
      :type: DefaultDict[multiprocessing.Queue]

      File pointer (offset) queue for each frame.

   .. attribute:: _mpmng
      :type: multiprocessing.sharedctypes.multiprocessing.Manager

      Multiprocessing manager context.

   .. attribute:: _mpkit
      :type: multiprocessing.managers.SyncManager.Namespace

      Multiprocessing utility namespace.

   .. attribute:: _mpkit.counter
      :type: int

      Number of active workers.

   .. attribute:: _mpkit.pool
      :type: int

      Number of prepared workers.

   .. attribute:: _mpkit.current
      :type: int

      Current processing frame number.

   .. attribute:: _mpkit.eof
      :type: bool

      EOF flag.

   .. attribute:: _mpkit.frames
      :type: Dict[int, pcapkit.protocols.pcap.frame.Frame]

      Frame storage.

   .. attribute:: _mpkit.trace
      :type: Optional[pcapkit.foundation.traceflow.TraceFlow]

      TCP flow tracer.

   .. attribute:: _mpkit.reassembly
      :type: List[Optiona[pcapkit.reassembly.ipv4.IPv4_Reassembly],
                  Optiona[pcapkit.reassembly.ipv6.IPv6_Reassembly],
                  Optiona[pcapkit.reassembly.tcp.TCP_Reassembly]]

      Reassembly buffers.

   .. attribute:: _mpsrv
      :type: multiprocessing.Proccess

      Server process for frame analysis and processing.

   .. attribute:: _mpbuf
      :type: Union[multiprocessing.managers.SyncManager.dict,
                   Dict[int, pcapkit.protocols.pcap.frame.Frame]]

      Multiprocessing buffer for parsed PCAP frames.

   .. attribute:: _mpfrm
      :type: Union[multiprocessing.managers.SyncManager.list,
                   List[pcapkit.protocols.pcap.frame.Frame]]

      Multiprocessing storage for proccessed PCAP frames.

   .. attribute:: _mprsm
      :type: Union[multiprocessing.managers.SyncManager.list,
                   List[Optiona[pcapkit.reassembly.ipv4.IPv4_Reassembly],
                        Optiona[pcapkit.reassembly.ipv6.IPv6_Reassembly],
                        Optiona[pcapkit.reassembly.tcp.TCP_Reassembly]]]

      Multiprocessing storage for reassembly buffers.

.. data:: pcapkit.foundation.extraction.CPU_CNT
   :type: int

   Number of available CPUs. The value is used as the maximum
   concurrent workers in multiprocessing engines.

.. autodata:: pcapkit.foundation.extraction.LAYER_LIST
.. autodata:: pcapkit.foundation.extraction.PROTO_LIST

.. |pypcap| replace:: ``pypcap``
.. _pypcap: https://pypcap.readthedocs.io/en/latest/
.. |pycapfile| replace:: ``pycapfile``
.. _pycapfile: https://github.com/kisom/pypcapfile
