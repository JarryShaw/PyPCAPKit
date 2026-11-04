=================
PCAP File Headers
=================

.. module:: pcapkit.protocols.misc.pcap

:mod:`pcapkit.protocols.misc.pcap` contains header descriptions for
PCAP files, including global header
(:class:`~pcapkit.protocols.misc.pcap.header.protocol.Header`) and frame header
(:class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame`).

Global Header
=============

.. module:: pcapkit.protocols.misc.pcap.header
.. module:: pcapkit.protocols.misc.pcap.header.protocol

:mod:`pcapkit.protocols.misc.pcap.header.protocol` contains
:class:`~pcapkit.protocols.misc.pcap.header.protocol.Header` only,
which implements an extractor for global headers [*]_
of PCAP, whose structure is described as below:

.. code-block:: c

   typedef struct pcap_hdr_s {
       guint32 magic_number;   /* magic number */
       guint16 version_major;  /* major version number */
       guint16 version_minor;  /* minor version number */
       gint32  thiszone;       /* GMT to local correction */
       guint32 sigfigs;        /* accuracy of timestamps */
       guint32 snaplen;        /* max length of captured packets, in octets */
       guint32 network;        /* data link type */
   } pcap_hdr_t;

.. versionchanged:: 1.5.0

   A global header cut short rebuilds as captured, where it rebuilt at full
   width (:issue:`1470`).

.. autoclass:: pcapkit.protocols.misc.pcap.header.protocol.Header
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: version
   .. autoproperty:: payload
   .. autoproperty:: protocol
   .. autoproperty:: protochain
   .. autoproperty:: byteorder
   .. autoproperty:: nanosecond

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _read_protos

Header Schemas
--------------

.. module:: pcapkit.protocols.misc.pcap.header.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.misc.pcap.header``, with no alias: the module moved here
   (:issue:`2534`).

.. autodata:: pcapkit.protocols.misc.pcap.header.schema.GLOBAL_HEADER_LEN

.. autodata:: pcapkit.protocols.misc.pcap.header.schema.MAGIC_NUMBER
   :no-value:

.. autodata:: pcapkit.protocols.misc.pcap.header.schema.RESOLUTION
   :no-value:

.. autodata:: pcapkit.protocols.misc.pcap.header.schema.RESOLUTION_PLACES
   :no-value:

.. autoclass:: pcapkit.protocols.misc.pcap.header.schema.Header
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.misc.pcap.header.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.misc.pcap.header``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.misc.pcap.header.data.Header
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcap.header.data.MagicNumber
   :members:
   :show-inheritance:

Frame Header
============

.. module:: pcapkit.protocols.misc.pcap.frame
.. module:: pcapkit.protocols.misc.pcap.frame.protocol

:mod:`pcapkit.protocols.misc.pcap.frame.protocol` contains
:class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame` only,
which implements an extractor for frame headers [*]_ of PCAP,
whose structure is described as below:

.. code-block:: c

   typedef struct pcaprec_hdr_s {
       guint32 ts_sec;     /* timestamp seconds */
       guint32 ts_usec;    /* timestamp microseconds */
       guint32 incl_len;   /* number of octets of packet saved in file */
       guint32 orig_len;   /* actual length of packet */
   } pcaprec_hdr_t;

.. versionchanged:: 1.5.0

   ``bytes(frame)`` and :attr:`~pcapkit.protocols.protocol.Protocol.packet`
   hold this frame's own octets, where they held the next frame's
   (:issue:`357`), and the parsed ``time`` is timezone-aware UTC. The parsed
   ``len`` is the on-wire length and ``cap_len`` the captured one, where the
   two were swapped (:issue:`618`).

.. autoclass:: pcapkit.protocols.misc.pcap.frame.protocol.Frame
   :no-members:
   :show-inheritance:

   .. autoattribute:: __proto__
      :no-value:

   .. autoattribute:: __proto_key__
      :no-value:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: header

   .. automethod:: register
   .. automethod:: index
   .. automethod:: pack
   .. automethod:: unpack
   .. automethod:: read
   .. automethod:: make

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _dispatch_linktype

Header Schemas
--------------

.. module:: pcapkit.protocols.misc.pcap.frame.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.misc.pcap.frame``, with no alias: the module moved here
   (:issue:`2534`).

.. autodata:: pcapkit.protocols.misc.pcap.frame.schema.RECORD_HEADER_LEN

.. autoclass:: pcapkit.protocols.misc.pcap.frame.schema.Frame
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.misc.pcap.frame.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.misc.pcap.frame``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.misc.pcap.frame.data.Frame
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.misc.pcap.frame.data.FrameInfo
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
