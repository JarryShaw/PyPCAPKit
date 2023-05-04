=================
PCAP File Headers
=================

.. module:: pcapkit.protocols.misc.pcap
.. module:: pcapkit.protocols.data.misc.pcap
.. module:: pcapkit.protocols.schema.misc.pcap

:mod:`pcapkit.protocols.misc.pcap` contains header descriptions for
PCAP files, including global header
(:class:`~pcapkit.protocols.misc.pcap.header.Header`) and frame header
(:class:`~pcapkit.protocols.misc.pcap.frame.Frame`).

Global Header
=============

.. module:: pcapkit.protocols.misc.pcap.header

:mod:`pcapkit.protocols.misc.pcap.header` contains
:class:`~pcapkit.protocols.misc.pcap.Header` only,
which implements extractor for global headers [*]_
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

.. autoclass:: pcapkit.protocols.misc.pcap.header.Header
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __post_init__
   .. automethod:: __index__

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

   .. automethod:: _make_data

   .. automethod:: __post_init__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.misc.pcap.header

.. autoclass:: pcapkit.protocols.schema.misc.pcap.header.Header
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Data Models
-----------

.. module:: pcapkit.protocols.data.misc.pcap.header

.. autoclass:: pcapkit.protocols.data.misc.pcap.header.Header
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcap.header.MagicNumber
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Frame Header
============

.. module:: pcapkit.protocols.misc.pcap.frame

:mod:`pcapkit.protocols.misc.pcap.frame` contains
:class:`~pcapkit.protocols.misc.pcap.frame.Frame` only,
which implements extractor for frame headers [*]_ of PCAP,
whose structure is described as below:

.. code-block:: c

   typedef struct pcaprec_hdr_s {
       guint32 ts_sec;     /* timestamp seconds */
       guint32 ts_usec;    /* timestamp microseconds */
       guint32 incl_len;   /* number of octets of packet saved in file */
       guint32 orig_len;   /* actual length of packet */
   } pcaprec_hdr_t;

.. autoclass:: pcapkit.protocols.misc.pcap.frame.Frame
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: header

   .. automethod:: register
   .. automethod:: index

   .. automethod:: unpack

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. autoattribute:: __proto__
      :no-value:

   .. automethod:: __post_init__
   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.misc.pcap.frame

.. autoclass:: pcapkit.protocols.schema.misc.pcap.frame.Frame
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Data Models
-----------

.. module:: pcapkit.protocols.data.misc.pcap.frame

.. autoclass:: pcapkit.protocols.data.misc.pcap.frame.Frame
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.protocols.data.misc.pcap.frame.FrameInfo
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. raw:: html

   <hr />

.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
