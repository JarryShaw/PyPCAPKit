Global Header
=============

.. module:: pcapkit.protocols.misc.pcap.header
.. module:: pcapkit.protocols.data.misc.pcap.header

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

.. raw:: html

   <br />

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

   .. .. automethod:: _read_protos
   .. .. automethod:: _make_magic

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.misc.pcap.header.Header(magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: magic_number
   .. autoattribute:: version
   .. autoattribute:: thiszone
   .. autoattribute:: sigfigs
   .. autoattribute:: snaplen
   .. autoattribute:: network

.. autoclass:: pcapkit.protocols.data.misc.pcap.header.MagicNumber(data, byteorder, nanosecond)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: data
   .. autoattribute:: byteorder
   .. autoattribute:: nanosecond

.. raw:: html

   <hr />

.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
