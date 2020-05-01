Global Header
-------------

:mod:`pcapkit.protocols.pcap.header` contains
:class:`~pcapkit.protocols.pcap.Header` only,
which implements extractor for global headers
[*]_ of PCAP, whose structure is described as
below:

.. code:: c

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

.. automodule:: pcapkit.protocols.pcap.header
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
~~~~~~~~~~~~~~

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_Header

   :bases: :class:`TypedDict`

   PCAP global header.

   .. attribute:: magic_number
      :type: DataType_MagicNumber

      magic number

   .. attribute:: version_major
      :type: int

      major version number

   .. attribute:: version_minor
      :type: int

      minor version number

   .. attribute:: thiszone
      :type: int

      GMT to local correction

   .. attribute:: sigfigs
      :type: int

      accuracy of timestamps

   .. attribute:: snaplen
      :type: int

      max length of captured packets, in octets

   .. attribute:: network
      :type: pcapkit.const.reg.linktype.LinkType

      data link type


.. class:: DataType_MagicNumber

   :bases: :class:`TypedDict`

   PCAP magic number.

   .. attribute:: data
      :type: bytes

      original magic number

   .. attribute:: byteorder
      :type: str

      byte order (``big`` / ``little``)

   .. attribute:: nanosecond
      :type: bool

      nanosecond-timestamp support

.. raw:: html

   <hr />

.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
