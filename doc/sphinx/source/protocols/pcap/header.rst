Global Header [*]_
------------------

:mod:`pcapkit.protocols.pcap.header` contains
:class:`~pcapkit.protocols.pcap.Header` only,
which implements extractor for global headers
of PCAP, whose structure is described as
below.

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

.. automodule:: pcapkit.protocols.pcap.header
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
