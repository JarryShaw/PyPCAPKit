Frame Header [*]_
-----------------

:mod:`pcapkit.protocols.pcap.frame` contains
:class:`~pcapkit.protocols.pcap.frame.Frame` only,
which implements extractor for frame headers of PCAP,
whose structure is described as below:

.. code:: c

   typedef struct pcaprec_hdr_s {
       guint32 ts_sec;     /* timestamp seconds */
       guint32 ts_usec;    /* timestamp microseconds */
       guint32 incl_len;   /* number of octets of packet saved in file */
       guint32 orig_len;   /* actual length of packet */
   } pcaprec_hdr_t;

.. automodule:: pcapkit.protocols.pcap.frame
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
