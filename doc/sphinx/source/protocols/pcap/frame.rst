Frame Header [*]_
-----------------

.. module:: pcapkit.protocols.pcap.frame

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

.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header

Protocol Class
~~~~~~~~~~~~~~

.. autoclass:: pcapkit.protocols.pcap.frame.Frame
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
~~~~~~~~~~~~~~

.. class:: DataType_pcap_frame_Frame

   :bases: typing.TypedDict

   PCAP frame header.

   .. attribute:: frame_info
      :type: DataType_FrameInfo

      PCAP frame information

   .. attribute:: time
      :type: datetime.datetime

      timestamp

   .. attribute:: number
      :type: int

      frame index number

   .. attribute:: time_epoch
      :type: float

      EPOCH timestamp

   .. attribute:: len
      :type: int

      captured packet length

   .. attribute:: cap_len
      :type: int

      actual packet length

   .. attribute:: packet
      :type: bytes

      packet raw data

   .. attribute:: protocols
      :type: pcapkit.corekit.protochain.ProtoChain

      protocol chain

   .. attribute:: error
      :type: typing.Optional[str]

      error message (optional)

.. class:: DataType_FrameInfo

   :bases: typing.TypedDict

   Frame information.

   .. attribute:: ts_sec
      :type: int

      timestamp seconds

   .. attribute:: ts_usec
      :type: int

      timestamp microseconds/nanoseconds

   .. attribute:: incl_len
      :type: int

      number of octets of packet saved in file

   .. attribute:: orig_len
      :type: int

      actual length of packet
