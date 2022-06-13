Frame Header
============

.. module:: pcapkit.protocols.misc.pcap.frame
.. module:: pcapkit.protocols.data.misc.pcap.frame

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

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.misc.pcap.frame.Frame
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __post_init__
   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: header

   .. automethod:: register
   .. automethod:: index
   .. automethod:: read
   .. automethod:: make

   .. .. automethod:: _make_timestamp
   .. automethod:: _decode_next_layer

   .. autoattribute:: __proto__
      :no-value:

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.misc.pcap.frame.Frame(frame_info, time, number, time_epoch, time_delta, len, cap_len)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: frame_info
   .. autoattribute:: time
   .. autoattribute:: number
   .. autoattribute:: time_epoch
   .. autoattribute:: len
   .. autoattribute:: cap_len

   .. autoattribute:: protocols

.. autoclass:: pcapkit.protocols.data.misc.pcap.frame.FrameInfo(ts_sec, ts_usec, incl_len, orig_len)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: ts_sec
   .. autoattribute:: ts_usec
   .. autoattribute:: incl_len
   .. autoattribute:: orig_len

.. raw:: html

   <hr />

.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
