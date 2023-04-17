IP Datagram Reassembly
======================

The following algorithm implement is based on IP
reassembly procedure introduced in :rfc:`791`, using
``RCVBT`` (fragment receivedbit table). Though another
algorithm is explained in :rfc:`815`, replacing ``RCVBT``,
however, this implement still used the elder one.

.. toctree::
   :maxdepth: 2

   algorithm
   ip
   ipv4
   ipv6
