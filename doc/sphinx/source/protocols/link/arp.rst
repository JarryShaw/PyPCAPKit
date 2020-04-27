.. module:: pcapkit.protocols.link.arp

ARP/InARP - (Inverse) Address Resolution Protocol
=================================================

:mod:`pcapkit.protocols.link.arp` contains
:class:`~pcapkit.protocols.link.arp.ARP` only,
which implements extractor for (Inverse) Address Resolution
Protocol (ARP/InARP) [*]_, whose structure is described as
below::

.. code:: text

    Octets      Bits        Name                    Description
      0           0     arp.htype               Hardware Type
      2          16     arp.ptype               Protocol Type
      4          32     arp.hlen                Hardware Address Length
      5          40     arp.plen                Protocol Address Length
      6          48     arp.oper                Operation
      8          64     arp.sha                 Sender Hardware Address
      14        112     arp.spa                 Sender Protocol Address
      18        144     arp.tha                 Target Hardware Address
      24        192     arp.tpa                 Target Protocol Address

.. [*] http://en.wikipedia.org/wiki/Address_Resolution_Protocol

.. automodule:: pcapkit.protocols.link.arp
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:
