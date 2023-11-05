Core Interface
==============

.. module:: pcapkit.interface.core

:mod:`pcapkit.interface.core` defines core user-oriented
interfaces, variables, and etc., which wraps around the
foundation classes from :mod:`pcapkit.foundation`.

.. autofunction:: pcapkit.interface.core.extract

.. autofunction:: pcapkit.interface.core.reassemble

.. autofunction:: pcapkit.interface.core.trace

Constants Defintion
-------------------

Output File Formats
~~~~~~~~~~~~~~~~~~~

.. data:: TREE
   :value: 'tree'

.. data:: JSON
   :value: 'json'

.. data:: PLIST
   :value: 'plist'

.. data:: PCAP
   :value: 'pcap'

Layer Thresholds
~~~~~~~~~~~~~~~~

.. data:: RAW
   :value: 'none'

.. data:: LINK
   :value: 'link'

.. data:: INET
   :value: 'internet'

.. data:: TRANS
   :value: 'transport'

.. data:: APP
   :value: 'application'

Extration Engines
~~~~~~~~~~~~~~~~~

.. data:: DPKT
   :value: 'dpkt'

.. data:: Scapy
   :value: 'scapy'

.. data:: PCAPKit
   :value: 'default'

.. data:: PyShark
   :value: 'pyshark'
