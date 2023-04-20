Core Interface
==============

.. module:: pcapkit.interface.core

:mod:`pcapkit.interface.core` defines core user-oriented
interfaces, variables, and etc., which wraps around the
foundation classes from :mod:`pcapkit.foundation`.

.. autofunction:: pcapkit.interface.core.extract

.. autofunction:: pcapkit.interface.core.reassemble

.. autofunction:: pcapkit.interface.core.trace

Miscellaneous Constants
-----------------------

Output File Formats
~~~~~~~~~~~~~~~~~~~

.. data:: pcapkit.interface.core.TREE
   :value: 'tree'

.. data:: pcapkit.interface.core.JSON
   :value: 'json'

.. data:: pcapkit.interface.core.PLIST
   :value: 'plist'

.. data:: pcapkit.interface.core.PCAP
   :value: 'pcap'

Layer Thresholds
~~~~~~~~~~~~~~~~

.. data:: pcapkit.interface.core.RAW
   :value: 'none'

.. data:: pcapkit.interface.core.LINK
   :value: 'link'

.. data:: pcapkit.interface.core.INET
   :value: 'internet'

.. data:: pcapkit.interface.core.TRANS
   :value: 'transport'

.. data:: pcapkit.interface.core.APP
   :value: 'application'

Extration Engines
~~~~~~~~~~~~~~~~~

.. data:: pcapkit.interface.core.DPKT
   :value: 'dpkt'

.. data:: pcapkit.interface.core.Scapy
   :value: 'scapy'

.. data:: pcapkit.interface.core.PCAPKit
   :value: 'default'

.. data:: pcapkit.interface.core.PyShark
   :value: 'pyshark'
