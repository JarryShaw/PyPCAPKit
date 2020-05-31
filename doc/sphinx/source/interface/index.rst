User Interface
==============

.. module:: pcapkit.interface

:mod:`pcapkit.interface` defines several user-oriented
interfaces, variables, and etc. These interfaces are
designed to help and simplify the usage of :mod:`pcapkit`.

PCAP Extration
--------------

.. autofunction:: pcapkit.interface.extract

Application Layer Analysis
--------------------------

.. autofunction:: pcapkit.interface.analyse

Payload Reassembly
------------------

.. autofunction:: pcapkit.interface.reassemble

TCP Flow Tracing
----------------

.. autofunction:: pcapkit.interface.trace

Output File Formats
-------------------

.. data:: pcapkit.interface.TREE
   :value: 'tree'

.. data:: pcapkit.interface.JSON
   :value: 'json'

.. data:: pcapkit.interface.PLIST
   :value: 'plist'

.. data:: pcapkit.interface.PCAP
   :value: 'pcap'

Layer Thresholds
----------------

.. data:: pcapkit.interface.RAW
   :value: 'None'

.. data:: pcapkit.interface.LINK
   :value: 'Link'

.. data:: pcapkit.interface.INET
   :value: 'Internet'

.. data:: pcapkit.interface.TRANS
   :value: 'Transport'

.. data:: pcapkit.interface.APP
   :value: 'Application'

Extration Engines
-----------------

.. data:: pcapkit.interface.DPKT
   :value: 'dpkt'

.. data:: pcapkit.interface.Scapy
   :value: 'scapy'

.. data:: pcapkit.interface.PCAPKit
   :value: 'default'

.. data:: pcapkit.interface.PyShark
   :value: 'pyshark'

.. data:: pcapkit.interface.MPServer
   :value: 'server'

.. data:: pcapkit.interface.MPPipeline
   :value: 'pipeline'
