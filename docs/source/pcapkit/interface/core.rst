Core Interface
==============

.. module:: pcapkit.interface.core

:mod:`pcapkit.interface.core` defines the core user-facing functions and
constants, which wrap the classes in :mod:`pcapkit.foundation`.

.. autofunction:: pcapkit.interface.core.extract

.. autofunction:: pcapkit.interface.core.reassemble

.. autofunction:: pcapkit.interface.core.trace

Constants Definition
--------------------

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

Extraction Engines
~~~~~~~~~~~~~~~~~~

.. data:: DPKT
   :value: 'dpkt'

.. data:: Scapy
   :value: 'scapy'

.. data:: PCAPKit
   :value: 'default'

.. data:: PyShark
   :value: 'pyshark'

.. data:: PyPCAP
   :value: 'pypcap'

.. data:: PCAP_CT
   :value: 'pcap_ct'

.. data:: PyPCAPFile
   :value: 'pypcapfile'

.. note::

   Every ``engine=`` string :mod:`pcapkit` ships has a constant here, and the
   constant *is* the string, so :data:`PyPCAP` and ``'pypcap'`` are
   interchangeable; :data:`PCAPKit` selects the built-in PCAP or PCAP-NG engine
   by the file's magic number. An engine registered at runtime with
   :func:`~pcapkit.foundation.registry.foundation.register_extractor_engine` has
   no constant, and is named by the string it was registered under.

   .. seealso::

      :doc:`../foundation/engines/index` for the full engine list, what each one
      supports, and the installation prerequisites the third-party ones carry.
