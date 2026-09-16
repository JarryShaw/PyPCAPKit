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

.. data:: PyPCAP
   :value: 'pypcap'

.. data:: PCAP_CT
   :value: 'pcap_ct'

.. data:: PyPCAPFile
   :value: 'pypcapfile'

.. note::

   Every engine :mod:`pcapkit` ships now has a constant here. The `PyPCAP`_,
   `pcap-ct`_ and `PyPCAPFile`_ ones were added after the first four, so code
   written against an earlier release may still select them by their literal
   ``engine=`` values -- ``'pypcap'``, ``'pcap_ct'`` and ``'pypcapfile'``. That
   keeps working: each constant *is* that string, so the two spellings are
   interchangeable. An engine registered at runtime with
   :func:`~pcapkit.foundation.registry.foundation.register_extractor_engine` has
   no constant and is addressed by the name it was registered under.

   .. seealso::

      :doc:`../foundation/engines/index` for the full engine list, what each one
      supports, and the installation prerequisites the third-party ones carry.

.. _PyPCAP: https://github.com/pynetwork/pypcap
.. _pcap-ct: https://pypi.org/project/pcap-ct
.. _PyPCAPFile: https://github.com/kisom/pypcapfile
