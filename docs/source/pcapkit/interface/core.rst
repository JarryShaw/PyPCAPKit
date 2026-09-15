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

.. note::

   These constants predate the `PyPCAP`_ and `PyPCAPFile`_ engines and no
   equivalents were added for them, so those two are selected by their literal
   ``engine=`` values -- ``'pypcap'`` and ``'pypcapfile'`` -- rather than through
   a named constant. Any engine registered at runtime with
   :func:`~pcapkit.foundation.registry.foundation.register_extractor_engine` is
   likewise addressed by its string name.

   .. seealso::

      :doc:`../foundation/engines/index` for the full engine list, what each one
      supports, and the installation prerequisites the third-party ones carry.

.. _PyPCAP: https://github.com/pynetwork/pypcap
.. _PyPCAPFile: https://github.com/kisom/pypcapfile
