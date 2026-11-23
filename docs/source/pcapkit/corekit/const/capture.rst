Capture-Format Constants
========================

.. module:: pcapkit.corekit.const.capture

:mod:`pcapkit.corekit.const.capture` holds the values the PCAP and PCAP-NG
file formats fix and that code beyond their own file-header protocols reads: the
capture engines, the dumpers and the toolkit. Each is the one home of its value
(:issue:`1739`), and none is configurable.

.. versionadded:: 1.7.0

   Moved here from ``pcapkit.protocols.misc.pcap.header.schema``,
   ``pcapkit.protocols.misc.pcap.frame.schema`` and
   ``pcapkit.protocols.misc.pcapng.schema`` (:issue:`2883`).

PCAP
----

.. autodata:: pcapkit.corekit.const.capture.MAGIC_NUMBER
   :no-value:

.. autodata:: pcapkit.corekit.const.capture.RESOLUTION
   :no-value:

.. autodata:: pcapkit.corekit.const.capture.RESOLUTION_PLACES
   :no-value:

.. autodata:: pcapkit.corekit.const.capture.RECORD_HEADER_LEN

PCAP-NG
-------

.. autodata:: pcapkit.corekit.const.capture.BYTE_ORDER_MAGIC

.. autodata:: pcapkit.corekit.const.capture.GENERIC_BLOCK_MINIMUM

.. autodata:: pcapkit.corekit.const.capture.BLOCK_MINIMUM
   :no-value:

.. autodata:: pcapkit.corekit.const.capture.DEFAULT_RESOLUTION
