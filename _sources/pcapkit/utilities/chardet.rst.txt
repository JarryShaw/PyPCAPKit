Character Set Detection
=======================

.. module:: pcapkit.utilities.chardet

:mod:`pcapkit.utilities.chardet` wraps `chardet`_ with a bounded cache, for
turning the bytes of a text field into a :obj:`str`. It is shared by
:meth:`StringField.post_process
<pcapkit.corekit.fields.strings.StringField.post_process>` and
:meth:`ProtocolBase.decode <pcapkit.protocols.protocol.Protocol.decode>`,
which is why it lives here rather than beside either of them.

.. _chardet: https://chardet.readthedocs.io

.. autofunction:: pcapkit.utilities.chardet.detect

The cache holds :data:`~pcapkit.utilities.config.DETECT_CACHE_SIZE` entries.

.. versionremoved:: 1.5.0

   ``pcapkit.utilities.chardet.DETECT_CACHE_SIZE``, now
   :data:`pcapkit.utilities.config.DETECT_CACHE_SIZE`, set with
   :envvar:`PCAPKIT_DETECT_CACHE_SIZE` (:issue:`1726`).
