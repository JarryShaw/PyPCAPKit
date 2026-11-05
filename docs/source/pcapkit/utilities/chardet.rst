Character Set Detection
=======================

.. module:: pcapkit.utilities.chardet

:mod:`pcapkit.utilities.chardet` wraps `chardet`_ with a bounded cache, for
turning the bytes of a text field into a :obj:`str`. :meth:`StringField.post_process
<pcapkit.corekit.fields.strings.StringField.post_process>`,
:meth:`Protocol.decode <pcapkit.protocols.protocol.Protocol.decode>` and the FTP
and HTTP/1.* dissectors share it, so it lives beside none of them.

.. autofunction:: pcapkit.utilities.chardet.detect

The cache holds :data:`~pcapkit.utilities.config.DETECT_CACHE_SIZE` entries.
