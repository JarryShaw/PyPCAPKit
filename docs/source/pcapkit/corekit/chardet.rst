Character Set Detection
=======================

.. module:: pcapkit.corekit.chardet

:mod:`pcapkit.corekit.chardet` wraps `chardet`_ with a bounded cache, for
turning the bytes of a text field into a :obj:`str`. It is shared by
:meth:`StringField.post_process
<pcapkit.corekit.fields.strings.StringField.post_process>` and
:meth:`ProtocolBase.decode <pcapkit.protocols.protocol.Protocol.decode>`,
which is why it sits directly under :mod:`pcapkit.corekit` -- below both of
them -- rather than in :mod:`pcapkit.corekit.fields`.

.. _chardet: https://chardet.readthedocs.io

.. autofunction:: pcapkit.corekit.chardet.detect

.. autodata:: pcapkit.corekit.chardet.DETECT_CACHE_SIZE
