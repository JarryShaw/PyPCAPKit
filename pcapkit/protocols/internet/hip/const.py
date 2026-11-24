# -*- coding: utf-8 -*-
"""constants for HIP protocol

.. versionadded:: 1.7.0

"""

__all__ = ['LOCATOR_SET_LEN']

#: Packet-context key under which
#: :class:`~pcapkit.protocols.internet.hip.schema.LocatorSetParameter` keeps its
#: own ``Length`` for the benefit of
#: :func:`~pcapkit.protocols.internet.hip.schema.locator_set_padding_len`.
#:
#: It exists because the contents of ``LOCATOR_SET`` are a
#: :class:`~pcapkit.corekit.fields.collections.ListField` of nested schemas,
#: and a nested schema packed through one **shares the
#: enclosing packet context**: :meth:`Schema.pack
#: <pcapkit.protocols.schema.Schema.pack>` opens with
#: ``packet.update(self.__dict__)``, and
#: :class:`~pcapkit.protocols.internet.hip.schema.Locator` declares a ``len`` of
#: its own. So by the time ``padding`` is evaluated -- after the list, since
#: fields are packed in declaration order -- ``pkt['len']`` is the *last
#: locator's* ``len``, not the parameter's -- 4 for any IPv6 locator,
#: whatever the locator count.
#:
#: The shadowing is specific to the packing path. :meth:`Schema.unpack
#: <pcapkit.protocols.schema.Schema.unpack>` hands each field
#: ``packet.copy()``, so nested writes do not propagate back and ``pkt['len']``
#: stays the parameter's there. Snapshotting under a key no nested schema
#: declares is what makes one callback correct on both paths rather than
#: accidentally correct on one.
LOCATOR_SET_LEN = '__locator_set_len__'
