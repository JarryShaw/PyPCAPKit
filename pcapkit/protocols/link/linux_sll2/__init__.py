# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Linux "Cooked" Capture Encapsulation v2
=============================================

.. module:: pcapkit.protocols.link.linux_sll2

:mod:`pcapkit.protocols.link.linux_sll2` holds the dissector,
:class:`~pcapkit.protocols.link.linux_sll2.protocol.LinuxSLL2`, in
:mod:`~pcapkit.protocols.link.linux_sll2.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.linux_sll2.schema` and its data model in
:mod:`~pcapkit.protocols.link.linux_sll2.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2

# Header Schemas
from pcapkit.protocols.link.linux_sll2.schema import LinuxSLL2 as Schema_LinuxSLL2

# Data Models
from pcapkit.protocols.link.linux_sll2.data import LinuxSLL2 as Data_LinuxSLL2

__all__ = ['LinuxSLL2']
