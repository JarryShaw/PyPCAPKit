# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Linux "Cooked" Capture Encapsulation
==========================================

.. module:: pcapkit.protocols.link.linux_sll1

:mod:`pcapkit.protocols.link.linux_sll1` holds the dissector,
:class:`~pcapkit.protocols.link.linux_sll1.protocol.LinuxSLL1`, in
:mod:`~pcapkit.protocols.link.linux_sll1.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.linux_sll1.schema` and its data model in
:mod:`~pcapkit.protocols.link.linux_sll1.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1

# Header Schemas
from pcapkit.protocols.link.linux_sll1.schema import LinuxSLL1 as Schema_LinuxSLL1

# Data Models
from pcapkit.protocols.link.linux_sll1.data import LinuxSLL1 as Data_LinuxSLL1

__all__ = ['LinuxSLL1']
