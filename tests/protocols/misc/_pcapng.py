# -*- coding: utf-8 -*-
"""The PCAP-NG section context the block tests build and parse blocks in.

A block past the Section Header Block is read against the context the engine
keeps for its section, as :class:`~pcapkit.foundation.engines.pcapng.Context`
holds it. :func:`make_context` is one section with one Ethernet interface. Shared
under #3148.

:mod:`pcapkit` is imported inside :func:`make_context`, so each test module keeps its
classes' own import, after :func:`~tests._support.reimport_once_per_class`.

"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Optional


def make_context(snaplen: 'int' = 0x40000, section: 'Optional[bytes]' = None) -> 'Any':
    """A one-section context with one Ethernet interface of ``snaplen``, as the engine builds it.

    The section is ``section`` parsed, or a little-endian one built when it is :data:`None`.

    """
    from pcapkit.const.pcapng.block_type import BlockType
    from pcapkit.const.reg.linktype import LinkType
    from pcapkit.foundation.engines.pcapng import Context
    from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

    if section is None:
        header = PCAPNG.from_fields(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={})
    else:
        header = PCAPNG(section, len(section), num=0, sct=1, ctx=None)
    built = Context(header.info)  # type: Any
    interface = PCAPNG.from_fields(num=1, sct=1, ctx=built, type=BlockType.Interface_Description_Block,
                                   block={'linktype': LinkType.ETHERNET, 'snaplen': snaplen})
    built.interfaces.append(interface.info)
    return built
