# -*- coding: utf-8 -*-
"""header schema for root protocol"""

from pcapkit.protocols.schema.schema import Schema

__all__ = ['NoPayload']


class NoPayload(Schema):
    """Schema for empty payload."""
