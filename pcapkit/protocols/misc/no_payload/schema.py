# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for empty payload"""

from pcapkit.protocols.schema import Schema, schema_final

__all__ = ['NoPayload']


@schema_final
class NoPayload(Schema):
    """Schema for empty payload."""

    # NOTE: So the class takes no arguments: ``schema_final`` generates its
    # ``dict_``-taking ``__init__`` only for a class that defines none.
    def __init__(self) -> 'None':  # pylint: disable=super-init-not-called
        pass
