# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for empty payload"""

from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['NoPayload']


@schema_final
class NoPayload(Schema):
    """Schema for empty payload."""

    # NOTE: We add this method for both type annotation and to mark that this
    # class accepts no arguments at runtime, since :class:`Schema` explicitly
    # skipped those whose :attr:`__dict__` is empty :obj:`dict`.
    def __init__(self) -> 'None':  # pylint: disable=super-init-not-called
        pass
