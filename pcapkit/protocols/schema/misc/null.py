# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for empty payload"""

from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['NoPayload']


@schema_final
class NoPayload(Schema):
    """Schema for empty payload."""

    # NOTE: Declared both for type annotation and to make this class accept no
    # arguments at runtime: :func:`schema_final` generates an ``__init__`` only
    # for a class that does not define one, so this one keeps the generated
    # ``dict_``-taking constructor from displacing it.
    def __init__(self) -> 'None':  # pylint: disable=super-init-not-called
        pass
