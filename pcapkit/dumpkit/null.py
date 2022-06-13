# -*- coding: utf-8 -*-
"""Null Dumper
=================

:mod:`pcapkit.dumpkit.null` is the dumper for :mod:`pcapkit` implementation,
specifically for **NotImplemented** format, which is alike those described in
:mod:`dictdumper`.

Notes:
   This dumper is used when the given format is not supported, as a fallback.
   It shall not produce any output.

"""
from typing import TYPE_CHECKING

import dictdumper

if TYPE_CHECKING:
    from typing import Any, BinaryIO, Optional

    from typing_extensions import Literal

__all__ = ['NotImplementedIO']


class NotImplementedIO(dictdumper.Dumper):
    """Unspecified output format."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def kind(self) -> 'Literal["null"]':
        """File format of current dumper."""
        return 'null'

    ##########################################################################
    # Data models.
    ##########################################################################

    def __call__(self, value: 'dict[str, Any]', name: 'Optional[str]' = None) -> 'NotImplementedIO':  # pylint: disable=unused-argument
        """Dump a new frame.

        Args:
            value: content to be dumped
            name: name of current content block

        Returns:
            The dumper class itself (to support chain calling).

        """
        return self

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _dump_header(self, **kwargs: 'Any') -> 'None':  # pylint: disable=unused-argument
        """Initially dump file heads and tails.

        Args:
            **kwargs: arbitrary keyword arguments

        """

    def _append_value(self, value: 'dict[str, Any]', file: 'BinaryIO', name: 'str') -> 'None':  # pylint: disable=unused-argument
        """Call this function to write contents.

        Args:
            value: content to be dumped
            file: output file
            name: name of current content block

        """
