# -*- coding: utf-8 -*-
"""Base Class
================

.. module:: pcapkit.foundation.engines.engine

This is the abstract base class implementation for
all engine support functionality.

"""
import abc
from typing import TYPE_CHECKING, Generic, TypeVar

__all__ = ['Engine']

if TYPE_CHECKING:
    from pcapkit.foundation.extraction import Extractor

T = TypeVar('T')


class Engine(Generic[T], metaclass=abc.ABCMeta):
    """Base class for engine support.

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @classmethod
    @abc.abstractmethod
    def name(cls) -> 'str':
        """Engine name."""

    @classmethod
    @abc.abstractmethod
    def module(cls) -> 'str':
        """Engine module name."""

    @property
    def extractor(self) -> 'Extractor':
        """Extractor instance."""
        return self._extractor

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, extractor: 'Extractor') -> 'None':
        self._extractor = extractor

    def __call__(self) -> 'None':
        """Start extraction.

        This method will directly call :meth:`run` to start the
        extraction process.

        """
        self.run()

    ##########################################################################
    # Methods.
    ##########################################################################

    @abc.abstractmethod
    def run(self) -> 'None':
        """Start extraction.

        This method is the entry point for file extraction. It is to be used
        for preparing the extraction process, such as parsing the file header
        and setting up the extraction engines.

        """

    @abc.abstractmethod
    def read_frame(self) -> 'T':
        """Read frame.

        This method is to be used for reading a frame from the file. It is to
        read a frame from the file using the prepared engine instance and
        return the parsed frame.

        """

    def close(self) -> 'None':
        """Close engine.

        This method is to be used for closing the engine instance. It is to
        close the engine instance after the extraction process is finished.

        """
