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
    from typing import Any, Optional

    from pcapkit.foundation.extraction import Extractor

T = TypeVar('T')


class EngineMeta(abc.ABCMeta, Generic[T]):
    """Meta class to add dynamic support to :class:`EngineBase`.

    This meta class is used to generate necessary attributes for the
    :class:`EngineBase` class. It can be useful to reduce unnecessary
    registry calls and simplify the customisation process.

    """


class EngineBase(Generic[T], metaclass=EngineMeta):
    """Base class for engine support.

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    Note:
        This class is for internal use only. For customisation, please use
        :class:`Engine` instead.

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


class Engine(EngineBase[T], Generic[T]):
    """Base class for engine support.

    Example:

        Use keyword argument ``name`` to specify the engine name at
        class definition:

        .. code-block:: python

           class MyEngine(Engine, name='my_engine'):
               ...

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    """

    @classmethod
    def name(cls) -> 'str':
        """Engine name."""
        return cls.__name__

    @classmethod
    def module(cls) -> 'str':
        """Engine module name."""
        return cls.__module__

    def __init_subclass__(cls, /, name: 'Optional[str]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialise subclass.

        This method is to be used for registering the engine class to
        :class:`~pcapkit.foundation.extraction.Extractor` class.

        Args:
            name: Engine name, default to class name.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        """
        if name is None:
            name = cls.name()

        from pcapkit.foundation.extraction import Extractor
        Extractor.register_engine(name, cls)

        return super().__init_subclass__()
