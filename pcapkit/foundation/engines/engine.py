# -*- coding: utf-8 -*-
"""Base Class
================

.. module:: pcapkit.foundation.engines.engine

This is the abstract base class implementation for
all engine support functionality.

"""
import abc
from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['Engine']

if TYPE_CHECKING:
    from typing import Any, Optional, Type

    from pcapkit.corekit.module import ModuleDescriptor
    from pcapkit.foundation.extraction import Extractor

_T = TypeVar('_T')


class EngineMeta(abc.ABCMeta, Generic[_T]):
    """Meta class to add dynamic support to :class:`EngineBase`.

    It provides :attr:`EngineBase.name`, :attr:`EngineBase.module` and
    :attr:`EngineBase.registry` as class properties, the first two read from
    ``__engine_name__`` and ``__engine_module__`` where a subclass sets them.

    """
    if TYPE_CHECKING:
        #: Engine name.
        __engine_name__: 'str'
        #: Engine module name.
        __engine_module__: 'str'

    @property
    def name(cls) -> 'str':
        """Engine name."""
        if hasattr(cls, '__engine_name__'):
            return cls.__engine_name__
        return cls.__name__

    @property
    def module(cls) -> 'str':
        """Engine module name."""
        if hasattr(cls, '__engine_module__'):
            return cls.__engine_module__
        return cls.__module__

    @property
    def registry(cls) -> 'dict[str, ModuleDescriptor[EngineBase] | Type[EngineBase]]':
        """Mapping of engine names to engine classes.

        Note:
            Unlike :attr:`EnumSchema.registry
            <pcapkit.protocols.schema.EnumSchema.registry>`, this is not
            a per-class mapping: every engine registration lands in the single
            :attr:`Extractor.__engine__
            <pcapkit.foundation.extraction.Extractor.__engine__>` table, so
            reading it through any subclass returns that same object. The
            property exists so ``MyEngine.registry`` is spelled the same way
            here as it is for schemas.

            Note also that :class:`EnumSchema` carries *two* ``registry``
            properties, one on its metaclass and one on the class body, so it
            answers on an instance as well. This one is on the metaclass only,
            so it is available as a class attribute and **not** on an instance.

        """
        from pcapkit.foundation.extraction import \
            Extractor  # pylint: disable=import-outside-toplevel

        return Extractor.__engine__


class EngineBase(Generic[_T], metaclass=EngineMeta):
    """Base class for engine support.

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    Note:
        This class is for internal use only. For customisation, please use
        :class:`Engine` instead.

    """
    if TYPE_CHECKING:
        #: Engine name.
        __engine_name__: 'str'
        #: Engine module name.
        __engine_module__: 'str'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'str':
        """Engine name.

        Note:
            This instance property is not what a class attribute lookup
            reaches: on the class, the metaclass property of the same name
            answers instead, with the same value.

        """
        if hasattr(self, '__engine_name__'):
            return self.__engine_name__
        return type(self).name  # type: ignore[return-value]

    @property
    def module(self) -> 'str':
        """Engine module name.

        Note:
            This instance property is not what a class attribute lookup
            reaches: on the class, the metaclass property of the same name
            answers instead, with the same value.

        """
        if hasattr(self, '__engine_module__'):
            return self.__engine_module__
        return type(self).module  # type: ignore[return-value]

    @property
    def extractor(self) -> 'Extractor':
        """Extractor instance."""
        return self._extractor

    ##########################################################################
    # Availability.
    ##########################################################################

    @classmethod
    def unsupported_reason(cls) -> 'Optional[str]':
        """Why this engine cannot run in this environment, if it cannot.

        Engines are normally gated by whether their third-party module imports,
        which :meth:`pcapkit.foundation.extraction.Extractor.import_test` decides.
        This hook is for the cases that question cannot answer -- most often a
        dependency that installs cleanly and only fails when it is *used*, so the
        import test passes and the error escapes from the engine's constructor as
        a hard failure instead of degrading to the default engine.

        The default is :data:`None`, i.e. always available; override it only where
        there is a real limitation, and return a short phrase naming the *cause*
        rather than merely refusing, since the string is shown to the user.

        Returns:
            A phrase describing the limitation, or :data:`None` when the engine is
            usable here.

        See Also:
            :class:`pcapkit.foundation.engines.pypcapfile.PyPCAPFile` overrides
            this, because ``pypcapfile`` installs on Python 3.12 and newer and then
            raises :exc:`ModuleNotFoundError` on first use.

        """
        return None

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, extractor: 'Extractor') -> 'None':
        #: Extractor instance this engine reads for.
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
    def read_frame(self) -> '_T':
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


class Engine(EngineBase[_T], Generic[_T]):
    """Base class for engine support.

    Example:

        Registration is opt-in. Pass keyword argument ``engine`` at class
        definition to register the engine under that name:

        .. code-block:: python

           class MyEngine(Engine, engine='my_engine'):
               ...

        Omit it and the subclass is *not* registered, which is how a class
        that is not meant to be selectable by name declines:

        .. code-block:: python

           class MyMixin(Engine):  # not registered
               ...

        Such a class can still be registered later, on demand:

        .. code-block:: python

           Extractor.register_engine('my_mixin', MyMixin)

    Args:
        extractor: :class:`~pcapkit.foundation.extraction.Extractor` instance.

    .. versionchanged:: 1.3.0

       :attr:`~EngineBase.name` and :attr:`~EngineBase.module` are properties,
       read from ``__engine_name__`` and ``__engine_module__`` or else from the
       class, where they were abstract class methods each engine implemented.
       A subclass registers itself with
       :class:`~pcapkit.foundation.extraction.Extractor` at class definition.

    .. versionchanged:: 1.5.0

       Registration is opt-in, under the ``engine`` class keyword, which
       replaces 1.4.x's ``name`` with no alias; 1.4.x registered every
       subclass, under its :attr:`~EngineBase.name` (its ``__engine_name__``,
       else its class name) when ``name`` was omitted (:issue:`514`).

    """

    def __init_subclass__(cls, /, engine: 'Optional[str]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialise subclass.

        This method is to be used for registering the engine class to
        :class:`~pcapkit.foundation.extraction.Extractor` class.

        Args:
            engine: Engine name to register the subclass under, lowercased.
                :data:`None` (the default) skips registration entirely.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            UnsupportedCall: If any unrecognised class keyword is given.

        Registration is **opt-in**: the subclass is registered if and only if
        ``engine`` is given. This is what lets a subclass decline registration
        rather than having to inherit :class:`EngineBase` to avoid it, and it
        matches :meth:`EnumSchema.__init_subclass__
        <pcapkit.protocols.schema.EnumSchema.__init_subclass__>`, which
        guards on its own ``code`` keyword the same way.

        Note:
            :attr:`__engine_name__
            <pcapkit.foundation.engines.engine.EngineBase.__engine_name__>` is
            *not* an opt-in. It supplies the
            :attr:`name <pcapkit.foundation.engines.engine.EngineBase.name>`
            the engine reports, which it does whether or not the engine is
            registered; only the keyword decides registration.

        Note:
            The keyword is ``engine`` rather than ``name`` because, below
            Python 3.11, ``abc.ABCMeta.__new__`` takes ``mcls``, ``name``,
            ``bases`` and ``namespace`` as positional-*or-keyword* parameters, so
            a class keyword by any of those names makes the class statement raise
            :exc:`TypeError` before this method is reached. ``metaclass`` is
            unusable on every version, since the ``class`` statement consumes it.

        See Also:
            For more details, please refer to
            :meth:`pcapkit.foundation.extraction.Extractor.register_engine`.

        """
        # NOTE: an unknown class keyword would be dropped by ``super().__init_subclass__()``,
        # silently skipping registration, so reject it; ``args`` is reachable by a direct call.
        if args or kwargs:
            unexpected = ', '.join([*map(repr, args), *sorted(kwargs)])
            raise UnsupportedCall(f'{cls.__name__}: unexpected class keyword(s): {unexpected}')

        if engine is not None:
            from pcapkit.foundation.extraction import \
                Extractor  # pylint: disable=import-outside-toplevel

            Extractor.register_engine(engine.lower(), cls)

        return super().__init_subclass__()
