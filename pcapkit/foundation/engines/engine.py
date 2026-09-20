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

    This meta class is used to generate necessary attributes for the
    :class:`EngineBase` class. It can be useful to reduce unnecessary
    registry calls and simplify the customisation process.

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
    def registry(cls) -> 'dict[str, ModuleDescriptor[Engine] | Type[Engine]]':
        """Mapping of engine names to engine classes.

        Note:
            Unlike :attr:`EnumSchema.registry
            <pcapkit.protocols.schema.schema.EnumSchema.registry>`, this is not
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
            This property is not available as a class
            attribute.

        """
        if hasattr(self, '__engine_name__'):
            return self.__engine_name__
        return type(self).name  # type: ignore[return-value]

    @property
    def module(self) -> 'str':
        """Engine module name.

        Note:
            This property is not available as a class
            attribute.

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

        Registration is opt-in. Pass keyword argument ``name`` at class
        definition to register the engine under that name:

        .. code-block:: python

           class MyEngine(Engine, name='my_engine'):
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

    """

    def __init_subclass__(cls, /, name: 'Optional[str]' = None, *args: 'Any', **kwargs: 'Any') -> 'None':
        """Initialise subclass.

        This method is to be used for registering the engine class to
        :class:`~pcapkit.foundation.extraction.Extractor` class.

        Args:
            name: Engine name to register the subclass under, lowercased.
                :data:`None` (the default) skips registration entirely.
            *args: Arbitrary positional arguments.
            **kwargs: Arbitrary keyword arguments.

        Raises:
            UnsupportedCall: If any unrecognised class keyword is given.

        Registration is **opt-in**: the subclass is registered if and only if
        ``name`` is given. This is what lets a subclass decline registration
        rather than having to inherit :class:`EngineBase` to avoid it, and it
        matches :meth:`EnumSchema.__init_subclass__
        <pcapkit.protocols.schema.schema.EnumSchema.__init_subclass__>`, which
        has guarded on its own ``code`` keyword all along.

        Note:
            :attr:`__engine_name__` is *not* an opt-in. It supplies the
            :attr:`name <pcapkit.foundation.engines.engine.EngineMeta.name>`
            the engine reports, which it does whether or not the engine is
            registered; only the keyword decides registration.

        Warning:
            **On Python 3.10 the ``name`` keyword cannot be passed at all.**
            :meth:`abc.ABCMeta.__new__` takes ``mcls``, ``name``, ``bases`` and
            ``namespace`` as positional-*or-keyword* parameters before 3.11, so a
            class keyword named ``name`` collides with one of them and the class
            statement raises :exc:`TypeError` -- ``ABCMeta.__new__() got multiple
            values for argument 'name'`` -- from the metaclass, before this method
            is reached. From 3.11 those parameters are positional-only and the
            keyword arrives here normally. Measured on 3.10.21, 3.11.15 and
            3.14.7.

            The consequence on 3.10 is that an engine cannot be registered at
            class definition; register it explicitly instead, which works on every
            version::

                class MyEngine(Engine):     # no keyword, so not registered
                    ...

                Extractor.register_engine('my_engine', MyEngine)

            The sibling hooks are unaffected, their keywords being ``protocol``
            and ``fmt``.

        See Also:
            For more details, please refer to
            :meth:`pcapkit.foundation.extraction.Extractor.register_engine`.

        """
        # NOTE: an unrecognised class keyword lands in ``**kwargs`` and is then
        # dropped by the bare ``super().__init_subclass__()`` below, since
        # ``object.__init_subclass__`` takes none. Silently swallowing it is how
        # ``class MyEngine(Engine, nmae='x')`` used to register under its class
        # name instead -- no exception, no warning. Now that a missing keyword
        # means "do not register", the same typo would silently skip
        # registration altogether, which is quieter still. So reject it.
        #
        # ``args`` is checked alongside ``kwargs`` for completeness rather than
        # because a ``class`` statement can fill it -- class creation passes
        # keywords only. It is reachable through a direct
        # ``__init_subclass__(...)`` call, which the declared signature permits.
        if args or kwargs:
            unexpected = ', '.join([*map(repr, args), *sorted(kwargs)])
            raise UnsupportedCall(f'{cls.__name__}: unexpected class keyword(s): {unexpected}')

        if name is not None:
            from pcapkit.foundation.extraction import \
                Extractor  # pylint: disable=import-outside-toplevel

            Extractor.register_engine(name.lower(), cls)

        return super().__init_subclass__()
