# -*- coding: utf-8 -*-
"""data models for PPP over Ethernet"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data, Protocol

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.const.pppoe.code import Code as Enum_Code
    from pcapkit.const.pppoe.tag import Tag as Enum_Tag

__all__ = ['PPPoE', 'Tag']


@info_final
class Tag(Data):
    """Data model for PPPoE discovery tags."""

    #: Tag type.
    type: 'Enum_Tag'
    #: Tag length.
    length: 'int'
    #: Tag value.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, type: 'Enum_Tag', length: 'int', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin


@info_final
class PPPoE(Protocol):
    """Data model for PPPoE packets."""

    #: Version.
    version: 'int'
    #: Type.
    type: 'int'
    #: Code, :attr:`~pcapkit.const.pppoe.code.Code.PPP_Session_Stage` in the
    #: session stage and a discovery packet's otherwise.
    code: 'Enum_Code'
    #: Session ID.
    session_id: 'int'
    #: Length of the payload.
    length: 'int'
    #: Tags of a discovery packet; :data:`None` in the session stage.
    tags: 'Optional[tuple[Tag, ...]]'

    if TYPE_CHECKING:
        def __init__(self, version: 'int', type: 'int', code: 'Enum_Code', session_id: 'int',  # pylint: disable=redefined-builtin
                     length: 'int', tags: 'Optional[tuple[Tag, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
