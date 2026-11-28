# -*- coding: utf-8 -*-
"""data models for IEEE 802.2 Logical Link Control"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data, Protocol

if TYPE_CHECKING:
    from typing import Optional

    from typing_extensions import Literal

    from pcapkit.const.llc.lsap import LSAP as Enum_LSAP
    from pcapkit.const.llc.modifier_function import ModifierFunction as Enum_ModifierFunction
    from pcapkit.const.llc.supervisory_function import \
        SupervisoryFunction as Enum_SupervisoryFunction

__all__ = ['LLC', 'Control']


@info_final
class Control(Data):
    """Data model for the LLC control field."""

    #: Format of the control field, ``'I'`` (information transfer), ``'S'``
    #: (supervisory) or ``'U'`` (unnumbered).
    format: 'Literal["I", "S", "U"]'
    #: Supervisory function of the S format, or modifier function of the U
    #: format; :data:`None` in the I format.
    function: 'Optional[Enum_SupervisoryFunction | Enum_ModifierFunction]'
    #: Send sequence number, N(S), of the I format; :data:`None` otherwise.
    send_seq: 'Optional[int]'
    #: Receive sequence number, N(R), of the I and S formats; :data:`None` in
    #: the U format.
    recv_seq: 'Optional[int]'
    #: Poll/final bit.
    poll_final: 'bool'
    #: Reserved bits 5 to 8 of the S format, sent as zero; :data:`None`
    #: otherwise.
    reserved: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, format: 'Literal["I", "S", "U"]',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
                     function: 'Optional[Enum_SupervisoryFunction | Enum_ModifierFunction]',  # pylint: disable=unused-argument
                     send_seq: 'Optional[int]', recv_seq: 'Optional[int]', poll_final: 'bool',  # pylint: disable=unused-argument
                     reserved: 'Optional[int]') -> 'None': ...  # pylint: disable=unused-argument


@info_final
class LLC(Protocol):
    """Data model for LLC PDUs."""

    #: DSAP address, whose least significant bit is the I/G bit, ``1`` for a
    #: group address.
    dsap: 'Enum_LSAP'
    #: SSAP address, without its C/R bit.
    ssap: 'Enum_LSAP'
    #: C/R bit of the SSAP, :data:`True` for a response.
    cr: 'bool'
    #: Control field.
    control: 'Control'

    if TYPE_CHECKING:
        def __init__(self, dsap: 'Enum_LSAP', ssap: 'Enum_LSAP', cr: 'bool', control: 'Control') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
