# -*- coding: utf-8 -*-
"""host identity protocol

:mod:`pcapkit.protocols.internet.hip` contains
:class:`~pcapkit.protocols.internet.hip.HIP` only,
which implements extractor for Host Identity
Protocol (HIP) [*]_, whose structure is described
as below:

======= ========= ====================== ==================================
Octets      Bits        Name                    Description
======= ========= ====================== ==================================
  0           0   ``hip.next``              Next Header
  1           8   ``hip.length``            Header Length
  2          16                             Reserved (\\x00)
  2          17   ``hip.type``              Packet Type
  3          24   ``hip.version``           Version
  3          28                             Reserved
  3          31                             Reserved (\\x01)
  4          32   ``hip.chksum``            Checksum
  6          48   ``hip.control``           Controls
  8          64   ``hip.shit``              Sender's Host Identity Tag
  24        192   ``hip.rhit``              Receiver's Host Identity Tag
  40        320   ``hip.parameters``        HIP Parameters
======= ========= ====================== ==================================

.. [*] https://en.wikipedia.org/wiki/Host_Identity_Protocol

"""
import collections
import ipaddress

from pcapkit.const.hip.certificate import Certificate as _CERT_TYPE
from pcapkit.const.hip.cipher import Cipher as _CIPHER_ID
from pcapkit.const.hip.di import DITypes as _DI_TYPE
from pcapkit.const.hip.ecdsa_curve import ECDSACurve as _ECDSA_CURVE
from pcapkit.const.hip.ecdsa_low_curve import ECDSALowCurve as _ECDSA_LOW_CURVE
from pcapkit.const.hip.esp_transform_suite import ESPTransformSuite as _ESP_SUITE_ID
from pcapkit.const.hip.group import Group as _GROUP_ID
from pcapkit.const.hip.hi_algorithm import HIAlgorithm as _HI_ALGORITHM
from pcapkit.const.hip.hit_suite import HITSuite as _HIT_SUITE_ID
from pcapkit.const.hip.nat_traversal import NATTraversal as _MODE_ID
from pcapkit.const.hip.notify_message import NotifyMessage as _NOTIFICATION_TYPE
from pcapkit.const.hip.packet import Packet as _HIP_TYPES
from pcapkit.const.hip.parameter import Parameter as _HIP_PARA
from pcapkit.const.hip.registration import Registration as _REG_TYPE
from pcapkit.const.hip.registration_failure import RegistrationFailure as _REG_FAILURE_TYPE
from pcapkit.const.hip.suite import Suite as _SUITE_ID
from pcapkit.const.hip.transport import Transport as _TP_MODE_ID
from pcapkit.const.reg.transtype import TransType as TP_PROTO
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

__all__ = ['HIP']


class HIP(Internet):
    """This class implements Host Identity Protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['Host Identity Protocol', 'Host Identity Protocol Version 2']
        """
        if self._info.version == 2:  # pylint: disable=E1101
            return 'Host Identity Protocol Version 2'
        return 'Host Identity Protocol'

    @property
    def alias(self):
        """Acronym of corresponding protocol.

        :rtype: str
        """
        return f'HIPv{self._info.version}'  # pylint: disable=E1101

    @property
    def length(self):
        """Header length of current protocol.

        :rtype: int
        """
        return self._info.length  # pylint: disable=E1101

    @property
    def payload(self):
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        :rtype: pcapkit.protocols.protocol.Protocol
        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return self._next

    @property
    def protocol(self):
        """Name of next layer protocol.

        :rtype: pcapkit.const.reg.transtype.TransType
        """
        return self._info.next  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_hip(self, length, extension):
        """Read Host Identity Protocol.

        Structure of HIP header [:rfc:`5201`][:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Next Header   | Header Length |0| Packet Type |Version| RES.|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Checksum             |           Controls            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                Sender's Host Identity Tag (HIT)               |
            |                                                               |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |               Receiver's Host Identity Tag (HIT)              |
            |                                                               |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            /                        HIP Parameters                         /
            /                                                               /
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length (int): packet length

        Returns:
            DataType_HIP: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        _type = self._read_binary(1)
        if _type[0] != '0':
            raise ProtocolError('HIP: invalid format')
        _vers = self._read_binary(1)
        if _vers[7] != '1':
            raise ProtocolError('HIP: invalid format')
        _csum = self._read_fileng(2)
        _ctrl = self._read_binary(2)
        _shit = self._read_unpack(16)
        _rhit = self._read_unpack(16)

        hip = dict(
            next=_next,
            length=(_hlen + 1) * 8,
            type=_HIP_TYPES.get(int(_type[1:], base=2), 'Unassigned'),
            version=int(_vers[:4], base=2),
            chksum=_csum,
            control=dict(
                anonymous=bool(int(_ctrl[15], base=2)),
            ),
            shit=_shit,
            rhit=_rhit,
        )

        _prml = _hlen - 38
        if _prml:
            parameters = self._read_hip_para(_prml, version=hip['version'])
            hip['parameters'] = parameters[0]   # tuple of parameter acronyms
            hip.update(parameters[1])           # merge parameters info to buffer

        length -= hip['length']
        hip['packet'] = self._read_packet(header=hip['length'], payload=length)

        if extension:
            self._protos = None
            return hip
        return self._decode_next_layer(hip, _next, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, *, extension=False, **kwargs):  # pylint: disable=super-init-not-called
        """Initialisation.

        Args:
            file (io.BytesIO): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            extension (bool): If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        """
        self._file = _file
        self._extf = extension
        self._info = Info(self.read_hip(length, extension))

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[40]
        """
        return 40

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            pcapkit.const.reg.transtype.TransType: Numeral registry index of the
            protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return TP_PROTO(139)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_hip_para(self, length, *, version):
        """Read HIP parameters.

        Arguments:
            length (int): length of parameters

        Keyword arguments:
            version (Litreal[1, 2]): HIP version

        Returns:
            Tuple[Tuple[pcapkit.const.hip.parameter.Parameter], DataType_Parameter]: extracted HIP parameters

        Raises:
            ProtocolError: if packet length threshold check failed

        """
        counter = 0         # length of read parameters
        optkind = list()    # parameter type list
        options = dict()    # dict of parameter data

        while counter < length:
            # break when eol triggered
            kind = self._read_binary(2)
            if not kind:
                break

            # get parameter type & C-bit
            code = int(kind, base=2)
            cbit = bool(int(kind[15], base=2))

            # get parameter length
            clen = self._read_unpack(2)
            plen = 11 + clen - (clen + 3) % 8

            # extract parameter
            dscp = _HIP_PARA.get(code, 'Unassigned')
            meth_name = f'_read_para_{dscp.name.split(" [")[0].lower()}'
            meth = getattr(self, meth_name, '_read_para_unassigned')
            data = meth(self, code, cbit, clen, desc=dscp, length=plen, version=version)

            # record parameter data
            counter += plen
            if dscp in optkind:
                if isinstance(options[dscp], tuple):
                    options[dscp] += (Info(data),)
                else:
                    options[dscp] = (Info(options[dscp]), Info(data))
            else:
                optkind.append(dscp)
                options[dscp] = data

        # check threshold
        if counter != length:
            raise ProtocolError(f'HIPv{version}: invalid format')

        return tuple(optkind), options

    def _read_para_unassigned(self, code, cbit, clen, *, desc, length, version):  # pylint: disable=unused-argument
        """Read HIP unassigned parameters.

        Structure of HIP unassigned parameters [:rfc:`5201`][:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type            |C|             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            /                          Contents                             /
            /                                               +-+-+-+-+-+-+-+-+
            |                                               |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_Unassigned: Parsed parameter data.

        """
        unassigned = dict(
            type=desc,
            critical=cbit,
            length=clen,
            contents=self._read_fileng(clen),
        )

        plen = length - clen
        if plen:
            self._read_fileng(plen)

        return unassigned

    def _read_para_esp_info(self, code, cbit, clen, *, desc, length, version):  # pylint: disable=unused-argument
        """Read HIP ``ESP_INFO`` parameter.

        Structure of HIP ``ESP_INFO`` parameter [:rfc:`7402`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Reserved            |         KEYMAT Index          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            OLD SPI                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            NEW SPI                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_ESP_Info: Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``12``.

        """
        if clen != 12:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _resv = self._read_fileng(2)
        _kind = self._read_unpack(2)
        _olds = self._read_unpack(2)
        _news = self._read_unpack(2)

        esp_info = dict(
            type=desc,
            critical=cbit,
            length=clen,
            index=_kind,
            old_spi=_olds,
            new_spi=_news,
        )

        return esp_info

    def _read_para_r1_counter(self, code, cbit, clen, *, desc, length, version):  # pylint: disable=unused-argument
        """Read HIP ``R1_COUNTER`` parameter.

        Structure of HIP ``R1_COUNTER`` parameter [:rfc:`5201`][:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                       Reserved, 4 bytes                       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                R1 generation counter, 8 bytes                 |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_R1_Counter: Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``12`` or the parameter is **NOT** used in HIPv1.

        """
        if clen != 12:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')
        if code == 128 and version != 1:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid parameter')

        _resv = self._read_fileng(4)
        _genc = self._read_unpack(8)

        r1_counter = dict(
            type=desc,
            critical=cbit,
            length=clen,
            count=_genc,
        )

        return r1_counter

    def _read_para_locator_set(self, code, cbit, clen, *, desc, length, version):  # pylint: disable=unused-argument
        """Read HIP ``LOCATOR_SET`` parameter.

        Structure of HIP ``LOCATOR_SET`` parameter [:rfc:`8046`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |            Length             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Traffic Type   | Locator Type | Locator Length | Reserved   |P|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                       Locator Lifetime                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Locator                            |
            |                                                               |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            .                                                               .
            .                                                               .
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Traffic Type   | Locator Type | Locator Length | Reserved   |P|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                       Locator Lifetime                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Locator                            |
            |                                                               |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_Locator_Set: Parsed parameter data.

        Raises:
            ProtocolError: If locator data is malformed.

        """
        def _read_locator(kind, size):
            """Parse locator data.

            Args:
                kind (int): locator type
                size (int): locator length

            Returns:
                * If ``kind`` is ``0`` and ``size`` is ``16``,
                  returns an :class:`~ipaddress.IPv4Address` object.
                * If ``kind`` is ``1`` and ``size`` is ``20``,
                  returns a :class:`locator <DataType_Locator_Dict>` object.

            Raises:
                ProtocolError: in other cases

            """
            if kind == 0 and size == 16:
                return ipaddress.ip_address(self._read_fileng(16))
            if kind == 1 and size == 20:
                return dict(
                    spi=self._read_unpack(4),
                    ip=ipaddress.ip_address(self._read_fileng(16)),
                )
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _size = 0           # length of read locators
        _locs = list()      # list of locators

        while _size < clen:
            _traf = self._read_unpack(1)
            _loct = self._read_unpack(1)
            _locl = self._read_unpack(1) * 4
            _resp = self._read_binary(1)
            _life = self._read_unpack(4)
            _lobj = _read_locator(_loct, _locl)

            _locs.append(Info(
                traffic=_traf,
                type=_loct,
                length=_locl,
                preferred=int(_resp[7], base=2),
                lifetime=_life,
                object=_lobj,
            ))

        locator_set = dict(
            type=desc,
            critical=cbit,
            length=clen,
            locator=tuple(_locs),
        )

        return locator_set

    def _read_para_puzzle(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ``PUZZLE`` parameter.

        Structure of HIP ``PUZZLE`` parameter [:rfc:`5201`][:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  #K, 1 byte   |    Lifetime   |        Opaque, 2 bytes        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                      Random #I, RHASH_len / 8 bytes           |
            /                                                               /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_Puzzle: Parsed parameter data.

        Raises:
            ProtocolError: The parameter is **ONLY** supported in HIPv1.

        """
        if version == 1 and clen != 12:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _numk = self._read_unpack(1)
        _time = self._read_unpack(1)
        _opak = self._read_fileng(2)
        _rand = self._read_unpack(clen-4)

        puzzle = dict(
            type=desc,
            critical=cbit,
            length=clen,
            number=_numk,
            lifetime=2 ** (_time - 32),
            opaque=_opak,
            random=_rand,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return puzzle

    def _read_para_solution(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ``SOLUTION`` parameter.

        Structure of HIP ``SOLUTION`` parameter [:rfc:`5201`][:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  #K, 1 byte   |    Lifetime   |        Opaque, 2 bytes        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                      Random #I, n bytes                       |
            /                                                               /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |            Puzzle solution #J, RHASH_len / 8 bytes            |
            /                                                               /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_Solution: Parsed parameter data.

        Raises:
            ProtocolError: The parameter is **ONLY** supported in HIPv1.

        """
        if version == 1 and clen != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')
        if (clen - 4) % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _numk = self._read_unpack(1)
        _time = self._read_unpack(1)
        _opak = self._read_fileng(2)
        _rand = self._read_unpack((clen-4)//2)
        _solv = self._read_unpack((clen-4)//2)

        solution = dict(
            type=desc,
            critical=cbit,
            length=clen,
            number=_numk,
            lifetime=2 ** (_time - 32),
            opaque=_opak,
            random=_rand,
            solution=_solv,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return solution

    def _read_para_seq(self, code, cbit, clen, *, desc, length, version):  # pylint: disable=unused-argument
        """Read HIP ``SEQ`` parameter.

        Structure of HIP ``SEQ`` parameter [:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Update ID                          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_SEQ: Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``4``.

        """
        if clen != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _upid = self._read_unpack(4)

        seq = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=_upid,
        )

        return seq

    def _read_para_ack(self, code, cbit, clen, *, desc, length, version):  # pylint: disable=unused-argument
        """Read HIP ``ACK`` parameter.

        Structure of HIP ``ACK`` parameter [:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                       peer Update ID 1                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                       peer Update ID n                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_ACK: Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``4`` modulo.

        """
        if clen % 4 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _upid = list()
        for _ in range(clen // 4):
            _upid.append(self._read_unpack(4))

        ack = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=tuple(_upid),
        )

        return ack

    def _read_para_dh_group_list(self, code, cbit, clen, *, desc, length, version):  # pylint: disable=unused-argument
        """Read HIP ``DH_GROUP_LIST`` parameter.

        Structure of HIP ``DH_GROUP_LIST`` parameter [:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | DH GROUP ID #1| DH GROUP ID #2| DH GROUP ID #3| DH GROUP ID #4|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | DH GROUP ID #n|                Padding                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_DH_Group_List: Parsed parameter data.

        """
        _dhid = list()
        for _ in range(clen):
            _dhid.append(_GROUP_ID.get(self._read_unpack(1), 'Unassigned'))

        dh_group_list = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=tuple(_dhid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return dh_group_list

    def _read_para_diffie_hellman(self, code, cbit, clen, *, desc, length, version):  # pylint: disable=unused-argument
        """Read HIP ``DIFFIE_HELLMAN`` parameter.

        Structure of HIP ``DIFFIE_HELLMAN`` parameter [:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Group ID    |      Public Value Length      | Public Value  /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_Diffie_Hellman: Parsed parameter data.

        """
        _gpid = self._read_unpack(1)
        _vlen = self._read_unpack(2)
        _pval = self._read_fileng(_vlen)

        diffie_hellman = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=_GROUP_ID.get(_gpid, 'Unassigned'),
            pub_len=_vlen,
            pub_val=_pval,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return diffie_hellman

    def _read_para_hip_transform(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ``HIP_TRANSFORM`` parameter.

        Structure of HIP ``HIP_TRANSFORM`` parameter [:rfc:`5201`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |            Suite ID #1        |          Suite ID #2          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |            Suite ID #n        |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_Transform: Parsed parameter data.

        Raises:
            ProtocolError: The parameter is **ONLY** supported in HIPv1.

        """
        if version != 1:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid parameter')
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _stid = list()
        for _ in range(clen // 2):
            _stid.append(_SUITE_ID.get(self._read_unpack(2), 'Unassigned'))

        hip_transform = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=tuple(_stid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_transform

    def _read_para_hip_cipher(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ``HIP_CIPHER`` parameter.

        Structure of HIP ``HIP_CIPHER`` parameter [:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Cipher ID #1         |          Cipher ID #2         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Cipher ID #n         |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_Cipher: Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** a ``2`` modulo.

        """
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _cpid = list()
        for _ in range(clen // 2):
            _cpid.append(_CIPHER_ID.get(self._read_unpack(2), 'Unassigned'))

        hip_cipher = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=_cpid,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_cipher

    def _read_para_nat_traversal_mode(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ``NAT_TRAVERSAL_MODE`` parameter.

        Structure of HIP ``NAT_TRAVERSAL_MODE`` parameter [:rfc:`5770`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Reserved            |            Mode ID #1         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Mode ID #2          |            Mode ID #3         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Mode ID #n          |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_NET_Traversal_Mode: Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** a ``2`` modulo.

        """
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _resv = self._read_fileng(2)
        _mdid = list()
        for _ in range((clen - 2) // 2):
            _mdid.append(_MODE_ID.get(self._read_unpack(2), 'Unassigned'))

        nat_traversal_mode = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=tuple(_mdid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return nat_traversal_mode

    def _read_para_transaction_pacing(self, code, cbit, clen, *, desc, length, version):  # pylint: disable=unused-argument
        """Read HIP ``TRANSACTION_PACING`` parameter.

        Structure of HIP ``TRANSACTION_PACING`` parameter [:rfc:`5770`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Min Ta                             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_Transaction_Pacing: Parsed parameter data.

        Raises:
            ProtocolError: If ``clen`` is **NOT** ``4``.

        """
        if clen != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _data = self._read_unpack(4)

        transaction_pacing = dict(
            type=desc,
            critical=cbit,
            length=clen,
            min_ta=_data,
        )

        return transaction_pacing

    def _read_para_encrypted(self, code, cbit, clen, *, desc, length, version):  # pylint: disable=unused-argument
        """Read HIP ``ENCRYPTED`` parameter.

        Structure of HIP ``ENCRYPTED`` parameter [:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                           Reserved                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                              IV                               /
            /                                                               /
            /                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
            /                        Encrypted data                         /
            /                                                               /
            /                               +-------------------------------+
            /                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_Encrypted: Parsed parameter data.

        """
        _resv = self._read_fileng(4)
        _data = self._read_fileng(clen-4)

        encrypted = dict(
            type=desc,
            critical=cbit,
            length=clen,
            raw=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return encrypted

    def _read_para_host_id(self, code, cbit, clen, *, desc, length, version):  # pylint: disable=unused-argument
        """Read HIP ``HOST_ID`` parameter.

        Structure of HIP ``HOST_ID`` parameter [:rfc:`7401`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          HI Length            |DI-Type|      DI Length        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Algorithm            |         Host Identity         /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                               |       Domain Identifier       /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                                               |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): parameter code
            cbit (bool): critical bit
            clen (int): length of contents

        Keyward args:
            desc (pcapkit.const.hip.parameter.Parameter): parameter type
            length (int): remaining packet length
            version (Literal[1, 2]): HIP protocol version

        Returns:
            DataType_Param_Host_ID: Parsed parameter data.

        """
        def _read_host_identifier(length, code):
            """Read host identity.

            Args:
                length (int): length of host identity
                code (int): host identity type

            Returns:
                Tuple[pcapkit.const.hip.hi_algorithm.HIAlgorithm, Union[bytes, DataType_Host_ID_ECDSA_Curve,
                DataType_Host_ID_ECDSA_LOW_Curve]]: Parsed host identity data.

            """
            algorithm = _HI_ALGORITHM.get(code, 'Unassigned')
            if algorithm == _HI_ALGORITHM.ECDSA:
                host_id = dict(
                    curve=_ECDSA_CURVE.get(self._read_unpack(2)),
                    pubkey=self._read_fileng(length-2),
                )
            elif algorithm == _HI_ALGORITHM.ECDSA_LOW:
                host_id = dict(
                    curve=_ECDSA_LOW_CURVE.get(self._read_unpack(2)),
                    pubkey=self._read_fileng(length-2),
                )
            else:
                host_id = self._read_fileng(length)
            return algorithm, host_id

        def _read_domain_identifier(di_data):
            """Read domain identifier.

            Args:
                di_data (str): bit string of DI information byte

            Returns:
                Tuple[pcapkit.const.hip.di_type.DIType, int, bytes]: A :data:`tuple` of
                DI type enumeration, DI content length and DI data.

            """
            di_type = _DI_TYPE.get(int(di_data[:4], base=2), 'Unassigned')
            di_len = int(di_data[4:], base=2)
            domain_id = self._read_fileng(di_len)
            return di_type, di_len, domain_id

        _hlen = self._read_unpack(2)
        _didt = self._read_binary(2)
        _algo = self._read_unpack(2)
        _hidf = _read_host_identifier(_hlen, _algo)
        _didf = _read_domain_identifier(_didt)

        host_id = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id_len=_hlen,
            di_type=_didf[0],
            di_len=_didf[1],
            algorithm=_hidf[0],
            host_id=_hidf[1],
            domain_id=_didf[2],
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return host_id

    def _read_para_hit_suite_list(self, code, cbit, clen, *, desc, length, version):
        """Read HIP HIT_SUITE_LIST parameter.

        Structure of HIP HIT_SUITE_LIST parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     ID #1     |     ID #2     |     ID #3     |     ID #4     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     ID #n     |                Padding                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     hit_suite_list.type     Parameter Type
              1          15     hit_suite_list.critical Critical Bit
              2          16     hit_suite_list.length   Length of Contents
              4          32     hit_suite_list.id       HIT Suite ID
                                ............
              ?           ?     -                       Padding

        """
        _hsid = list()
        for _ in range(clen):
            _hsid.append(_HIT_SUITE_ID.get(self._read_unpack(1), 'Unassigned'))

        hit_suite_list = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=tuple(_hsid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hit_suite_list

    def _read_para_cert(self, code, cbit, clen, *, desc, length, version):
        """Read HIP CERT parameter.

        Structure of HIP CERT parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  CERT group   |  CERT count   |    CERT ID    |   CERT type   |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                          Certificate                          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                               |   Padding (variable length)   |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                Description
              0           0     cert.type           Parameter Type
              1          15     cert.critical       Critical Bit
              2          16     cert.length         Length of Contents
              4          32     cert.group          CERT Group
              5          40     cert.count          CERT Count
              6          48     cert.id             CERT ID
              7          56     cert.cert_type      CERT Type
              8          64     cert.certificate    Certificate
              ?           ?     -                   Padding

        """
        _ctgp = self._read_unpack(1)
        _ctct = self._read_unpack(1)
        _ctid = self._read_unpack(1)
        _cttp = self._read_unpack(1)
        _ctdt = self._read_fileng(clen-4)

        cert = dict(
            type=desc,
            critical=cbit,
            length=clen,
            group=_GROUP_ID.get(_ctgp, 'Unassigned'),
            count=_ctct,
            id=_ctid,
            cert_type=_CERT_TYPE.get(_cttp, 'Unassigned'),
            certificate=_ctdt,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return cert

    def _read_para_notification(self, code, cbit, clen, *, desc, length, version):
        """Read HIP NOTIFICATION parameter.

        Structure of HIP NOTIFICATION parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Reserved             |      Notify Message Type      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               /
            /                   Notification Data                           /
            /                                               +---------------+
            /                                               |     Padding   |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     notification.type       Parameter Type
              1          15     notification.critical   Critical Bit
              2          16     notification.length     Length of Contents
              4          32     -                       Reserved
              6          48     notification.msg_type   Notify Message Type
              8          64     notification.data       Notification Data
              ?           ?     -                       Padding

        """
        _resv = self._read_fileng(2)
        _code = self._read_unpack(2)
        _data = self._read_fileng(2)

        _type = _NOTIFICATION_TYPE.get(_code)
        if _type is None:
            if 1 <= _code <= 50:
                _type = 'Unassigned (IETF Review)'
            elif 51 <= _code <= 8191:
                _type = 'Unassigned (Specification Required; Error Message)'
            elif 8192 <= _code <= 16383:
                _type = 'Unassigned (Reserved for Private Use; Error Message)'
            elif 16384 <= _code <= 40959:
                _type = 'Unassigned (Specification Required; Status Message)'
            elif 40960 <= _code <= 65535:
                _type = 'Unassigned (Reserved for Private Use; Status Message)'
            else:
                raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        notification = dict(
            type=desc,
            critical=cbit,
            length=clen,
            msg_type=_type,
            data=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return notification

    def _read_para_echo_request_signed(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ECHO_REQUEST_SIGNED parameter.

        Structure of HIP ECHO_REQUEST_SIGNED parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                 Opaque data (variable length)                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     echo_request_signed.type        Parameter Type
              1          15     echo_request_signed.critical    Critical Bit
              2          16     echo_request_signed.length      Length of Contents
              4          32     echo_request_signed.data        Opaque Data

        """
        _data = self._read_fileng(clen)

        echo_request_signed = dict(
            type=desc,
            critical=cbit,
            length=clen,
            data=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_request_signed

    def _read_para_reg_info(self, code, cbit, clen, *, desc, length, version):
        """Read HIP REG_INFO parameter.

        Structure of HIP REG_INFO parameter [RFC 8003]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Min Lifetime  | Max Lifetime  |  Reg Type #1  |  Reg Type #2  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |      ...      |     ...       |  Reg Type #n  |               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    Padding    +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     reg_info.type           Parameter Type
              1          15     reg_info.critical       Critical Bit
              2          16     reg_info.length         Length of Contents
              4          32     reg_info.lifetime       Lifetime
              4          32     reg_info.lifetime.min   Min Lifetime
              5          40     reg_info.lifetime.max   Max Lifetime
              6          48     reg_info.reg_type       Reg Type
                                ...........
              ?           ?     -                       Padding

        """
        _life = collections.namedtuple('Lifetime', ('min', 'max'))
        _mint = self._read_unpack(1)
        _maxt = self._read_unpack(1)
        _type = list()
        for _ in range(clen-2):
            _code = self._read_unpack(1)
            _kind = _REG_TYPE.get(_code)
            if _kind is None:
                if 0 <= _code <= 200:
                    _kind = 'Unassigned (IETF Review)'
                elif 201 <= _code <= 255:
                    _kind = 'Unassigned (Reserved for Private Use)'
                else:
                    raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')
            _type.append(_kind)

        reg_info = dict(
            type=desc,
            critical=cbit,
            length=clen,
            lifetime=_life(_mint, _maxt),
            reg_type=tuple(_type),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return reg_info

    def _read_para_reg_request(self, code, cbit, clen, *, desc, length, version):
        """Read HIP REG_REQUEST parameter.

        Structure of HIP REG_REQUEST parameter [RFC 8003]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Lifetime    |  Reg Type #1  |  Reg Type #2  |  Reg Type #3  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |      ...      |     ...       |  Reg Type #n  |               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    Padding    +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     reg_request.type            Parameter Type
              1          15     reg_request.critical        Critical Bit
              2          16     reg_request.length          Length of Contents
              4          32     reg_request.lifetime        Lifetime
              4          32     reg_request.lifetime.min    Min Lifetime
              5          40     reg_request.lifetime.max    Max Lifetime
              6          48     reg_request.reg_type        Reg Type
                                ...........
              ?           ?     -                           Padding

        """
        _life = collections.namedtuple('Lifetime', ('min', 'max'))
        _mint = self._read_unpack(1)
        _maxt = self._read_unpack(1)
        _type = list()
        for _ in range(clen-2):
            _code = self._read_unpack(1)
            _kind = _REG_TYPE.get(_code)
            if _kind is None:
                if 0 <= _code <= 200:
                    _kind = 'Unassigned (IETF Review)'
                elif 201 <= _code <= 255:
                    _kind = 'Unassigned (Reserved for Private Use)'
                else:
                    raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')
            _type.append(_kind)

        reg_request = dict(
            type=desc,
            critical=cbit,
            length=clen,
            lifetime=_life(_mint, _maxt),
            reg_type=tuple(_type),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return reg_request

    def _read_para_reg_response(self, code, cbit, clen, *, desc, length, version):
        """Read HIP REG_RESPONSE parameter.

        Structure of HIP REG_RESPONSE parameter [RFC 8003]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Lifetime    |  Reg Type #1  |  Reg Type #2  |  Reg Type #3  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |      ...      |     ...       |  Reg Type #n  |               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    Padding    +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     reg_response.type           Parameter Type
              1          15     reg_response.critical       Critical Bit
              2          16     reg_response.length         Length of Contents
              4          32     reg_response.lifetime       Lifetime
              4          32     reg_response.lifetime.min   Min Lifetime
              5          40     reg_response.lifetime.max   Max Lifetime
              6          48     reg_response.reg_type       Reg Type
                                ...........
              ?           ?     -                           Padding

        """
        _life = collections.namedtuple('Lifetime', ('min', 'max'))
        _mint = self._read_unpack(1)
        _maxt = self._read_unpack(1)
        _type = list()
        for _ in range(clen-2):
            _code = self._read_unpack(1)
            _kind = _REG_TYPE.get(_code)
            if _kind is None:
                if 0 <= _code <= 200:
                    _kind = 'Unassigned (IETF Review)'
                elif 201 <= _code <= 255:
                    _kind = 'Unassigned (Reserved for Private Use)'
                else:
                    raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')
            _type.append(_kind)

        reg_response = dict(
            type=desc,
            critical=cbit,
            length=clen,
            lifetime=_life(_mint, _maxt),
            reg_type=tuple(_type),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return reg_response

    def _read_para_reg_failed(self, code, cbit, clen, *, desc, length, version):
        """Read HIP REG_FAILED parameter.

        Structure of HIP REG_FAILED parameter [RFC 8003]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Lifetime    |  Reg Type #1  |  Reg Type #2  |  Reg Type #3  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |      ...      |     ...       |  Reg Type #n  |               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    Padding    +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     reg_failed.type             Parameter Type
              1          15     reg_failed.critical         Critical Bit
              2          16     reg_failed.length           Length of Contents
              4          32     reg_failed.lifetime         Lifetime
              4          32     reg_failed.lifetime.min     Min Lifetime
              5          40     reg_failed.lifetime.max     Max Lifetime
              6          48     reg_failed.reg_typetype     Reg Type
                                ...........
              ?           ?     -                           Padding

        """
        _life = collections.namedtuple('Lifetime', ('min', 'max'))
        _mint = self._read_unpack(1)
        _maxt = self._read_unpack(1)
        _type = list()
        for _ in range(clen-2):
            _code = self._read_unpack(1)
            _kind = _REG_FAILURE_TYPE.get(_code)
            if _kind is None:
                if 0 <= _code <= 200:
                    _kind = 'Unassigned (IETF Review)'
                elif 201 <= _code <= 255:
                    _kind = 'Unassigned (Reserved for Private Use)'
                else:
                    raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')
            _type.append(_kind)

        reg_failed = dict(
            type=desc,
            critical=cbit,
            length=clen,
            lifetime=_life(_mint, _maxt),
            reg_type=tuple(_type),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return reg_failed

    def _read_para_reg_from(self, code, cbit, clen, *, desc, length, version):
        """Read HIP REG_FROM parameter.

        Structure of HIP REG_FROM parameter [RFC 5770]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Port              |    Protocol   |     Reserved  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            Address                            |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     reg_from.type               Parameter Type
              1          15     reg_from.critical           Critical Bit
              2          16     reg_from.length             Length of Contents
              4          32     reg_from.port               Port
              6          48     reg_from.protocol           Protocol
              7          56     -                           Reserved
              8          64     reg_from.ip                 Address (IPv6)

        """
        if clen != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _port = self._read_unpack(2)
        _ptcl = self._read_unpack(1)
        _resv = self._read_fileng(1)
        _addr = self._read_fileng(16)

        reg_from = dict(
            type=desc,
            critical=cbit,
            length=clen,
            port=_port,
            protocol=TP_PROTO.get(_ptcl),
            ip=ipaddress.ip_address(_addr),
        )

        return reg_from

    def _read_para_echo_response_signed(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ECHO_RESPONSE_SIGNED parameter.

        Structure of HIP ECHO_RESPONSE_SIGNED parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                 Opaque data (variable length)                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     echo_response_signed.type       Parameter Type
              1          15     echo_response_signed.critical   Critical Bit
              2          16     echo_response_signed.length     Length of Contents
              4          32     echo_response_signed.data       Opaque Data

        """
        _data = self._read_fileng(clen)

        echo_response_signed = dict(
            type=desc,
            critical=cbit,
            length=clen,
            data=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_response_signed

    def _read_para_transport_format_list(self, code, cbit, clen, *, desc, length, version):
        """Read HIP TRANSPORT_FORMAT_LIST parameter.

        Structure of HIP TRANSPORT_FORMAT_LIST parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          TF type #1           |           TF type #2          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /          TF type #n           |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     transport_format_list.type      Parameter Type
              1          15     transport_format_list.critical  Critical Bit
              2          16     transport_format_list.length    Length of Contents
              4          32     transport_format_list.tf_type   TF Type
                                ............
              ?           ?     -                               Padding

        """
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _tfid = list()
        for _ in range(clen // 2):
            _tfid.append(self._read_unpack(2))

        transport_format_list = dict(
            type=desc,
            critical=cbit,
            length=clen,
            tf_type=tuple(_tfid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return transport_format_list

    def _read_para_esp_transform(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ESP_TRANSFORM parameter.

        Structure of HIP ESP_TRANSFORM parameter [RFC 7402]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Reserved             |           Suite ID #1         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Suite ID #2          |           Suite ID #3         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Suite ID #n          |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     esp_transform.type              Parameter Type
              1          15     esp_transform.critical          Critical Bit
              2          16     esp_transform.length            Length of Contents
              4          32     -                               Reserved
              6          48     esp_transform.id                Suite ID
                                ............
              ?           ?     -                               Padding

        """
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _resv = self._read_fileng(2)
        _stid = list()
        for _ in range((clen - 2) // 2):
            _stid.append(_ESP_SUITE_ID.get(self._read_unpack(2), 'Unassigned'))

        esp_transform = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=tuple(_stid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return esp_transform

    def _read_para_seq_data(self, code, cbit, clen, *, desc, length, version):
        """Read HIP SEQ_DATA parameter.

        Structure of HIP SEQ_DATA parameter [RFC 6078]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                        Sequence number                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     seq_data.type                   Parameter Type
              1          15     seq_data.critical               Critical Bit
              2          16     seq_data.length                 Length of Contents
              4          32     seq_data.seq                    Sequence number

        """
        if clen != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _seqn = self._read_unpack(4)

        seq_data = dict(
            type=desc,
            critical=cbit,
            length=clen,
            seq=_seqn,
        )

        return seq_data

    def _read_para_ack_data(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ACK_DATA parameter.

        Structure of HIP ACK_DATA parameter [RFC 6078]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                     Acked Sequence number                     /
            /                                                               /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     ack_data.type                   Parameter Type
              1          15     ack_data.critical               Critical Bit
              2          16     ack_data.length                 Length of Contents
              4          32     ack_data.ack                    Acked Sequence number

        """
        if clen % 4 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _ackn = list()
        for _ in range(clen // 4):
            _ackn.append(self._read_unpack(4))

        ack_data = dict(
            type=desc,
            critical=cbit,
            length=clen,
            ack=tuple(_ackn),
        )

        return ack_data

    def _read_para_payload_mic(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ACK_DATA parameter.

        Structure of HIP ACK_DATA parameter [RFC 6078]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |                   Reserved                    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                         Payload Data                          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            /                         MIC Value                             /
            /                                               +-+-+-+-+-+-+-+-+
            |                                               |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     payload_mic.type                Parameter Type
              1          15     payload_mic.critical            Critical Bit
              2          16     payload_mic.length              Length of Contents
              4          32     payload_mic.next                Next Header
              5          40     -                               Reserved
              8          64     payload_mic.data                Payload Data
              12         96     payload_mic.value               MIC Value
              ?           ?     -                               Padding

        """
        _next = self._read_unpack(1)
        _resv = self._read_fileng(3)
        _data = self._read_fileng(4)
        _micv = self._read_fileng(clen-8)

        payload_mic = dict(
            type=desc,
            critical=cbit,
            length=clen,
            next=TP_PROTO.get(_next),
            data=_data,
            value=_micv,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return payload_mic

    def _read_para_transaction_id(self, code, cbit, clen, *, desc, length, version):
        """Read HIP TRANSACTION_ID parameter.

        Structure of HIP TRANSACTION_ID parameter [RFC 6078]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                           Identifier                          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                                               |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     transaction_id.type             Parameter Type
              1          15     transaction_id.critical         Critical Bit
              2          16     transaction_id.length           Length of Contents
              4          32     transaction_id.id               Identifier

        """
        _tsid = self._read_unpack(clen)

        transaction_id = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=_tsid,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return transaction_id

    def _read_para_overlay_id(self, code, cbit, clen, *, desc, length, version):
        """Read HIP TRANSACTION_ID parameter.

        Structure of HIP TRANSACTION_ID parameter [RFC 6079]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                           Identifier                          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                                               |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     overlay_id.type                 Parameter Type
              1          15     overlay_id.critical             Critical Bit
              2          16     overlay_id.length               Length of Contents
              4          32     overlay_id.id                   Identifier

        """
        _olid = self._read_unpack(clen)

        overlay_id = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=_olid,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return overlay_id

    def _read_para_route_dst(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ROUTE_DST parameter.

        Structure of HIP ROUTE_DST parameter [RFC 6028]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Flags             |            Reserved           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            HIT #1                             |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            .                               .                               .
            .                               .                               .
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            HIT #n                             |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     route_dst.type                  Parameter Type
              1          15     route_dst.critical              Critical Bit
              2          16     route_dst.length                Length of Contents
              4          32     route_dst.flags                 Flags
              4          32     route_dst.flags.symmetric       SYMMETRIC [RFC 6028]
              4          33     route_dst.flags.must_follow     MUST_FOLLOW [RFC 6028]
              6          48     -                               Reserved
              8          64     route_dst.ip                    HIT
                                ............

        """
        if (clen - 4) % 16 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _flag = self._read_binary(2)
        _resv = self._read_fileng(2)
        _addr = list()
        for _ in range((clen - 4) // 16):
            _addr.append(ipaddress.ip_address(self._read_fileng(16)))

        route_dst = dict(
            type=desc,
            critical=cbit,
            length=clen,
            flags=dict(
                symmetric=True if int(_flag[0], base=2) else False,
                must_follow=True if int(_flag[1], base=2) else False,
            ),
            ip=tuple(_addr),
        )

        return route_dst

    def _read_para_hip_transport_mode(self, code, cbit, clen, *, desc, length, version):
        """Read HIP HIP_TRANSPORT_MODE parameter.

        Structure of HIP HIP_TRANSPORT_MODE parameter [RFC 6261]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Port              |           Mode ID #1          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Mode ID #2           |           Mode ID #3          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Mode ID #n           |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     hip_transport_mode.type         Parameter Type
              1          15     hip_transport_mode.critical     Critical Bit
              2          16     hip_transport_mode.length       Length of Contents
              4          32     hip_transport_mode.port         Port
              6          48     hip_transport_mode.id           Mode ID
                                ............
              ?           ?     -                               Padding

        """
        if clen % 2 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _port = self._read_unpack(2)
        _mdid = list()
        for _ in range((clen - 2) // 2):
            _mdid.append(_TP_MODE_ID.get(self._read_unpack(2), 'Unassigned'))

        hip_transport_mode = dict(
            type=desc,
            critical=cbit,
            length=clen,
            port=_port,
            id=tuple(_mdid),
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_transport_mode

    def _read_para_hip_mac(self, code, cbit, clen, *, desc, length, version):
        """Read HIP HIP_MAC parameter.

        Structure of HIP HIP_MAC parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                             HMAC                              |
            /                                                               /
            /                               +-------------------------------+
            |                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     hip_mac.type                    Parameter Type
              1          15     hip_mac.critical                Critical Bit
              2          16     hip_mac.length                  Length of Contents
              4          32     hip_mac.hmac                    HMAC
              ?           ?     -                               Padding

        """
        _hmac = self._read_fileng(clen)

        hip_mac = dict(
            type=desc,
            critical=cbit,
            length=clen,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_mac

    def _read_para_hip_mac_2(self, code, cbit, clen, *, desc, length, version):
        """Read HIP HIP_MAC_2 parameter.

        Structure of HIP HIP_MAC_2 parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                             HMAC                              |
            /                                                               /
            /                               +-------------------------------+
            |                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     hip_mac_2.type                  Parameter Type
              1          15     hip_mac_2.critical              Critical Bit
              2          16     hip_mac_2.length                Length of Contents
              4          32     hip_mac_2.hmac                  HMAC
              ?           ?     -                               Padding

        """
        _hmac = self._read_fileng(clen)

        hip_mac_2 = dict(
            type=desc,
            critical=cbit,
            length=clen,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_mac_2

    def _read_para_hip_signature_2(self, code, cbit, clen, *, desc, length, version):
        """Read HIP HIP_SIGNATURE_2 parameter.

        Structure of HIP HIP_SIGNATURE_2 parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |    SIG alg                    |            Signature          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                               |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     hip_signature_2.type            Parameter Type
              1          15     hip_signature_2.critical        Critical Bit
              2          16     hip_signature_2.length          Length of Contents
              4          32     hip_signature_2.algorithm       SIG Algorithm
              6          48     hip_signature_2.signature       Signature
              ?           ?     -                               Padding

        """
        _algo = self._read_unpack(2)
        _sign = self._read_fileng(clen-2)

        hip_signature_2 = dict(
            type=desc,
            critical=cbit,
            length=clen,
            algorithm=_HI_ALGORITHM.get(_algo, 'Unassigned'),
            signature=_sign,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_signature_2

    def _read_para_hip_signature(self, code, cbit, clen, *, desc, length, version):
        """Read HIP HIP_SIGNATURE parameter.

        Structure of HIP HIP_SIGNATURE parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |    SIG alg                    |            Signature          /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                               |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     hip_signature.type              Parameter Type
              1          15     hip_signature.critical          Critical Bit
              2          16     hip_signature.length            Length of Contents
              4          32     hip_signature.algorithm         SIG Algorithm
              6          48     hip_signature.signature         Signature
              ?           ?     -                               Padding

        """
        _algo = self._read_unpack(2)
        _sign = self._read_fileng(clen-2)

        hip_signature = dict(
            type=desc,
            critical=cbit,
            length=clen,
            algorithm=_HI_ALGORITHM.get(_algo, 'Unassigned'),
            signature=_sign,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_signature

    def _read_para_echo_request_unsigned(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ECHO_REQUEST_UNSIGNED parameter.

        Structure of HIP ECHO_REQUEST_UNSIGNED parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                 Opaque data (variable length)                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     echo_request_unsigned.type      Parameter Type
              1          15     echo_request_unsigned.critical  Critical Bit
              2          16     echo_request_unsigned.length    Length of Contents
              4          32     echo_request_unsigned.data      Opaque Data

        """
        _data = self._read_fileng(clen)

        echo_request_unsigned = dict(
            type=desc,
            critical=cbit,
            length=clen,
            data=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_request_unsigned

    def _read_para_echo_response_unsigned(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ECHO_RESPONSE_UNSIGNED parameter.

        Structure of HIP ECHO_RESPONSE_UNSIGNED parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                 Opaque data (variable length)                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     echo_response_unsigned.type     Parameter Type
              1          15     echo_response_unsigned.critical Critical Bit
              2          16     echo_response_unsigned.length   Length of Contents
              4          32     echo_response_unsigned.data     Opaque Data

        """
        _data = self._read_fileng(clen)

        echo_response_unsigned = dict(
            type=desc,
            critical=cbit,
            length=clen,
            data=_data,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return echo_response_unsigned

    def _read_para_relay_from(self, code, cbit, clen, *, desc, length, version):
        """Read HIP RELAY_FROM parameter.

        Structure of HIP RELAY_FROM parameter [RFC 5770]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Port              |    Protocol   |     Reserved  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            Address                            |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     relay_from.type             Parameter Type
              1          15     relay_from.critical         Critical Bit
              2          16     relay_from.length           Length of Contents
              4          32     relay_from.port             Port
              6          48     relay_from.protocol         Protocol
              7          56     -                           Reserved
              8          64     relay_from.ip               Address (IPv6)

        """
        if clen != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _port = self._read_unpack(2)
        _ptcl = self._read_unpack(1)
        _resv = self._read_fileng(1)
        _addr = self._read_fileng(16)

        relay_from = dict(
            type=desc,
            critical=cbit,
            length=clen,
            port=_port,
            protocol=TP_PROTO.get(_ptcl),
            ip=ipaddress.ip_address(_addr),
        )

        return relay_from

    def _read_para_relay_to(self, code, cbit, clen, *, desc, length, version):
        """Read HIP RELAY_TO parameter.

        Structure of HIP RELAY_TO parameter [RFC 5770]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Port              |    Protocol   |     Reserved  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            Address                            |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     relay_to.type               Parameter Type
              1          15     relay_to.critical           Critical Bit
              2          16     relay_to.length             Length of Contents
              4          32     relay_to.port               Port
              6          48     relay_to.protocol           Protocol
              7          56     -                           Reserved
              8          64     relay_to.ip                 Address (IPv6)

        """
        if clen != 20:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _port = self._read_unpack(2)
        _ptcl = self._read_unpack(1)
        _resv = self._read_fileng(1)
        _addr = self._read_fileng(16)

        relay_to = dict(
            type=desc,
            critical=cbit,
            length=clen,
            port=_port,
            protocol=TP_PROTO.get(_ptcl),
            ip=ipaddress.ip_address(_addr),
        )

        return relay_to

    def _read_para_overlay_ttl(self, code, cbit, clen, *, desc, length, version):
        """Read HIP OVERLAY_TTL parameter.

        Structure of HIP OVERLAY_TTL parameter [RFC 6078]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             TTL               |            Reserved           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     overlay_ttl.type                Parameter Type
              1          15     overlay_ttl.critical            Critical Bit
              2          16     overlay_ttl.length              Length of Contents
              4          32     overlay_ttl.ttl                 TTL
              6          48     -                               Reserved

        """
        if clen != 4:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _ttln = self._read_unpack(2)

        overlay_ttl = dict(
            type=desc,
            critical=cbit,
            length=clen,
            ttl=_ttln,
        )

        return overlay_ttl

    def _read_para_route_via(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ROUTE_VIA parameter.

        Structure of HIP ROUTE_VIA parameter [RFC 6028]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Flags             |            Reserved           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            HIT #1                             |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            .                               .                               .
            .                               .                               .
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            HIT #n                             |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     route_via.type                  Parameter Type
              1          15     route_via.critical              Critical Bit
              2          16     route_via.length                Length of Contents
              4          32     route_via.flags                 Flags
              4          32     route_via.flags.symmetric       SYMMETRIC [RFC 6028]
              4          33     route_via.flags.must_follow     MUST_FOLLOW [RFC 6028]
              6          48     -                               Reserved
              8          64     route_dst.ip                    HIT
                                ............

        """
        if (clen - 4) % 16 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _flag = self._read_binary(2)
        _resv = self._read_fileng(2)
        _addr = list()
        for _ in range((clen - 4) // 16):
            _addr.append(ipaddress.ip_address(self._read_fileng(16)))

        route_via = dict(
            type=desc,
            critical=cbit,
            length=clen,
            flags=dict(
                symmetric=True if int(_flag[0], base=2) else False,
                must_follow=True if int(_flag[1], base=2) else False,
            ),
            ip=tuple(_addr),
        )

        return route_via

    def _read_para_from(self, code, cbit, clen, *, desc, length, version):
        """Read HIP FROM parameter.

        Structure of HIP FROM parameter [RFC 8004]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                             Address                           |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     from.type                       Parameter Type
              1          15     from.critical                   Critical Bit
              2          16     from.length                     Length of Contents
              4          32     from.ip                         Address

        """
        if clen != 16:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _addr = self._read_fileng(16)

        from_ = dict(
            type=desc,
            critical=cbit,
            length=clen,
            ip=ipaddress.ip_address(_addr),
        )

        return from_

    def _read_para_rvs_hmac(self, code, cbit, clen, *, desc, length, version):
        """Read HIP RVS_HMAC parameter.

        Structure of HIP RVS_HMAC parameter [RFC 8004]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                             HMAC                              |
            /                                                               /
            /                               +-------------------------------+
            |                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     rvs_hmac.type                   Parameter Type
              1          15     rvs_hmac.critical               Critical Bit
              2          16     rvs_hmac.length                 Length of Contents
              4          32     rvs_hmac.hmac                   HMAC
              ?           ?     -                               Padding

        """
        _hmac = self._read_fileng(clen)

        rvs_hmac = dict(
            type=desc,
            critical=cbit,
            length=clen,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return rvs_hmac

    def _read_para_via_rvs(self, code, cbit, clen, *, desc, length, version):
        """Read HIP VIA_RVS parameter.

        Structure of HIP VIA_RVS parameter [RFC 6028]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            Address                            |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            .                               .                               .
            .                               .                               .
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                            Address                            |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     via_rvs.type                    Parameter Type
              1          15     via_rvs.critical                Critical Bit
              2          16     via_rvs.length                  Length of Contents
              4          32     via_rvs.ip                      Address
                                ............

        """
        if clen % 16 != 0:
            raise ProtocolError(f'HIPv{version}: [ParamNo {code}] invalid format')

        _addr = list()
        for _ in range(clen // 16):
            _addr.append(ipaddress.ip_address(self._read_fileng(16)))

        via_rvs = dict(
            type=desc,
            critical=cbit,
            length=clen,
            ip=tuple(_addr),
        )

        return via_rvs

    def _read_para_relay_hmac(self, code, cbit, clen, *, desc, length, version):
        """Read HIP RELAY_HMAC parameter.

        Structure of HIP RELAY_HMAC parameter [RFC 5770]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            |                             HMAC                              |
            /                                                               /
            /                               +-------------------------------+
            |                               |            Padding            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                            Description
              0           0     relay_hmac.type                 Parameter Type
              1          15     relay_hmac.critical             Critical Bit
              2          16     relay_hmac.length               Length of Contents
              4          32     relay_hmac.hmac                 HMAC
              ?           ?     -                               Padding

        """
        _hmac = self._read_fileng(clen)

        relay_hmac = dict(
            type=desc,
            critical=cbit,
            length=clen,
            hmac=_hmac,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return relay_hmac
