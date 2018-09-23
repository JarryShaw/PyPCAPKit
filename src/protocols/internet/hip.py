# -*- coding: utf-8 -*-
"""host identity protocol

`pcapkit.protocols.internet.hip` contains `HIP`
only, which implements extractor for Host Identity
Protocol (HIP), whose structure is described as below.

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

"""
import collections
import ipaddress

from pcapkit._common.hip_cert_type import CertType as _CERT_TYPE
from pcapkit._common.hip_cipher_id import CipherID as _CIPHER_ID
from pcapkit._common.hip_di_type import DI_TYPE as _DI_TYPE
from pcapkit._common.hip_ecdsa_curve import ECDSA as _ECDSA_CURVE
from pcapkit._common.hip_ecdsa_low_curve import ECDSA_LOW as _ECDSA_LOW_CURVE
from pcapkit._common.hip_esp_suite_id import ESP_SuiteID as _ESP_SUITE_ID
from pcapkit._common.hip_group_id import GroupID as _GROUP_ID
from pcapkit._common.hip_hi_algorithm import HI_ALG as _HI_ALGORITHM
from pcapkit._common.hip_hit_suite_id import HIT_SuiteID as _HIT_SUITE_ID
from pcapkit._common.hip_mode_id import ModeID as _MODE_ID
from pcapkit._common.hip_notification_type import MsgType as _NOTIFICATION_TYPE
from pcapkit._common.hip_para import ParamType as _HIP_PARA
from pcapkit._common.hip_reg_failure_type import \
    RegFailType as _REG_FAILURE_TYPE
from pcapkit._common.hip_reg_type import RegType as _REG_TYPE
from pcapkit._common.hip_suite_id import SuiteID as _SUITE_ID
from pcapkit._common.hip_tp_mode_id import TAT_ModeID as _TP_MODE_ID
from pcapkit._common.hip_types import PktType as _HIP_TYPES
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.transport.transport import TP_PROTO
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

__all__ = ['HIP']


def _HIP_PROC(dscp):
    """HIP parameter process functions."""
    return eval('lambda self, code, cbit, clen, *, desc, length, version: '
                'self._read_para_{}(code, cbit, clen, '
                'desc=desc, length=length, version=version)'.format(dscp.name.split(" [")[0].lower()))


class HIP(Internet):
    """This class implements Host Identity Protocol.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_hip -- read Host Identity Protocol (HIP)

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol."""
        if self._info.version == 2:
            return 'Host Identity Protocol Version 2'
        return 'Host Identity Protocol'

    @property
    def alias(self):
        """Acronym of corresponding protocol."""
        return 'HIPv{}'.format(self._info.version)

    @property
    def length(self):
        """Header length of current protocol."""
        return self._info.length

    @property
    def payload(self):
        """Payload of current instance."""
        if self._extf:
            raise UnsupportedCall("'{}' object has no attribute 'payload'".format(self.__class__.__name__))
        return self._next

    @property
    def protocol(self):
        """Name of next layer protocol."""
        return self._info.next

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_hip(self, length, extension):
        """Read Host Identity Protocol.

        Structure of HIP header [RFC 5201][RFC 7401]:
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

            Octets      Bits        Name                    Description
              0           0     hip.next                Next Header
              1           8     hip.length              Header Length
              2          16     -                       Reserved (0)
              2          17     hip.type                Packet Type
              3          24     hip.version             Version
              3          28     -                       Reserved
              3          31     -                       Reserved (1)
              4          32     hip.chksum              Checksum
              6          48     hip.control             Controls
              8          64     hip.shit                Sender's Host Identity Tag
              24        192     hip.rhit                Receiver's Host Identity Tag
              40        320     hip.parameters          HIP Parameters

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
                anonymous=True if int(_ctrl[15], base=2) else False,
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

    def __init__(self, _file, length=None, *, extension=False, **kwargs):
        self._file = _file
        self._extf = extension
        self._info = Info(self.read_hip(length, extension))

    def __length_hint__(self):
        return 40

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_hip_para(self, length, *, version):
        """Read HIP parameters.

        Positional arguments:
            * length -- int, length of parameters

        Keyword arguments:
            * version -- int, HIP version

        Returns:
            * dict -- extracted HIP parameters

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
            cbit = True if int(kind[15], base=2) else False

            # get parameter length
            clen = self._read_unpack(2)
            plen = 11 + clen - (clen + 3) % 8

            # extract parameter
            dscp = _HIP_PARA.get(code, 'Unassigned')
            # if 0 <= code <= 1023 or 61440 <= code <= 65535:
            #     desc = f'{dscp} (IETF Review)'
            # elif 1024 <= code <= 32767 or 49152 <= code <= 61439:
            #     desc = f'{dscp} (Specification Required)'
            # elif 32768 <= code <= 49151:
            #     desc = f'{dscp} (Reserved for Private Use)'
            # else:
            #     raise ProtocolError(f'HIPv{version}: [Parano {code}] invalid parameter')
            data = _HIP_PROC(dscp)(self, code, cbit, clen, desc=dscp, length=plen, version=version)

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
            raise ProtocolError('HIPv{}: invalid format'.format(version))

        return tuple(optkind), options

    def _read_para_unassigned(self, code, cbit, clen, *, desc, length, version):
        """Read HIP unassigned parameters.

        Structure of HIP unassigned parameters [RFC 5201][RFC 7401]:
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

            Octets      Bits        Name                    Description
              0           0     para.type               Parameter Type
              1          15     para.critical           Critical Bit
              2          16     para.length             Length of Contents
              4          32     para.contents           Contents
              -           -     -                       Padding

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

    def _read_para_esp_info(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ESP_INFO parameter.

        Structure of HIP ESP_INFO parameter [RFC 7402]:
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

            Octets      Bits        Name                    Description
              0           0     esp_info.type           Parameter Type
              1          15     esp_info.critical       Critical Bit
              2          16     esp_info.length         Length of Contents
              4          32     -                       Reserved
              6          48     esp_info.index          KEYMAT Index
              8          64     esp_info.old_spi        OLD SPI
              12         96     esp_info.new_spi        NEW SPI

        """
        if clen != 12:
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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

    def _read_para_r1_counter(self, code, cbit, clen, *, desc, length, version):
        """Read HIP R1_COUNTER parameter.

        Structure of HIP R1_COUNTER parameter [RFC 5201][RFC 7401]:
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

            Octets      Bits        Name                    Description
              0           0     ri_counter.type         Parameter Type
              1          15     ri_counter.critical     Critical Bit
              2          16     ri_counter.length       Length of Contents
              4          32     -                       Reserved
              8          64     ri_counter.count        Generation of Valid Puzzles

        """
        if clen != 12:
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))
        if code == 128 and version != 1:
            raise ProtocolError('HIPv{}: [Parano {}] invalid parameter'.format(version, code))

        _resv = self._read_fileng(4)
        _genc = self._read_unpack(8)

        r1_counter = dict(
            type=desc,
            critical=cbit,
            length=clen,
            count=_genc,
        )

        return r1_counter

    def _read_para_locator_set(self, code, cbit, clen, *, desc, length, version):
        """Read HIP LOCATOR_SET parameter.

        Structure of HIP LOCATOR_SET parameter [RFC 8046]:
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

            Octets      Bits        Name                    Description
              0           0     locator_set.type        Parameter Type
              1          15     locator_set.critical    Critical Bit
              2          16     locator_set.length      Length of Contents
              4          32     locator.traffic         Traffic Type
              5          40     locator.type            Locator Type
              6          48     locator.length          Locator Length
              7          56     -                       Reserved
              7          63     locator.preferred       Preferred Locator
              8          64     locator.lifetime        Locator Lifetime
              12         96     locator.object          Locator
                                ............

        """
        def _read_locator(kind, size):
            if kind == 0 and size == 16:
                return ipaddress.ip_address(self._read_fileng(16))
            elif kind == 1 and size == 20:
                return dict(
                    spi=self._read_unpack(4),
                    ip=ipaddress.ip_address(self._read_fileng(16)),
                )
            else:
                raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
        """Read HIP PUZZLE parameter.

        Structure of HIP PUZZLE parameter [RFC 5201][RFC 7401]:
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


            Octets      Bits        Name                    Description
              0           0     puzzle.type             Parameter Type
              1          15     puzzle.critical         Critical Bit
              2          16     puzzle.length           Length of Contents
              4          32     puzzle.number           Number of Verified Bits
              5          40     puzzle.lifetime         Lifetime
              6          48     puzzle.opaque           Opaque
              8          64     puzzle.random           Random Number

        """
        if version == 1 and clen != 12:
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
        """Read HIP SOLUTION parameter.

        Structure of HIP SOLUTION parameter [RFC 5201][RFC 7401]:
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


            Octets      Bits        Name                    Description
              0           0     solution.type           Parameter Type
              1          15     solution.critical       Critical Bit
              2          16     solution.length         Length of Contents
              4          32     solution.number         Number of Verified Bits
              5          40     solution.lifetime       Lifetime
              6          48     solution.opaque         Opaque
              8          64     solution.random         Random Number
              ?           ?     solution.solution       Puzzle Solution

        """
        if version == 1 and clen != 20:
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))
        if (clen - 4) % 2 != 0:
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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

    def _read_para_seq(self, code, cbit, clen, *, desc, length, version):
        """Read HIP SEQ parameter.

        Structure of HIP SEQ parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Update ID                          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     seq.type                Parameter Type
              1          15     seq.critical            Critical Bit
              2          16     seq.length              Length of Contents
              4          32     seq.id                  Update ID

        """
        if clen != 4:
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

        _upid = self._read_unpack(4)

        seq = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=_upid,
        )

        return seq

    def _read_para_ack(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ACK parameter.

        Structure of HIP ACK parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                       peer Update ID 1                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                       peer Update ID n                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     ack.type                Parameter Type
              1          15     ack.critical            Critical Bit
              2          16     ack.length              Length of Contents
              4          32     ack.id                  Peer Update ID

        """
        if clen % 4 != 0:
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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

    def _read_para_dh_group_list(self, code, cbit, clen, *, desc, length, version):
        """Read HIP DH_GROUP_LIST parameter.

        Structure of HIP DH_GROUP_LIST parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | DH GROUP ID #1| DH GROUP ID #2| DH GROUP ID #3| DH GROUP ID #4|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | DH GROUP ID #n|                Padding                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     dh_group_list.type      Parameter Type
              1          15     dh_group_list.critical  Critical Bit
              2          16     dh_group_list.length    Length of Contents
              4          32     dh_group_list.id        DH GROUP ID

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

    def _read_para_diffie_hellman(self, code, cbit, clen, *, desc, length, version):
        """Read HIP DIFFIE_HELLMAN parameter.

        Structure of HIP DIFFIE_HELLMAN parameter [RFC 7401]:
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

            Octets      Bits        Name                    Description
              0           0     diffie_hellman.type     Parameter Type
              1          15     diffie_hellman.critical Critical Bit
              2          16     diffie_hellman.length   Length of Contents
              4          32     diffie_hellman.id       Group ID
              5          40     diffie_hellman.pub_len  Public Value Length
              6          48     diffie_hellman.pub_val  Public Value
              ?           ?     -                       Padding

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
        """Read HIP HIP_TRANSFORM parameter.

        Structure of HIP HIP_TRANSFORM parameter [RFC 5201]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |            Suite ID #1        |          Suite ID #2          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |            Suite ID #n        |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     hip_transform.type      Parameter Type
              1          15     hip_transform.critical  Critical Bit
              2          16     hip_transform.length    Length of Contents
              4          32     hip_transform.id        Group ID
                                ............
              ?           ?     -                       Padding

        """
        if version != 1:
            raise ProtocolError('HIPv{}: [Parano {}] invalid parameter'.format(version, code))
        if clen % 2 != 0:
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

        _stid = list()
        for _ in range(clen // 2):
            _stid.append(_SUITE_ID.get(self._read_unpack(2), 'Unassigned'))

        hip_transform = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=_stid,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return hip_transform

    def _read_para_hip_cipher(self, code, cbit, clen, *, desc, length, version):
        """Read HIP HIP_CIPHER parameter.

        Structure of HIP HIP_CIPHER parameter [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Cipher ID #1         |          Cipher ID #2         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Cipher ID #n         |             Padding           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     hip_cipher.type         Parameter Type
              1          15     hip_cipher.critical     Critical Bit
              2          16     hip_cipher.length       Length of Contents
              4          32     hip_cipher.id           Cipher ID
                                ............
              ?           ?     -                       Padding

        """
        if clen % 2 != 0:
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
        """Read HIP NAT_TRAVERSAL_MODE parameter.

        Structure of HIP NAT_TRAVERSAL_MODE parameter [RFC 5770]:
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

            Octets      Bits        Name                        Description
              0           0     nat_traversal_mode.type     Parameter Type
              1          15     nat_traversal_mode.critical Critical Bit
              2          16     nat_traversal_mode.length   Length of Contents
              4          32     -                           Reserved
              6          48     nat_traversal_mode.id       Mode ID
                                ............
              ?           ?     -                           Padding

        """
        if clen % 2 != 0:
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

        _resv = self._read_fileng(2)
        _mdid = list()
        for _ in range((clen - 2) // 2):
            _mdid.append(_MODE_ID.get(self._read_unpack(2), 'Unassigned'))

        nat_traversal_mode = dict(
            type=desc,
            critical=cbit,
            length=clen,
            id=_mdid,
        )

        _plen = length - clen
        if _plen:
            self._read_fileng(_plen)

        return nat_traversal_mode

    def _read_para_transaction_pacing(self, code, cbit, clen, *, desc, length, version):
        """Read HIP TRANSACTION_PACING parameter.

        Structure of HIP TRANSACTION_PACING parameter [RFC 5770]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Type              |             Length            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Min Ta                             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                        Description
              0           0     transaction_pacing.type     Parameter Type
              1          15     transaction_pacing.critical Critical Bit
              2          16     transaction_pacing.length   Length of Contents
              4          32     transaction_pacing.min_ta   Min Ta

        """
        if clen != 4:
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

        _data = self._read_unpack(4)

        transaction_pacing = dict(
            type=desc,
            critical=cbit,
            length=clen,
            min_ta=_data,
        )

        return transaction_pacing

    def _read_para_encrypted(self, code, cbit, clen, *, desc, length, version):
        """Read HIP ENCRYPTED parameter.

        Structure of HIP ENCRYPTED parameter [RFC 7401]:
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

            Octets      Bits        Name                Description
              0           0     encrypted.type      Parameter Type
              1          15     encrypted.critical  Critical Bit
              2          16     encrypted.length    Length of Contents
              4          32     -                   Reserved
              8          48     encrypted.iv        Initialization Vector
              ?           ?     encrypted.data      Encrypted data
              ?           ?     -                   Padding


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

    def _read_para_host_id(self, code, cbit, clen, *, desc, length, version):
        """Read HIP HOST_ID parameter.

        Structure of HIP HOST_ID parameter [RFC 7401]:
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

            Octets      Bits        Name                Description
              0           0     host_id.type        Parameter Type
              1          15     host_id.critical    Critical Bit
              2          16     host_id.length      Length of Contents
              4          32     host_id.id_len      Host Identity Length
              6          48     host_id.di_type     Domain Identifier Type
              6          52     host_id.di_len      Domain Identifier Length
              8          64     host_id.algorithm   Algorithm
              10         80     host_id.host_id     Host Identity
              ?           ?     host_id.domain_id   Domain Identifier
              ?           ?     -                   Padding


        """
        def _read_host_identifier(length, code):
            algorithm = _HI_ALGORITHM.get(code, 'Unassigned')
            if algorithm == 'ECDSA':
                host_id = dict(
                    curve=_ECDSA_CURVE.get(self._read_unpack(2)),
                    pubkey=self._read_fileng(length-2),
                )
            elif algorithm == 'ECDSA_LOW':
                host_id = dict(
                    curve=_ECDSA_LOW_CURVE.get(self._read_unpack(2)),
                    pubkey=self._read_fileng(length-2),
                )
            else:
                host_id = self._read_fileng(length)
            return algorithm, host_id

        def _read_domain_identifier(di_data):
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
                raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
                    raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))
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
                    raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))
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
                    raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))
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
                    raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))
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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
            raise ProtocolError('HIPv{}: [Parano {}] invalid format'.format(version, code))

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
