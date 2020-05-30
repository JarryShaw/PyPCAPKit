# -*- coding: utf-8 -*-
"""destination options for IPv6

:mod:`pcapkit.protocols.internet.ipv6_opts` contains
:class:`~pcapkit.protocols.internet.ipv6_opts.IPv6_Opts`
only, which implements extractor for Destination Options
for IPv6 (IPv6-Opts) [*]_, whose structure is described
as below:

======= ========= =================== =================================
Octets      Bits        Name                    Description
======= ========= =================== =================================
  0           0   ``opt.next``              Next Header
  1           8   ``opt.length``            Header Extensive Length
  2          16   ``opt.options``           Options
======= ========= =================== =================================

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Hop-by-hop_options_and_destination_options

"""
import datetime
import ipaddress

from pcapkit.const.ipv6.option import Option as _OPT_TYPE
from pcapkit.const.ipv6.qs_function import QSFunction as _QS_FUNC
from pcapkit.const.ipv6.router_alert import RouterAlert as _ROUTER_ALERT
from pcapkit.const.ipv6.seed_id import SeedID as _IPv6_Opts_SEED
from pcapkit.const.ipv6.tagger_id import TaggerID as _TID_TYPE
from pcapkit.const.reg.transtype import TransType
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

__all__ = ['IPv6_Opts']

#: IPv6_Opts Unknown Option Actions
_IPv6_Opts_ACT = {
    '00': 'skip over this option and continue processing the header',
    '01': 'discard the packet',
    '10': 'discard the packet and, regardless of whether or not the'
          "packet's Destination Address was a multicast address, send an"
          "ICMP Parameter Problem, Code 2, message to the packet's"
          'Source Address, pointing to the unrecognized Option Type',
    '11': "discard the packet and, only if the packet's Destination"
          'Address was not a multicast address, send an ICMP Parameter'
          "Problem, Code 2, message to the packet's Source Address,"
          'pointing to the unrecognized Option Type',
}

# :IPv6_Opts Options
_IPv6_Opts_OPT = {
    0x00: ('pad', 'Pad1'),                                                  # [RFC 8200] 0
    0x01: ('pad', 'PadN'),                                                  # [RFC 8200]
    0x04: ('tun', 'Tunnel Encapsulation Limit'),                            # [RFC 2473] 1
    0x05: ('ra', 'Router Alert'),                                           # [RFC 2711] 2
    0x07: ('calipso', 'Common Architecture Label IPv6 Security Option'),    # [RFC 5570]
    0x08: ('smf_dpd', 'Simplified Multicast Forwarding'),                   # [RFC 6621]
    0x0F: ('pdm', 'Performance and Diagnostic Metrics'),                    # [RFC 8250] 10
    0x26: ('qs', 'Quick-Start'),                                            # [RFC 4782][RFC Errata 2034] 6
    0x63: ('rpl', 'Routing Protocol for Low-Power and Lossy Networks'),     # [RFC 6553]
    0x6D: ('mpl', 'Multicast Protocol for Low-Power and Lossy Networks'),   # [RFC 7731]
    0x8B: ('ilnp', 'Identifier-Locator Network Protocol Nonce'),            # [RFC 6744]
    0x8C: ('lio', 'Line-Identification Option'),                            # [RFC 6788]
    0xC2: ('jumbo', 'Jumbo Payload'),                                       # [RFC 2675]
    0xC9: ('home', 'Home Address'),                                         # [RFC 6275]
    0xEE: ('ip_dff', 'Depth-First Forwarding'),                             # [RFC 6971]
}

#: IPv6_Opts Unknown Option Descriptions
_IPv6_Opts_NULL = {
    0x1E: 'RFC3692-style Experiment',                               # [RFC 4727]
    0x3E: 'RFC3692-style Experiment',                               # [RFC 4727]
    0x4D: 'Deprecated',                                             # [RFC 7731]
    0x5E: 'RFC3692-style Experiment',                               # [RFC 4727]
    0x7E: 'RFC3692-style Experiment',                               # [RFC 4727]
    0x8A: 'Endpoint Identification',                                # DEPRECATED
    0x9E: 'RFC3692-style Experiment',                               # [RFC 4727]
    0xBE: 'RFC3692-style Experiment',                               # [RFC 4727]
    0xDE: 'RFC3692-style Experiment',                               # [RFC 4727]
    0xFE: 'RFC3692-style Experiment',                               # [RFC 4727]
}


class IPv6_Opts(Internet):
    """This class implements Destination Options for IPv6."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['Destination Options for IPv6']
        """
        return 'Destination Options for IPv6'

    @property
    def alias(self):
        """Acronym of corresponding protocol.

        :rtype: Literal['IPv6-Opts']
        """
        return 'IPv6-Opts'

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

    def read(self, length=None, *, extension=False, **kwargs):  # pylint: disable=arguments-differ,unused-argument
        """Read Destination Options for IPv6.

        Structure of IPv6-Opts header [:rfc:`8200`]::

            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |  Hdr Ext Len  |                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
            |                                                               |
            .                                                               .
            .                            Options                            .
            .                                                               .
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            extension (bool): If the packet is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_IPv6_Opts: Parsed packet data.

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        # _opts = self._read_fileng(_hlen*8+6)

        ipv6_opts = dict(
            next=_next,
            length=(_hlen + 1) * 8,
        )

        options = self._read_ipv6_opts_options(_hlen * 8 + 6)
        ipv6_opts['options'] = options[0]       # tuple of option acronyms
        ipv6_opts.update(options[1])            # merge option info to buffer

        length -= ipv6_opts['length']
        ipv6_opts['packet'] = self._read_packet(header=ipv6_opts['length'], payload=length)

        if extension:
            self._protos = None
            return ipv6_opts
        return self._decode_next_layer(ipv6_opts, _next, length)

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    def __post_init__(self, file, length=None, *, extension=False, **kwargs):  # pylint: disable=arguments-differ
        """Post initialisation hook.

        Args:
            file (io.BytesIO): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            extension (bool): If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[2]
        """
        return 2

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            pcapkit.const.reg.transtype.TransType: Numeral registry index of the
            protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return TransType(60)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_opt_type(self, kind):  # pylint: disable=no-self-use
        """Read option type field.

        Arguments:
            kind (int): option kind value

        Returns:
            DataType_IPv6_Opts_Option_Type: extracted IPv6-Opts option type field

        """
        bin_ = bin(kind)[2:].zfill(8)

        type_ = dict(
            value=kind,
            action=_IPv6_Opts_ACT.get(bin_[:2]),
            change=bool(int(bin_[2], base=2)),
        )

        return type_

    def _read_ipv6_opts_options(self, length):
        """Read IPv6-Opts options.

        Positional arguments:
            length (int): length of options

        Returns:
            Tuple[Tuple[pcapkit.const.ipv6.option.Option],
            Dict[str, DataType_Option]]: extracted IPv6-Opts options

        Raises:
            ProtocolError: If the threshold is **NOT** matching.

        """
        counter = 0         # length of read options
        optkind = list()    # option type list
        options = dict()    # dict of option data

        while counter < length:
            # break when eol triggered
            code = self._read_unpack(1)
            if not code:
                break

            # extract parameter
            abbr, desc = _IPv6_Opts_OPT.get(code, ('None', 'Unassigned'))
            meth_name = f'_read_opt_{abbr}'
            meth = getattr(self, meth_name, '_read_opt_none')
            data = meth(self, code, desc=desc)
            enum = _OPT_TYPE.get(code)

            # record parameter data
            counter += data['length']
            if enum in optkind:
                if isinstance(options[abbr], tuple):
                    options[abbr] += (Info(data),)
                else:
                    options[abbr] = (Info(options[abbr]), Info(data))
            else:
                optkind.append(enum)
                options[abbr] = data

        # check threshold
        if counter != length:
            raise ProtocolError(f'{self.alias}: invalid format')

        return tuple(optkind), options

    def _read_opt_none(self, code, *, desc):
        """Read IPv6-Opts unassigned options.

        Structure of IPv6-Opts unassigned options [:rfc:`8200`]:

        .. code:: text

            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
            |  Option Type  |  Opt Data Len |  Option Data
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_None: parsed option data

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        _data = self._read_fileng(_size)

        opt = dict(
            desc=_IPv6_Opts_NULL.get(code, desc),
            type=_type,
            length=_size + 2,
            data=_data,
        )

        return opt

    def _read_opt_pad(self, code, *, desc):
        """Read IPv6-Opts padding options.

        Structure of IPv6-Opts padding options [:rfc:`8200`]:

        * ``Pad1`` option:

          .. code:: text

             +-+-+-+-+-+-+-+-+
             |       0       |
             +-+-+-+-+-+-+-+-+

        * ``PadN`` option:

          .. code:: text

             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
             |       1       |  Opt Data Len |  Option Data
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            Union[DataType_Dest_Opt_Pad1, DataType_Dest_Opt_PadN]: parsed option data

        Raises:
            ProtocolError: If ``code`` is **NOT** ``0`` or ``1``.

        """
        _type = self._read_opt_type(code)

        if code == 0:
            opt = dict(
                desc=desc,
                type=_type,
                length=1,
            )
        elif code == 1:
            _size = self._read_unpack(1)
            _padn = self._read_fileng(_size)

            opt = dict(
                desc=desc,
                type=_type,
                length=_size + 2,
                padding=_padn,
            )
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        return opt

    def _read_opt_tun(self, code, *, desc):
        """Read IPv6-Opts Tunnel Encapsulation Limit option.

        Structure of IPv6-Opts Tunnel Encapsulation Limit option [:rfc:`2473`]:

        .. code:: text

            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |Hdr Ext Len = 0| Opt Type = 4  |Opt Data Len=1 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Tun Encap Lim |PadN Opt Type=1|Opt Data Len=1 |       0       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_TUN: parsed option data

        Raises:
            ProtocolError: If ``ipv6_opts.tun.length`` is **NOT** ``1``.

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        if _size != 1:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _limt = self._read_unpack(1)

        opt = dict(
            desc=desc,
            type=_type,
            length=_size + 2,
            limit=_limt,
        )

        return opt

    def _read_opt_ra(self, code, *, desc):
        """Read IPv6-Opts Router Alert option.

        Structure of IPv6-Opts Router Alert option [:rfc:`2711`]:

        .. code:: text

            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |0 0 0|0 0 1 0 1|0 0 0 0 0 0 1 0|        Value (2 octets)       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_RA: parsed option data

        Raises:
            ProtocolError: If ``ipv6_opts.tun.length`` is **NOT** ``2``.

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        if _size != 2:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _rval = self._read_unpack(2)

        _dscp = _ROUTER_ALERT.get(_rval)
        opt = dict(
            desc=desc,
            type=_type,
            length=_size + 2,
            value=_rval,
            alert=_dscp,
        )

        return opt

    def _read_opt_calipso(self, code, *, desc):
        """Read IPv6-Opts ``CALIPSO`` option.

        Structure of IPv6-Opts ``CALIPSO`` option [:rfc:`5570`]:

        .. code:: text

            ------------------------------------------------------------
            | Next Header | Hdr Ext Len   | Option Type | Option Length|
            +-------------+---------------+-------------+--------------+
            |             CALIPSO Domain of Interpretation             |
            +-------------+---------------+-------------+--------------+
            | Cmpt Length |  Sens Level   |     Checksum (CRC-16)      |
            +-------------+---------------+-------------+--------------+
            |      Compartment Bitmap (Optional; variable length)      |
            +-------------+---------------+-------------+--------------+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_CALIPSO: parsed option data

        Raises:
            ProtocolError: If the option is malformed.

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        if _size < 8 and _size % 8 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _cmpt = self._read_unpack(4)
        _clen = self._read_unpack(1)
        if _clen % 2 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _sens = self._read_unpack(1)
        _csum = self._read_fileng(2)

        opt = dict(
            desc=desc,
            type=_type,
            length=_size + 2,
            domain=_cmpt,
            cmpt_len=_clen * 4,
            level=_sens,
            chksum=_csum,
        )

        if _clen:
            _bmap = list()
            for _ in range(_clen // 2):
                _bmap.append(self._read_binary(8))
            opt['bitmap'] = tuple(_bmap)

        _plen = _size - _clen * 4 - 8
        if _plen:
            self._read_fileng(_plen)

        return opt

    def _read_opt_smf_dpd(self, code, *, desc):
        """Read IPv6-Opts ``SMF_DPD`` option.

        Structure of IPv6-Opts ``SMF_DPD`` option [:rfc:`5570`]:

        * IPv6 ``SMF_DPD`` option header in **I-DPD** mode

          .. code:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                            ...              |0|0|0|  01000  | Opt. Data Len |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |0|TidTy| TidLen|             TaggerID (optional) ...           |
             +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                               |            Identifier  ...
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        * IPv6 ``SMF_DPD`` option header in **H-DPD** mode

          .. code:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                            ...              |0|0|0| OptType | Opt. Data Len |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |1|    Hash Assist Value (HAV) ...
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            Union[DataType_Dest_Opt_SMF_I_PDP, DataType_Dest_Opt_SMF_H_PDP]: parsed option data

        Raises:
            ProtocolError: If the option is malformed.

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        _tidd = self._read_binary(1)

        if _tidd[0] == '0':
            _mode = 'I-DPD'
            _tidt = _TID_TYPE.get(_tidd[1:4], 'Unassigned')
            _tidl = int(_tidd[4:], base=2)

            if _tidt == _TID_TYPE.NULL:
                if _tidl != 0:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
                _iden = self._read_fileng(_size-1)

                opt = dict(
                    desc=desc,
                    type=_type,
                    length=_size + 2,
                    dpd_type=_mode,
                    tid_type=_tidt,
                    tid_len=_tidl,
                    id=_iden,
                )
            elif _tidt == _TID_TYPE.IPv4:
                if _tidl != 3:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
                _tidf = self._read_fileng(4)
                _iden = self._read_fileng(_size-4)

                opt = dict(
                    desc=desc,
                    type=_type,
                    length=_size + 2,
                    dpd_type=_mode,
                    tid_type=_tidt,
                    tid_len=_tidl,
                    tid=ipaddress.ip_address(_tidf),
                    id=_iden,
                )
            elif _tidt == _TID_TYPE.IPv6:
                if _tidl != 15:
                    raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
                _tidf = self._read_fileng(15)
                _iden = self._read_fileng(_size-15)

                opt = dict(
                    desc=desc,
                    type=_type,
                    length=_size + 2,
                    dpd_type=_mode,
                    tid_type=_tidt,
                    tid_len=_tidl,
                    tid=ipaddress.ip_address(_tidf),
                    id=_iden,
                )
            else:
                _tidf = self._read_unpack(_tidl+1)
                _iden = self._read_fileng(_size-_tidl-2)

                opt = dict(
                    desc=desc,
                    type=_type,
                    length=_size + 2,
                    dpd_type=_mode,
                    tid_type=_tidt,
                    tid_len=_tidl,
                    tid=_tidf,
                    id=_iden,
                )
        elif _tidd[0] == '1':
            _mode = 'H-DPD'
            _tidt = _TID_TYPE.get(_tidd[1:4])
            _data = self._read_binary(_size-1)

            opt = dict(
                desc=desc,
                type=_type,
                length=_size + 2,
                dpd_type=_mode,
                tid_type=_tidt,
                hav=_tidd[1:] + _data,
            )
        else:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        return opt

    def _read_opt_pdm(self, code, *, desc):
        """Read IPv6-Opts ``PDM`` option.

        Structure of IPv6-Opts ``PDM`` option [:rfc:`8250`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Option Type  | Option Length |    ScaleDTLR  |     ScaleDTLS |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   PSN This Packet             |  PSN Last Received            |
            |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Delta Time Last Received    |  Delta Time Last Sent         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_PDM: parsed option data

        Raises:
            ProtocolError: If ``ipv6_opts.pdm.length`` is **NOT** ``10``.

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        if _size != 10:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _stlr = self._read_unpack(1)
        _stls = self._read_unpack(1)
        _psnt = self._read_unpack(2)
        _psnl = self._read_unpack(2)
        _dtlr = self._read_unpack(2)
        _dtls = self._read_unpack(2)

        opt = dict(
            desc=desc,
            type=_type,
            length=_size + 2,
            scaledtlr=datetime.timedelta(seconds=_stlr),
            scaledtls=datetime.timedelta(seconds=_stls),
            psntp=_psnt,
            psnlr=_psnl,
            deltatlr=datetime.timedelta(seconds=_dtlr),
            deltatls=datetime.timedelta(seconds=_dtls),
        )

        return opt

    def _read_opt_qs(self, code, *, desc):  # pylint: disable=unused-argument
        """Read IPv6-Opts Quick Start option.

        Structure of IPv6-Opts Quick-Start option [:rfc:`4782`]:

        * A Quick-Start Request:

          .. code:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |   Option      |  Length=6     | Func. | Rate  |   QS TTL      |
             |               |               | 0000  |Request|               |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                        QS Nonce                           | R |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        * Report of Approved Rate:

          .. code:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |   Option      |  Length=6     | Func. | Rate  |   Not Used    |
             |               |               | 1000  | Report|               |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                        QS Nonce                           | R |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_QS: parsed option data

        Raises:
            ProtocolError: If the option is malformed.

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        if _size != 6:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        _fcrr = self._read_binary(1)
        _func = int(_fcrr[:4], base=2)
        _rate = int(_fcrr[4:], base=2)
        _ttlv = self._read_unpack(1)
        _nonr = self._read_binary(4)
        _qsnn = int(_nonr[:30], base=2)

        if _func not in (0, 8):
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')

        data = dict(
            type=_type,
            length=_size + 2,
            func=_QS_FUNC.get(_func),
            rate=40000 * (2 ** _rate) / 1000,
            ttl=None if _func else _rate,
            nounce=_qsnn,
        )

        return data

    def _read_opt_rpl(self, code, *, desc):
        """Read IPv6-Opts ``RPL`` option.

        Structure of IPv6-Opts ``RPL`` option [:rfc:`6553`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                            |  Option Type  |  Opt Data Len |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |O|R|F|0|0|0|0|0| RPLInstanceID |          SenderRank           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                         (sub-TLVs)                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_RPL: parsed option data

        Raises:
            ProtocolError: If ``ipv6_opts.rpl.length`` is **LESS THAN** ``4``.

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        if _size < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _flag = self._read_binary(1)
        _rpld = self._read_unpack(1)
        _rank = self._read_unpack(2)

        opt = dict(
            desc=desc,
            type=_type,
            length=_size + 2,
            flags=dict(
                down=bool(int(_flag[0], base=2)),
                rank_error=bool(int(_flag[1], base=2)),
                fwd_error=bool(int(_flag[2], base=2)),
            ),
            id=_rpld,
            rank=_rank,
        )

        if _size > 4:
            opt['data'] = self._read_fileng(_size-4)

        return opt

    def _read_opt_mpl(self, code, *, desc):
        """Read IPv6-Opts ``MPL`` option.

        Structure of IPv6-Opts ``MPL`` option [:rfc:`7731`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                            |  Option Type  |  Opt Data Len |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | S |M|V|  rsv  |   sequence    |      seed-id (optional)       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_MPL: parsed option data

        Raises:
            ProtocolError: If the option is malformed.

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        if _size < 2:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _smvr = self._read_binary(1)
        _seqn = self._read_unpack(1)

        opt = dict(
            desc=desc,
            type=_type,
            length=_size + 2,
            seed_len=_IPv6_Opts_SEED.get(int(_smvr[:2], base=2)),
            flags=dict(
                max=bool(int(_smvr[2], base=2)),
                verification=bool(int(_smvr[3], base=2)),
            ),
            seq=_seqn,
        )

        _kind = _smvr[:2]
        if _kind == '00':
            if _size != 2:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        elif _kind == '01':
            if _size != 4:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
            opt['seed_id'] = self._read_unpack(2)
        elif _kind == '10':
            if _size != 10:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
            opt['seed_id'] = self._read_unpack(8)
        elif _kind == '11':
            if _size != 18:
                raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
            opt['seed_id'] = self._read_unpack(16)
        else:
            opt['seed_id'] = self._read_unpack(_size-2)

        _plen = _size - opt['seed_len']
        if _plen:
            self._read_fileng(_plen)

        return opt

    def _read_opt_ilnp(self, code, *, desc):
        """Read IPv6-Opts ``ILNP`` Nonce option.

        Structure of IPv6-Opts ``ILNP`` Nonce option [:rfc:`6744`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Next Header   | Hdr Ext Len   |  Option Type  | Option Length |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            /                         Nonce Value                           /
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_ILNP: parsed option data

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        _nval = self._read_fileng(_size)

        opt = dict(
            desc=desc,
            type=_type,
            length=_size + 2,
            value=_nval,
        )

        return opt

    def _read_opt_lio(self, code, *, desc):
        """Read IPv6-Opts Line-Identification option.

        Structure of IPv6-Opts Line-Identification option [:rfc:`6788`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                            |  Option Type  | Option Length |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | LineIDLen     |     Line ID...
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_LIO: parsed option data

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        _llen = self._read_unpack(1)
        _line = self._read_fileng(_llen)

        opt = dict(
            desc=desc,
            type=_type,
            length=_size + 2,
            lid_len=_llen,
            lid=_line,
        )

        _plen = _size - _llen
        if _plen:
            self._read_fileng(_plen)

        return opt

    def _read_opt_jumbo(self, code, *, desc):
        """Read IPv6-Opts Jumbo Payload option.

        Structure of IPv6-Opts Jumbo Payload option [:rfc:`2675`]:

        .. code:: text

                                            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                            |  Option Type  |  Opt Data Len |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                     Jumbo Payload Length                      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_Jumbo: parsed option data

        Raises:
            ProtocolError: If ``ipv6_opts.jumbo.length`` is **NOT** ``4``.

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        if _size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _jlen = self._read_unpack(4)

        opt = dict(
            desc=desc,
            type=_type,
            length=_size + 2,
            payload_len=_jlen,
        )

        return opt

    def _read_opt_home(self, code, *, desc):
        """Read IPv6-Opts Home Address option.

        Structure of IPv6-Opts Home Address option [:rfc:`6275`]:

        .. code:: text

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                            |  Option Type  | Option Length |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            +                                                               +
            |                                                               |
            +                          Home Address                         +
            |                                                               |
            +                                                               +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_Home: parsed option data

        Raises:
            ProtocolError: If ``ipv6_opts.jumbo.length`` is **NOT** ``16``.

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        if _size != 16:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _addr = self._read_fileng(16)

        opt = dict(
            desc=desc,
            type=_type,
            length=_size + 2,
            ip=ipaddress.ip_address(_addr),
        )

        return opt

    def _read_opt_ip_dff(self, code, *, desc):
        """Read IPv6-Opts ``IP_DFF`` option.

        Structure of IPv6-Opts ``IP_DFF`` option [:rfc:`6971`]:

        .. code:: text

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |  Hdr Ext Len  |  OptTypeDFF   | OptDataLenDFF |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |VER|D|R|0|0|0|0|        Sequence Number        |      Pad1     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            code (int): option type value

        Keyword Args:
            desc (str): option description

        Returns:
            DataType_Dest_Opt_IP_DFF: parsed option data

        Raises:
            ProtocolError: If ``ipv6_opts.ip_dff.length`` is **NOT** ``2``.

        """
        _type = self._read_opt_type(code)
        _size = self._read_unpack(1)
        if _size != 2:
            raise ProtocolError(f'{self.alias}: [OptNo {code}] invalid format')
        _verf = self._read_binary(1)
        _seqn = self._read_unpack(2)

        opt = dict(
            desc=desc,
            type=_type,
            length=_size + 2,
            version=int(_verf[:2], base=2),
            flags=dict(
                dup=bool(int(_verf[2], base=2)),
                ret=bool(int(_verf[3], base=2)),
            ),
            seq=_seqn,
        )

        return opt
