#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Internet Protocol
# Analyser for IP header


from jspcap.utilities import Info, seekset
from jspcap.protocols.internet.internet import Internet


__all__ = ['IP']


class IP(Internet):
    """This class implements all protocols in IP family.

    - Internet Protocol version 4 (IPv4) [RFC 791]
    - Internet Protocol version 6 (IPv6) [RFC 2460]
    - Authentication Header (AH) [RFC 4302]
    - Encapsulating Security Payload (ESP) [RFC 4303]

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance
        * src -- str, source IP address
        * dst -- str, destination IP address

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor
        * _read_ip_seekset -- when fragmented, read payload throughout first

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    # source IP address
    @property
    def src(self):
        return self._info.src

    # destination IP address
    @property
    def dst(self):
        return self._info.dst

    ##########################################################################
    # Utilities.
    ##########################################################################

    @seekset
    def _read_ip_seekset(self, ip, hdr_len, raw_len):
        """When fragmented, read payload throughout first.

        Keyword arguments:
            * ip -- dict, info buffer
            * hdr_len -- int, internal header length
            * raw_len -- int, raw payload length

        """
        ip['header'] = self._read_fileng(hdr_len)
        ip['raw'] = self._read_fileng(raw_len)
        padding = self._read_fileng()
        if padding:
            ip['padding'] = padding
        return ip
