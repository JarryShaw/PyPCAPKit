# -*- coding: utf-8 -*-
"""analyser for application layer

`jspcap.analyser` works as a header quater to analyse and
match application layer protocol. Then, call corresponding
modules and functions to extract the attributes.

"""
# Analyser for Application Layer
# Match Protocols and Extract Attributes


from jspcap.exceptions import ProtocolError
from jspcap.utilities import beholder_ng, seekset_ng
from jspcap.protocols.raw import Raw


__all__ = ['analyse']


class Analysis:
    """Analyse report."""
    @property
    def info(self):
        return self._info

    @property
    def name(self):
        return self._ptch.tuple[0]

    @property
    def alias(self):
        return self._acnm

    @property
    def protochain(self):
        return self._ptch

    def __init__(self, info, ptch, acnm):
        self._info = info
        self._ptch = ptch
        self._acnm = acnm

    def __str__(self):
        return f'Analysis({self._ptch.alias[0]}, info={self._info})'

    def __repr__(self):
        return f'Analysis({self._ptch.alias[0]})'


@beholder_ng
def analyse(file, length=None):
    """Analyse application layer packets."""
    flag, http = _analyse_httpv1(file, length)
    if flag:
        return Analysis(http.info, http.protochain, http.alias)

    # NOTE: due to format similarity of HTTP/2 and TLS/SSL, HTTP/2 won't be analysed before TLS/SSL is implemented.
    # NB: the NOTE abrove is deprecated, since validations are performed
    
    flag, http = _analyse_httpv2(file, length)
    if flag:
        return Analysis(http.info, http.protochain, http.alias)

    raw = Raw(file, length)
    return Analysis(raw.info, raw.protochain, raw.alias)


@seekset_ng
def _analyse_httpv1(file, length):
    try:
        from jspcap.protocols.application.httpv1 import HTTPv1
        http = HTTPv1(file, length)
    except ProtocolError:
        return False, None
    return True, http


@seekset_ng
def _analyse_httpv2(file, length):
    try:
        from jspcap.protocols.application.httpv2 import HTTPv2
        http = HTTPv2(file, length)
    except ProtocolError:
        return False, None
    return True, http
