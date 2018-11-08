# -*- coding: utf-8 -*-
"""analyser for application layer

`pcapkit.foundation.analysis` works as a header quarter to
analyse and match application layer protocol. Then, call
corresponding modules and functions to extract the attributes.

"""
import os

from pcapkit.protocols.raw import Raw
from pcapkit.utilities.decorators import seekset_ng
from pcapkit.utilities.exceptions import ProtocolError

###############################################################################
# from pcapkit.protocols.application.httpv1 import HTTPv1
# from pcapkit.protocols.application.httpv2 import HTTPv2
###############################################################################

__all__ = ['analyse']


def analyse(file, length=None, *, _termination=False):
    """Analyse application layer packets."""
    seekset = file.tell()
    if not _termination:
        # HTTP/1.* analysis
        flag, http = _analyse_httpv1(file, length, seekset=seekset)
        if flag:
            return http

        # NOTE: due to format similarity of HTTP/2 and TLS/SSL, HTTP/2 won't be analysed before TLS/SSL is implemented.
        # NB: the NOTE above is deprecated, since validations are performed

        # HTTP/2 analysis
        flag, http = _analyse_httpv2(file, length, seekset=seekset)
        if flag:
            return http

    # raw packet analysis
    return Raw(file, length)


@seekset_ng
def _analyse_httpv1(file, length, *, seekset=os.SEEK_SET):
    try:
        from pcapkit.protocols.application.httpv1 import HTTPv1
        http = HTTPv1(file, length)
    except ProtocolError:
        return False, None
    return True, http


@seekset_ng
def _analyse_httpv2(file, length, *, seekset=os.SEEK_SET):
    try:
        from pcapkit.protocols.application.httpv2 import HTTPv2
        http = HTTPv2(file, length)
    except ProtocolError:
        return False, None
    return True, http
