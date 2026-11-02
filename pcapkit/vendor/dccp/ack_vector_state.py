# -*- coding: utf-8 -*-
"""DCCP Ack Vector States
=========================

.. module:: pcapkit.vendor.dccp.ack_vector_state

This module contains the vendor crawler for **DCCP Ack Vector States**,
which is automatically generating :class:`pcapkit.const.dccp.ack_vector_state.AckVectorState`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['AckVectorState']


class AckVectorState(Vendor):
    """DCCP Ack Vector States"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 3'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/dccp-parameters/dccp-parameters-10.csv'


if __name__ == '__main__':
    sys.exit(AckVectorState())  # type: ignore[arg-type]
