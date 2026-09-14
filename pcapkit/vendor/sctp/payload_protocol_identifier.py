# -*- coding: utf-8 -*-
"""SCTP Payload Protocol Identifiers
=======================================

.. module:: pcapkit.vendor.sctp.payload_protocol_identifier

This module contains the vendor crawler for **SCTP Payload Protocol Identifiers**,
which is automatically generating :class:`pcapkit.const.sctp.payload_protocol_identifier.PayloadProtocolIdentifier`.

"""

import sys

from pcapkit.vendor.default import Vendor

__all__ = ['PayloadProtocolIdentifier']


class PayloadProtocolIdentifier(Vendor):
    """SCTP Payload Protocol Identifiers"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0 <= value <= 4294967295'
    #: Link to registry.
    LINK = 'https://www.iana.org/assignments/sctp-parameters/sctp-parameters-25.csv'


if __name__ == '__main__':
    sys.exit(PayloadProtocolIdentifier())  # type: ignore[arg-type]
