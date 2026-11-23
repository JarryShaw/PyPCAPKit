# -*- coding: utf-8 -*-
"""constants for FTP protocol

.. versionadded:: 1.7.0

"""
import re

__all__ = ['FTP_REQUEST', 'FTP_RESPONSE']

#: An FTP command line, ``<command> [<SP> <argument>] <CRLF>`` (:rfc:`959`,
#: sections 4 and 5). Only the one SP is syntax, so :meth:`FTP.make
#: <pcapkit.protocols.application.ftp.protocol.FTP.make>` writes back the line as
#: read. It ends at ``\Z``, as ``$`` also matches before a ``\n``.
FTP_REQUEST = re.compile(rb'^(?P<cmmd>[A-Z]{3,4})(?: (?P<args>.*))?\r\n\Z', re.I)
#: An FTP reply line, ``<code> [<SP> <text>] <CRLF>``, or the opening
#: ``<code>-<text> <CRLF>`` of a multi-line reply, read as :data:`FTP_REQUEST`
#: reads a command.
FTP_RESPONSE = re.compile(rb'^(?P<code>[0-9]{3})'
                          rb'(?:(?P<more>-)(?P<text>.*)|(?: (?P<args>.*))?)\r\n\Z', re.I)
