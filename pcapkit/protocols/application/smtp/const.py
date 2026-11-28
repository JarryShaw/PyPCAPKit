# -*- coding: utf-8 -*-
"""constants for SMTP protocol

.. versionadded:: 1.10.0

"""
import re

__all__ = ['SMTP_COMMAND', 'SMTP_REPLY']

#: An SMTP command line, CRLF excluded. A verb of letters, then SP and the
#: argument clause where one follows (:rfc:`5321#section-4.1.1`); only the one SP
#: is syntax, so trailing white space stays in the argument clause.
SMTP_COMMAND = re.compile(rb'(?P<cmmd>[A-Za-z]+)(?: (?P<args>[^\r\n]*))?\Z')
#: An SMTP reply line, CRLF excluded. A ``Reply-code`` (:rfc:`5321#section-4.2`),
#: then a hyphen or SP and the text, or nothing where the line closes the reply.
SMTP_REPLY = re.compile(rb'(?P<code>[2-5][0-5][0-9])(?:(?P<sep>[- ])(?P<text>[^\r\n]*))?\Z')
