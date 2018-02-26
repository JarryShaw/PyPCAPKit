#!/usr/bin/python3
# -*- coding: utf-8 -*-


import traceback


# user defined exceptions
# show refined infomation when exceptions raised


##############################################################################
# BaseError (abc of exceptions) session.
##############################################################################

class BaseError(Exception):
    """Base error class of all kinds.

    Cautions:

    * Turn off system-default traceback function by set `sys.tracebacklimit` to 0.
    * But bugs appear in Python 3.6, so we have to set `sys.tracebacklimit` to None.
    * In Python 2.7, `trace.print_stack(limit=None)` dose not support negative limit.

    """
    def __init__(self, message):
        tb = traceback.extract_stack()
        for tbitem in tb:
            if 'jspcap' in tbitem[0]:
                break
        index = tb.index(tbitem)

        print('Traceback (most recent call last):')
        traceback.print_stack(limit=-index)
        sys.tracebacklimit = None
        super().__init__(message)


##############################################################################
# TypeError session.
##############################################################################

class BoolError(BaseError, TypeError):
    """The argument(s) must be bool type."""
    pass

class DictError(BaseError, TypeError):
    """The argument(s) must be dict type."""
    pass

class IntError(BaseError, TypeError):
    """The argument(s) must be integral."""
    pass


##############################################################################
# AttributeError session.
##############################################################################

class UnsupportedCall(BaseError, AttributeError):
    """Unsupported function or property call."""
    pass
