import os

import functools
import io
from plistlib import *
import datetime
import time

# pl = dict(
#     aString = "Doodah",
#     aList = ["A", "B", 12, 32.1, [1, 2, 3]],
#     aFloat = 0.1,
#     anInt = 728,
#     aDict = dict(
#         anotherString = "<hello & hi there!>",
#         aUnicodeValue = "M\xe4ssig, Ma\xdf",
#         aTrueValue = True,
#         aFalseValue = False,
#     ),
#     someData = b"<binary gunk>",
#     someMoreData = b"<lots of binary gunk>" * 10,
#     aDate = datetime.datetime.fromtimestamp(time.mktime(time.gmtime())),
# )
# pl1 = dict(
#     bString = 'BBBBB'
# )
# with open('info.plist', 'wb') as fp:
#     dump(pl, fp)
#     dump(pl1, fp)

with open('a.pcap', 'br') as f:
    # aDict = dict(
    #     a = ' '.join([H for H in iter(functools.partial(io.StringIO(f.read(40).hex()).read, 2), '')]),
    #     b = ' '.join([H for H in iter(functools.partial(io.StringIO(f.read(8).hex()).read, 2), '')]),
    #     c = ' '.join([H for H in iter(functools.partial(io.StringIO(f.read(2).hex()).read, 2), '')])
    # )
    # print()

    print('Global Header')
    print(' '.join([H for H in iter(functools.partial(io.StringIO(f.read(24).hex()).read, 2), '')]))
    # to split bytes string into length-2 hex string list
    # print(f.seek(0, os.SEEK_CUR))

    # print('\n---------------\n')

    print('Frame Header')
    print(' '.join([H for H in iter(functools.partial(io.StringIO(f.read(16).hex()).read, 2), '')]))
    # print(f.read(8).hex())
    # print(f.seek(0, os.SEEK_CUR))

    print('Ethernet Header')
    print(' '.join([H for H in iter(functools.partial(io.StringIO(f.read(14).hex()).read, 2), '')]))
    # print(f.read(6).hex())
    # print(f.seek(0, os.SEEK_CUR))

    # a = f.tell()
    # print(f.seek(a+1, os.SEEK_SET))
    print(' '.join([H for H in iter(functools.partial(io.StringIO(f.read(6).hex()).read, 2), '')]))
    # print(f.read(6).hex())
    # print(f.seek(a, os.SEEK_SET))

    print(' '.join([H for H in iter(functools.partial(io.StringIO(f.read(6).hex()).read, 2), '')]))
