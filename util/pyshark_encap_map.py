# -*- coding: utf-8 -*-
"""Regenerate the two hand-maintained tables in :mod:`pcapkit.toolkit.pyshark`.

GitHub issue #851. :file:`pcapkit/toolkit/pyshark.py` carries
``ENCAP_TYPE_TO_LINKTYPE`` (Wireshark's internal ``WTAP_ENCAP_*`` number ->
:class:`~pcapkit.const.reg.linktype.LinkType`) and ``FILTER_NAME_TO_LINKTYPE``
(a PDML root protocol's *filter* name -> the same enum), added by #850 as two
literal dict blocks. Neither table was ever transcribed from a Wireshark
source file -- there is not one on this host to transcribe -- each entry is
one round trip through Wireshark's own ``wiretap/pcap-common.c``, and this
script is that round trip, made runnable instead of ad hoc.

The method, unchanged from #850
--------------------------------

For every encapsulation :program:`editcap` accepts under ``-T``:

1. ``editcap -F pcap -T <encap> <source> <tmp>`` rewrites the source capture
   as that encapsulation. Some of the 226 encapsulations refuse the rewrite
   entirely -- their dissector cannot re-encode this capture's Ethernet
   frames -- and are simply skipped; that is the *69 refused* the acceptance
   arithmetic below asserts.
2. The **value** is read from the 4-byte little-endian ``network`` field at
   offset 20 of ``<tmp>``'s own pcap file header -- not looked up in a table,
   since the whole point is not to trust a second table transcribed by hand.
3. The **key**, for ``ENCAP_TYPE_TO_LINKTYPE``, is ``frame.encap_type`` as
   :program:`tshark`'s PDML output reports it for ``<tmp>``'s first packet.
   The **key** for ``FILTER_NAME_TO_LINKTYPE`` is the ``name`` of the first
   ``<proto>`` PDML emits after ``frame`` -- the outermost dissector's filter
   name, which is what :mod:`pyshark` exposes as ``packet.layers[0]
   .layer_name`` and what :func:`pcapkit.toolkit.pyshark.tcp_traceflow` falls
   back to when a capture carries no ``frame.encap_type`` field at all.

Two traps, both costing real time when #850's tables were first produced
--------------------------------------------------------------------------

**A PDML ``showname`` can hold a ``/``.** ``tshark`` renders
``frame.encap_type``'s ``showname`` as ``"Encapsulation type: NULL/Loopback
(15)"`` -- the display name itself, not just this one, can contain the
character. A regex that expects the name to be made of "word" characters up
to the parenthesised number -- ``r'(\\w+) \\((\\d+)\\)'``, say -- stops at the
``/`` and drops the row outright. That silently lost 10 of 157 rows,
including ``null`` itself, when #850's tables were first produced.
:func:`parse_parenthesised_number` is anchored to the *end* of the string
instead, so the name in front of the number can contain anything at all.

**The ``editcap -T`` help listing carries bogus tokens.** Piping
``editcap -T ''`` (an empty argument, which is how the flag's own help text
says to list the encapsulations) through any plain whitespace-based split --
:func:`str.split` over the whole output, with no maxsplit -- gives **1237**
tokens (measured against Wireshark 4.6.9, the version every other count here
was taken against), because ``editcap: The available encapsulation types for
the "-T" flag are:`` and every one-line description contribute their own
words on top of the 226 real tokens. The listing also opens with **two**
banner lines, not one: ``editcap: "" isn't a valid encapsulation type`` (the
error for the empty argument itself) and then ``editcap: The available
encapsulation types for the "-T" flag are:`` immediately after it -- so a
line-oriented split still has two non-entries to exclude, not the single line
an earlier draft of this docstring assumed. The true count is **226**, and
the shape that yields it is ``<token> - <description>``, anchored to leading
whitespace so neither banner line -- both flush against the left margin, with
no leading whitespace at all -- can match:

.. code-block:: shell

   sed -n 's/^[[:space:]]\\{1,\\}\\([A-Za-z0-9._-]\\{1,\\}\\) - .*/\\1/p'

:data:`_ENCAP_LINE` is that same shape, read with :mod:`re` instead of
:program:`sed` so the count is asserted in-process rather than trusted from a
shell pipeline.

What is deliberately left out
------------------------------

A DLT with no :class:`~pcapkit.const.reg.linktype.LinkType` member --
``editcap -T hhdlc`` writes DLT 121, which the enum does not define -- is
skipped rather than invented, in both tables, the same way an unmapped
``frame.encap_type`` already raises :exc:`~pcapkit.utilities.exceptions
.MissingKeyError` rather than resolving to a near-miss DLT (#843).
``FILTER_NAME_TO_LINKTYPE`` additionally excludes a root name that resolved
to more than one distinct DLT across the sweep (ambiguous: the PDML node does
not say which arrived) and the two pseudo-protocol roots ``fake-field-wrapper``
(:mod:`pyshark`'s ``data``, meaning no dissector recognised the frame) and
``_ws.malformed`` (the one capture :program:`tshark` could not parse). Both
tables' own module-level comments in :file:`pcapkit/toolkit/pyshark.py` --
untouched by this script, which only rewrites the two dict *bodies* -- record
the full accounting of what was excluded and why.

Byte-stable output
-------------------

Re-running this script against an unchanged tree must change nothing, which
is the only thing that makes it worth having. Each dict's entries are
emitted key-ascending, one entry per line, with the trailing ``# <sources>``
comment aligned to one column past the longest entry in *that* dict -- exactly
the formatting already committed, verified below by :func:`main`'s own diff
against the file it just wrote back.

Usage
-----

.. code-block:: shell

   python util/pyshark_encap_map.py            # regenerate pcapkit/toolkit/pyshark.py
   python util/pyshark_encap_map.py --check     # exit non-zero if it has drifted

Requires the :program:`tshark` and :program:`editcap` binaries (Wireshark
4.6.9 is what every measurement here was taken against); their absence is
reported on :data:`sys.stderr` and exits cleanly rather than raising, so a
host without Wireshark installed does not turn "nothing to regenerate" into a
traceback.

This cannot be run in CI to verify the committed tables, only locally against
a pinned Wireshark
------------------------------------------------------------------------------

:data:`EXPECTED_ACCEPTED` / :data:`EXPECTED_WRITABLE` / :data:`EXPECTED_REFUSED`
are properties of Wireshark 4.6.9, not of this script's method, and this
script refuses to rewrite anything when the installed Wireshark disagrees with
them rather than silently regenerating a *different* table (#851 was explicit
that a discrepancy here is a finding, not license to overwrite what was
measured and committed) -- see :class:`EncapSweepError`. Ubuntu noble's
packaged Wireshark, what every ``apt``-based CI runner installs, is 4.2.2: its
``editcap -T`` accepts 224 encapsulations, not 226, so this script's own
assertion trips there every time, by design (found the hard way: PR #853's
first CI run, three legs, ``AssertionError: 224 != 226``).

That is harmless to the *committed* tables at runtime -- an
``ENCAP_TYPE_TO_LINKTYPE``/``FILTER_NAME_TO_LINKTYPE`` entry a 4.2.2 install
would never produce is simply never looked up by one -- and is arguably the
right way round: the tables should be at least as rich as the newest
Wireshark a user might have, not capped at whatever a distribution happens to
package. The real consequence is narrower and worth being plain about: **this
generator can only be re-run, and its output only re-verified, on a host with
Wireshark pinned to :data:`EXPECTED_ACCEPTED`'s version (4.6.9) or one that
still sweeps to the same 226/157/69**. CI cannot do either with its packaged
Wireshark, so CI does not run this script at all; what it does still exercise
against whatever Wireshark it has -- structural invariants that hold at any
version, plus the parsing and formatting helpers against fabricated
input -- lives in ``tests/project/test_pyshark_encap_map.py``, not here.

"""
from __future__ import annotations

import argparse
import difflib
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from typing import Any, Optional, Sequence

__all__ = [
    'EncapSweepError', 'parse_parenthesised_number', 'list_encap_types',
    'measure_encap', 'build_tables', 'render_dict', 'rewrite', 'main',
]

#: Repository root, taken from this file's location rather than the working
#: directory -- the same spelling :file:`util/changelog_md.py` and
#: :file:`util/bump_version.py` use, and for the same reason: the script gives
#: the same answer run from anywhere.
ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The module both generated dict blocks live in.
TARGET = ROOT / 'pcapkit' / 'toolkit' / 'pyshark.py'

#: The capture every encapsulation is measured from. Generated by
#: :file:`examples/generators/make_samples.py`; this script does not run that
#: generator itself -- see :func:`main`.
SOURCE_CAPTURE = ROOT / 'examples' / 'captures' / 'in.pcap'

#: Expected sweep arithmetic against :data:`SOURCE_CAPTURE`, asserted rather
#: than assumed (#851's acceptance criterion). A mismatch means either
#: Wireshark's own encapsulation list moved since 4.6.9, or the source
#: capture is not the one every comment in :data:`TARGET` was measured
#: against -- either way, a generated table nobody checked is worse than a
#: script that refuses to run.
EXPECTED_ACCEPTED = 226
EXPECTED_WRITABLE = 157
EXPECTED_REFUSED = 69

#: The ``<token> - <description>`` shape of ``editcap -T ''``'s listing,
#: anchored to leading whitespace so the banner line -- which has none --
#: cannot match. See the module docstring's second trap.
_ENCAP_LINE = re.compile(r'^[ \t]+([A-Za-z0-9._-]+) - .*$')

#: The trailing parenthesised integer of a PDML ``showname``, e.g.
#: ``"Encapsulation type: NULL/Loopback (15)"`` -> ``15``. Anchored to the
#: *end* of the string rather than to a run of name-shaped characters, so a
#: ``/`` earlier in the name -- as in that example -- cannot stop the match.
#: See the module docstring's first trap.
_PAREN_NUMBER = re.compile(r'\((\d+)\)\s*$')

#: PDML root-protocol names that name a parser outcome rather than a
#: link-layer or payload dissector, and are therefore never eligible for
#: ``FILTER_NAME_TO_LINKTYPE`` regardless of how many DLTs they cover.
#: ``fake-field-wrapper`` is what :program:`tshark` emits when no dissector
#: recognised the frame at all -- :mod:`pyshark` reports it as ``data`` --
#: and ``_ws.malformed`` is what it emits when it could not parse the frame
#: it did recognise.
_PSEUDO_PROTOCOLS = frozenset({'fake-field-wrapper', '_ws.malformed', 'data'})

#: Offset of the ``network`` field in a classic pcap file header (RFC-less,
#: but stable since libpcap's very first release): magic (4) + version (4) +
#: thiszone (4) + sigfigs (4) + snaplen (4) = 20 bytes in.
_DLT_OFFSET = 20


class EncapSweepError(RuntimeError):
    """The sweep did not match what every comment in :data:`TARGET` asserts.

    Raised rather than silently regenerating a different table -- per #851,
    a discrepancy here is a finding about the generator (or about Wireshark
    having moved), not license to overwrite what #850 measured and committed.

    """


class Missing(NamedTuple):
    """Why the sweep skipped one encapsulation."""

    #: The ``editcap -T`` token.
    name: str
    #: Human-readable reason, for the summary :func:`main` prints.
    reason: str


class Measurement(NamedTuple):
    """One encapsulation's round trip through :program:`editcap`/:program:`tshark`."""

    #: The ``editcap -T`` token that produced this measurement.
    name: str
    #: The DLT read from the rewritten file's own pcap header.
    dlt: int
    #: ``frame.encap_type``, read from the rewritten file's first packet.
    encap_type: int
    #: The first PDML ``<proto>`` after ``frame``, or :obj:`None` if there
    #: was none at all.
    root_name: 'Optional[str]'


def parse_parenthesised_number(showname: str) -> int:
    """Extract the trailing ``(N)`` integer from a PDML ``showname``.

    Args:
        showname: A field's ``showname`` attribute, e.g.
            ``"Encapsulation type: NULL/Loopback (15)"``.

    Returns:
        The integer, ``15`` for that example.

    Raises:
        ValueError: If *showname* does not end in a parenthesised integer.

    """
    match = _PAREN_NUMBER.search(showname)
    if match is None:
        raise ValueError(f'no parenthesised number at the end of {showname!r}')
    return int(match.group(1))


def list_encap_types(editcap: str) -> 'list[str]':
    """The ``editcap -T`` tokens this binary accepts, in the order it lists them.

    Args:
        editcap: Path (or bare name, resolved against ``PATH``) of the
            :program:`editcap` binary.

    Returns:
        Every accepted encapsulation token. 226 of them, against Wireshark
        4.6.9 -- see :data:`EXPECTED_ACCEPTED`.

    Raises:
        EncapSweepError: If the listing does not parse to any tokens at all,
            which means ``-T ''`` no longer lists encapsulations the way it
            does in 4.6.9.

    """
    # An empty ``-T`` argument is deliberately invalid input -- it is how the
    # flag's own ``--help`` text says to get the listing -- so a non-zero
    # exit is the expected outcome and is not treated as a failure here.
    completed = subprocess.run(
        [editcap, '-T', ''], capture_output=True, text=True, check=False,
    )
    text = completed.stdout + completed.stderr

    names = [match.group(1) for line in text.splitlines()
             for match in (_ENCAP_LINE.match(line),) if match]
    if not names:
        raise EncapSweepError(
            f"{editcap} -T '' produced no recognisable encapsulation listing; "
            f'either the binary is not editcap, or its -T help output has '
            f'changed shape since Wireshark 4.6.9:\n{text}'
        )
    return names


def measure_encap(editcap: str, tshark: str, source: pathlib.Path,
                   name: str, tmp_dir: pathlib.Path) -> 'Measurement | Missing':
    """Round-trip one encapsulation through :program:`editcap` and :program:`tshark`.

    Args:
        editcap: Path or bare name of the :program:`editcap` binary.
        tshark: Path or bare name of the :program:`tshark` binary.
        source: Capture to rewrite -- :data:`SOURCE_CAPTURE` in practice.
        name: The ``editcap -T`` token to measure.
        tmp_dir: Scratch directory for the rewritten capture.

    Returns:
        A :class:`Measurement` if *name* could be written as pcap from
        *source* and read back; a :class:`Missing` naming why not, if
        :program:`editcap` refused the rewrite.

    """
    out_path = tmp_dir / f'{name}.pcap'
    written = subprocess.run(
        [editcap, '-F', 'pcap', '-T', name, str(source), str(out_path)],
        capture_output=True, text=True, check=False,
    )
    if written.returncode != 0 or not out_path.is_file():
        return Missing(name, written.stderr.strip() or 'editcap refused the rewrite')

    with open(out_path, 'rb') as file:
        header = file.read(_DLT_OFFSET + 4)
    dlt, = struct.unpack_from('<I', header, _DLT_OFFSET)

    pdml = subprocess.run(
        [tshark, '-r', str(out_path), '-c', '1', '-T', 'pdml'],
        capture_output=True, text=True, check=False,
    )
    root = ET.fromstring(pdml.stdout)
    packet = root.find('packet')
    if packet is None:
        return Missing(name, 'tshark produced no packet in its PDML output')

    protos = packet.findall('proto')
    frame_index = next((index for index, proto in enumerate(protos)
                         if proto.get('name') == 'frame'), None)
    if frame_index is None:
        return Missing(name, 'PDML output carried no "frame" protocol')

    frame = protos[frame_index]
    field = frame.find(".//field[@name='frame.encap_type']")
    if field is None:
        return Missing(name, 'frame layer carried no frame.encap_type field')
    try:
        encap_type = parse_parenthesised_number(field.get('showname', ''))
    except ValueError as error:
        return Missing(name, f'frame.encap_type showname unreadable: {error}')

    root_name = (protos[frame_index + 1].get('name')
                 if frame_index + 1 < len(protos) else None)

    return Measurement(name=name, dlt=dlt, encap_type=encap_type, root_name=root_name)


def build_tables(measurements: 'Sequence[Measurement]', linktype: 'Any') -> (
        'tuple[dict[int, tuple[Any, list[str]]], dict[str, tuple[Any, list[str]]], list[str]]'):
    """Group the sweep's measurements into the two tables' entries.

    Args:
        measurements: Every successfully written-and-read encapsulation, in
            the order :func:`list_encap_types` produced them -- ascending
            within a shared key, which is what lets the multi-source comment
            (``# fddi,fddi-nettl,fddi-swapped``) come out in the same order
            every time.
        linktype: The :class:`~pcapkit.const.reg.linktype.LinkType` enum.

    Returns:
        ``(encap_entries, filter_entries, notes)`` -- the two tables' key ->
        (member, [source names]) mappings, plus human-readable notes about
        what was measured but excluded (an unmapped DLT, an ambiguous filter
        name, ...), for :func:`main` to print.

    """
    notes = []  # type: list[str]

    # *linktype* is one of this project's registry enums: an unknown value
    # does not raise out of the constructor, it mints a placeholder member
    # via ``_missing_``/``extend_enum`` (#575) -- so ``LinkType(121)``
    # *succeeds*, returning a freshly minted ``Unassigned_121`` rather than
    # telling us 121 was never a real member. The set of values genuinely
    # registered has to be captured *before* any such lookup runs, or the
    # very first miss would mint a member that every later check then finds
    # already there. ``dlt in known_values`` is the check; ``linktype(dlt)``
    # is only ever called once *that* has already said yes, so it can never
    # reach ``_missing_`` itself.
    known_values = frozenset(member.value for member in linktype)

    by_encap_type = {}  # type: dict[int, list[Measurement]]
    by_root_name = {}  # type: dict[str, list[Measurement]]
    for measurement in measurements:
        by_encap_type.setdefault(measurement.encap_type, []).append(measurement)
        if measurement.root_name is not None:
            by_root_name.setdefault(measurement.root_name, []).append(measurement)

    encap_entries = {}  # type: dict[int, tuple[Any, list[str]]]
    for key, group in sorted(by_encap_type.items()):
        dlts = {item.dlt for item in group}
        if len(dlts) != 1:
            notes.append(
                f'frame.encap_type {key} maps to more than one DLT within the '
                f'sweep ({sorted(dlts)}); left out of ENCAP_TYPE_TO_LINKTYPE '
                f'rather than guessing one'
            )
            continue
        dlt = dlts.pop()
        if dlt not in known_values:
            names = ','.join(item.name for item in group)
            notes.append(
                f'frame.encap_type {key} (editcap -T {names}, DLT {dlt}) has no '
                f'LinkType member; left out of ENCAP_TYPE_TO_LINKTYPE'
            )
            continue
        encap_entries[key] = (linktype(dlt), [item.name for item in group])

    filter_entries = {}  # type: dict[str, tuple[Any, list[str]]]
    for name, group in sorted(by_root_name.items()):
        if name in _PSEUDO_PROTOCOLS:
            continue
        dlts = {item.dlt for item in group}
        members = {linktype(dlt) for dlt in dlts if dlt in known_values}
        if len(members) != 1:
            if len(dlts) > 1:
                notes.append(
                    f'filter name {name!r} is ambiguous within the sweep '
                    f'({len(dlts)} distinct DLTs); left out of '
                    f'FILTER_NAME_TO_LINKTYPE'
                )
            continue
        filter_entries[name] = (members.pop(), [item.name for item in group])

    return encap_entries, filter_entries, notes


def _key_repr(key: 'int | str') -> str:
    """Render a dict key the way the committed tables spell it."""
    return repr(key) if isinstance(key, str) else str(key)


def render_dict(name: str, entries: 'dict[Any, tuple[Any, list[str]]]',
                 value_type: str) -> str:
    """Render one ``NAME = { ... }`` block, byte-for-byte as it is committed.

    Args:
        name: The dict's variable name, e.g. ``ENCAP_TYPE_TO_LINKTYPE``.
        entries: Key -> (enum member, [source names]), key-ascending.
        value_type: The key type's spelling in the trailing
            ``# type: dict[...]`` comment (``int`` or ``str``).

    Returns:
        The complete block, ending in a single newline.

    """
    rows = []  # type: list[tuple[str, str]]
    for key, (member, sources) in entries.items():
        code = f'    {_key_repr(key)}: Enum_LinkType.{member.name},'
        rows.append((code, ','.join(sources)))

    width = max((len(code) for code, _ in rows), default=0) + 2

    lines = [f'{name} = {{']
    for code, comment in rows:
        lines.append(f'{code.ljust(width)}# {comment}')
    lines.append(f'}}  # type: dict[{value_type}, Enum_LinkType]')
    return '\n'.join(lines) + '\n'


def _replace_block(text: str, name: str, replacement: str) -> str:
    """Swap ``NAME = { ... }`` for *replacement* in *text*.

    The block is found by its opening ``NAME = {`` line and its first
    closing ``}`` line after that -- sufficient here because no value in
    either table is itself a mapping, so no line before the close can start
    with ``}``.

    Args:
        text: The file's current contents.
        name: The dict's variable name.
        replacement: The complete rendered block, from :func:`render_dict`.

    Returns:
        *text* with that one block replaced.

    Raises:
        EncapSweepError: If *name*'s block cannot be found, which means
            :data:`TARGET` no longer has the shape this script rewrites.

    """
    lines = text.split('\n')
    start = next((index for index, line in enumerate(lines)
                  if line == f'{name} = {{'), None)
    if start is None:
        raise EncapSweepError(f'{TARGET} has no {name!r} block to replace')
    end = next((index for index in range(start + 1, len(lines))
                if lines[index].startswith('}')), None)
    if end is None:
        raise EncapSweepError(f'{TARGET} has no closing brace for {name!r}')

    return '\n'.join(lines[:start] + replacement.rstrip('\n').split('\n') + lines[end + 1:])


def rewrite(current: str, encap_entries: 'dict[int, tuple[Any, list[str]]]',
            filter_entries: 'dict[str, tuple[Any, list[str]]]') -> str:
    """Return *current* with both dict blocks replaced by freshly rendered ones.

    Args:
        current: :data:`TARGET`'s current contents.
        encap_entries: As returned by :func:`build_tables`.
        filter_entries: As returned by :func:`build_tables`.

    Returns:
        The rewritten contents.

    """
    updated = _replace_block(
        current, 'ENCAP_TYPE_TO_LINKTYPE',
        render_dict('ENCAP_TYPE_TO_LINKTYPE', encap_entries, 'int'),
    )
    return _replace_block(
        updated, 'FILTER_NAME_TO_LINKTYPE',
        render_dict('FILTER_NAME_TO_LINKTYPE', filter_entries, 'str'),
    )


def main(argv: 'Optional[Sequence[str]]' = None) -> int:
    """Command line entry point.

    Args:
        argv: Argument list, defaulting to :data:`sys.argv`.

    Returns:
        ``0`` on success, or when :program:`tshark`/:program:`editcap` are
        absent -- see the module docstring for why that is not a failure.
        ``1`` if ``--check`` found :data:`TARGET` stale, or if the sweep's
        arithmetic did not match :data:`EXPECTED_ACCEPTED` /
        :data:`EXPECTED_WRITABLE` / :data:`EXPECTED_REFUSED`.

    """
    parser = argparse.ArgumentParser(
        prog='pyshark_encap_map.py',
        description=(
            'Regenerate ENCAP_TYPE_TO_LINKTYPE and FILTER_NAME_TO_LINKTYPE in '
            'pcapkit/toolkit/pyshark.py by sweeping every encapsulation editcap '
            'accepts.'
        ),
    )
    parser.add_argument('--check', action='store_true',
                         help='write nothing; exit non-zero if the committed '
                              'file has drifted')
    parser.add_argument('--editcap', default='editcap',
                         help='editcap binary (default: %(default)s, resolved '
                              'against PATH)')
    parser.add_argument('--tshark', default='tshark',
                         help='tshark binary (default: %(default)s, resolved '
                              'against PATH)')
    parser.add_argument('--source', type=pathlib.Path, default=SOURCE_CAPTURE,
                         help='capture to sweep from (default: %(default)s)')
    args = parser.parse_args(argv)

    editcap = shutil.which(args.editcap)
    tshark = shutil.which(args.tshark)
    if editcap is None or tshark is None:
        missing = [tool for tool, path in (('editcap', editcap), ('tshark', tshark))
                   if path is None]
        print(
            f'{", ".join(missing)} not found on PATH -- skipping. '
            f'ENCAP_TYPE_TO_LINKTYPE and FILTER_NAME_TO_LINKTYPE were measured '
            f'with Wireshark 4.6.9 and nothing here can re-measure them without '
            f'it; the committed tables in {TARGET} are left exactly as they are.',
            file=sys.stderr,
        )
        return 0

    if not args.source.is_file():
        print(
            f'{args.source} does not exist. It is generated -- run '
            f'"python examples/generators/make_samples.py" first, then re-run '
            f'this script.',
            file=sys.stderr,
        )
        return 0

    # Imported here rather than at module level, the same way
    # util/bump_version.py's current_version() imports pcapkit lazily: this
    # script has to run -- and print its --check verdict -- even where
    # pcapkit itself is not importable, which is exactly the case argparse
    # and the earlier tshark/editcap and source-capture checks exist to
    # report cleanly rather than as a bare ImportError traceback.
    #
    # ROOT is put at the front of sys.path, and any pip-installed editable
    # finder is evicted from sys.meta_path first, so that "the LinkType this
    # process sees" is unconditionally *this* checkout's
    # pcapkit/const/reg/linktype.py rather than whatever an unrelated
    # editable install (`pip install -e .` run against a different checkout
    # entirely -- a sibling clone, another git worktree) happens to point
    # at. A meta_path finder is consulted before sys.path is, so inserting
    # ROOT alone is not enough to override one; measured the hard way while
    # regenerating this table across a git worktree whose venv's editable
    # install pointed at the main checkout, where it silently kept reading
    # the main checkout's (older) linktype.py and produced a table that
    # matched the *wrong* base.
    sys.path.insert(0, str(ROOT))
    for _finder in list(sys.meta_path):
        if 'editable' in type(_finder).__module__.lower():
            sys.meta_path.remove(_finder)
    from pcapkit.const.reg.linktype import LinkType as Enum_LinkType

    _pcapkit_file = getattr(sys.modules.get('pcapkit'), '__file__', None) or ''
    if not _pcapkit_file.startswith(str(ROOT)):
        raise EncapSweepError(
            f'pcapkit resolved to {_pcapkit_file!r}, not under {ROOT} -- an '
            f'editable install pointed at a different checkout is still '
            f'winning, and this script refuses to measure LinkType membership '
            f'against the wrong tree'
        )

    accepted = list_encap_types(editcap)

    measurements = []  # type: list[Measurement]
    refused = []  # type: list[Missing]
    with tempfile.TemporaryDirectory(prefix='pyshark_encap_map_') as tmp:
        tmp_dir = pathlib.Path(tmp)
        for name in accepted:
            result = measure_encap(editcap, tshark, args.source, name, tmp_dir)
            if isinstance(result, Missing):
                refused.append(result)
            else:
                measurements.append(result)

    if len(accepted) != EXPECTED_ACCEPTED:
        raise EncapSweepError(
            f'editcap -T accepted {len(accepted)} encapsulations, expected '
            f'{EXPECTED_ACCEPTED}; Wireshark has moved since 4.6.9 and every '
            f'table comment measured against that version needs re-checking, '
            f'not just this script'
        )
    if len(measurements) != EXPECTED_WRITABLE:
        raise EncapSweepError(
            f'{len(measurements)} encapsulations were writable from {args.source}, '
            f'expected {EXPECTED_WRITABLE}'
        )
    if len(refused) != EXPECTED_REFUSED:
        raise EncapSweepError(
            f'{len(refused)} encapsulations were refused, expected {EXPECTED_REFUSED}'
        )
    print(f'sweep: {len(accepted)} accepted, {len(measurements)} writable, '
          f'{len(refused)} refused (matches the committed arithmetic)')

    encap_entries, filter_entries, notes = build_tables(measurements, Enum_LinkType)
    for note in notes:
        print(f'note: {note}', file=sys.stderr)

    current = TARGET.read_text(encoding='utf-8')
    want = rewrite(current, encap_entries, filter_entries)

    if not args.check:
        if want != current:
            # newline='\n' rather than the default None: every string this
            # script builds already ends its lines in '\n', so on Windows the
            # default would translate each into '\r\n' on the way out and
            # rewrite all ~210 lines rather than the handful that actually
            # changed. .gitattributes' `* text=auto` keeps CRLF from reaching
            # a commit either way, so this is hardening against a noisy local
            # diff, not a fix for output this repository would ever ship.
            TARGET.write_text(want, encoding='utf-8', newline='\n')
            print(f'wrote {TARGET}')
        else:
            print(f'{TARGET} already matches the sweep; nothing to write')
        return 0

    if want == current:
        print(f'{TARGET} matches the sweep')
        return 0

    print(f'{TARGET} has drifted from the sweep', file=sys.stderr)
    sys.stderr.writelines(difflib.unified_diff(
        current.splitlines(keepends=True),
        want.splitlines(keepends=True),
        fromfile=f'{TARGET.name} (committed)',
        tofile=f'{TARGET.name} (regenerated)',
    ))
    return 1


if __name__ == '__main__':
    sys.exit(main())
