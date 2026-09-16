# PyPCAPKit profiling notes (pre-1.5.0)

Working notes from a profiling pass over `pcapkit`, kept so the measurements and
— more importantly — the **ruled-out hypotheses** survive the session that
produced them. Delete this file once its contents have been folded into
`docs/source/pep.rst` or wherever the owner wants them to live.

Branch: `perf/hot-path-wins`. Every number below is from this host, this venv,
Python 3.14.

## How to reproduce

The editable install in `.venv` points at the **main** checkout, so `PYTHONPATH`
must name the tree under test or you profile the wrong code:

```bash
PY=/local/home/jarryx/GitHub/PyPCAPKit/.venv/bin/python
WT=/local/home/jarryx/GitHub/PyPCAPKit/.claude/worktrees/agent-a14f0c4dddc25f516

$PY examples/generators/make_samples.py          # build the un-committed fixtures
PYTHONPATH=$WT $PY -m pytest -q                  # 782 passed, 17 skipped
```

A subagent found that `PYTHONPATH` alone was not always enough — `sys.path[0]`
(the cwd) can shadow it, so `PYTHONSAFEPATH=1` is worth adding when the cwd is
itself a checkout.

Scratch harnesses (outside the repo, so they are not committed):

- `/tmp/pcapprof/bench.py` — best-of-N wall clock per capture per shape. This is
  the before/after instrument; **use best-of-N, not mean**, the host is noisy.
- `/tmp/pcapprof/prof.py` — cProfile `tottime` table for one shape.
- `/tmp/pcapprof/callers.py` — `print_callers` for attributing a cost to its
  call site. Essential: three of the findings below were misattributed until
  this was run.
- `/tmp/pcapprof/dump.py` — serialises **all 14 fixtures** to both `tree` and
  `json`, with and without reassembly (60 runs, 33 MB), for equivalence
  checking. `/tmp/pcapprof/ref/` holds the pristine-tree output; `diff -r`
  against it is how every change below was shown to be behaviour-neutral.
- `/tmp/pcapkit-ref/` — pristine `git archive HEAD` of the pre-optimisation tree,
  used to generate the reference output.

**Caveat on profiled percentages.** cProfile inflates Python-level call overhead
roughly 6x on this workload (6.83 s profiled vs 1.04 s wall for the same run), so
it *understates* work done in C. Charset detection profiled at 14.8% of extraction
but removing it recovered 30% of wall time. Where a figure below is "profiled",
treat it as a lower bound for C-heavy code and an upper bound for call-heavy code.

## Baseline, before any change

`store=False, nofile=True, verbose=False`, best of 7:

| capture | frames | wall | ms/frame |
|---|---|---|---|
| `http.pcap` | 1117 | 1041.5 ms | 0.932 |
| `http.pcap` (`store=True`) | 1117 | 1055.3 ms | 0.945 |
| `test.pcap` | 34 | 28.3 ms | 0.831 |
| `ipv4.pcap` | 4 | 1.90 ms | 0.476 |
| `ipv6.pcap` | 16 | 5.06 ms | 0.316 |
| `profile.pcapng` | 40 | 43.9 ms | 1.097 |
| `many_interfaces.pcapng` | 64 | 49.6 ms | 0.775 |

`store=True` costs **1.3%** over `store=False` on `http.pcap`. Storing frames is
not a hot spot; do not bother optimising it.

## What landed on `perf/hot-path-wins`

Cumulative on `http.pcap`: **1041.5 ms -> 574.4 ms, -44.8%** (1.81x). Every
commit was verified byte-identical over the 60-run / 33 MB serialisation diff, the
full suite is green, and both `pylint` and `mypy` report exactly the message set
the pristine tree does (124 mypy errors either side, identical; pylint message
multiset identical).

| # | sha | change | `http.pcap` | all captures |
|---|---|---|---|---|
| 1 | `fa0920f97` | memoise charset detection | -30.3% | HTTP/text only |
| 2 | `5ce03cd77` | `FieldBase.__copy__` | -16.6% | -11% to -15% everywhere |
| 3 | `0c1387460` | read `Field.length` once | -2.0% | -2% to -3% |
| 4 | `0aca00690` | `Schema.__setattr__` recursion | -3.7% | -2.6% to -4.2% |
| ~~5~~ | `1794c43d2`, reverted in `8296e362b` | `OptionField` isinstance taken once | ~~-1.0%~~ | **reverted, see below** |

(Shas are post-rebase onto `origin/main` at `42eb0d912`. That rebase brought in
only `examples/benchmark/**` and the `Makefile` from PR #410 — **no `pcapkit/`
source changed**, so every measurement and equivalence check above still describes
the code on this branch. Note that #410 landed a real benchmark harness at
`examples/benchmark/benchmark.py`; future numbers may be better taken through it
than through the scratch scripts listed above. It is not collected by `pytest`,
which has `testpaths = ["tests"]`.)

Per-capture, base -> final: `test.pcap` 28.3 -> 17.0 ms (-39.8%), `ipv4.pcap`
1.90 -> 1.66 ms (-12.6%), `ipv6.pcap` 5.06 -> 4.37 ms (-13.6%),
`profile.pcapng` 43.9 -> 35.2 ms (-19.7%), `many_interfaces.pcapng`
49.6 -> 39.2 ms (-20.9%).

### Why change 5 was reverted — a worked example of the trade going the wrong way

Taking `isinstance(field, OptionField)` once into `is_option` instead of testing
it inline at `schema.py:656` and `:661` measured a real **-1.0%**. It was reverted
anyway: storing the result costs **mypy its type narrowing**, so `field` stays
`FieldBase` in the branches below and `field.option_padding` stops resolving —
**four new `attr-defined` errors, 124 -> 128 across the package.** A flag variable
in place of a self-evident test, plus four static-analysis regressions, is not a
trade worth 1%.

The general lesson for the rest of this list: **check `mypy` and `pylint` parity
against the pristine tree, not just the test suite.** `/tmp/pcapprof/mypy_diff.sh`
and `/tmp/pcapprof/lint_diff.sh` do it by diffing message multisets with line
numbers normalised away. Any narrowing-dependent rewrite in these loops — which
includes route 3 of finding C below — will hit the same wall.

### 1. Charset detection was uncached — 30% of an HTTP extraction

`pcapkit/protocols/protocol.py:334` (`ProtocolBase.decode`) and
`pcapkit/corekit/fields/strings.py:171` (`StringField.post_process`) both called
`chardet.detect(...)` on every text value of every packet.

- `http.pcap`: **3011 `detect()` calls over 163 distinct bytestrings — 94.6%
  redundant.** Top repeats `b'Connection'` x222, `b'1.1'` x222, `b'close'` x210.
- Attribution matters here: on `http.pcap` **100%** of the calls come from
  `ProtocolBase.decode` (HTTP/1 header parsing, `httpv1.py:292-309`) and none
  from `StringField`; on `many_interfaces.pcapng` it is the exact reverse — 21
  calls, all from `StringField.post_process`, worth 1.3% of that extraction.
  Both sites needed fixing; a profile of only `http.pcap` would have missed one.
- Fix: bounded `functools.lru_cache` helper `_detect_charset` in `strings.py`
  (the module that already owns the `chardet` dependency), used from both sites.
  `chardet.detect` is a pure function of its bytes, so the memoised verdict is
  **by construction** the one it would have returned — no heuristic involved.

Rejected alternative: an `value.isascii()` fast path skipping chardet entirely.
Every one of the 163 distinct values on `http.pcap` is pure ASCII and chardet
calls all of them `'ascii'`, so it would have recovered ~100% rather than 94.6%.
Dismissed because it is **not** provably behaviour-preserving: NUL-interleaved
ASCII-range bytes (`b'a\x00b\x00'`) satisfy `isascii()` but chardet may call them
UTF-16, and the two decode differently. The cache has no such exposure.

Residual risk of the cache: it retains up to `DETECT_CACHE_SIZE` (1024)
bytestrings. Observed max length 116 bytes, so ~100 KB worst case here, but
`ProtocolBase.decode` is public and a caller could hand it megabyte strings.
Lower the bound or add a length guard if that matters.

### 2. `copy.copy` on fields fell through to the pickle machinery — ~15% everywhere

`Schema.unpack` (`pcapkit/protocols/schema/schema.py:615-616`) calls
`field(packet)` once per field per packet, and `Field.__call__`
(`pcapkit/corekit/fields/field.py:265`) returns `copy.copy(self)`. With no
`__copy__` hook, `copy.copy` took the generic route —
`object.__reduce_ex__(4)` -> `copyreg.__newobj__` -> `copy._reconstruct` — four
Python frames per copy, **63207 copies per `http.pcap` extraction** (~56/frame).

`FieldBase.__copy__` now does what `_reconstruct` did for an object with a plain
`__dict__`: `cls.__new__(cls)` then `__dict__.update`. Verified equivalent:
no field class defines `__new__`, `__slots__`, `__reduce__`, `__getstate__` or
`__setstate__`, and `copy.copy(f).__dict__ == f.__dict__` both ways.
Microbenchmark **1.66 us -> 0.43 us, 3.8x**.

This is the most broadly useful of the five — it is on the universal field path,
so it helps ARP, IPv4, IPv6, PCAP-NG and construction alike.

**Still available here:** `copy.copy`'s own dispatch (`_copy_dispatch.get`,
`issubclass(cls, type)`, `getattr(cls, '__copy__')`) now costs *more* than
`__copy__` itself — 0.134 s vs 0.131 s tottime. Calling `self.__copy__()`
directly at the ~8 call sites would recover ~2.6% profiled. Not done: it is a
legibility call the owner should make, since `copy.copy(x)` is the idiomatic
spelling.

### 3. `Field.length` recomputed `struct.calcsize` on every read

`pcapkit/corekit/fields/field.py:98-101` is a property calling
`struct.calcsize(self.template)` afresh each access. `FieldBase.unpack` read it
**three times** to unpack one field; `Schema.unpack` read it twice more per field.
**176908 `calcsize` calls per `http.pcap` extraction for 43110 fields** (158
calls/frame); a subagent counted 159.47/frame on `profile.pcapng` over only **26
distinct format strings for the whole capture**.

Both loops now bind it to a local. Safety argument, checked exhaustively: every
assignment to `_length` or `_template` in `pcapkit/corekit/fields/` lives in
`__init__`, `__call__` or `pre_process` — i.e. on the construction and packing
paths. **No `unpack()` anywhere mutates either**, so the hoisted read is the same
value each use site saw. (`OptionField.unpack` does mutate `self._option_padding`,
which is why `option_padding` is deliberately *not* hoisted.)

Only -2%: the remaining cost is the property *call*, not `calcsize` (0.072 s of
5.099 s profiled). **Caching `length` on the instance is still worth ~6.5x per
access** (63.4 ns -> 9.8 ns measured) but needs invalidation wherever `_template`
changes; not attempted.

### 4. `Schema.__setattr__` re-entered itself once per field

`pcapkit/protocols/schema/schema.py:381`. The `__fields__` branch marked the
schema dirty with `self.__updated__ = True`, which is itself an attribute store,
so it re-entered `__setattr__`, missed the `__fields__` test, and fell through to
`object.__setattr__`. **180297 of the 254043 primitive `__setattr__` calls in an
`http.pcap` extraction were that round trip and nothing else.**

Now writes `self.__dict__['__updated__'] = True`. Equivalent: `__updated__` is an
instance attribute established in `__new__` (`schema.py:276`), it is not
name-mangled (two trailing underscores), and no class in the `Schema` hierarchy
overrides `__setattr__` — only `Info` does, in a different hierarchy.

`self.__updated__ = False` at `schema.py:556` and `:684` has the same round trip
but runs once per schema rather than once per field (12291 vs 144780 per run), so
it was left alone.

### 5. `OptionField` isinstance asked twice

`schema.py:656` and `:661` ran the same `isinstance(field, OptionField)`. Taken
once now. Small (-1.0%) but it removes a literally duplicated test.

## Reassembly and flow tracing

Measured separately, `http.pcap`, one clean subprocess per shape, warm-up
discarded, 3 reps pooled over 2 passes (n=6). **Measuring several shapes in one
process inflates all of them** — the same shape read 1026 ms early in a shared
process and 594 ms in a clean one, a 73% error that grows monotonically with
position in the run. Use one process per shape.

```
shape                             ms   ms/frame     delta   vs base
baseline-nostore               564.4     0.5053         -
baseline-store                 576.7     0.5163         -
reasm-bare  (reassembly=True)  584.0     0.5228      +7.3     +1.3%
reasm-ip    (+ip=True)        1059.5     0.9485    +482.8    +83.7%
reasm-tcp   (+tcp=True)        672.6     0.6021     +95.9    +16.6%
reasm-ip-tcp                  1134.9     1.0160    +558.2    +96.8%
trace-bare  (trace=True)       587.2     0.5257     +22.8     +4.0%
trace-tcp-pcap                1413.9     1.2658    +849.5   +150.5%
trace-tcp-json                1817.4     1.6270   +1253.0   +222.0%
```

**A trap for anyone benchmarking these:** `reassembly=True` and `trace=True` are
master switches only (`pcapkit/interface/core.py:61-72`). Without also passing
`ip`/`ipv4`/`ipv6`/`tcp`, **no per-protocol work happens at all** — `+1.3%` and
`+4.0%` respectively. A "reassembly benchmark" that passes only `reassembly=True`
measures nothing.

`reasm_store=False` saves nothing (+98.8% vs +96.8%): the cost is the reassembly
work, not retaining the datagrams.

**The `foundation/reassembly/` and `foundation/traceflow/` modules are not the
cost — each is under 1.3% of its run in every shape.** All of it is in what they
call, which is where the two findings below land. They are the largest single
opportunities found anywhere in this pass.

### Z1. IP reassembly re-parses every frame, fragmented or not — 86% of its cost

`pcapkit/foundation/reassembly/ip.py:189`:

```python
packet=self.protocol.analyze(bufid[3], bytes(payload)),
```

`analyze()` is a **full second parse** of the reassembled payload through TCP and
HTTP. It is 98.0% of `submit()`'s cumulative time and 33.6% of the whole
`reasm-ip` run.

And it runs on **every frame**, because nothing filters out unfragmented ones:
`pcapkit/toolkit/pcap.py:53` dismisses a frame only when **DF is set**
(`if ipv4_info.flags.df: return None`), so a frame with DF=0, MF=0, FO=0 — not
fragmented in any sense — passes; `ip.py:73` then sees `not FO and not MF`,
allocates a buffer, sets TDL and submits. Counted across the fixtures:
**`http.pcap` has 1117 IPv4 frames, 0 with DF set and 0 actual fragments, and IP
reassembly still yields 1117 "datagrams".** Same in `tcp.pcap` (4/4),
`test.pcap` (21/21), `ipv4.pcap` (4/4).

Counterfactual, `submit()` setting `packet=None` (patched in a scratch copy only):

```
reasm-ip      1059.5 -> 655.3 ms   feature cost +482.8 -> +66.8 ms   analyze() = 416.0 ms = 86.2%
reasm-tcp      672.6 -> 650.1 ms   feature cost  +95.9 -> +61.6 ms   analyze() =  34.3 ms = 35.8%
reasm-ip-tcp  1134.9 -> 714.6 ms   feature cost +558.2 -> +126.1 ms  analyze() = 432.1 ms = 77.4%
```

Retaining those 1117 re-parsed object graphs also makes GC real: `gc.disable()`
saves 132.6 ms on `reasm-ip` (27% of the feature's cost) but nothing at all on the
plain baseline or on tracing.

**Two separable questions here, and they should not be conflated.** Whether a
never-fragmented packet ought to be emitted as a trivially-complete datagram is a
*design* decision the owner owns — it may well be intended. But `analyze()` being
eager is not: making `packet` lazy (a cached property evaluated on first access)
would remove ~86% of the cost with no change to what a caller who reads it sees.
That is the recommended fix; changing the filter is the owner's call.
`reassembly/tcp.py:298` has the same eager `analyze()`, but only 222 submits per
pass (driven by FIN/RST), so it costs proportionally less.

### Z2. The PCAP flow dumper reopens the file and rebuilds the frame per packet — 80% of its cost

`pcapkit/dumpkit/pcap.py:94` and `:128`:

```python
def __call__(self, value, name=None):
    with open(self._file, 'ab') as file:        # :94  -- once PER FRAME
        self._append_value(value, file, name or '')

def _append_value(self, value, file, name):
    packet = Frame(                             # :128 -- full re-parse PER FRAME
        nanosecond=self._nsec, num=self._fnum, proto=self._link,
        packet=value.packet, header=self._ghdr, **value.frame_info,
    ).data
    file.write(packet)
```

`dumpkit/pcap.py:85(__call__)` is **48.70% of the `trace-tcp-pcap` run**, of which
the `Frame(...)` rebuild is 97%. 4347 `_io.open` calls over 3 reps (1449/pass:
1117 frame appends + 331 flow-file creations + 1).

Isolating the tracing logic from the dumper, via an unsupported `trace_format` so
`NotImplementedIO` is installed: **5.8% of the traceflow cost is tracing, 94.2% is
the dumper.** Split by counterfactual:

```
trace-tcp-pcap  1413.9 ms baseline (+849.5)
  keep the file open only            1339.0 ms  ->  -87.6 ms  = 10.3% of feature cost
  + no Frame() rebuild                743.5 ms  -> -681.2 ms  = 80.2% of feature cost
```

The rebuild is **provably** redundant: replacing `_append_value` with
`struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len) + value.packet` gives
**330 of 331 output files byte-identical** to the real dumper's. (The one mismatch
was an unflushed cached handle in the scratch patch, not a semantic difference.)
Lowest-risk, best-evidenced fix in this whole document.

`trace_format='json'` sidesteps the re-parse but is the slowest shape measured
(+222.0%): `dictdumper` is 22.33% of it and `pcapkit/dumpkit/common.py:124`
(`object_hook`) another 5.39% — a linear chain of up to 9 `isinstance` tests run
114,469 times per pass, which is where its 6.3M `isinstance` calls come from.

## Ranked findings NOT acted on

Ordered by measured cost. These are the expensive things to rediscover.

### A. Every option is parsed twice — 15.5% of `profile.pcapng`, 10.3% of `http.pcap`

**The largest single win left.** `pcapkit/corekit/fields/collections.py:262-270`
(`OptionField.unpack`):

```python
meta = self._base_schema.unpack(file, length, packet)   # full Schema unpack…
code = cast('int', meta[self._type_name])               # …to read ONE field
schema = self._registry[code]
file.seek(-len(meta), io.SEEK_CUR)                      # rewind
data = schema.unpack(file, length, packet)              # full unpack, again
```

Measured **2274 schema unpacks for 1137 options — exactly 2x**. The base-schema
pre-parse is *always* discarded (`base schema class is the real schema class:
0 / 379`). Instrumented per option: pre-parse 15.52 us (35.1% of the option
loop), real unpack 25.76 us, `len(meta)` 1.26 us, `len(data)` 1.65 us; the loop
is **44.2%** of a `profile.pcapng` extraction. `len(meta)`/`len(data)` go through
`Schema.__len__` -> `__bytes__` -> `b''.join` over every field (1.18 us) for two
numbers the unpack already knew — another ~6.5% of the loop.

Fix: read the type code with a direct `struct.unpack` of its 1-2 bytes instead of
a throwaway `Schema.unpack`, and return consumed lengths from `unpack` rather than
re-deriving them by re-serialising. **Risk: medium-high.** It is the option
parser for every protocol with TLVs, the rewind arithmetic is subtle, and
`__option_padding__` interacts with it. Wants its own review with the option-heavy
fixtures (`profile.pcapng` 9.47 options/frame, `test.pcapng` 13.40) as evidence.

### B. `pcapkit/utilities/warnings.py:129` builds a log record nobody reads — 7.19 us per warning

`warn()` calls `logger.warning(..., stacklevel=...)` **unconditionally** before
`warnings.warn(...)`. The `pcapkit` logger has only a `NullHandler`, but
`isEnabledFor(WARNING)` is `True`, so the record is fully constructed —
`logging.findCaller` -> `_is_internal_frame` **15x per call**, plus
`posixpath.normcase` and `posix.fspath` per frame — and then dropped.

| | us/call |
|---|---|
| pcapkit `warn()` | **7.19** |
| — `logger.warning(stacklevel=)` | 5.29 (**73%**) |
| — `stacklevel()` (`exceptions.py:60`) | 0.73 |
| — `warnings.warn()` | 0.51 |

**Not on the parse hot path** — a clean extraction of `http.pcap` emits one
warning (`EOF reached`), so this is ~0% of the numbers above. It is 20.5% of a
`Protocol(**kwargs)` construction workload that emits six. Cheap, low-risk fix
(gate on a handler actually wanting the record); worth doing, but its value is in
malformed-capture and construction workloads, not in steady-state parsing.

### C. ABCMeta makes every field isinstance a Python-level call — 11.5% profiled

`FieldMeta` inherits `abc.ABCMeta` (`field.py:37`), so `isinstance(field, X)`
dispatches through `ABCMeta.__instancecheck__` instead of the C fast path:
**278123 such calls per `http.pcap` extraction**, 0.293 s of 5.099 s profiled for
the ABC portion, 0.585 s for isinstance overall. `Schema.unpack` asks 5-6 of them
per field (now 5, after commit 5) and a plain field fails all of them.

Three routes considered, all rejected:

1. **Drop `abc.ABCMeta` from `FieldMeta`.** Would put every check on the C fast
   path. Rejected: there is a real `@abc.abstractmethod` at
   `pcapkit/corekit/fields/ipaddress.py:42`, and removing the metaclass silently
   stops enforcing it. Trades a safety net for speed.
2. **Override `FieldMeta.__instancecheck__` to `type.__instancecheck__`.** Same
   gain, keeps abstractmethod enforcement. Rejected: silently drops
   `ABCMeta.register()` virtual subclasses and `__subclasshook__` from a public
   metaclass. No field class uses either today, but it is an invisible narrowing.
3. **Precompute the classification per declared field.** Sound —
   `type(field(packet))` is always `type(declared_field)` (`Field.__call__`,
   `ListField.__call__` and `SwitchField.__call__` all `copy.copy(self)`, and
   `ConditionalField._field` is fixed at construction), so a flags tuple could be
   computed at schema finalisation. Estimated 4-5% real. Rejected **for the owner
   to decide**: it replaces five readable `isinstance` checks with a lookup into
   a precomputed table, which is exactly the clarity-for-speed trade the brief
   says to flag rather than make.

### D. `NumberField.__call__` rebuilds the struct format on every copy — <=2.5% profiled

`pcapkit/corekit/fields/numbers.py:99-109`. Every field copy re-runs the
`endian` ternary, the 5-branch `build_template`, and an f-string, even though
`_length`, `_byteorder` and `_signed` are unchanged from the declared field in the
overwhelming majority of cases. 102483 calls, 0.128 s tottime / 0.450 s cumtime of
5.099 s profiled.

A guard skipping the rebuild when those three inputs are unchanged looks obvious
but is **not** safely equivalent, and this is the trap:

- `__init__` (`numbers.py:80-84`) derives the template from `self.__template__`
  when the subclass sets one, but `__call__` (`:106`) always derives it from
  `build_template(...)`. Those two agree for all eight fixed-width subclasses
  today (`Int32Field.__template__ == 'i' == build_template(4, True)`, and so on
  for the other seven), so a guard would be correct **by coincidence**, and a
  future subclass with a deliberately different `__template__` would silently
  change behaviour.
- `__init__` also calls `build_template(self._length, signed)` with the
  **argument** `signed`, while `_signed` is `signed if self.__signed__ is None
  else self.__signed__` (`:75`). If a subclass ever sets `__signed__` without
  `__template__`, `__init__` and `__call__` disagree about the template.
- `build_template` has a side effect (`self._need_process = True`, `:132`) which
  skipping the call would not reproduce in general.

Recorded as a **latent inconsistency worth fixing on correctness grounds**,
independently of performance. Once `__init__` and `__call__` derive the template
the same way, the guard becomes safe and the ~2.5% is collectable.

### E. PCAP-NG re-derives per-interface timestamp constants per block — ~1.9%

`pcapkit/protocols/misc/pcapng.py:1277` (`_read_timestamp`) calls
`_get_timezone` + `_get_resolution` + `_get_offset` (`:1228`, `:1182`, `:1205`),
which between them make **4 `_get_interface` calls and 3
`OrderedMultiDict.get()` option re-scans per packet block**, then a
`decimal.localcontext(prec=64)` and a `Decimal` division — all to recover
`if_tsresol` / `if_tsoffset` / `if_tzone`, which are **fixed for the interface for
the whole capture**. 18.92 us/call, 1.15 calls/frame, ~1.9% of
`profile.pcapng`. Memoising them on the interface context would remove it. Low
risk, modest payoff.

Related: PCAP-NG does **23.2 schema unpacks per frame against PCAP's 3.0** (7.7x).
Container-only (`layer='Link'`), PCAP-NG is 5.47x PCAP per frame — 0.731 vs
0.134 ms/frame. Most of that gap is finding A, not anything intrinsic to the
format.

### F. Const enums hash 3.1x slower than ints

`pcapkit/const/pcapng/option_type.py:71,77` override `__eq__`/`__hash__` in
Python. `dict[OptionType]` lookup **72.4 ns vs 23.6 ns** for `dict[int]`;
`hash(OptionType)` 64.4 ns; `OptionType.get(2)` **446.3 ns**. 1137 registry
lookups per 3-rep `profile.pcapng` run. Real but second-order; it is inside
finding A's loop, so fix A first and re-measure.

### G. Construction (`make`) — measured, and mostly fine

Constructions/s, best of 3 over 5000 iterations, arguments taken from
`tests/protocols/transport/test_tcp_udp_unit.py:172-181` and
`tests/protocols/link/test_link_unit.py:355-364`:

| case | ctor/s | us each |
|---|---|---|
| `HTTP.make` | 212157 | 4.71 |
| `Ethernet.make` | 182888 | 5.47 |
| `IPv4.make` | 116648 | 8.57 |
| `TCP.make` (no options) | 114593 | 8.73 |
| **`TCP.make` + 6 options** | **9812** | **101.91** |
| `Ethernet.pack` | 51532 | 19.41 |
| `IPv4.pack` | 15946 | 62.71 |
| `TCP.pack` + 6 options | 4106 | 243.56 |
| `IPv4(**kwargs)` full ctor | 4849 | 206.21 |
| `Ethernet(**kwargs)` full ctor | 4261 | 234.71 |

- `make()` itself is cheap because it does **not** pack — see finding H.
- **`TCP.make` + options is 12x the no-options case.** `_make_tcp_options`
  (`pcapkit/protocols/transport/tcp.py:1914`) eagerly builds *and packs* each
  option schema to compute lengths: **91.6% of that workload's cumtime**.
- `copy.copy` per construction: `Ethernet.pack` 4, `IPv4.pack` 13,
  `TCP.pack`+6opts **62** — at 578 ns each (post-commit-2) that is 35.8 us of
  243.6 us (14.7%); the whole of `Field.__call__` is 34% of it.
- `struct.calcsize` per construction: `IPv4.pack` 7, `Ethernet(**kw)` 21, over
  2-6 distinct formats.
- **`infoclass.py` is 0.0% of `make()` and `pack()`**, and 6.7% of the full
  constructor. `Info`/`InfoMeta` was a listed suspect; on the construction path it
  is not one.

### H. `schema_final`'s generated `__init__` is dead code (correctness, not perf)

`pcapkit/protocols/schema/schema.py:77` guards the `exec`-generated typed
`__init__` behind `if not hasattr(cls, '__init__')`, but `Schema` assigns
`__init__ = __update__` at `schema.py:329`, so **the guard is always False and the
generated `__init__` is never installed**. Measured: `Schema.__post_init__` call
count is **0** during `make()`, `pack()` and `Protocol(**kwargs)`;
`S_IPv4.__init__ is Schema.__update__` is `True`.

So the typed per-schema signature `schema_final` goes to the trouble of
generating is unreachable, and `__post_init__` -> `pack()` never runs. Packing
happens lazily via `Schema.__bytes__` instead. Report this to the owner; fixing it
would make construction *slower* and change behaviour, so it is not a perf item.

### I. `Protocol(**kwargs)` re-parses everything it just built

`pcapkit/protocols/protocol.py:670-680`: with `file is None` it calls
`self.pack(**kwargs)` and then **unconditionally** `self._info =
self.unpack(length, **kwargs)`. `Ethernet.pack` 19.4 us -> `Ethernet(**kw)`
60.2 us (3.1x) -> **239.6 us** when `type=IPv4` makes it dissect `b'payload'` as a
malformed IPv4 header (12.3x). Per construction: 3 `Schema.__new__` (1 built, 2
parsed), 6-10 `Info.__new__`, 21 `struct.calcsize`.

### J. Pre-existing bug: `TCP(**kwargs)` full constructor raises

`pcapkit/protocols/transport/tcp.py:479`:

```python
return self._decode_next_layer(tcp, (tcp.srcport.port, tcp.dstport.port), length - tcp.hdr_len)
```

-> `AttributeError: 'int' object has no attribute 'port'`. `make()` leaves
`srcport`/`dstport` as plain `int`, while the parse path yields `AppType` objects
carrying `.port`; the unconditional reparse from finding I then meets parse-path
assumptions with construct-path data. `TCP.make()` and `TCP.pack()` are both
fine — only the full constructor fails. **Reproducible every run.** Believed
pre-existing and unrelated to anything on this branch — confirm against
`/tmp/pcapkit-ref/` before filing.

## Hypotheses ruled out — do not re-tread these

Each was a listed suspect. Each was measured and dismissed.

- **`pcapkit/utilities/logging.py` on the hot path: NO.** A plain `http.pcap`
  extraction makes **zero** `logger` calls — nothing from `logging` appears
  anywhere in the profile. Every hot-path call site uses lazy `%s` formatting,
  not f-string interpolation; the only f-string logger call in the whole package
  is `pcapkit/vendor/__main__.py:56`, which is not on any parse path. Two calls in
  `protocol.py` (lines 431, 560) are already commented out. Confirmed again on the
  heaviest shape measured (`trace-tcp-pcap`): stdlib `logging` is 4944 calls /
  **0.03%**, and `pcapkit.utilities.logging` contributes **0 runtime calls** —
  `get_logger` is import-time only. The logger carries only a `NullHandler` and
  sets no level, so `logger.debug` bails at `isEnabledFor` without formatting.
  The logging system is clean. (The *warning* path does call the logger
  unconditionally — that is finding B, a different mechanism.)
- **`pcapkit/corekit/multidict.py`: NO, under 1%.** It *is* genuinely on the
  per-packet path (`OptionField.unpack`, `transport/tcp.py:664` for TCP options,
  `application/httpv1.py:306` for HTTP headers) — 16.9 `add` calls per frame — but
  costs 0.037 s of 6.831 s profiled on plain `http.pcap`, and 0.82% on the
  reassembly shape. Microbenched at 206.8 ns per `add`. Not worth touching.
- **Repeated `enum` lookups: NO, under 1.4%.** All of `pcapkit/const/**` is 42219
  calls / **0.37%** of the reassembly shape; `aenum` adds another 0.98%; stdlib
  `enum` never appears. Biggest single site `const/reg/apptype.py:30585(get)`,
  13404 calls / 0.0161 s. *Caveat:* on the PCAP-NG option path specifically the
  custom `OptionType.__eq__`/`__hash__` (`const/pcapng/option_type.py:71,77`) do
  make a registry lookup 3.1x a plain int dict (72.4 ns vs 23.6 ns) — that is
  finding F, and it sits inside finding A's loop, so fix A first and re-measure.
- **`ProtoChain` construction: NO, ~0.3%.** All `protochain.py` functions
  together are 0.02 s of 6.831 s profiled on `http.pcap`.
- **`Protocol._import_next_layer`: NO.** 10053 calls, 0.035 s *tottime*. Its
  6.148 s cumtime is just the recursive descent through the whole protocol stack
  and says nothing about its own cost.
- **`Info`/`InfoMeta` construction: NO on construction, ~4.4% on parse.**
  `infoclass.py:259(__update__)` 0.127 s + `:232(__new__)` 0.099 s + the
  generated `<string>:2(__init__)` of 5.099 s profiled. It builds the library's
  actual product and is already lean; 0.0% of `make()`/`pack()`.
- **`store=True`: NO, 1.3%.** Retaining every frame costs almost nothing.
- **`in.pcap` as a profiling target: NO.** 6 frames, ~0.5 ms total. Far too small
  to profile; the per-run fixed setup (0.168 ms for PCAP, 0.30-0.43 ms for
  PCAP-NG) swamps the per-frame work. Use `http.pcap` (1117 frames) and say which
  capture every number came from — the answers differ a lot by capture shape, and
  chardet in particular is ~30% on HTTP and 0% on ARP.

## Verification status

- Four surviving optimisation commits, plus one measured-and-reverted. Suite on
  the branch: **782 passed, 17 skipped, 767 subtests passed** in 413 s. The 17
  skips are exactly the number expected for this repo.
- **Serialisation equivalence** is the strongest evidence and it is clean: all 14
  fixtures, `tree` and `json`, with and without reassembly — 60 runs, 33 MB —
  byte-identical to the pristine tree after every single commit.
- **`pylint` and `mypy` parity** against the pristine tree, checked per commit via
  `/tmp/pcapprof/lint_diff.sh` and `/tmp/pcapprof/mypy_diff.sh`: identical message
  multisets, 124 mypy errors either side. This is what caught change 5.
- On test *counts*: a first attempt to baseline the suite ran against a
  `git archive` of the older base commit `5e4378d9b` and reported 764 passed / 35
  skipped, i.e. **more** skips than the branch's 17. That is an artifact of
  comparing two different commits in two different tree layouts, not a signal
  about these changes, so it was superseded by a properly isolated run: the same
  tree as `HEAD` with **only the four touched source files** reverted to
  `origin/main`, in `/tmp/pcapkit-iso`, result in `/tmp/pcapprof/iso-suite.txt`.
  That is the comparison to trust. Note in general that these optimisations cannot
  change the *collected* count — they would surface as failures, not as fewer
  tests.

## What is not covered, and what to do next

All five shapes the brief asked for are measured: plain extraction, `store=True`,
reassembly, flow tracing, PCAP-NG, and construction (`make` / `pack` / the full
constructor).

Nothing in Z1, Z2 or A-J is implemented. In the order the numbers justify:

1. **Z2, the PCAP flow dumper** — ~80% of the flow-tracing cost, and the
   best-evidenced change in this document (330/331 output files byte-identical
   under the counterfactual). Two independent parts: hold the file open, and stop
   rebuilding a `Frame` to obtain bytes already in hand. Lowest risk of anything
   here.
2. **Z1, eager `analyze()` in IP reassembly** — ~86% of the IP-reassembly cost
   plus most of a 133 ms GC bill. Make `packet` lazy; leave the "should
   unfragmented frames be emitted at all" question to the owner.
3. **A, the double option parse** — ~15% of a PCAP-NG extraction, ~10% of
   `http.pcap`. Highest risk of the three: it is the option parser for every
   protocol with TLVs and the rewind arithmetic interacts with
   `__option_padding__`. Wants its own review with the option-heavy fixtures.
4. **Caching `Field.length`** — a flat ~2.7-2.9% on *every* shape including the
   plain baseline, still 79 `calcsize` calls per frame after commit 3. The template
   is immutable per field instance, so it is pure waste; the work is invalidating
   the cache at the ~15 sites that assign `_template`. Note the cheap version
   (memoising `struct.calcsize` itself, which needs no invalidation) only recovers
   ~0.8% — the property *call*, not `calcsize`, is the bulk. Do the real one.
5. **B, the unconditional `logger.warning` in `warn()`** — cheap, low risk, but
   only pays off on malformed-capture and construction workloads.
6. Then C/D/E/F/H/I, and file J as a bug.
