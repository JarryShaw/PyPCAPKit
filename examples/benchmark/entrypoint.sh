#!/usr/bin/env bash
#
# Inside the image, in one of two modes.
#
# `BENCH_MODE=measure` (the default) times every environment this image holds and
# writes one JSON document per environment. Which environments those are is read
# from `/opt/environments`, written at build time by the interpreter itself -- so
# this script never has to work out whether it is on a version that can hold
# `pypcap`, and cannot get the answer wrong.
#
# The split into two virtualenvs, where there are two, is forced. `pypcap` and
# `pcap-ct` both install a top-level `pcap` module, and with both present
# `import pcap` resolves to `pcap-ct`, leaving upstream's extension module shadowed
# and unreachable -- so no single environment can hold every engine. The `default`
# engine is in all of them, and is what report.py normalises against to join them.
#
# `BENCH_MODE=report` reports on documents produced by *other* containers, handed in
# through `/in`. The matrix spans several interpreters and no single one of them
# measured all of it, so the reporting pass cannot be the tail of a measuring run
# the way it was when there was one image. It runs here rather than on the host
# because the host is not required to have a Python at all -- docker is the only
# thing `run.sh` insists on, and report.py is standard library only, so the
# interpreter it happens to run under does not affect what it says.
set -euo pipefail

CAPTURE="${BENCH_CAPTURE:-/src/examples/captures/in.pcap}"
ROUNDS="${BENCH_ROUNDS:-1000}"
REPEATS="${BENCH_REPEATS:-3}"
ENGINES="${BENCH_ENGINES:-default,dpkt,scapy,pypcap,pcap_ct,pypcapfile,pyshark}"
EMULATED="${BENCH_EMULATED:-}"
MODE="${BENCH_MODE:-measure}"
OUT="${BENCH_OUT:-/out}"
IN="${BENCH_IN:-/in}"

mkdir -p "$OUT"

if [ "$MODE" = measure ]; then
    # Every environment runs the *whole* engine list, not just the engine unique to
    # it. The engines it cannot run then come back with the reason it cannot -- which
    # for `pcap_ct` in the `pypcap` environment is the mutual exclusion itself, stated
    # by the engine rather than asserted by this script.
    #
    # Read on file descriptor 3 rather than on stdin. `pyshark` spawns a `tshark`
    # per extraction and those children inherit this shell's stdin, so a loop fed
    # through stdin is a loop whose remaining lines a subprocess is free to swallow
    # -- and the symptom would be an environment silently never measured rather than
    # an error.
    while read -r label venv lock <&3; do
        [ -n "$label" ] || continue

        echo "==> measuring in the ${label} environment" >&2
        "$venv/bin/python" /src/examples/benchmark/benchmark.py \
            --capture "$CAPTURE" \
            --label "$label" \
            --out "$OUT/$label.json" \
            --rounds "$ROUNDS" \
            --repeats "$REPEATS" \
            --engines "$ENGINES"

        # The locks record the resolved transitive closure, which the pinned
        # requirements files only partly fix. Copied out under the environment's own
        # label rather than the virtualenv's, because the matrix has one lock per
        # (version, `pcap` provider) pair and `pypcap.txt` from five images would be
        # four files overwriting each other.
        cp -f "$lock" "$OUT/$label.txt" 2>/dev/null || true
    done 3< /opt/environments
    exit 0
fi

if [ "$MODE" != report ]; then
    echo "entrypoint.sh: unknown BENCH_MODE '${MODE}'; expected 'measure' or 'report'." >&2
    exit 2
fi

# `[ -e "$path" ] || continue` rather than `shopt -s nullglob`, so an empty directory
# is handled by the loop that reads it instead of by a shell option set a screen
# earlier.
documents=()
for path in "$IN"/*.json; do
    [ -e "$path" ] || continue
    documents+=("$path")
done

if [ "${#documents[@]}" -eq 0 ]; then
    echo "entrypoint.sh: no benchmark documents in ${IN}; nothing to report on." >&2
    exit 1
fi

# A version whose image could not be built or run leaves a note here rather than
# leaving its column out. `run.sh` writes them; the file name is the Python series
# and the contents are the reason, flattened to one line because it becomes a
# bullet in the emitted markup.
report_args=()
for path in "$IN"/missing/*.txt; do
    [ -e "$path" ] || continue
    series="$(basename "$path" .txt)"
    reason="$(tr '\n' ' ' < "$path")"
    report_args+=(--missing "${series}=${reason}")
done

# Built with `if` rather than `[ -n "$X" ] && args+=(...)`: under `set -e` a top-level
# AND-list whose test fails is itself a failed command, so the short form would exit
# the script whenever the variable happened to be empty -- which for a native run, the
# common case, is always.
if [ -n "$EMULATED" ]; then
    report_args+=(--emulated "$EMULATED")
fi

# `${report_args[@]+"${report_args[@]}"}` rather than a bare `"${report_args[@]}"`:
# expanding an empty array under `set -u` is an error before bash 4.4, and a native run
# with no missing versions leaves it empty, which is the common case. The image ships
# bash 5, so this is belt and braces -- but the alternative is a line that is only
# correct because of a fact about the base image that nothing here states.
echo >&2
exec python /src/examples/benchmark/report.py \
    "${documents[@]}" \
    --rst-out "$OUT/table.rst" \
    --versions-rst-out "$OUT/table-versions.rst" \
    ${report_args[@]+"${report_args[@]}"}
