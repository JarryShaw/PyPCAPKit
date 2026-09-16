#!/usr/bin/env bash
#
# Inside the image: measure each virtualenv, then report across all of them.
#
# The split into two virtualenvs is forced. `pypcap` and `pcap-ct` both install a
# top-level `pcap` module, and with both present `import pcap` resolves to
# `pcap-ct`, leaving upstream's extension module shadowed and unreachable -- so no
# single environment can hold every engine. The `default` engine is in both, and
# is what report.py normalises against to join the two runs.
set -euo pipefail

CAPTURE="${BENCH_CAPTURE:-/src/examples/captures/in.pcap}"
ROUNDS="${BENCH_ROUNDS:-1000}"
REPEATS="${BENCH_REPEATS:-3}"
ENGINES="${BENCH_ENGINES:-default,dpkt,scapy,pypcap,pcap_ct,pypcapfile,pyshark}"
IMAGE="${BENCH_IMAGE:-}"
EMULATED="${BENCH_EMULATED:-}"
OUT="${BENCH_OUT:-/out}"

mkdir -p "$OUT"

# Every environment runs the *whole* engine list, not just the engine unique to
# it. The engines it cannot run then come back with the reason it cannot -- which
# for `pcap_ct` in the `pypcap` environment is the mutual exclusion itself, stated
# by the engine rather than asserted by this script.
for env_name in pypcap pcap_ct; do
    case "$env_name" in
        pypcap)  venv=/opt/venv-pypcap ;;
        pcap_ct) venv=/opt/venv-pcap_ct ;;
    esac

    echo "==> measuring in the ${env_name} environment" >&2
    "$venv/bin/python" /src/examples/benchmark/benchmark.py \
        --capture "$CAPTURE" \
        --label "$env_name" \
        --out "$OUT/$env_name.json" \
        --rounds "$ROUNDS" \
        --repeats "$REPEATS" \
        --engines "$ENGINES"
done

# The locks record the resolved transitive closure, which the pinned requirements
# files only partly fix. Copied out so a run stays reconstructable after the image
# is gone.
cp -f /opt/locks/*.txt "$OUT/" 2>/dev/null || true

# report.py is standard library only, so it runs on the base interpreter rather
# than in either virtualenv -- neither environment gets to be the privileged one.
#
# Built with `if` rather than `[ -n "$X" ] && args+=(...)`: under `set -e` a
# top-level AND-list whose test fails is itself a failed command, so the short
# form would exit the script whenever the variable happened to be empty.
report_args=()
if [ -n "$IMAGE" ]; then
    report_args+=(--image "$IMAGE")
fi
if [ -n "$EMULATED" ]; then
    report_args+=(--emulated "$EMULATED")
fi

echo >&2
exec python /src/examples/benchmark/report.py \
    "$OUT/pypcap.json" "$OUT/pcap_ct.json" \
    --rst-out "$OUT/table.rst" \
    "${report_args[@]}"
