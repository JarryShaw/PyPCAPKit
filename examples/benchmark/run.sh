#!/usr/bin/env bash
#
# One command: build a benchmark image per Python version, run them all, print a
# paste-ready RST table for every version at once.
#
#     examples/benchmark/run.sh
#
# Everything that decides what the numbers mean lives in the images -- the
# interpreters, the pinned engine versions, the capture -- so that the host running
# this script is irrelevant to the result. That is the whole reason for
# containerising a benchmark, and it is why nothing here reports the host's name,
# kernel or CPU. The one host fact that does matter is the architecture, because
# asking for an image that does not match it means running under emulation, and
# emulated timings are not comparable with native ones. This script detects that
# and says so, in its own output.
#
# The versions, their base image digests, and which of them can hold `pypcap` come
# from `python-images.txt`, which is a table rather than logic precisely so that a
# reader can check it. Nothing about the matrix is hard-coded here.
#
# **A version that cannot be built or run does not end the run.** The suite's
# standing promise is that a missing engine is an explained row rather than an
# absent one; a missing *column* is held to the same standard. The reason is written
# where the reporting pass will read it, so it reaches the table rather than
# scrolling past in this script's stderr.
#
# Written for bash 3.2, which is what macOS ships as /bin/bash: no associative
# arrays, and every array expansion guarded so `set -u` does not trip over an
# empty one.
set -euo pipefail

# Assigned before being made readonly, rather than in one statement: `readonly x=$(...)`
# succeeds even when the command substitution fails, so `set -e` would not catch a
# `cd` into a directory that is not there and the script would carry on with a
# wrong path.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly PINS_FILE="${SCRIPT_DIR}/python-images.txt"
readonly IMAGE_PREFIX="pcapkit-benchmark"

ROUNDS=1000
REPEATS=3
ENGINES='default,dpkt,scapy,pypcap,pcap_ct,pypcapfile,pyshark'
CAPTURE='/src/examples/captures/in.pcap'
OUT_DIR="${SCRIPT_DIR}/out"
PLATFORM=''
PYTHONS=''
DO_BUILD=1

usage() {
    cat <<'USAGE'
usage: run.sh [options]

Builds one benchmark image per Python version and runs them all, printing a
summary and two paste-ready reStructuredText tables for README.rst: absolute
milliseconds per (engine, Python version), and engine ratios pooled across the
whole matrix.

options:
  --rounds N       timed extractions per engine per pass (default 1000, matching
                   the methodology the published figures were taken with)
  --repeats N      passes over the whole engine set (default 3; more than one is
                   what makes the run-to-run spread observable, and the spread is
                   what says which gaps in the table are real)
  --engines LIST   comma-separated engines to measure; must include 'default',
                   which every ratio is taken against
  --pythons LIST   comma-separated Python versions, e.g. 3.11,3.12. Defaults to
                   every version python-images.txt marks 'default'; versions it
                   marks 'opt-in' are measured only when named here
  --quick          --rounds 50 --repeats 2, for checking the harness works
                   without waiting for a real measurement
  --platform P     docker platform, e.g. linux/arm64 or linux/amd64. Defaults to
                   this machine's architecture, which is the only setting that
                   produces comparable numbers
  --out DIR        where to write the JSON, the tables and the dependency locks
                   (default examples/benchmark/out)
  --no-build       reuse existing images instead of rebuilding
  -h, --help       this message

A full matrix takes a long while: five versions, up to two virtualenvs each, and
almost all of the measuring time is pyshark, which spawns a tshark process per
extraction. Cut it down with --pythons for fewer columns, --engines to drop
pyshark, or --quick to check the harness rather than measure anything.

exit status:
  0   every requested version was measured, and both tables were written
  3   the tables were written, but at least one version could not be measured
      in full; its reason is in the tables and in <out>/missing/
  1   no table was produced
  2   the arguments were wrong; nothing was built or measured
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --rounds)   ROUNDS="${2:?--rounds needs a value}"; shift 2 ;;
        --repeats)  REPEATS="${2:?--repeats needs a value}"; shift 2 ;;
        --engines)  ENGINES="${2:?--engines needs a value}"; shift 2 ;;
        --pythons)  PYTHONS="${2:?--pythons needs a value}"; shift 2 ;;
        --platform) PLATFORM="${2:?--platform needs a value}"; shift 2 ;;
        --out)      OUT_DIR="${2:?--out needs a value}"; shift 2 ;;
        --capture)  CAPTURE="${2:?--capture needs a value}"; shift 2 ;;
        --quick)    ROUNDS=50; REPEATS=2; shift ;;
        --no-build) DO_BUILD=0; shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          echo "run.sh: unknown option '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo 'run.sh: docker is not on PATH.' >&2
    echo '  On macOS, install Docker Desktop and make sure it is running.' >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo 'run.sh: docker is installed but not responding.' >&2
    echo '  Start Docker Desktop and wait for it to report "running", then retry.' >&2
    exit 1
fi
if [ ! -f "${PINS_FILE}" ]; then
    echo "run.sh: ${PINS_FILE} is missing; it is the version matrix." >&2
    exit 1
fi

# The pins file read through awk rather than parsed in bash. Comment lines and the
# blank lines between them are skipped by requiring four fields, which every real
# row has and no comment line does.
#
# `$1 "" == version ""` rather than `$1 == version`, and this is not noise. awk
# compares two operands *numerically* when both look like numbers, and these look
# exactly like numbers: measured, `--pythons 3.1` matched the `3.10` row, because
# 3.1 == 3.10 is true of the numbers and false of the strings. It built an image
# tagged `py3.1` from 3.10's base and started measuring it -- a typo silently
# becoming a run, which is the class of error the rest of this harness exists to
# refuse. Concatenating an empty string makes both operands strings, so the
# comparison is the one intended.
pin_field() {
    awk -v version="$1" -v field="$2" \
        'substr($1, 1, 1) != "#" && NF >= 4 && $1 "" == version "" { print $field; exit }' \
        "${PINS_FILE}"
}

# Versions measured when --pythons is not given. Reading the tier from the file
# keeps "which versions does a plain run cover" a property of the matrix rather
# than of this script, so adding a version is a one-line change in one place.
default_versions() {
    awk 'substr($1, 1, 1) != "#" && NF >= 4 && $4 == "default" { printf "%s ", $1 }' \
        "${PINS_FILE}"
}

known_versions() {
    awk 'substr($1, 1, 1) != "#" && NF >= 4 { printf "%s ", $1 }' "${PINS_FILE}"
}

if [ -z "${PYTHONS}" ]; then
    VERSIONS="$(default_versions)"
else
    VERSIONS="$(echo "${PYTHONS}" | tr ',' ' ')"
fi

if [ -z "${VERSIONS// /}" ]; then
    echo 'run.sh: no Python versions to measure.' >&2
    exit 2
fi

# An unknown version is a typo, and a typo is fatal here rather than reported as a
# missing column. A column that says "3.1 could not be measured" would be an
# honest-looking answer to a question nobody asked.
#
# Repeats are dropped in the same pass. `--pythons 3.11,3.11` would otherwise give both
# iterations the same container name, so the second `docker run` fails on the collision
# and the version gets written off as a gap -- a spurious failure reported for a version
# that in fact measured perfectly well the first time round.
WANTED=''
for version in ${VERSIONS}; do
    if [ -z "$(pin_field "${version}" 1)" ]; then
        echo "run.sh: '${version}' is not in ${PINS_FILE}." >&2
        echo "  Known versions: $(known_versions)" >&2
        exit 2
    fi
    case " ${WANTED} " in
        *" ${version} "*) ;;
        *) WANTED="${WANTED} ${version}" ;;
    esac
done
VERSIONS="${WANTED}"

# `default` is what every ratio in the report is taken against and the only engine
# present in every environment, so `collect` refuses to build a table without it.
# Caught here rather than there: without this the whole matrix builds and measures
# first, and the failure arrives as a traceback from inside the reporting container
# minutes -- or hours -- after the mistake was made.
case ",${ENGINES}," in
    *,default,*) ;;
    *)  echo "run.sh: --engines must include 'default'; it is the baseline every ratio uses." >&2
        exit 2 ;;
esac

# What this machine is, and hence what it can run without emulation. `uname -m`
# says arm64 on Apple Silicon and aarch64 on Linux ARM; both mean linux/arm64 to
# docker.
HOST_ARCH="$(uname -m)"
case "${HOST_ARCH}" in
    arm64|aarch64)  HOST_PLATFORM='linux/arm64' ;;
    x86_64|amd64)   HOST_PLATFORM='linux/amd64' ;;
    *)              HOST_PLATFORM='' ;;
esac

if [ -z "${PLATFORM}" ]; then
    if [ -z "${HOST_PLATFORM}" ]; then
        echo "run.sh: cannot map '${HOST_ARCH}' onto a docker platform; pass --platform." >&2
        exit 1
    fi
    PLATFORM="${HOST_PLATFORM}"
fi

# Emulation is the one thing that silently invalidates the whole table, so it is
# detected here and threaded all the way into the report rather than left as a
# remark in this script's output that a reader of the table would never see.
EMULATED=''
if [ -n "${HOST_PLATFORM}" ] && [ "${PLATFORM}" != "${HOST_PLATFORM}" ]; then
    EMULATED="Measured under emulation: a ${PLATFORM} image on a ${HOST_PLATFORM} host."
    echo "run.sh: WARNING -- ${EMULATED}" >&2
    echo '  Emulated timings are not comparable with native ones, and the ratios are' >&2
    echo '  only as trustworthy as the emulator is uniform across the work each engine' >&2
    echo '  does. Prefer the native platform unless an engine cannot build on it.' >&2
fi

# Recorded in the report. `pcapkit` is installed from the working tree rather than
# from PyPI, so the git revision is its only meaningful version -- and a dirty tree
# has to say so, or the revision is a claim about code that was not measured.
REVISION='unknown'
if command -v git >/dev/null 2>&1 && git -C "${REPO_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
    REVISION="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
    if ! git -C "${REPO_ROOT}" diff --quiet HEAD -- pcapkit; then
        REVISION="${REVISION}-dirty"
    fi
fi

mkdir -p "${OUT_DIR}" "${OUT_DIR}/missing"

# A previous run's output must not be inherited, and this is not tidiness. The
# reporting pass reports on every document it is handed, so a `3.11-pypcap.json`
# left over from a run on another `pcapkit` revision would be pooled into this run's
# ratios and would fill a column of this run's table -- and the provenance block,
# which reports one revision, would not show the disagreement. A stale note is the
# same problem in the other direction: a version that failed yesterday and builds
# today would still be reported as a missing column, citing a failure nobody could
# reproduce. And a stale table is what makes "no table was produced" below
# unfalsifiable.
#
# Removed by extension rather than with `rm -rf "${OUT_DIR}"`, because --out points
# wherever the caller says and deleting a directory this script did not create is
# not its business.
rm -f "${OUT_DIR}/missing/"*.txt "${OUT_DIR}"/*.json "${OUT_DIR}"/*.rst "${OUT_DIR}"/*.txt

# Results come out with `docker cp` rather than through a bind mount. A mount puts
# the container's uid up against the host directory's ownership, which differs
# between Docker Desktop's file sharing and a plain Linux daemon; copying from a
# stopped container behaves the same everywhere. Containers are therefore not
# `--rm`, and the trap is what stops them leaking one per version. `-v` goes with
# the removal because /out is a declared VOLUME, so each container brings an
# anonymous volume that outlives it otherwise.
CONTAINERS=''
cleanup() {
    for name in ${CONTAINERS}; do
        docker rm --force --volumes "${name}" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT INT TERM

# Recorded rather than announced: this is the note the reporting pass turns into a
# bullet under the table, so the person reading the table months later sees the same
# reason as the person who watched the run.
#
# "a gap" rather than "not measured", because the two callers below that record a note
# *after* copying results out may well have collected an environment or two first, and
# the reporting pass tells those cases apart -- a column with figures in it and a note
# attached is partly measured, not unmeasured.
GAPS=0
record_missing() {
    local version="$1"
    local reason="$2"
    printf '%s\n' "${reason}" > "${OUT_DIR}/missing/${version}.txt"
    GAPS=$((GAPS + 1))
    echo "run.sh: ${version} will be reported as a gap in the table -- ${reason}" >&2
}

REPORT_IMAGE=''

for version in ${VERSIONS}; do
    base_image="$(pin_field "${version}" 2)"
    pypcap_flag="$(pin_field "${version}" 3)"
    image_tag="${IMAGE_PREFIX}:py${version}"

    if [ "${pypcap_flag}" = 'pypcap' ]; then
        with_pypcap=1
    else
        with_pypcap=0
    fi

    echo >&2
    echo "==> Python ${version}: ${image_tag}" >&2

    if [ "${DO_BUILD}" -eq 1 ]; then
        echo "==> building for ${PLATFORM} (pcapkit ${REVISION}, base ${base_image})" >&2
        # The one place a build failure is caught rather than propagated. Five
        # versions means five chances for a base image to have gone missing or a
        # wheel to have stopped publishing for one interpreter, and none of those is
        # a reason to abandon the four columns that would have worked.
        if ! docker build \
                --platform "${PLATFORM}" \
                --file "${SCRIPT_DIR}/Dockerfile" \
                --tag "${image_tag}" \
                --build-arg "PYTHON_IMAGE=${base_image}" \
                --build-arg "WITH_PYPCAP=${with_pypcap}" \
                --build-arg "PCAPKIT_REVISION=${REVISION}" \
                "${REPO_ROOT}"; then
            record_missing "${version}" \
                "the ${image_tag} image failed to build from ${base_image}; see the build log"
            continue
        fi
    elif ! docker image inspect "${image_tag}" >/dev/null 2>&1; then
        record_missing "${version}" \
            "--no-build was given and ${image_tag} does not exist, so nothing was measured"
        continue
    fi

    # The architecture of the image that exists is checked against the one asked for.
    # Without this, a tag left over from a build for the other platform sends
    # `docker run --platform` off to the registry for an image that was never
    # published -- and the resulting "pull access denied" says nothing at all about
    # the real problem. Only the os/arch pair is compared, so `linux/arm64/v8` and
    # `linux/arm64` are not treated as a mismatch.
    # Guarded, unlike every other command substitution in this script: an unguarded
    # one here would take `set -e` and the whole matrix down with it, which is exactly
    # the behaviour the per-version failure handling exists to prevent. Everywhere else
    # a failing substitution really should be fatal; inside this loop nothing should be.
    if ! image_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${image_tag}")"; then
        record_missing "${version}" \
            "${image_tag} could not be inspected, so nothing was measured for this version"
        continue
    fi
    wanted_platform="$(echo "${PLATFORM}" | cut -d/ -f1,2)"
    if [ "${image_platform}" != "${wanted_platform}" ]; then
        record_missing "${version}" \
            "${image_tag} is a ${image_platform} image but ${wanted_platform} was requested; rebuild it"
        continue
    fi

    # The image ID is the reference the report quotes. A locally built image has no
    # registry digest to name, and the ID is a digest of its config, so it identifies
    # the exact image these numbers came from -- which is what the reader needs.
    if ! image_id="$(docker image inspect --format '{{.Id}}' "${image_tag}")"; then
        record_missing "${version}" \
            "${image_tag} could not be inspected, so nothing was measured for this version"
        continue
    fi

    if [ -z "${REPORT_IMAGE}" ]; then
        # Whichever version's image is usable first does the reporting. report.py is
        # standard library only and its arithmetic does not depend on the interpreter,
        # so this is a choice of "one that exists" rather than a choice that matters --
        # but it is made deterministically all the same, so two runs of the same matrix
        # report under the same interpreter. Recorded before the measuring run rather
        # than after it, because a version whose *run* failed still leaves an image
        # perfectly capable of reporting on whatever the others managed.
        REPORT_IMAGE="${image_tag}"
    fi

    container="${IMAGE_PREFIX}-${version}-$$"
    CONTAINERS="${CONTAINERS} ${container}"

    echo "==> running ${ROUNDS} rounds x ${REPEATS} passes" >&2
    if ! docker run \
            --name "${container}" \
            --platform "${PLATFORM}" \
            --env "BENCH_ROUNDS=${ROUNDS}" \
            --env "BENCH_REPEATS=${REPEATS}" \
            --env "BENCH_ENGINES=${ENGINES}" \
            --env "BENCH_CAPTURE=${CAPTURE}" \
            --env "BENCH_IMAGE=${image_tag} (${image_id})" \
            "${image_tag}"; then
        # A run that died partway may still have written a document or two, so its
        # output is collected before the version is written off -- an environment
        # that finished is a column cell that can be reported.
        docker cp "${container}:/out/." "${OUT_DIR}/" >/dev/null 2>&1 || true
        record_missing "${version}" \
            "measuring in ${image_tag} exited non-zero; any environment that finished first is still reported"
        continue
    fi

    if ! docker cp "${container}:/out/." "${OUT_DIR}/" >/dev/null 2>&1; then
        record_missing "${version}" \
            "the measurements could not be copied out of ${container}"
        continue
    fi
done

# Whether there is anything to report is decided by counting the documents that
# landed, not by counting the versions that finished cleanly. A container that died
# after writing its first environment's JSON still contributed a measurement, and
# refusing to report it would throw away real work while a note explaining the
# failure sat next to it.
DOCUMENTS=0
for path in "${OUT_DIR}"/*.json; do
    [ -e "${path}" ] || continue
    DOCUMENTS=$((DOCUMENTS + 1))
done

echo >&2
if [ "${DOCUMENTS}" -eq 0 ] || [ -z "${REPORT_IMAGE}" ]; then
    echo 'run.sh: no environment produced a measurement; there is nothing to report.' >&2
    echo '  The reasons are in:' >&2
    ls -1 "${OUT_DIR}/missing" >&2 2>/dev/null || true
    exit 1
fi

# The reporting pass. It runs inside an image rather than on the host because the
# host is not required to have a Python -- docker is the only thing this script
# insists on -- and because a pinned interpreter is one less thing that can differ
# between two runs of the same matrix.
#
# Inputs go in through /in and results come back out of /out, both with `docker cp`,
# for the same reason the measuring containers avoid a bind mount: ownership of a
# host directory behaves differently under Docker Desktop's file sharing than under
# a plain Linux daemon, and copying to and from a stopped container behaves the same
# everywhere.
REPORTER="${IMAGE_PREFIX}-report-$$"
CONTAINERS="${CONTAINERS} ${REPORTER}"

echo "==> reporting on ${DOCUMENTS} environment(s) in ${REPORT_IMAGE}" >&2
docker create \
    --name "${REPORTER}" \
    --platform "${PLATFORM}" \
    --env 'BENCH_MODE=report' \
    --env "BENCH_EMULATED=${EMULATED}" \
    "${REPORT_IMAGE}" >/dev/null

status=0
if ! docker cp "${OUT_DIR}/." "${REPORTER}:/in/" >/dev/null 2>&1; then
    echo "run.sh: could not hand the measurements to the reporting container." >&2
    exit 1
fi
# `|| status=$?` rather than a bare invocation: the report's output is still worth
# collecting when it fails partway, and `set -e` would abandon it.
docker start --attach "${REPORTER}" || status=$?
docker cp "${REPORTER}:/out/." "${OUT_DIR}/" >/dev/null 2>&1 || status=1

# What actually landed is checked rather than announced. `docker cp` of an empty
# directory succeeds, so an earlier version of this reported "wrote ... table.rst"
# after a run that crashed before writing anything -- which is worse than saying
# nothing, because it sends the reader looking for a file that is not there.
echo >&2
if [ -f "${OUT_DIR}/table-versions.rst" ] && [ -f "${OUT_DIR}/table.rst" ]; then
    echo "==> wrote ${OUT_DIR}/table-versions.rst -- absolute milliseconds per engine" >&2
    echo "    and Python version, ready to paste into README.rst's Test Results," >&2
    echo "    and ${OUT_DIR}/table.rst -- the machine-independent ratio view," >&2
    echo '    alongside the raw JSON and the per-environment locks' >&2

    # A run that lost a column produced everything it could and is still not a run that
    # went as asked, so it says so in the exit status as well as in the tables. Nothing
    # was aborted -- the requirement is that a failing version must not end the run, not
    # that it must be indistinguishable from success -- and an exit code is the only part
    # of this a scheduled invocation reads. A distinct code rather than 1, so "some
    # columns are missing, the tables are written" can be told from "there is no table".
    if [ "${GAPS}" -gt 0 ] && [ "${status}" -eq 0 ]; then
        echo >&2
        echo "run.sh: ${GAPS} of the requested Python version(s) could not be measured in" >&2
        echo '    full; the tables were still written, with the reasons in them and in' >&2
        echo "    ${OUT_DIR}/missing/. Exiting 3 to say so." >&2
        status=3
    fi
else
    echo "run.sh: no table was produced; ${OUT_DIR} holds whatever the run got to." >&2
    ls -1 "${OUT_DIR}" >&2 2>/dev/null || true
    if [ "${status}" -eq 0 ]; then
        status=1
    fi
fi

exit "${status}"
