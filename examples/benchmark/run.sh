#!/usr/bin/env bash
#
# One command: build the benchmark image, run it, print a paste-ready RST table.
#
#     examples/benchmark/run.sh
#
# Everything that decides what the numbers mean lives in the image -- the
# interpreter, the pinned engine versions, the capture -- so that the host running
# this script is irrelevant to the result. That is the whole reason for
# containerising a benchmark, and it is why nothing here reports the host's name,
# kernel or CPU. The one host fact that does matter is the architecture, because
# asking for an image that does not match it means running under emulation, and
# emulated timings are not comparable with native ones. This script detects that
# and says so, in its own output.
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
readonly IMAGE_TAG="pcapkit-benchmark:local"

ROUNDS=1000
REPEATS=3
ENGINES='default,dpkt,scapy,pypcap,pcap_ct,pypcapfile,pyshark'
CAPTURE='/src/examples/captures/in.pcap'
OUT_DIR="${SCRIPT_DIR}/out"
PLATFORM=''
DO_BUILD=1

usage() {
    cat <<'USAGE'
usage: run.sh [options]

Builds the benchmark image and runs it, printing a summary and a paste-ready
reStructuredText table for README.rst.

options:
  --rounds N       timed extractions per engine per pass (default 1000, matching
                   the methodology the published figures were taken with)
  --repeats N      passes over the whole engine set (default 3; more than one is
                   what makes the run-to-run spread observable, and the spread is
                   what says which gaps in the table are real)
  --engines LIST   comma-separated engines to measure; must include 'default',
                   which every ratio is taken against
  --quick          --rounds 50 --repeats 2, for checking the harness works
                   without waiting for a real measurement
  --platform P     docker platform, e.g. linux/arm64 or linux/amd64. Defaults to
                   this machine's architecture, which is the only setting that
                   produces comparable numbers
  --out DIR        where to write the JSON, the table and the dependency locks
                   (default examples/benchmark/out)
  --no-build       reuse an existing image instead of rebuilding
  -h, --help       this message

A full run takes a while, and almost all of it is pyshark: it spawns a tshark
process per extraction, so at the default settings it accounts for the large
majority of the wall clock. Drop it with --engines to get everything else quickly.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --rounds)   ROUNDS="${2:?--rounds needs a value}"; shift 2 ;;
        --repeats)  REPEATS="${2:?--repeats needs a value}"; shift 2 ;;
        --engines)  ENGINES="${2:?--engines needs a value}"; shift 2 ;;
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

if [ "${DO_BUILD}" -eq 1 ]; then
    echo "==> building ${IMAGE_TAG} for ${PLATFORM} (pcapkit ${REVISION})" >&2
    docker build \
        --platform "${PLATFORM}" \
        --file "${SCRIPT_DIR}/Dockerfile" \
        --tag "${IMAGE_TAG}" \
        --build-arg "PCAPKIT_REVISION=${REVISION}" \
        "${REPO_ROOT}"
elif ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
    echo "run.sh: --no-build was given but ${IMAGE_TAG} does not exist." >&2
    exit 1
fi

# The architecture of the image that exists is checked against the one asked for.
# Without this, a tag left over from a build for the other platform sends
# `docker run --platform` off to the registry for an image that was never
# published -- and the resulting "pull access denied" says nothing at all about
# the real problem. Only the os/arch pair is compared, so `linux/arm64/v8` and
# `linux/arm64` are not treated as a mismatch.
IMAGE_PLATFORM="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${IMAGE_TAG}")"
WANTED_PLATFORM="$(echo "${PLATFORM}" | cut -d/ -f1,2)"
if [ "${IMAGE_PLATFORM}" != "${WANTED_PLATFORM}" ]; then
    echo "run.sh: ${IMAGE_TAG} is a ${IMAGE_PLATFORM} image but ${WANTED_PLATFORM} was requested." >&2
    echo '  Rebuild it (drop --no-build) or ask for the platform it was built for.' >&2
    exit 1
fi

# The image ID is the reference the report quotes. A locally built image has no
# registry digest to name, and the ID is a digest of its config, so it identifies
# the exact image these numbers came from -- which is what the reader needs.
IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${IMAGE_TAG}")"
IMAGE_REF="${IMAGE_TAG} (${IMAGE_ID})"

mkdir -p "${OUT_DIR}"

# Results come out with `docker cp` rather than through a bind mount. A mount puts
# the container's uid up against the host directory's ownership, which differs
# between Docker Desktop's file sharing and a plain Linux daemon; copying from a
# stopped container behaves the same everywhere. The container is therefore not
# `--rm`, and the trap is what stops that leaking one per run.
CONTAINER="pcapkit-benchmark-$$"
cleanup() {
    docker rm --force "${CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "==> running ${ROUNDS} rounds x ${REPEATS} passes in two environments" >&2

# `|| status=$?` rather than a bare invocation: the run's output is still worth
# collecting when it fails partway, and `set -e` would abandon it.
status=0
docker run \
    --name "${CONTAINER}" \
    --platform "${PLATFORM}" \
    --env "BENCH_ROUNDS=${ROUNDS}" \
    --env "BENCH_REPEATS=${REPEATS}" \
    --env "BENCH_ENGINES=${ENGINES}" \
    --env "BENCH_CAPTURE=${CAPTURE}" \
    --env "BENCH_IMAGE=${IMAGE_REF}" \
    --env "BENCH_EMULATED=${EMULATED}" \
    "${IMAGE_TAG}" || status=$?

if ! docker cp "${CONTAINER}:/out/." "${OUT_DIR}/" >/dev/null 2>&1; then
    echo "run.sh: could not copy results out of the container." >&2
    if [ "${status}" -eq 0 ]; then
        status=1
    fi
fi

# What actually landed is checked rather than announced. `docker cp` of an empty
# directory succeeds, so the previous version of this reported "wrote ... table.rst"
# after a run that crashed before writing anything -- which is worse than saying
# nothing, because it sends the reader looking for a file that is not there.
echo >&2
if [ -f "${OUT_DIR}/table.rst" ]; then
    echo "==> wrote ${OUT_DIR}/table.rst -- the snippet above, on its own," >&2
    echo "    ready to paste into README.rst, alongside the raw JSON and the locks" >&2
else
    echo "run.sh: no table was produced; ${OUT_DIR} holds whatever the run got to." >&2
    ls -1 "${OUT_DIR}" >&2 2>/dev/null || true
    if [ "${status}" -eq 0 ]; then
        status=1
    fi
fi

exit "${status}"
