#!/usr/bin/env bash
#
# run.sh without Docker: measure the interpreters already on this machine, and
# print the same two tables.
#
#     examples/benchmark/native.sh --pythons 3.11,3.12
#
# For each version it builds the virtualenvs the Dockerfile builds -- `pcap_ct`
# always, and `pypcap` where python-images.txt says it can be built -- runs
# benchmark.py in each, as entrypoint.sh does, and then report.py over every
# document. .github/workflows/benchmark.yml runs it on a hosted runner, which is a
# fresh VM per job already, so containers there would add a build per version and
# no isolation (#2125).
#
# **What this does not pin**, against run.sh: the interpreter's patch release, and
# the system's tshark and libpcap. Each is recorded in the report rather than
# fixed, so the absolute times compare only within one run. The README's "On
# GitHub Actions" says more. For a table to publish from a machine of your own,
# run.sh is still the reproducible path.
#
# Failures are held to run.sh's standard: a version that cannot be found, built or
# measured is written to <out>/missing/ and becomes an explained column, and an
# engine that cannot be installed is an explained row. Exit status is run.sh's:
# 0 measured in full, 3 tables written with gaps, 1 no table, 2 bad arguments.
#
# Written for bash 3.2, which is what macOS ships as /bin/bash, and for Git Bash
# on Windows, where a virtualenv's interpreter is under Scripts/ and a hosted
# runner's interpreters are found in its tool cache rather than as `python3.X`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly PINS_FILE="${SCRIPT_DIR}/python-images.txt"

PYTHONS=''
ENGINES=''
ROUNDS=''
REPEATS=''
OUT_DIR="${SCRIPT_DIR}/out"
WORK_DIR="${REPO_ROOT}/.bench-venvs"
IMAGE="${BENCH_IMAGE:-}"
CAPTURE="${REPO_ROOT}/examples/captures/in.pcap"

usage() {
    cat <<'USAGE'
usage: native.sh [options]

Measures each named Python version with the interpreter already on this machine,
in the virtualenvs the Dockerfile builds, and prints the two tables run.sh prints.

options:
  --pythons LIST   comma-separated Python versions, e.g. 3.11,3.12; defaults to
                   every version python-images.txt marks 'default'
  --engines LIST   comma-separated engines, including 'default' (default: all)
  --rounds N       timed extractions per engine per pass (default: benchmark.py's)
  --repeats N      passes over the whole engine set (default: benchmark.py's)
  --image TEXT     what to name as the image in the report, e.g. the runner
  --out DIR        where to write the results (default examples/benchmark/out)
  --work DIR       where to build the virtualenvs (default .bench-venvs)
  -h, --help       this message

exit status: 0 measured in full; 3 tables written, some version not measured in
full; 1 no table; 2 bad arguments.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --pythons)  PYTHONS="${2:?--pythons needs a value}"; shift 2 ;;
        --engines)  ENGINES="${2:?--engines needs a value}"; shift 2 ;;
        --rounds)   ROUNDS="${2:?--rounds needs a value}"; shift 2 ;;
        --repeats)  REPEATS="${2:?--repeats needs a value}"; shift 2 ;;
        --image)    IMAGE="${2:?--image needs a value}"; shift 2 ;;
        --out)      OUT_DIR="${2:?--out needs a value}"; shift 2 ;;
        --work)     WORK_DIR="${2:?--work needs a value}"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *)          echo "native.sh: unknown option '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

# The pins file's column for a version, as run.sh's `pin_field` reads it: `$1 ""`
# makes awk compare strings, so 3.1 is not 3.10.
pin_field() {
    awk -v version="$1" -v field="$2" \
        'substr($1, 1, 1) != "#" && NF >= 4 && $1 "" == version "" { print $field; exit }' \
        "${PINS_FILE}"
}

if [ -z "${PYTHONS}" ]; then
    VERSIONS="$(awk 'substr($1, 1, 1) != "#" && NF >= 4 && $4 == "default" { printf "%s ", $1 }' "${PINS_FILE}")"
else
    VERSIONS="$(echo "${PYTHONS}" | tr -s ',[:space:]' ' ')"
fi
if [ -z "${VERSIONS// /}" ]; then
    echo 'native.sh: no Python versions to measure.' >&2
    exit 2
fi

# As in run.sh: a version python-images.txt does not name is a typo, and fatal
# rather than a column; a repeat is dropped, so it is not measured twice.
WANTED=''
for version in ${VERSIONS}; do
    if [ -z "$(pin_field "${version}" 1)" ]; then
        echo "native.sh: '${version}' is not in ${PINS_FILE}." >&2
        echo "  Known versions: $(awk 'substr($1, 1, 1) != "#" && NF >= 4 { printf "%s ", $1 }' "${PINS_FILE}")" >&2
        exit 2
    fi
    case " ${WANTED} " in
        *" ${version} "*) ;;
        *) WANTED="${WANTED} ${version}" ;;
    esac
done
VERSIONS="${WANTED}"
if [ -n "${ENGINES}" ]; then
    case ",${ENGINES}," in
        *,default,*) ;;
        *)  echo "native.sh: --engines must include 'default'; it is the baseline every ratio uses." >&2
            exit 2 ;;
    esac
fi

BENCH_ARGS=()
if [ -n "${ENGINES}" ]; then BENCH_ARGS+=(--engines "${ENGINES}"); fi
if [ -n "${ROUNDS}" ]; then BENCH_ARGS+=(--rounds "${ROUNDS}"); fi
if [ -n "${REPEATS}" ]; then BENCH_ARGS+=(--repeats "${REPEATS}"); fi

# The interpreter for a series, asked for its own version, as the Dockerfile labels
# an environment: a `python3.12` that is really something else must not fill the
# 3.12 column. `python3.X` first; then, on Windows, where setup-python provides no
# such names, the tool cache and the `py` launcher.
interpreter() {
    local version="$1" candidate cache
    local candidates=()
    if command -v "python${version}" >/dev/null 2>&1; then
        candidates+=("$(command -v "python${version}")")
    fi
    if [ -n "${RUNNER_TOOL_CACHE:-}" ]; then
        cache="$(cygpath -u "${RUNNER_TOOL_CACHE}" 2>/dev/null || echo "${RUNNER_TOOL_CACHE}")"
        for candidate in "${cache}/Python/${version}".*/x64/python.exe "${cache}/Python/${version}".*/arm64/python.exe; do
            if [ -f "${candidate}" ]; then candidates+=("${candidate}"); fi
        done
    fi
    if command -v py >/dev/null 2>&1; then
        candidate="$(py "-${version}" -c 'import sys; print(sys.executable)' 2>/dev/null || true)"
        if [ -n "${candidate}" ]; then candidates+=("${candidate}"); fi
    fi
    for candidate in ${candidates[@]+"${candidates[@]}"}; do
        if [ "$("${candidate}" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)" = "${version}" ]; then
            echo "${candidate}"
            return 0
        fi
    done
    return 1
}

# A virtualenv's own interpreter: bin/ everywhere but Windows, which uses Scripts/.
venv_python() {
    if [ -d "$1/Scripts" ]; then echo "$1/Scripts/python"; else echo "$1/bin/python"; fi
}

REVISION='unknown'
if command -v git >/dev/null 2>&1 && git -C "${REPO_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
    REVISION="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
    if ! git -C "${REPO_ROOT}" diff --quiet HEAD -- pcapkit; then
        REVISION="${REVISION}-dirty"
    fi
fi
export PCAPKIT_REVISION="${REVISION}"
export BENCH_IMAGE="${IMAGE}"

# A previous run's output is not inherited, for run.sh's reasons.
mkdir -p "${OUT_DIR}/missing" "${WORK_DIR}"
rm -f "${OUT_DIR}/missing/"*.txt "${OUT_DIR}"/*.json "${OUT_DIR}"/*.rst "${OUT_DIR}"/*.txt

GAPS=0
record_missing() {
    printf '%s\n' "$2" > "${OUT_DIR}/missing/$1.txt"
    GAPS=$((GAPS + 1))
    echo "native.sh: $1 will be reported as a gap in the table -- $2" >&2
}

REPORTER=''
for version in ${VERSIONS}; do
    echo >&2
    echo "==> Python ${version}" >&2
    if ! python="$(interpreter "${version}")"; then
        record_missing "${version}" "no Python ${version} interpreter was found on this machine"
        continue
    fi
    "${python}" -c 'import platform, sys; print("==> " + platform.python_version() + " at " + sys.executable)' >&2

    notes="${WORK_DIR}/${version}/notes"
    rm -rf "${WORK_DIR:?}/${version}"
    mkdir -p "${notes}/install-failures" "${notes}/not-attempted"
    environments=''

    # pcap-ct's virtualenv is the one every interpreter holds, so a failure here
    # costs the whole column.
    venv="${WORK_DIR}/${version}/pcap_ct"
    if "${python}" -m venv "${venv}" \
            && "$(venv_python "${venv}")" -m pip install --quiet --upgrade pip setuptools wheel \
            && "$(venv_python "${venv}")" -m pip install --quiet \
                --requirement "${SCRIPT_DIR}/requirements-pcap_ct.txt" \
            && "$(venv_python "${venv}")" -m pip install --quiet --no-deps "${REPO_ROOT}"; then
        environments="${environments} pcap_ct"
    else
        record_missing "${version}" "the pcap_ct virtualenv could not be built for Python ${version}; see the log"
        continue
    fi

    # pypcap compiles, so its install alone may fail, and is then a row with the
    # pip error, in the Dockerfile's words.
    if [ "$(pin_field "${version}" 3)" = 'pypcap' ]; then
        venv="${WORK_DIR}/${version}/pypcap"
        log="${WORK_DIR}/${version}/pypcap-install.log"
        if "${python}" -m venv "${venv}" \
                && "$(venv_python "${venv}")" -m pip install --quiet --upgrade pip setuptools wheel \
                && "$(venv_python "${venv}")" -m pip install --quiet \
                    --requirement "${SCRIPT_DIR}/requirements-common.txt"; then
            if ! "$(venv_python "${venv}")" -m pip install \
                    --requirement "${SCRIPT_DIR}/requirements-pypcap.txt" > "${log}" 2>&1; then
                echo 'WARNING: pypcap failed to install; it will be reported as not measured.' >&2
                { echo 'pypcap failed to build here, so it could not be measured.'
                  echo 'The tail of the pip output was:'
                  tail -n 12 "${log}"; } > "${notes}/install-failures/pypcap.txt"
                cat "${log}" >&2
            fi
            if "$(venv_python "${venv}")" -m pip install --quiet --no-deps "${REPO_ROOT}"; then
                environments="${environments} pypcap"
            fi
        else
            echo 'pypcap could not be measured: its virtualenv failed to build; see the log.' \
                > "${notes}/install-failures/pypcap.txt"
        fi
    else
        { echo 'pypcap is not installable on this interpreter, so it was not built here:'
          echo 'pypcap 1.3.0 ships a pcap.c pre-generated by Cython 0.29.32, which does'
          echo 'not compile against the Python 3.12+ C API. The engine is unsupported here'
          echo 'rather than broken here.'; } > "${notes}/not-attempted/pypcap.txt"
    fi

    if [ -z "${REPORTER}" ]; then
        REPORTER="$(venv_python "${WORK_DIR}/${version}/pcap_ct")"
    fi

    failed=''
    for provider in ${environments}; do
        label="${version}-${provider}"
        venv="${WORK_DIR}/${version}/${provider}"
        echo "==> measuring in the ${label} environment" >&2
        if ! BENCH_INSTALL_FAILURES="${notes}/install-failures" BENCH_NOT_ATTEMPTED="${notes}/not-attempted" \
                "$(venv_python "${venv}")" "${SCRIPT_DIR}/benchmark.py" --capture "${CAPTURE}" \
                --label "${label}" --out "${OUT_DIR}/${label}.json" ${BENCH_ARGS[@]+"${BENCH_ARGS[@]}"}; then
            failed="${failed} ${label}"
        fi
        "$(venv_python "${venv}")" -m pip freeze > "${OUT_DIR}/${label}.txt" 2>/dev/null || true
    done
    if [ -n "${failed}" ]; then
        record_missing "${version}" \
            "measuring in${failed} exited non-zero; any environment that finished first is still reported"
    fi
done

DOCUMENTS=()
for path in "${OUT_DIR}"/*.json; do
    if [ -e "${path}" ]; then DOCUMENTS+=("${path}"); fi
done

echo >&2
if [ "${#DOCUMENTS[@]}" -eq 0 ] || [ -z "${REPORTER}" ]; then
    echo 'native.sh: no environment produced a measurement; there is nothing to report.' >&2
    exit 1
fi

REPORT_ARGS=()
for path in "${OUT_DIR}"/missing/*.txt; do
    if [ -e "${path}" ]; then
        REPORT_ARGS+=(--missing "$(basename "${path}" .txt)=$(tr '\n' ' ' < "${path}")")
    fi
done

status=0
"${REPORTER}" "${SCRIPT_DIR}/report.py" "${DOCUMENTS[@]}" \
    --rst-out "${OUT_DIR}/table.rst" --versions-rst-out "${OUT_DIR}/table-versions.rst" \
    ${REPORT_ARGS[@]+"${REPORT_ARGS[@]}"} || status=$?

if [ ! -f "${OUT_DIR}/table.rst" ] || [ ! -f "${OUT_DIR}/table-versions.rst" ]; then
    echo "native.sh: no table was produced; ${OUT_DIR} holds whatever the run got to." >&2
    exit 1
fi
if [ "${status}" -ne 0 ]; then
    exit 1
fi
if [ "${GAPS}" -gt 0 ]; then
    echo "native.sh: ${GAPS} of the requested Python version(s) could not be measured in full;" >&2
    echo "    the tables were still written, with the reasons in them and in ${OUT_DIR}/missing/." >&2
    exit 3
fi
exit 0
