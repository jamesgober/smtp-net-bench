#!/usr/bin/env bash
# Runs every competitor benchmark (B1-B4) pinned to two cores and writes a
# results file under results/, named by date and commit.
#
# Usage:
#   scripts/run.sh            full run (3 s measurement, 1 s warm-up)
#   scripts/run.sh --smoke    short run (1 s measurement) to check that
#                             everything works; labelled as a smoke run
#
# Environment:
#   CORES=2,3                 the cores to pin to (taskset -c): B4 runs a
#                             client and the test server, so it needs two
#   CARGO_TARGET_DIR          honoured
#   SMTP_NET_PATH             build against a local smtp-net checkout
#                             instead of crates.io (for a run before a
#                             release); the results file records it
#
# Linux only (taskset, /proc/cpuinfo); in WSL run it from the Linux side.
# Close other work first: a busy machine moves every row.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

MODE="measurement"
CRITERION_ARGS=(--warm-up-time 1 --measurement-time 3 --noplot)
if [[ "${1:-}" == "--smoke" ]]; then
    MODE="smoke"
    CRITERION_ARGS=(--warm-up-time 1 --measurement-time 1 --noplot)
    shift
fi
if [[ $# -gt 0 ]]; then
    echo "usage: $0 [--smoke]" >&2
    exit 2
fi

CORES="${CORES:-2,3}"
command -v taskset >/dev/null || { echo "taskset not found (util-linux)" >&2; exit 1; }

PATCH=(--locked)
SOURCE="crates.io"
if [[ -n "${SMTP_NET_PATH:-}" ]]; then
    # A patched build rewrites the lock file's smtp-net entry: not --locked.
    PATCH=(--config "patch.crates-io.smtp-net.path=\"$SMTP_NET_PATH\"")
    SOURCE="local checkout $(git -C "$SMTP_NET_PATH" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
fi

COMMIT="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
DIRTY=""
if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
    DIRTY="-dirty"
fi
NAME="$(date -u +%Y-%m-%d)-${COMMIT}${DIRTY}"
if [[ "$MODE" == "smoke" ]]; then
    NAME="${NAME}-smoke"
fi
OUT="$ROOT/results/$NAME.md"
mkdir -p "$ROOT/results"

cargo bench --no-run "${PATCH[@]}" >/dev/null

{
    echo "# smtp-net-bench results: $NAME ($MODE)"
    echo
    echo "- Date (UTC): $(date -u '+%Y-%m-%d %H:%M')"
    echo "- CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')"
    echo "- Cores used: $CORES (taskset); logical CPUs: $(nproc)"
    echo "- Load average before the run: $(cut -d' ' -f1-3 /proc/loadavg)"
    echo "- Kernel: $(uname -sr)"
    echo "- Rust: $(rustc --version)"
    echo "- smtp-net: $SOURCE"
    echo "- Competitors (Cargo.lock):"
    for c in lettre mail-builder mail-send mail-auth base64 quoted_printable; do
        v="$(cargo tree -i "$c" --depth 0 "${PATCH[@]}" 2>/dev/null | head -1 | awk '{print $2}')"
        echo "  - $c $v"
    done
    echo
    echo '```'
} > "$OUT"

for b in b1_build b2_encode b3_dkim b4_send; do
    taskset -c "$CORES" cargo bench "${PATCH[@]}" --bench "$b" -- "${CRITERION_ARGS[@]}" 2>&1 \
        | grep -E '^(b[1-4]_|[a-z].*/)|time:|thrpt:' | grep -v '^Benchmarking' >> "$OUT"
done

{
    echo '```'
    echo
    echo "- Load average after the run: $(cut -d' ' -f1-3 /proc/loadavg)"
} >> "$OUT"
echo "wrote $OUT"
