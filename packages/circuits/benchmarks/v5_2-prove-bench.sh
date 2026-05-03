#!/usr/bin/env bash
# V5.2 native-CLI prove benchmark.  Runs `scripts/v5_2-prove.mjs` under both
# backends (snarkjs + rapidsnark) and captures TRUE peak RSS by polling
# /proc/<pid>/status:VmRSS at 100 ms cadence in a side process.
#
# Why /proc/<pid> polling instead of Node's process.resourceUsage().maxRSS:
#   - For --backend rapidsnark, the heavy work happens in a SPAWNED child
#     (the rapidsnark binary).  process.resourceUsage() in the parent
#     misses the child's peak entirely.
#   - For --backend snarkjs, in-process maxRSS is fine but the side-process
#     poller gives a single uniform measurement source for cross-backend
#     comparison.
#   - 100 ms cadence catches MSM/NTT spikes that 1-second granularity
#     (which top/htop default to) misses.
#
# Output: prints both runs' summaries side-by-side at the end.
#
# Prereqs (set via env or hardcode):
#   RAPIDSNARK_BIN   path to iden3 rapidsnark prover binary (Linux x86_64)

set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WITNESS="$PKG_DIR/ceremony/v5_2/witness-input-sample.json"
ZKEY="$PKG_DIR/ceremony/v5_2/qkb-v5_2-stub.zkey"
WASM="$PKG_DIR/build/v5_2-stub/QKBPresentationV5_js/QKBPresentationV5.wasm"
VKEY="$PKG_DIR/ceremony/v5_2/verification_key.json"

RAPIDSNARK_BIN="${RAPIDSNARK_BIN:-/home/alikvovk/.cache/qkb-bin/rapidsnark-linux-x86_64-v0.0.8/bin/prover}"

OUT_BASE="${OUT_BASE:-/tmp/v5_2-prove-bench}"
mkdir -p "$OUT_BASE"

for f in "$WITNESS" "$ZKEY" "$WASM" "$VKEY"; do
  [[ -f "$f" ]] || { echo "[FATAL] missing fixture: $f" >&2; exit 1; }
done
[[ -x "$RAPIDSNARK_BIN" ]] || { echo "[FATAL] rapidsnark bin not executable: $RAPIDSNARK_BIN" >&2; exit 1; }

# Side-process RSS poller.  Watches the entire process tree rooted at
# the given pid (parent + spawned children) so the rapidsnark child is
# accounted for.  Emits one CSV row per 100 ms tick: epoch_ms, sum_rss_kb.
poll_pid_tree_rss() {
  local root_pid="$1"
  local out_csv="$2"
  echo "epoch_ms,sum_rss_kb" > "$out_csv"
  while [[ -d "/proc/$root_pid" ]]; do
    # Walk the tree: collect root + all descendants via /proc/<pid>/task/<tid>/children
    pids=("$root_pid")
    queue=("$root_pid")
    while [[ ${#queue[@]} -gt 0 ]]; do
      cur="${queue[0]}"
      queue=("${queue[@]:1}")
      for tid_dir in "/proc/$cur/task/"*; do
        [[ -r "$tid_dir/children" ]] || continue
        for child in $(cat "$tid_dir/children" 2>/dev/null); do
          pids+=("$child")
          queue+=("$child")
        done
      done
    done
    sum=0
    for pid in "${pids[@]}"; do
      if [[ -r "/proc/$pid/status" ]]; then
        rss=$(awk '/^VmRSS:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null || echo 0)
        sum=$((sum + rss))
      fi
    done
    echo "$(date +%s%3N),${sum}" >> "$out_csv"
    sleep 0.1
  done
}

run_backend() {
  local backend="$1"
  local extra_args="$2"
  local out_dir="$OUT_BASE/$backend"
  local rss_csv="$OUT_BASE/$backend-rss.csv"
  rm -rf "$out_dir"; mkdir -p "$out_dir"

  echo
  echo "=== backend: $backend ==="
  local t0 t1
  t0=$(date +%s%3N)
  # Spawn the prove command in background, immediately attach the RSS
  # poller to its pid tree, wait for it to exit.
  node --max-old-space-size=24576 \
    "$PKG_DIR/scripts/v5_2-prove.mjs" \
    --witness "$WITNESS" \
    --zkey "$ZKEY" \
    --wasm "$WASM" \
    --vkey "$VKEY" \
    --out-dir "$out_dir" \
    --backend "$backend" \
    $extra_args \
    > "$out_dir/cli.stdout" 2> "$out_dir/cli.stderr" &
  local cli_pid=$!

  poll_pid_tree_rss "$cli_pid" "$rss_csv" &
  local poller_pid=$!

  set +e
  wait "$cli_pid"
  local exit_code=$?
  set -e
  # Stop the poller.
  kill "$poller_pid" 2>/dev/null || true
  wait "$poller_pid" 2>/dev/null || true

  t1=$(date +%s%3N)
  local total_ms=$((t1 - t0))

  if [[ $exit_code -ne 0 ]]; then
    echo "[FAIL] $backend prove exited $exit_code"
    sed 's/^/  /' "$out_dir/cli.stderr" | tail -20
    return $exit_code
  fi

  # Peak RSS from poller.
  local peak_rss_kb peak_rss_gb
  peak_rss_kb=$(awk -F, 'NR>1 {if ($2>p) p=$2} END{print p}' "$rss_csv")
  peak_rss_gb=$(awk -v k="$peak_rss_kb" 'BEGIN{printf "%.2f", k/1024/1024}')

  echo "[ok] $backend prove total=${total_ms} ms, peak_pid_tree_rss=${peak_rss_gb} GiB (${peak_rss_kb} kB)"
  echo "[summary line from CLI:]"
  cat "$out_dir/cli.stdout"
  echo "[stderr tail:]"
  tail -8 "$out_dir/cli.stderr" | sed 's/^/  /'
  echo "[rss trace:] $rss_csv"

  # Echo peak so caller can collect.
  echo "$backend $total_ms $peak_rss_kb $peak_rss_gb" >> "$OUT_BASE/results.tsv"
}

rm -f "$OUT_BASE/results.tsv"

# Default: rapidsnark only.  snarkjs's profile is already documented
# (ceremony script: 85s/26 GB; browser benchmark: 90s/38 GiB) and a
# Node-hosted snarkjs prove against the V5.2 zkey OOMs the 48 GB
# cgroup we use for these benches (ffjavascript + zkey resident +
# witness calc in same process pushes higher than browser content RSS).
# Set BENCH_INCLUDE_SNARKJS=1 to attempt it anyway (uncapped).
if [[ "${BENCH_INCLUDE_SNARKJS:-0}" == "1" ]]; then
  run_backend "snarkjs" ""
fi
run_backend "rapidsnark" "--rapidsnark-bin $RAPIDSNARK_BIN"

echo
echo "=========================================================="
echo "V5.2 prove benchmark — side-by-side"
echo "=========================================================="
printf "%-12s %12s %14s %12s\n" "backend" "wall_ms" "peak_rss_kb" "peak_rss_GiB"
echo "----------------------------------------------------------"
while read -r b w r g; do
  printf "%-12s %12s %14s %12s\n" "$b" "$w" "$r" "$g"
done < "$OUT_BASE/results.tsv"
echo "=========================================================="
echo "raw RSS traces: $OUT_BASE/{snarkjs,rapidsnark}-rss.csv"
echo "raw outputs:    $OUT_BASE/{snarkjs,rapidsnark}/"
