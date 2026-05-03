#!/usr/bin/env bash
# Polls Firefox per-process RSS at 250 ms intervals and emits CSV to stdout.
# Run in a separate terminal alongside the V5.x harness.  Captures the TRUE
# browser-process working set (versus user-observed system-wide RAM, which
# inflates by OS file cache + other processes).
#
# Usage:
#   bash packages/circuits/benchmarks/watch-firefox-rss.sh > rss-trace.csv
#   # ... in browser, click "Run (default)" ...
#   # Ctrl-C when prove finishes
#
# Output columns:
#   epoch_ms,parent_rss_kb,content_rss_max_kb,total_rss_kb,n_content_procs
#
# Linux-only (reads /proc/<pid>/status).  macOS variant TBD.

set -euo pipefail

# Header.
echo "epoch_ms,parent_rss_kb,content_rss_max_kb,total_rss_kb,n_content_procs"

while :; do
  # Parent firefox process (the launcher / main).
  parent_pid="$(pgrep -x firefox | head -1 || true)"
  if [[ -z "$parent_pid" ]]; then
    sleep 1
    continue
  fi

  parent_rss=0
  if [[ -r "/proc/$parent_pid/status" ]]; then
    parent_rss="$(awk '/^VmRSS:/ {print $2}' "/proc/$parent_pid/status" 2>/dev/null || echo 0)"
  fi

  # Content processes — these are the per-tab sandboxed renderers; the heavy
  # snarkjs work runs in one of them.  Sum all + report max separately so
  # we can isolate the prove tab.
  total_rss="$parent_rss"
  max_content=0
  n_content=0
  while IFS= read -r pid; do
    [[ -z "$pid" || "$pid" == "$parent_pid" ]] && continue
    if [[ -r "/proc/$pid/status" ]]; then
      rss="$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
      total_rss=$((total_rss + rss))
      (( rss > max_content )) && max_content="$rss"
      n_content=$((n_content + 1))
    fi
  done < <(pgrep -f "firefox -contentproc")

  ms="$(date +%s%3N)"
  echo "${ms},${parent_rss},${max_content},${total_rss},${n_content}"

  # 250 ms cadence — same as the harness's heap sampler so traces line up.
  sleep 0.25
done
