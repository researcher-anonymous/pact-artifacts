#!/usr/bin/env bash
set -euo pipefail

COUNT="${COUNT:-100}"
TIMEOUT="${TIMEOUT:-120m}"
BENCHTIME="${BENCHTIME:-}"
OUTDIR="${OUTDIR:-bench-results-$(date +%Y%m%d-%H%M%S)}"
GOCACHE_DIR="${GOCACHE_DIR:-/tmp/go-build-benchmark}"
BENCH_GROUPS="${BENCH_GROUPS:-paper}"

mkdir -p "$OUTDIR"

echo "Benchmark output directory: $OUTDIR"
echo "COUNT=$COUNT"
echo "TIMEOUT=$TIMEOUT"
if [[ -n "$BENCHTIME" ]]; then
  echo "BENCHTIME=$BENCHTIME"
fi
echo "GOCACHE=$GOCACHE_DIR"
echo "BENCH_GROUPS=$BENCH_GROUPS"
echo

run_group() {
  local name="$1"
  local regex="$2"
  local outfile="$OUTDIR/${name}.txt"

  echo "Running $name: $regex"
  local cmd=(
    env GOCACHE="$GOCACHE_DIR" go test
    -timeout="$TIMEOUT"
    -run '^$'
    -bench "$regex"
    -benchmem
    -count="$COUNT"
  )
  if [[ -n "$BENCHTIME" ]]; then
    cmd+=("-benchtime=$BENCHTIME")
  fi
  cmd+=(./...)

  "${cmd[@]}" | tee "$outfile"

  echo "Saved raw output to $outfile"
  echo
}

should_run() {
  local group="$1"
  case "$BENCH_GROUPS" in
    all)
      return 0
      ;;
    paper)
      [[ ",jws-static,jws-reissued,pact-operation,pact-code-maintenance,pact-depth-scaling,pact-disclosure-layer," == *",$group,"* ]]
      return
      ;;
    *)
      [[ ",$BENCH_GROUPS," == *",$group,"* ]]
      return
      ;;
  esac
}

if should_run "jws-static"; then
  run_group "jws-static" '^BenchmarkJWSStatic'
fi
if should_run "jws-reissued"; then
  run_group "jws-reissued" '^BenchmarkJWSReissued'
fi
if should_run "pact-operation"; then
  run_group "pact-operation" '^BenchmarkPACTOperation'
fi
if should_run "pact-code-maintenance"; then
  run_group "pact-code-maintenance" '^BenchmarkPACTCodeMaintenance'
fi
if should_run "pact-depth-scaling"; then
  run_group "pact-depth-scaling" '^BenchmarkPACT(DepthScaling|ParameterScaling)'
fi
if should_run "pact-disclosure-layer"; then
  run_group "pact-disclosure-layer" '^BenchmarkPACTDisclosureLayer'
fi
if should_run "sd"; then
  run_group "sd" '^BenchmarkSD'
fi

if ! compgen -G "$OUTDIR/*.txt" > /dev/null; then
  echo "No benchmark groups selected. Use BENCH_GROUPS=paper, all, or a comma-separated subset of: jws-static,jws-reissued,pact-operation,pact-code-maintenance,pact-depth-scaling,pact-disclosure-layer,sd" >&2
  exit 1
fi

python3 - "$OUTDIR" <<'PY'
import csv
import json
import math
import pathlib
import re
import statistics
import sys
from collections import defaultdict

outdir = pathlib.Path(sys.argv[1])

bench_re = re.compile(r'^(Benchmark\S+)-(\d+)\s+(\d+)\s+(.+)$')

rows = []
custom_keys = set()

dimension_fields = [
    "benchmark_class",
    "strategy",
    "mode",
    "presentation_profile",
    "workflow",
    "branch_count",
    "nodes_per_branch",
    "unique_logical_nodes",
    "authenticated_nodes",
    "k",
    "issuer_interactions",
    "timed_scope",
    "depth_k",
    "fields_per_node",
    "opened_fields_per_node",
    "profile",
]

def benchmark_dimensions(bench_name, suite=""):
    dims = {k: "" for k in dimension_fields}
    suite_class = {
        "jws-static": "jws-static",
        "jws-reissued": "jws-reissued",
        "pact-operation": "pact-operation",
        "pact-code-maintenance": "pact-code-maintenance",
        "pact-depth-scaling": "pact-depth-scaling",
        "pact-disclosure-layer": "pact-disclosure-layer",
        "sd": "sd",
    }
    dims["benchmark_class"] = suite_class.get(suite, suite)
    parts = bench_name.split("/")
    if not parts:
        return dims

    if parts[0] == "BenchmarkJWSStatic":
        dims["mode"] = "JWS-ES256"
        if len(parts) >= 4 and parts[1] == "CodeMaintenanceBranch":
            dims.update({
                "strategy": "jws-static-final-artifact",
                "presentation_profile": "final-token",
                "workflow": "CodeMaintenanceBranch",
                "branch_count": "3",
                "nodes_per_branch": "context=3;patch=3;repository=5",
                "unique_logical_nodes": "9",
                "authenticated_nodes": "1",
                "issuer_interactions": "1",
                "timed_scope": parts[-1],
            })
        elif len(parts) >= 3 and parts[1] == "Operation":
            dims["strategy"] = "jws-static"
            dims["workflow"] = "operation"
            dims["timed_scope"] = parts[-1]

    elif parts[0] == "BenchmarkJWSReissued":
        dims["mode"] = "JWS-ES256"
        if len(parts) >= 4 and parts[1] == "CodeMaintenanceBranch":
            dims.update({
                "strategy": "jws-reissued-branch-states",
                "presentation_profile": "independent-signed-claims",
                "workflow": "CodeMaintenanceBranch",
                "branch_count": "3",
                "nodes_per_branch": "context=3;patch=3;repository=5",
                "unique_logical_nodes": "9",
                "authenticated_nodes": "11",
                "issuer_interactions": "11",
                "timed_scope": parts[-1],
            })
        elif len(parts) >= 3 and parts[1] == "LinearSixState":
            dims["strategy"] = "jws-reissued-linear"
            dims["workflow"] = "LinearSixState"
            dims["issuer_interactions"] = "6"
            dims["timed_scope"] = parts[2]

    elif parts[0] == "BenchmarkPACTOperation":
        dims["strategy"] = "pact-operation"
        dims["workflow"] = "operation"
        if len(parts) >= 2:
            dims["mode"] = parts[1]
        if len(parts) >= 3:
            dims["timed_scope"] = parts[2]
            if parts[2] == "ExtendOneFromRoot":
                dims["k"] = "0"
                dims["depth_k"] = "0"

    elif parts[0] == "BenchmarkPACTCodeMaintenance":
        if len(parts) >= 2:
            dims["mode"] = parts[1]
        profile = parts[2] if len(parts) >= 3 else ""
        profile_map = {
            "TransparentPresentation": "transparent",
            "CompletePresentation": "complete",
            "SelectivePresentation": "selective",
        }
        dims.update({
            "strategy": "pact-code-maintenance",
            "presentation_profile": profile_map.get(profile, profile),
            "workflow": "CodeMaintenanceBranch",
            "branch_count": "3",
            "nodes_per_branch": "context=3;patch=3;repository=5",
            "unique_logical_nodes": "9",
            "authenticated_nodes": "11",
            "issuer_interactions": "3",
            "timed_scope": parts[-1] if len(parts) >= 4 else "",
        })

    elif parts[0] == "BenchmarkPACTDepthScaling":
        dims["strategy"] = "synthetic-linear-depth"
        dims["workflow"] = "SyntheticLinear"
        if len(parts) >= 3:
            dims["mode"] = parts[2]
        for part in parts:
            if part.startswith("k="):
                dims["k"] = part.split("=", 1)[1]
                dims["depth_k"] = dims["k"]
        dims["fields_per_node"] = "8"
        dims["presentation_profile"] = parts[-1] if len(parts) >= 5 else ""
        dims["timed_scope"] = parts[-1] if len(parts) >= 5 else ""

    elif parts[0] == "BenchmarkPACTParameterScaling":
        dims["strategy"] = "synthetic-parameter-scaling"
        dims["workflow"] = parts[1] if len(parts) >= 2 else ""
        if len(parts) >= 3:
            dims["mode"] = parts[2]
        for part in parts:
            if part.startswith("k="):
                dims["k"] = part.split("=", 1)[1]
                dims["depth_k"] = dims["k"]
            elif part.startswith("fields="):
                dims["fields_per_node"] = part.split("=", 1)[1]
        dims["presentation_profile"] = parts[-1] if len(parts) >= 4 else ""
        dims["timed_scope"] = parts[-1] if len(parts) >= 4 else ""

    elif parts[0] == "BenchmarkPACTDisclosureLayer" and len(parts) >= 5:
        dims["strategy"] = "pact-disclosure-layer"
        dims["workflow"] = "DisclosureLayer"
        dims["profile"] = parts[-1]
        dims["presentation_profile"] = parts[-1]
        dims["timed_scope"] = parts[-1]
        for part in parts[1:-1]:
            if part.startswith("k="):
                dims["k"] = part.split("=", 1)[1]
                dims["depth_k"] = dims["k"]
            elif part.startswith("fields="):
                dims["fields_per_node"] = part.split("=", 1)[1]
            elif part.startswith("open="):
                dims["opened_fields_per_node"] = part.split("=", 1)[1]
    return dims

for path in sorted(outdir.glob("*.txt")):
    suite = path.stem
    pkg = ""
    cpu = ""

    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()

        if line.startswith("pkg:"):
            pkg = line.split(":", 1)[1].strip()
            continue

        if line.startswith("cpu:"):
            cpu = line.split(":", 1)[1].strip()
            continue

        m = bench_re.match(line)
        if not m:
            continue

        bench_name, gomaxprocs, iterations, metrics = m.groups()
        tokens = metrics.split()

        row = {
            "suite": suite,
            "pkg": pkg,
            "cpu": cpu,
            "benchmark": bench_name,
            "gomaxprocs": gomaxprocs,
            "iterations": int(iterations),
            "ns_per_op": "",
            "bytes_per_op": "",
            "allocs_per_op": "",
            "raw_metrics": metrics,
        }

        custom = {}

        i = 0
        while i + 1 < len(tokens):
            value = tokens[i]
            unit = tokens[i + 1]
            i += 2

            try:
                numeric = float(value)
            except ValueError:
                continue

            if unit == "ns/op":
                row["ns_per_op"] = numeric
            elif unit == "B/op":
                row["bytes_per_op"] = numeric
            elif unit == "allocs/op":
                row["allocs_per_op"] = numeric
            else:
                custom[unit] = numeric
                custom_keys.add(unit)

        row["custom_metrics_json"] = json.dumps(custom, sort_keys=True)
        row["_custom"] = custom
        row.update(benchmark_dimensions(bench_name, suite))
        rows.append(row)

stable_custom_keys = [
    "evidence_bytes",
    "serialized_token_bytes",
    "serialized_presentation_bytes",
    "total_serialized_bytes_validated",
    "serialized_package_bytes",
    "authenticated_nodes",
    "branch_count",
    "context_branch_nodes",
    "patch_branch_nodes",
    "repository_branch_nodes",
    "authenticated_nodes_repeated_root",
    "unique_logical_nodes",
    "issuer_interactions",
    "context_branch_token_bytes",
    "patch_branch_token_bytes",
    "repository_branch_token_bytes",
    "context_branch_evidence_bytes",
    "patch_branch_evidence_bytes",
    "repository_branch_evidence_bytes",
    "context_branch_disclosure_bytes",
    "patch_branch_disclosure_bytes",
    "repository_branch_disclosure_bytes",
    "context_branch_presentation_bytes",
    "patch_branch_presentation_bytes",
    "repository_branch_presentation_bytes",
    "joint_presentation_bytes",
    "checkpoint_bytes",
]
custom_keys = sorted((custom_keys | set(stable_custom_keys)) - set(dimension_fields))

raw_fields = [
    "suite",
    "pkg",
    "cpu",
    "benchmark",
] + dimension_fields + [
    "gomaxprocs",
    "iterations",
    "ns_per_op",
    "bytes_per_op",
    "allocs_per_op",
] + custom_keys + [
    "custom_metrics_json",
    "raw_metrics",
]

raw_csv = outdir / "benchmark_raw.csv"
with raw_csv.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=raw_fields)
    writer.writeheader()

    for row in rows:
        out = {k: row.get(k, "") for k in raw_fields}
        for key in custom_keys:
            out[key] = row["_custom"].get(key, "")
        writer.writerow(out)

def percentile(xs, pct):
    if not xs:
        return ""
    ordered = sorted(xs)
    if len(ordered) == 1:
        return ordered[0]
    rank = math.ceil((pct / 100.0) * len(ordered)) - 1
    rank = max(0, min(rank, len(ordered) - 1))
    return ordered[rank]

def stats(xs):
    if not xs:
        return None
    return {
        "count": len(xs),
        "mean": statistics.mean(xs),
        "median": statistics.median(xs),
        "stdev": statistics.stdev(xs) if len(xs) >= 2 else 0,
        "p95": percentile(xs, 95),
        "min": min(xs),
        "max": max(xs),
    }

metric_sources = [
    ("ns/op", "ns_per_op"),
    ("B/op", "bytes_per_op"),
    ("allocs/op", "allocs_per_op"),
]
metric_sources.extend((key, key) for key in custom_keys)

groups = defaultdict(list)
for row in rows:
    groups[(row["suite"], row["benchmark"])].append(row)

summary_fields = [
    "suite",
    "benchmark",
    *dimension_fields,
    "metric",
    "count",
    "mean",
    "median",
    "stdev",
    "p95",
    "min",
    "max",
]

summary_csv = outdir / "benchmark_summary.csv"
with summary_csv.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=summary_fields)
    writer.writeheader()

    for (suite, bench), rs in sorted(groups.items()):
        dims = benchmark_dimensions(bench, suite)
        for metric, field in metric_sources:
            if field in ("ns_per_op", "bytes_per_op", "allocs_per_op"):
                xs = [float(r[field]) for r in rs if r.get(field) not in ("", None)]
            else:
                xs = [float(r["_custom"][field]) for r in rs if field in r["_custom"]]
            s = stats(xs)
            if s is None:
                continue
            writer.writerow({
                "suite": suite,
                "benchmark": bench,
                **dims,
                "metric": metric,
                **s,
            })

print(f"Wrote {raw_csv}")
print(f"Wrote {summary_csv}")
PY

echo
echo "Done."
echo "Raw CSV:     $OUTDIR/benchmark_raw.csv"
echo "Summary CSV: $OUTDIR/benchmark_summary.csv"
