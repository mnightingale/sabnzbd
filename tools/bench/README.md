# SABnzbd benchmark harness

Repeatable download/post-processing benchmarks recorded to disk, tagged with branch,
commit and timestamp so results stay comparable across changes.

Each scenario gets a **throwaway SABnzbd instance**: a fresh `sabnzbd.ini` rendered from
`sabnzbd.template.ini`, an empty incomplete/complete dir, a random free web port, and a
clean history db. Nothing touches your real config.

## Setup

```sh
pip install psutil          # optional, but without it only wall time is measured
```

That's it. The default scenarios reference the standard test NZBs by URL:

- `https://sabnzbd.org/tests/test_download_100MB.nzb` (prewarm)
- `https://sabnzbd.org/tests/test_download_1000MB.nzb`
- `https://sabnzbd.org/tests/test_download_10GB.nzb`

They are downloaded once into `tools/bench/nzbs/` and reused from there, so a benchmark
run never depends on the network. `--refresh-nzbs` re-fetches them.

A scenario's `nzb` can equally be a bare filename in `nzbs/` or an absolute path, if you
want to benchmark against something of your own.

`nzbs/`, `work/` and `results/` are gitignored.

Point `scenarios.json` at your NNTP server (defaults to `nntp:6791`) or override per run
with `--server`. SAB needs the `par2` and `unrar` binaries on PATH — the harness checks
at startup and fails immediately rather than hanging if they are missing.

## Running

```sh
# everything, 3 measured repeats each
python3 tools/bench/bench.py run

# one scenario, more repeats, tagged
python3 tools/bench/bench.py run -s 1000MB-dl -r 5 --label baseline

# different server / connection count
python3 tools/bench/bench.py run -s 10GB-dl --server 192.168.1.50:6791 --connections 40
```

Scenarios are `100MB-dl/-full`, `1000MB-dl/-full`, `1000MB-dl-lowcache` and
`10GB-dl/-full`. The `-dl` variants use `pp=0` (download and decode only); `-full` uses
`pp=3` (repair, unpack, delete), so a regression can be attributed to one side or the
other.

Every run does a **prewarm job first** (imports, thread pools, page cache, DB), discards
it, clears queue and history, then runs the measured repeats — clearing queue and history
between each.

`run` refuses to start on a dirty working tree, since the result could not be attributed
to a commit. Use `--allow-dirty` while iterating; those runs are flagged with `*` in
`list` output.

## Comparing

```sh
python3 tools/bench/bench.py list
python3 tools/bench/bench.py compare develop my-feature-branch
python3 tools/bench/bench.py compare baseline candidate -m cpu_s_per_gb -m postproc_s
```

Selectors accept a branch name, short commit, `--label` value, or a run id.

Comparison reports **medians and median absolute deviation**, and calls anything within
`2 x MAD + 1%` noise rather than a regression.

## Metrics

| Metric | Source | Notes |
|---|---|---|
| `wall_s` | harness `perf_counter` | add → history Completed |
| `download_s` | SAB history `download_time` | SAB's own accounting |
| `postproc_s` | SAB history `postproc_time` | par2 + unpack |
| `cpu_s` | psutil, SAB **plus all children** | includes par2/unrar subprocesses |
| `cpu_s_per_gb` | derived | **the headline number** |
| `throughput_mbps` | derived | |
| `peak_rss_mb` | psutil, whole process tree | |

`cpu_s_per_gb` is what you want for regression hunting: it is near-immune to background
load on the machine and to the NNTP server having a slow moment, so a few percent change
is actually meaningful. Wall time on its own is much noisier.

Child CPU is tracked as last-seen-max per pid, so par2/unrar time still counts even
though those processes exit between samples. Each result also carries a
`getrusage(RUSAGE_CHILDREN)` total for the whole run as a cross-check.

## Comparing two branches properly

Machines drift — thermal throttling, background work, page cache state. Running all of A
then all of B will produce a difference even when the code is identical. **Interleave**,
using worktrees so no checkout happens mid-benchmark:

```sh
git worktree add ../sab-base develop
git worktree add ../sab-cand my-feature-branch

for i in 1 2 3 4 5; do
  (cd ../sab-base && python3 tools/bench/bench.py run -s 1000MB-dl -r 1 --label base)
  (cd ../sab-cand && python3 tools/bench/bench.py run -s 1000MB-dl -r 1 --label cand)
done

python3 tools/bench/bench.py compare base cand
```

Note `results/` lives inside each worktree. Symlink both to one directory, or pass
`--workdir` and collect the JSON together, if you want a single index.

## Reducing noise further

- Put `--workdir` on a ramdisk to take disk I/O out of the measurement:
  `diskutil erasevolume APFS bench $(hdiutil attach -nomount ram://16777216)` on macOS,
  `mount -t tmpfs -o size=32G tmpfs /mnt/bench` on Linux.
- Close everything else; disable Spotlight indexing on the workdir.
- Pin cores on Linux with `taskset -c 0-7`.
- Prefer more repeats over longer NZBs — `1000MB x 5` tells you more than `10GB x 1`.
- Keep `connections` fixed. Changing it changes the thread count and invalidates
  comparison with older results.

## Once a number moves

The harness tells you *that* something changed, not *why*. To find the cause:

```sh
# attach to the running SAB, including par2/unrar
py-spy record --subprocesses --format speedscope --pid <sab-pid> -o profile.json

# thread-aware profiling - cProfile lies about SAB's threading model
python3 Yappi.py
```

`perf stat -e instructions,cycles,context-switches` around a run gives an
instruction count, which has far lower variance than any time-based metric.

## Adding scenarios

Edit `scenarios.json`. Each entry takes `name`, `nzb`, `pp`, and optional `timeout`,
`config` (misc ini overrides) and `server` overrides:

```json
{
  "name": "1000MB-directunpack",
  "nzb": "test_download_1000MB.nzb",
  "pp": 3,
  "config": { "direct_unpack": 1 }
}
```

`pp` follows the API: `0` = download only, `1` = repair, `2` = +unpack, `3` = +delete.
The `-dl` (pp=0) and `-full` (pp=3) pairs let you attribute a regression to the download
path versus post-processing.
