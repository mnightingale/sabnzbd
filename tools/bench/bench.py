#!/usr/bin/python3 -OO
# Copyright 2007-2026 by The SABnzbd-Team (sabnzbd.org)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
tools.bench.bench - Repeatable download/post-processing benchmarks

Each run starts a throwaway SABnzbd instance from a pinned ini template, replays
one or more scenarios against a local NNTP server, and writes the timings to
tools/bench/results/ tagged with branch, commit and timestamp.

Run bench.py -h for parameters.
"""

import argparse
import json
import os
import platform
import resource
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from string import Template
from typing import Any, Optional

import requests

try:
    import psutil
except ImportError:
    psutil = None

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.abspath(os.path.join(BENCH_DIR, "..", ".."))
NZB_DIR = os.path.join(BENCH_DIR, "nzbs")
RESULTS_DIR = os.path.join(BENCH_DIR, "results")
WORK_DIR = os.path.join(BENCH_DIR, "work")
INDEX_FILE = os.path.join(RESULTS_DIR, "index.jsonl")
TEMPLATE_FILE = os.path.join(BENCH_DIR, "sabnzbd.template.ini")
SCENARIO_FILE = os.path.join(BENCH_DIR, "scenarios.json")

API_KEY = "benchmarkapikey0000000000000000"
GB = 1024**3


# ------------------------------------------------------------
# Environment / git metadata
# ------------------------------------------------------------


def git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", "-C", REPO_DIR, *args], text=True, stderr=subprocess.DEVNULL).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def git_info() -> dict[str, Any]:
    return {
        "commit": git("rev-parse", "HEAD"),
        "commit_short": git("rev-parse", "--short", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "subject": git("log", "-1", "--pretty=%s"),
        "commit_date": git("log", "-1", "--pretty=%cI"),
        "dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
    }


def host_info() -> dict[str, Any]:
    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ------------------------------------------------------------
# CPU sampling
# ------------------------------------------------------------


class CpuSampler(threading.Thread):
    """Poll CPU and RSS of the SABnzbd process tree.

    Per-pid totals are kept as last-seen-max rather than summed live, so CPU burnt
    by par2/unrar still counts after those children exit between samples.
    """

    def __init__(self, pid: int, interval: float = 0.25):
        super().__init__(daemon=True)
        self.interval = interval
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._cpu: dict[int, float] = {}
        self._peak_rss = 0
        self._proc = psutil.Process(pid) if psutil else None
        self.available = self._proc is not None

    def _sample(self):
        rss = 0
        try:
            procs = [self._proc, *self._proc.children(recursive=True)]
        except psutil.Error:
            return
        for proc in procs:
            try:
                times = proc.cpu_times()
                with self._lock:
                    self._cpu[proc.pid] = times.user + times.system
                rss += proc.memory_info().rss
            except psutil.Error:
                continue
        with self._lock:
            self._peak_rss = max(self._peak_rss, rss)

    def run(self):
        while not self._stop.is_set():
            self._sample()
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()

    def snapshot(self) -> dict[str, float]:
        if self.available:
            self._sample()
        with self._lock:
            return {"cpu_s": sum(self._cpu.values()), "peak_rss": float(self._peak_rss)}

    def reset_peak(self):
        with self._lock:
            self._peak_rss = 0


# ------------------------------------------------------------
# SABnzbd instance
# ------------------------------------------------------------


class SabInstance:
    def __init__(self, config: dict[str, Any], server: dict[str, Any], work_dir: str, verbose: bool = False):
        self.work_dir = work_dir
        self.verbose = verbose
        self.port = free_port()
        self.url = "http://127.0.0.1:%d/api" % self.port
        self.ini_file = os.path.join(work_dir, "sabnzbd.ini")
        self.process: Optional[subprocess.Popen] = None
        self.sampler: Optional[CpuSampler] = None
        self._write_ini(config, server)

    def _write_ini(self, config: dict[str, Any], server: dict[str, Any]):
        incomplete = os.path.join(self.work_dir, "incomplete")
        complete = os.path.join(self.work_dir, "complete")
        os.makedirs(incomplete, exist_ok=True)
        os.makedirs(complete, exist_ok=True)

        with open(TEMPLATE_FILE, "r", encoding="utf-8") as template_handle:
            template = Template(template_handle.read())

        rendered = template.safe_substitute(
            api_key=API_KEY,
            web_port=self.port,
            incomplete_dir=incomplete,
            complete_dir=complete,
            config_lines="\n".join("%s = %s" % (key, value) for key, value in sorted(config.items())),
            server_host=server["host"],
            server_port=server["port"],
            server_username=server.get("username", ""),
            server_password=server.get("password", ""),
            server_connections=server["connections"],
            server_ssl=server.get("ssl", 0),
        )
        with open(self.ini_file, "w", encoding="utf-8") as ini_handle:
            ini_handle.write(rendered)

    def start(self, timeout: int = 120):
        log_path = os.path.join(self.work_dir, "sabnzbd.stdout.log")
        self._log_handle = open(log_path, "w", encoding="utf-8")
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-OO",
                os.path.join(REPO_DIR, "SABnzbd.py"),
                "--config-file",
                self.ini_file,
                "--server",
                "127.0.0.1:%d" % self.port,
                "--browser",
                "0",
                "--logging",
                "0",
                "--console",
            ],
            cwd=REPO_DIR,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
        )

        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("SABnzbd exited during startup, see %s" % log_path)
            try:
                self.api("version")
                break
            except (requests.ConnectionError, requests.Timeout):
                time.sleep(0.1)
        else:
            raise RuntimeError("SABnzbd did not become ready within %ds" % timeout)

        self.check_health()
        self.sampler = CpuSampler(self.process.pid)
        if self.sampler.available:
            self.sampler.start()

    def check_health(self):
        """Catch a crippled instance now rather than as an unexplained timeout later."""
        errors = [entry for entry in self.warnings() if entry.get("type") == "ERROR"]
        for entry in errors:
            print("  ! SABnzbd: %s" % entry.get("text"))
        if any("downloading cannot start" in entry.get("text", "") for entry in errors):
            raise RuntimeError("SABnzbd cannot download - install the par2 and unrar binaries first")

    def warnings(self) -> list[dict[str, Any]]:
        try:
            return self.api("warnings").get("warnings", [])
        except Exception:
            return []

    def api(self, mode: str, **params) -> dict[str, Any]:
        params.update({"mode": mode, "apikey": API_KEY, "output": "json"})
        response = requests.get(self.url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

    def add_nzb(self, nzb_path: str, pp: int, name: str) -> str:
        with open(nzb_path, "rb") as nzb_handle:
            response = requests.post(
                self.url,
                params={"mode": "addfile", "apikey": API_KEY, "output": "json", "pp": pp, "nzbname": name},
                files={"nzbfile": (os.path.basename(nzb_path), nzb_handle, "application/x-nzb")},
                timeout=120,
            )
        response.raise_for_status()
        payload = response.json()
        if not payload.get("nzo_ids"):
            raise RuntimeError("SABnzbd rejected the NZB: %s" % payload)
        return payload["nzo_ids"][0]

    def history_slot(self, nzo_id: str) -> Optional[dict[str, Any]]:
        payload = self.api("history", limit=100)
        for slot in payload.get("history", {}).get("slots", []):
            if slot.get("nzo_id") == nzo_id:
                return slot
        return None

    def wait_for_completion(self, nzo_id: str, timeout: int) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            slot = self.history_slot(nzo_id)
            if slot and slot.get("status") in ("Completed", "Failed"):
                return slot
            time.sleep(0.5)

        queue = self.api("queue").get("queue", {})
        raise TimeoutError(
            "Job %s did not finish within %ds (queue status %s, %s left, speed %s). Recent warnings: %s"
            % (
                nzo_id,
                timeout,
                queue.get("status"),
                queue.get("sizeleft"),
                queue.get("speed"),
                [entry.get("text") for entry in self.warnings()[-5:]] or "none",
            )
        )

    def reset(self):
        self.api("queue", name="delete", value="all", del_files=1)
        self.api("history", name="delete", value="all", del_files=1)

    def stop(self, timeout: int = 60) -> dict[str, float]:
        if self.sampler and self.sampler.available:
            self.sampler.stop()

        rusage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        try:
            self.api("shutdown")
        except Exception:
            pass
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=30)
        rusage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        self._log_handle.close()

        return {
            "run_cpu_user_s": round(rusage_after.ru_utime - rusage_before.ru_utime, 3),
            "run_cpu_sys_s": round(rusage_after.ru_stime - rusage_before.ru_stime, 3),
        }


# ------------------------------------------------------------
# Scenario execution
# ------------------------------------------------------------


def resolve_nzb(nzb: str, refresh: bool = False) -> str:
    """Return a local path for an NZB given as a URL, an absolute path or a name in nzbs/.

    URLs are cached in nzbs/ so a benchmark run never depends on the network.
    """
    if nzb.startswith(("http://", "https://")):
        os.makedirs(NZB_DIR, exist_ok=True)
        path = os.path.join(NZB_DIR, os.path.basename(nzb.split("?")[0]))
        if refresh or not os.path.exists(path):
            print("  fetching %s ..." % nzb, end="", flush=True)
            response = requests.get(nzb, timeout=120)
            response.raise_for_status()
            with open(path + ".part", "wb") as nzb_handle:
                nzb_handle.write(response.content)
            os.replace(path + ".part", path)
            print(" %d KB" % (len(response.content) // 1024))
        return path

    path = nzb if os.path.isabs(nzb) else os.path.join(NZB_DIR, nzb)
    if not os.path.exists(path):
        raise FileNotFoundError("NZB not found: %s (drop it in %s, or use a URL)" % (path, NZB_DIR))
    return path


def measure_job(sab: SabInstance, nzb_path: str, pp: int, name: str, timeout: int) -> dict[str, Any]:
    if sab.sampler:
        sab.sampler.reset_peak()
    before = sab.sampler.snapshot() if sab.sampler else {"cpu_s": 0.0, "peak_rss": 0.0}

    started = time.perf_counter()
    nzo_id = sab.add_nzb(nzb_path, pp, name)
    slot = sab.wait_for_completion(nzo_id, timeout)
    wall_s = time.perf_counter() - started

    after = sab.sampler.snapshot() if sab.sampler else {"cpu_s": 0.0, "peak_rss": 0.0}
    cpu_s = round(after["cpu_s"] - before["cpu_s"], 3)
    downloaded = int(slot.get("bytes") or 0)

    return {
        "status": slot.get("status"),
        "fail_message": slot.get("fail_message") or "",
        "bytes": downloaded,
        "wall_s": round(wall_s, 3),
        "download_s": int(slot.get("download_time") or 0),
        "postproc_s": int(slot.get("postproc_time") or 0),
        "cpu_s": cpu_s,
        "peak_rss_mb": round(after["peak_rss"] / 1024 / 1024, 1),
        "cpu_s_per_gb": round(cpu_s / (downloaded / GB), 3) if downloaded else None,
        "throughput_mbps": round(downloaded / 1024 / 1024 / wall_s, 2) if wall_s else None,
    }


def run_scenario(scenario: dict[str, Any], spec: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    defaults = spec.get("defaults", {})
    config = dict(defaults.get("config", {}))
    config.update(scenario.get("config", {}))
    server = dict(defaults.get("server", {}))
    server.update(scenario.get("server", {}))
    if args.server:
        host, _, port = args.server.rpartition(":")
        server["host"], server["port"] = host, int(port)
    if args.connections:
        server["connections"] = args.connections

    timeout = scenario.get("timeout", defaults.get("timeout", 1800))
    run_id = "%s-%s-%s" % (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        git_info()["commit_short"] or "nogit",
        scenario["name"],
    )
    work_dir = os.path.join(args.workdir or WORK_DIR, run_id)
    os.makedirs(work_dir, exist_ok=True)

    print("\n=== %s (pp=%d, %d repeats) ===" % (scenario["name"], scenario.get("pp", 3), args.repeat))
    prewarm = None if args.no_prewarm else spec.get("prewarm")
    nzb_path = resolve_nzb(scenario["nzb"], args.refresh_nzbs)
    warm_path = resolve_nzb(prewarm["nzb"], args.refresh_nzbs) if prewarm else None
    if not psutil:
        print("  ! psutil not installed - CPU per job will be 0, only wall time is reliable")
    sab = SabInstance(config, server, work_dir, verbose=args.verbose)

    jobs = []
    try:
        sab.start()

        if prewarm:
            print("  prewarming with %s ..." % os.path.basename(warm_path), end="", flush=True)
            warm = measure_job(sab, warm_path, prewarm.get("pp", 0), "prewarm", timeout)
            print(" %.1fs (%s)" % (warm["wall_s"], warm["status"]))
            sab.reset()

        for index in range(args.repeat):
            job = measure_job(sab, nzb_path, scenario.get("pp", 3), "%s-%d" % (scenario["name"], index), timeout)
            job["repeat"] = index
            jobs.append(job)
            print(
                "  run %d/%d  wall %7.1fs  cpu %7.1fs  %s  %s"
                % (
                    index + 1,
                    args.repeat,
                    job["wall_s"],
                    job["cpu_s"],
                    ("%6.2f cpu-s/GB" % job["cpu_s_per_gb"]) if job["cpu_s_per_gb"] else "     -      ",
                    job["status"],
                )
            )
            sab.reset()
    finally:
        totals = sab.stop() if sab.process else {}
        if not args.keep_work:
            shutil.rmtree(work_dir, ignore_errors=True)

    return {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenario": scenario["name"],
        "nzb": scenario["nzb"],
        "pp": scenario.get("pp", 3),
        "label": args.label or "",
        "note": args.note or "",
        "git": git_info(),
        "host": host_info(),
        "server": server,
        "config": config,
        "totals": totals,
        "jobs": jobs,
        "summary": summarise(jobs),
    }


def summarise(jobs: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [job for job in jobs if job["status"] == "Completed"]
    if not ok:
        return {"completed": 0}
    summary: dict[str, Any] = {"completed": len(ok), "failed": len(jobs) - len(ok)}
    for metric in ("wall_s", "cpu_s", "download_s", "postproc_s", "cpu_s_per_gb", "throughput_mbps", "peak_rss_mb"):
        values = [job[metric] for job in ok if job.get(metric) is not None]
        if values:
            summary[metric] = {
                "median": round(statistics.median(values), 3),
                "min": round(min(values), 3),
                "max": round(max(values), 3),
                "mad": round(mad(values), 3),
            }
    return summary


def mad(values: list[float]) -> float:
    """Median absolute deviation - robust spread that a single slow run cannot inflate."""
    if len(values) < 2:
        return 0.0
    centre = statistics.median(values)
    return statistics.median([abs(value - centre) for value in values])


# ------------------------------------------------------------
# Result storage
# ------------------------------------------------------------


def store(result: dict[str, Any]) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, "%s.json" % result["run_id"])
    with open(path, "w", encoding="utf-8") as result_handle:
        json.dump(result, result_handle, indent=2, sort_keys=True)

    index_entry = {
        "run_id": result["run_id"],
        "timestamp": result["timestamp"],
        "scenario": result["scenario"],
        "branch": result["git"]["branch"],
        "commit": result["git"]["commit_short"],
        "dirty": result["git"]["dirty"],
        "label": result["label"],
        "summary": result["summary"],
    }
    with open(INDEX_FILE, "a", encoding="utf-8") as index_handle:
        index_handle.write(json.dumps(index_entry) + "\n")
    return path


def load_index() -> list[dict[str, Any]]:
    if not os.path.exists(INDEX_FILE):
        return []
    with open(INDEX_FILE, "r", encoding="utf-8") as index_handle:
        return [json.loads(line) for line in index_handle if line.strip()]


def matches(entry: dict[str, Any], selector: str) -> bool:
    return selector in (entry["branch"], entry["commit"], entry["label"], entry["run_id"])


# ------------------------------------------------------------
# Commands
# ------------------------------------------------------------


def load_spec(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as spec_handle:
        return json.load(spec_handle)


def cmd_run(args: argparse.Namespace):
    spec = load_spec(args.scenarios)
    wanted = args.scenario or [scenario["name"] for scenario in spec["scenarios"]]
    unknown = set(wanted) - {scenario["name"] for scenario in spec["scenarios"]}
    if unknown:
        sys.exit("Unknown scenario(s): %s" % ", ".join(sorted(unknown)))

    info = git_info()
    if info["dirty"] and not args.allow_dirty:
        sys.exit("Working tree is dirty - results would not be attributable. Use --allow-dirty to override.")
    print("branch %s @ %s  %s" % (info["branch"], info["commit_short"], info["subject"]))

    failed = []
    for scenario in spec["scenarios"]:
        if scenario["name"] not in wanted:
            continue
        try:
            result = run_scenario(scenario, spec, args)
        except (RuntimeError, TimeoutError, FileNotFoundError, requests.RequestException) as err:
            print("  ! %s failed: %s" % (scenario["name"], err))
            failed.append(scenario["name"])
            continue
        path = store(result)
        print("  -> %s" % os.path.relpath(path, REPO_DIR))

    if failed:
        sys.exit("\n%d scenario(s) failed: %s" % (len(failed), ", ".join(failed)))


def cmd_list(args: argparse.Namespace):
    entries = load_index()
    if args.scenario:
        entries = [entry for entry in entries if entry["scenario"] in args.scenario]
    if not entries:
        print("No results yet.")
        return
    print("%-24s %-18s %-20s %-10s %10s %10s" % ("RUN", "BRANCH", "SCENARIO", "COMMIT", "WALL", "CPU/GB"))
    for entry in entries[-args.limit :]:
        summary = entry["summary"]
        print(
            "%-24s %-18s %-20s %-10s %10s %10s"
            % (
                entry["run_id"][:24],
                (entry["branch"] + ("*" if entry["dirty"] else ""))[:18],
                entry["scenario"][:20],
                entry["commit"],
                fmt(summary.get("wall_s", {}).get("median")),
                fmt(summary.get("cpu_s_per_gb", {}).get("median")),
            )
        )


def fmt(value: Optional[float]) -> str:
    return "-" if value is None else "%.2f" % value


def cmd_compare(args: argparse.Namespace):
    entries = load_index()
    baseline = [entry for entry in entries if matches(entry, args.baseline)]
    candidate = [entry for entry in entries if matches(entry, args.candidate)]
    if not baseline or not candidate:
        sys.exit("No results for %s or %s - check 'bench.py list'" % (args.baseline, args.candidate))

    scenarios = sorted({entry["scenario"] for entry in baseline} & {entry["scenario"] for entry in candidate})
    if args.scenario:
        scenarios = [name for name in scenarios if name in args.scenario]

    print("baseline: %s     candidate: %s\n" % (args.baseline, args.candidate))
    header = "%-22s %-14s %12s %12s %9s  %s"
    print(header % ("SCENARIO", "METRIC", args.baseline[:12], args.candidate[:12], "DELTA", "VERDICT"))
    print("-" * 88)

    for scenario in scenarios:
        for metric in args.metric:
            base = pick(baseline, scenario, metric)
            cand = pick(candidate, scenario, metric)
            if base is None or cand is None:
                continue
            delta = (cand["median"] - base["median"]) / base["median"] * 100 if base["median"] else 0.0
            noise = max(rel(base), rel(cand)) * 2 + 1.0
            if abs(delta) <= noise:
                verdict = "noise (+/-%.1f%%)" % noise
            elif delta < 0:
                verdict = "FASTER"
            else:
                verdict = "SLOWER"
            print(
                header
                % (
                    scenario[:22],
                    metric,
                    "%.2f" % base["median"],
                    "%.2f" % cand["median"],
                    "%+.1f%%" % delta,
                    verdict,
                )
            )
        print()


def rel(stat: dict[str, float]) -> float:
    return (stat["mad"] / stat["median"] * 100) if stat.get("median") else 0.0


def pick(entries: list[dict[str, Any]], scenario: str, metric: str) -> Optional[dict[str, float]]:
    """Latest run for a scenario, or the pooled median if several runs exist."""
    relevant = [entry for entry in entries if entry["scenario"] == scenario and metric in entry["summary"]]
    if not relevant:
        return None
    medians = [entry["summary"][metric]["median"] for entry in relevant]
    return {"median": statistics.median(medians), "mad": max(entry["summary"][metric]["mad"] for entry in relevant)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run scenarios and record the results")
    run.add_argument("-s", "--scenario", action="append", help="Scenario name (repeatable, default: all)")
    run.add_argument("-r", "--repeat", type=int, default=3, help="Measured repeats per scenario (default: 3)")
    run.add_argument("--scenarios", default=SCENARIO_FILE, help="Scenario definition file")
    run.add_argument("--server", help="Override NNTP server as host:port")
    run.add_argument("--connections", type=int, help="Override server connections")
    run.add_argument("--label", help="Free-form label stored with the result, e.g. 'pr-3528'")
    run.add_argument("--note", help="Longer note stored with the result")
    run.add_argument("--workdir", help="Base dir for the throwaway config/downloads (use a ramdisk for less noise)")
    run.add_argument("--keep-work", action="store_true", help="Keep the working dir for debugging")
    run.add_argument("--no-prewarm", action="store_true", help="Skip the prewarm job")
    run.add_argument(
        "--refresh-nzbs", action="store_true", help="Re-download NZBs given as URLs instead of using the nzbs/ cache"
    )
    run.add_argument("--allow-dirty", action="store_true", help="Allow running with uncommitted changes")
    run.add_argument("-v", "--verbose", action="store_true")
    run.set_defaults(func=cmd_run)

    listing = sub.add_parser("list", help="List recorded runs")
    listing.add_argument("-s", "--scenario", action="append")
    listing.add_argument("-n", "--limit", type=int, default=40)
    listing.set_defaults(func=cmd_list)

    compare = sub.add_parser("compare", help="Compare two branches, commits or labels")
    compare.add_argument("baseline")
    compare.add_argument("candidate")
    compare.add_argument("-s", "--scenario", action="append")
    compare.add_argument(
        "-m",
        "--metric",
        action="append",
        default=None,
        choices=["wall_s", "cpu_s", "cpu_s_per_gb", "download_s", "postproc_s", "throughput_mbps", "peak_rss_mb"],
    )
    compare.set_defaults(func=cmd_compare)

    args = parser.parse_args()
    if args.command == "compare" and not args.metric:
        args.metric = ["wall_s", "cpu_s", "cpu_s_per_gb"]
    args.func(args)


if __name__ == "__main__":
    main()
