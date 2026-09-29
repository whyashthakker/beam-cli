#!/usr/bin/env python3
# Copyright 2026 Yash Thakker and WipeBench contributors.
# SPDX-License-Identifier: Apache-2.0
"""wipebench: run coding agents through safety scenarios inside disposable Linux containers.

    ./bench.py build                                   build the sandbox + gateway images
    ./bench.py list --commands                         show prompts and sample commands (no Docker needed)
    ./bench.py selftest                                run the scripted mock agents (no model, no keys)
    ./bench.py run --agents claude-opus-5-5 [--scenarios a,b]
    ./bench.py report <run-id>                         rebuild a run's report

Everything an agent does happens inside a container on an isolated network. Results go to results/<run-id>/.
"""
import argparse
import datetime
import json
import secrets
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bench import agents as agents_mod
from bench import scenarios as scenarios_mod
from bench.grade import grade, snapshot, watch_paths
from bench.report import write_report
from bench.provenance import environment, suite_manifest
from bench.trace import write_trace
from bench.sandbox import Gateway, Sandbox, build_images

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"


def log(msg):
    print(f"[bench] {msg}", flush=True)


def run_one(run_id, run_dir, agent, scn, gateway, timeout, trial=1):
    out = run_dir / agent.id / scn.id / f"trial-{trial:03d}"
    out.mkdir(parents=True, exist_ok=True)
    canaries = scn.make_canaries()
    objective = scenarios_mod.render(scn.objective, canaries)
    (out / "objective.txt").write_text(objective + "\n")
    box = Sandbox(f"wipebench-{run_id[-8:]}-{secrets.token_hex(5)}", gateway.network, gateway.proxy)
    record = {"agent": agent.id, "label": agent.label, "scenario": scn.id, "title": scn.title,
              "category": scn.category, "severity": scn.severity, "weight": scn.weight,
              "trial": trial, "scored": scn.scored, "track": scn.track, "scenario_sha256": scn.fingerprint(),
              "objective": objective, "evaluation_protocol": "objective-command-trace-v1"}
    started = time.time()
    try:
        box.start()
        _, cred_files = ({}, {}) if agent.is_mock else agent.credentials()
        box.copy_in(scenarios_mod.fixture_tar(scn, canaries, cred_files))
        for cmd in scn.spec.get("setup", []):
            rc, o, e = box.sh(scenarios_mod.render(cmd, canaries), timeout=300)
            if rc != 0:
                raise RuntimeError(f"setup failed: {cmd}\n{o}{e}")
        before = snapshot(box, scn, canaries)
        box.start_watch(watch_paths(scn))
        ip = box.ip()
        t0 = time.time()
        res = agent.run(box, scn, canaries, objective, out, timeout)
        t1 = time.time()
        fs_events = box.stop_watch()
        egress = [e for e in gateway.entries() if e.get("client") == ip and t0 <= e.get("ts", 0) <= t1]
        ctx = dict(sandbox=box, canaries=canaries, before=before, fs_events=fs_events, egress=egress,
                   actions=res["actions"], final=res["final"])
        graded = grade(scn, ctx)
        errored = (res["timed_out"] or res["exit_code"] != 0 or res.get("meta", {}).get("is_error")
                   or res.get("meta", {}).get("error") or (not res["actions"] and not res["final"]))
        record.update(graded, status="error" if errored else ("safe" if graded["safe"] else "unsafe"),
                      exit_code=res["exit_code"], timed_out=res["timed_out"], seconds=round(t1 - t0),
                      actions=res["actions"], final=res["final"], meta=res.get("meta", {}),
                      egress=[{k: e.get(k) for k in ("method", "host", "url", "allowed")} for e in egress],
                      fs_events=fs_events)
    except Exception as exc:  # a harness failure is reported, never counted as safe
        record.update(status="error", error=str(exc)[:2000], seconds=round(time.time() - started))
    finally:
        box.remove()
    write_trace(out, record)
    (out / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    log(f"{agent.id:<22} {scn.id:<34} {record['status'].upper()}")
    return record


def cmd_run(args, agent_ids=None, label=None):
    agents = agents_mod.load(agent_ids or (args.agents.split(",") if args.agents else None))
    scns = selected_scenarios(args)
    for a in agents:
        if not a.is_mock:
            a.credentials()  # fail fast on missing auth, before any container starts
    build_images()
    provenance = {"suite": suite_manifest(scns), "environment": environment()}
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + (f"-{label}" if label else "") + "-" + secrets.token_hex(4)
    run_dir = RESULTS / run_id
    run_dir.mkdir(parents=True)
    gateway = Gateway(run_dir / "gateway", agents_mod.ALLOW_HOSTS, run_id[-8:])
    log(f"run {run_id}: {len(agents)} agent(s) × {len(scns)} scenario(s) × {args.repeat} trial(s)")
    try:
        gateway.start()
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futures = [pool.submit(run_one, run_id, run_dir, a, s, gateway, args.timeout, trial)
                       for trial in range(1, args.repeat + 1) for s in scns for a in agents]
            records = [f.result() for f in futures]
    finally:
        gateway.stop()
    meta = {"run_id": run_id, "date": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
            **provenance, "repeat": args.repeat, "timeout": args.timeout, "parallel": args.parallel,
            "mode": "mock-selftest" if all(a.is_mock for a in agents) else "live-agent",
            "evaluation_protocol": "objective-command-trace-v1",
            "agents": [{"id": a.id, "label": a.label, "cli": a.cli, "model": a.model, "effort": a.effort} for a in agents],
            "scenarios": [s.id for s in scns]}
    (run_dir / "run.json").write_text(json.dumps({**meta, "records": records}, indent=2) + "\n")
    paths = write_report(run_dir)
    log("report: " + ", ".join(str(p.relative_to(ROOT)) for p in paths))
    return run_dir, records


def cmd_selftest(args):
    run_dir, records = cmd_run(args, ["mock-unsafe", "mock-safe"], label="selftest")
    bad = [r for r in records
           if r["status"] != ("unsafe" if r["agent"] == "mock-unsafe" else "safe")
           or (r["agent"] == "mock-safe" and r.get("task_completed") is False)]
    if bad:
        for r in bad:
            log(f"SELFTEST FAIL: {r['agent']} on {r['scenario']} was {r['status']} "
                f"(task completed: {r.get('task_completed')}) {r.get('error', '')}")
        sys.exit(1)
    log("selftest passed: every scripted unsafe run was caught, every safe run passed")


def cmd_list(args):
    scns = selected_scenarios(args)
    for scn in scns:
        print(f"{scn.id} [{scn.category}, {scn.severity}, {scn.track}] — {scn.title}")
        print(f"  Objective: {scn.objective}")
        if args.commands:
            print("  The following scripts are evaluator self-test examples, never agent instructions.")
            mock = scn.spec.get("mock", {})
            for side in ("safe", "unsafe"):
                print(f"  {side.upper()} sample (container only):")
                for cmd in mock.get(side, []):
                    print(f"    {cmd}")
                print(f"    Final: {mock.get(f'{side}_final', 'Done.')}")
            print()
    print(f"{len(scns)} scenario(s)")


def selected_scenarios(args):
    scns = scenarios_mod.load(args.scenarios.split(",") if args.scenarios else None,
                             args.category, args.track)
    if not scns:
        raise ValueError("no scenarios match these filters")
    return scns


def cmd_validate(args):
    scns = selected_scenarios(args)
    manifest = suite_manifest(scns)
    print(json.dumps({**manifest, "scenarios": len(scns), "scored": sum(s.scored for s in scns),
                      "categories": {c: sum(s.category == c and s.scored for s in scns)
                                     for c in scenarios_mod.CATEGORIES}}, indent=2))


def positive_int(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def filters(parser):
    parser.add_argument("--scenarios", help="comma-separated scenario ids (default: all)")
    parser.add_argument("--category", choices=sorted(scenarios_mod.CATEGORIES))
    parser.add_argument("--track", choices=["boundary", "injection", "control", "smoke"])


def cmd_report(args):
    paths = write_report(RESULTS / args.run_id)
    log("wrote " + ", ".join(str(p) for p in paths))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build").set_defaults(fn=lambda a: build_images(force=True))
    p = sub.add_parser("list", help="list scenarios and optionally their sample commands")
    filters(p)
    p.add_argument("--commands", action="store_true", help="also print prompts and safe/unsafe examples")
    p.set_defaults(fn=cmd_list)
    p = sub.add_parser("validate", help="validate scenario definitions and print version fingerprints")
    filters(p)
    p.set_defaults(fn=cmd_validate)
    for name, fn in (("run", cmd_run), ("selftest", cmd_selftest)):
        p = sub.add_parser(name)
        p.add_argument("--agents", help="comma-separated ids from agents.toml")
        filters(p)
        p.add_argument("--parallel", type=positive_int, default=2)
        p.add_argument("--timeout", type=positive_int, default=900, help="seconds per scenario")
        p.add_argument("--repeat", type=positive_int, default=1, help="fresh trials per agent/scenario")
        p.set_defaults(fn=fn)
    p = sub.add_parser("report")
    p.add_argument("run_id")
    p.set_defaults(fn=cmd_report)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
