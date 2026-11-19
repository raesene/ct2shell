"""One-off: recompute bulk grouping for records in matches.jsonl using the
same rules as internal/monitor/bulk.go, with registrars taken from the
records themselves. Fixes records written before bulk detection existed, or
grouped while peers' registrars were missing from state.

usage: reclassify_bulk.py matches.jsonl state.json [--apply]
"""
import json, sys, datetime

WINDOW = datetime.timedelta(minutes=30)
MIN = 3
NEWISH = {"new", "likely_new", "dormant", "unknown", ""}

def ts(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")[:26] + "+00:00" if "." in s else s.replace("Z", "+00:00"))

def main():
    out_path, state_path = sys.argv[1], sys.argv[2]
    apply = "--apply" in sys.argv
    recs = [json.loads(l) for l in open(out_path) if l.strip()]
    for r in recs:
        r["_t"] = ts(r["first_seen"])
        r["_reg"] = ((r.get("enrichment") or {}).get("registrar") or "")
        r["_base"] = r.get("base_verdict") or r.get("verdict") or ""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    changed = []
    for r in recs:
        if r["_base"] not in NEWISH:
            continue
        peers, same_reg = [], bool(r["_reg"])
        for p in sorted(recs, key=lambda x: x["_t"]):
            if p is r or abs(p["_t"] - r["_t"]) > WINDOW or p["_base"] == "existing":
                continue
            if r["_reg"] and p["_reg"] and r["_reg"].lower() != p["_reg"].lower():
                continue
            if not p["_reg"]:
                same_reg = False
            peers.append(p["domain"])
        size = len(peers) + 1
        is_bulk = size >= MIN
        bulk = {"is_bulk": is_bulk, "group_size": size, "window_sec": int(WINDOW.total_seconds())}
        if is_bulk:
            bulk["peers"] = peers[:25]
            if same_reg:
                bulk["registrar"] = r["_reg"]
        verdict = "bulk" if is_bulk else r["_base"]
        old = (r.get("verdict"), (r.get("bulk") or {}).get("is_bulk"), (r.get("bulk") or {}).get("group_size"))
        if old[0] != verdict or old[1] != is_bulk or (r.get("bulk") is None):
            changed.append((r["domain"], old, verdict, size, r["_reg"]))
            r["bulk"] = bulk
            r["verdict"] = verdict
            if verdict != r["_base"]:
                r["base_verdict"] = r["_base"]
            else:
                r.pop("base_verdict", None)
            r["reclassified_at"] = now
    for d, old, v, size, reg in changed:
        print(f"{d:24} {str(old[0]):6} (bulk={old[1]}, grp={old[2]}) -> {v:6} grp={size:<3} {reg}")
    print(f"{len(changed)} record(s) to change of {len(recs)}")
    if not apply:
        return
    with open(out_path + ".tmp", "w") as f:
        for r in recs:
            f.write(json.dumps({k: v for k, v in r.items() if not k.startswith("_")}, separators=(",", ":")) + "\n")
    import os
    os.replace(out_path + ".tmp", out_path)
    st = json.load(open(state_path))
    for r in recs:
        ds = st["domains"].get(r["domain"])
        if ds is not None:
            if r["_reg"]:
                ds["registrar"] = r["_reg"]
            ds["verdict"] = r["verdict"]
    with open(state_path + ".tmp", "w") as f:
        json.dump(st, f, indent=1)
    os.replace(state_path + ".tmp", state_path)
    print("applied")

main()
