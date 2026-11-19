# AGENTS.md: working on ct2shell

Notes for coding agents (and humans) changing, testing or operating this project.
Read this before touching the monitor, the publisher or the site.

## What this is

ct2shell spots newly registered **vulnerability-branded domains** (the
log4shell.com / react2shell.com pattern) by reading **Certificate Transparency
(CT) logs**. Every publicly trusted TLS cert must be logged, so a new site shows
up seconds after its cert is issued.

It matches registrable domains whose label ends in `4shell`, `2shell`, `2root`
or `4root`, enriches each one, classifies it, and publishes the results to a
public site: **https://raesene.github.io/ct2shell/**.

What we learned building it (2026-11-19):

- **Warning time is short.** Historically the first cert lands on or after
  disclosure day (log4shell.com +1 day, react2shell.com same day). Expect hours
  of warning at best, not days.
- **Most matches are squatting.** In the first four hours, 93 of the first 100
  matches came from one actor registering `<product>2shell/2root` domains
  (fortinet2root, nodejs2root, openssl2shell, …) at Name.com in overnight batches. Bulk detection exists to separate these from
  genuine one-offs.
- The CT ecosystem has largely moved to **tiled logs** (static-ct-api). Google's
  RFC 6962 logs are read-only and Let's Encrypt is tiled-only, so both formats
  are required.

## Architecture

```
            ┌──────────────── test server (systemd user units) ──────────────────┐
CT logs ──► │ ct2shell (continuous) ──► matches.jsonl + state.json                │
(58, both   │                                   │                                 │
 formats)   │ ct2shell-publish.timer (:00/:15/:30/:45) ─► publish.sh ─► ct2export │
            └───────────────────────────────────────────────┬────────────────────┘
                                                            │ git push data/data.json
                                                            ▼ (deploy key, main)
                               GitHub Actions (pages.yml): go test → ct2site → Pages
```

Ingestion deliberately does **not** run on GitHub Actions. Jobs are capped at
6h, full ingest is ~2.5–4k entries/s (~100–150 GB/day), and continuous bulk
processing conflicts with GitHub's Actions terms. GitHub only renders and hosts
the page.

## Repository map

| Path | What it does |
|---|---|
| `cmd/ct2shell` | The monitor. Tails every active log, matches, enriches, writes `matches.jsonl`. All flags are in `main.go`. |
| `cmd/ct2export` | Converts private `matches.jsonl` + `state.json` into public `data/data.json`. Prints `new`, `check` or `unchanged`. |
| `cmd/ct2site` | Renders the static site from `data.json` into `_site/` (html/template). |
| `internal/loglist` | Fetches Chrome's v3 log list. `Active()` keeps usable/qualified logs whose shard covers certs issued now. |
| `internal/ctlog` | Log readers. `rfc6962.go` (get-sth/get-entries), `tiled.go` (checkpoint + data tiles), `leaf.go` (TLS-struct parsing), `runner.go` (per-log tail loop: ordered concurrent fetches, adaptive concurrency, error classes), `http.go` (per-host 429 gate, Retry-After parsing, gzip sniffing). |
| `internal/match` | Normalises names and matches the **registrable label** via the Public Suffix List (private section included, so `x2shell.github.io` matches but `x2shell.example.com` doesn't). |
| `internal/enrich` | RDAP (registration date, registrar; IANA bootstrap) and crt.sh history; `Verdict()`. |
| `internal/monitor` | Prefilter, cert parsing, dedupe, the two-stage enrichment pipeline, JSONL output. `bulk.go` holds the bulk rules. |
| `internal/state` | JSON state file: per-log positions, seen domains (registrar, verdict, pending record). Saved atomically every 10s. |
| `internal/publish` | Public `data.json` schema, `ReadMatches`, `MonitorStatus`, burst `Groups`, `SameContent`. |
| `site/` | `templates/index.html.tmpl`, `style.css`, `app.js`, `assets/hero.webp`. |
| `deploy/` | `ct2shell.service`, `ct2shell-publish.{service,timer}`, `publish.sh`. |
| `scripts/reclassify_bulk.py` | One-off: recompute bulk verdicts in `matches.jsonl`/`state.json` (dry run unless `--apply`). |
| `data/data.json` | Published data. **Written by the server; never edit by hand.** |

## How the monitor works

1. **Log list.** Refreshed every 6h. On a fresh state file, every log starts at
   its tip (`-backfill N` to start earlier). A log that appears later (a new
   shard) starts at 0 if it has ≤5M entries, so nothing is missed.
2. **Tailing** (`ctlog.Runner`). Fetches up to `-concurrency` ranges in parallel
   but hands them to the handler strictly in order, so the saved position is
   always consistent. Tiled logs fetch full 256-entry tiles. A partial tile is
   fetched only after `-partial-delay` without progress. RFC 6962 requests are
   `-batch` (1024) aligned; logs that return fewer per call are looped.
3. **Errors are classified.** "Not ready" (tile 404/403 from a CDN that lags the
   checkpoint; get-entries 400 or an empty response at the tip) is retried quietly. Rate
   limits (429/503) halve concurrency and wait out Retry-After, shared per host.
   Anything else backs off exponentially. Transient noise logs at debug level and
   is promoted to WARN if a log makes no progress for 10 minutes.
4. **Prefilter.** Each entry's raw TBS/cert bytes are lowercased and searched
   for the suffixes. Only hits are parsed with `crypto/x509`. If parsing fails,
   a regex pulls hostnames out of the raw DER, so a malformed cert can't hide a
   match. `//go:debug x509negativeserial=1` is set.
5. **Match and dedupe** by registrable domain (eTLD+1). The first sighting
   creates a pending record in state.
6. **Enrichment, stage 1** (immediately): an RDAP lookup gives registration
   date and registrar. It's skipped for private suffixes like `github.io`.
7. **Enrichment, stage 2** (after `-bulk-hold`, 3m, so a burst can assemble):
   - **Bulk check:** peers first seen within ±`-bulk-window` (30m), excluding
     `existing` peers and peers with a different *known* registrar.
     A group of ≥`-bulk-min` (3) makes the verdict `bulk`; `base_verdict`
     keeps what it would have been.
   - **crt.sh history,** skipped when RDAP already shows a fresh registration
     (crt.sh lags by hours) and for bulk members (each lookup takes 30s+).
   - **Write** one JSONL line, then mark the domain emitted. On restart,
     unemitted domains are requeued.
8. **Verdicts:** `new` (registered ≤30d ago), `bulk`, `dormant` (old
   registration, no cert history), `existing`, `likely_new` (no registration
   data, no history), `unknown`.

`matches.jsonl` is **append-only**. To change verdicts after the fact, follow
the pattern in `scripts/reclassify_bulk.py`:
1. Stop the service.
2. Back up `matches.jsonl` and `state.json`.
3. Dry-run the script, then run it with `--apply`.
4. Mark changed records with `reclassified_at`.
5. Update `state.json` to match.

## Publishing and the site

- `publish.sh` runs every quarter-hour (systemd `OnCalendar=*:00/15`). It
  resets its own clone in `~/ct2shell/publish` to `origin/main`, runs
  `ct2export`, and commits `data/data.json`. Commits are titled `data: N domains`
  when records changed and `check: no new domains` otherwise. Every run commits,
  so the page's "last checked" stays current. Set `CT2SHELL_HEARTBEAT=1h` to
  reduce check-only commits.
- Every push to `main` runs `.github/workflows/pages.yml`: `go test ./...`,
  then `go run ./cmd/ct2site`, then a Pages deploy. Overlapping runs cancel
  each other, so "cancelled" runs in the list are normal.
- **The page works without JavaScript.** `app.js` only:
  - moves the "lamp" (pointer-following spotlight)
  - shows relative ages
  - filters the All domains table
  - reloads when `data.json` has a newer `generated_at` (checked every 2 min)
  - repaints status as `[WARN]` after 45 min without a check-in and `[ERR]` after 2h
- **Health check:** if the monitor hadn't saved a log position in the 10 minutes
  before a check, the page is rendered `[ERR]` ("monitor not reading logs"),
  marked by `<meta name="ct2-health" content="down">`, and JS leaves it alone.
- `data.json` contains only public facts (CT, RDAP, crt.sh). Keep it that way.

### Design: Katagami "Cathode"

The site uses the Cathode design language
(https://katagami.ai/language/en-01a100fa-7443-7490-b733-370fa661b031). Rules to keep:

- Near-black `#0A0A0A` ground and Geist Mono throughout. Corners are square
  (radius 0). No glow, blur, gradients, shadows or scanlines.
- **State is always a bracketed word**, coloured second: `[NEW]` green,
  `[LIKELY]`/`[DORMANT]`/`[SYNC]` cyan, `[BULK]`/`[WARN]` amber, `[ERR]` red,
  `[KNOWN]`/`[UNKN]` muted. Never use colour alone.
- One green button per view. Rows are separated by dashed 1px `#262626`
  rules, never boxes. No em dashes in page copy.
- **Hero:** the plate `assets/hero.webp` (generated in the paired "Phosphor"
  art style) shown dimmed to 34%. A hard-edged lamp circle follows the pointer
  over it. Six numbered pins mark pipeline stages, and their positions are
  hard-coded percentages in the template, tied to objects in the image. If you
  replace the image, re-place the pins.
- "Latest domains" is **newest first** (a deliberate departure from Cathode's
  oldest-first log), with the live status row on top.
- After visual changes, run Katagami's `check_page_against_language` with the
  HTML plus inlined CSS. One known false "fail": the hover colour `#5CFF85`,
  which Cathode's spec prescribes but its token set omits (reported to
  Katagami).

## Testing and verifying changes

```bash
go vet ./... && go test ./...                 # unit tests (CI runs these too)
CGO_ENABLED=0 go build -trimpath -o bin/ct2shell ./cmd/ct2shell
```

**Smoke-test the monitor** with a common suffix so matches arrive in seconds.
Run it in its own directory so the real state isn't touched:

```bash
mkdir -p /tmp/smoke && cd /tmp/smoke
ct2shell -suffixes shop -no-enrich -backfill 3000 -run-for 2m -stats 30s
# expect: matches from many logs, parse_fails=0, stats lines with entries_per_sec
```

Use a rare suffix with enrichment on (e.g. `-suffixes bakery -backfill 20000
-run-for 5m`) to exercise RDAP, crt.sh and the verdicts. Use `-include`/`-exclude`
(regexp on log names) to isolate one log while debugging.

**Preview the site locally:**

```bash
go run ./cmd/ct2site -data data/data.json -site site -out _site
python3 -m http.server <free-port> -d _site --bind 127.0.0.1
```

- **Port:** pick a free port. The dev machine may already be serving something
  on common ports such as 8765.
- **Desktop screenshot:**
  `google-chrome --headless=new --window-size=1440,900 --screenshot=out.png URL`.
- **Phone width:** headless Chrome won't lay out narrower than **500px**. To see
  a real 390px layout, load the page in a `<iframe style="width:390px">` and
  screenshot that.
- **Monitor-down state:** render a `data.json` exported from an old `state.json`
  to check the `[ERR]` rendering.

**Exporter modes:** run `ct2export` twice on the same inputs. You should get
`new`, then `check`; with `-heartbeat 1h` the second run prints `unchanged`.

## Operating the deployment

The monitor runs on the project's test server. Its address, and the contact
address used in the User-Agent, are **not in this repo**; they're in the
operator's private agent config (e.g. `~/.claude/CLAUDE.md`). On the server,
as the operator's user:

| Thing | Location |
|---|---|
| Binaries | `~/ct2shell/ct2shell`, `~/ct2shell/ct2export`, `~/ct2shell/publish.sh` |
| Runtime data | `~/ct2shell/live/state.json`, `~/ct2shell/live/matches.jsonl` (+ dated `.bak-*` backups) |
| User-Agent contact | `~/ct2shell/ct2shell.env` (`CT2SHELL_CONTACT=…`), read by `ct2shell.service` |
| Publisher clone | `~/ct2shell/publish` (reset to `origin/main` every run) |
| Deploy key | `~/.ssh/ct2shell_deploy` (repo-scoped, write) |
| Units | `~/.config/systemd/user/ct2shell.service`, `ct2shell-publish.{service,timer}`; linger is enabled |

```bash
systemctl --user status ct2shell ct2shell-publish.timer
journalctl --user -u ct2shell -f | grep -E "NEW MATCH|stats|WARN|ERROR"
journalctl --user -u ct2shell-publish -n 20
systemctl --user list-timers ct2shell-publish.timer
```

**Redeploy the monitor.** Restarting resumes from `state.json`; never delete it,
since it holds log positions and dedupe state:

```bash
CGO_ENABLED=0 go build -trimpath -o bin/ct2shell ./cmd/ct2shell
scp bin/ct2shell $HOST:ct2shell/ct2shell.new
ssh $HOST 'cd ~/ct2shell && systemctl --user stop ct2shell && mv ct2shell.new ct2shell && systemctl --user start ct2shell'
```

For `ct2export` or `publish.sh`, scp them over; the next timer run picks them
up. For unit files, scp them to `~/.config/systemd/user/`, then run
`systemctl --user daemon-reload`.

## Gotchas (each one bit us)

- **The server commits to `main` every 15 minutes.** Always `git pull --rebase`
  before pushing, and expect an occasional push race; just rebase and push
  again. Restarting the publish timer fires an immediate catch-up run.
- **Never `pkill -f ct2shell` over ssh.** The pattern matches the ssh session's
  own `bash -c` command line and kills it. Use `systemctl --user stop`, or kill
  by PID.
- **The dev machine and the test server share a public IP**, so rate limits
  are shared. Probing a log by hand from the dev machine eats the monitor's quota.
- **Cloudflare Nimbus** returns error 1015 (429) under its per-IP limit and
  advances its tree in ~1M-entry jumps. We read it at about its growth rate, so
  it sits ~0.9–1.2M entries behind. This is the main contributor to the page's
  "entries behind" figure. Coverage is mostly fine because every cert is in ≥2
  logs. **Open issue.**
- **Geomys (Sunlight/Skylight) logs** throttle clients without contact info in
  the User-Agent, and send `Retry-After` as an HTTP date. Hence `-contact` and
  `parseRetryAfter`.
- **Tiled-log CDNs** can serve a cached 404 (TrustAsia) or 403 (HARICA,
  BunnyCDN) for a tile the checkpoint already covers. Sectigo and DigiCert
  sometimes advertise an STH ahead of what get-entries will serve. All of
  these are "not ready" and resolve on their own within a minute or so.
- **crt.sh** is slow (30–70s per query) and flaky. Requests are serialised and
  spaced, and skipped whenever the verdict doesn't need them.
- **The `gh` CLI token on the dev machine** can push code and read runs, but
  **cannot** change Pages settings, manage deploy keys or rerun/dispatch
  workflows (HTTP 403). Ask the user to do those in the web UI. Any push
  triggers a deploy anyway.
- `.gitignore` excludes `*.jsonl`, `*state*.json` and `*.env`. Runtime data and
  secrets must never be committed.

## Conventions

- **Privacy:** never commit the test server address, the User-Agent contact,
  personal emails or tokens. This repo and its site are public. Before
  committing, grep the staged files for addresses and emails.
- **Data:** never hand-edit `data/data.json` or rewrite `main`'s history.
- **Tests:** `go test ./...` must pass; CI runs it before every deploy. Add a
  test alongside any change to matching, verdicts, bulk rules, parsing or
  rendering logic.
- **Code style:** run `gofmt` before committing. The project targets the Go
  version in `go.mod`, and builds use `CGO_ENABLED=0` (static binaries).
- **Commit titles:** short and lowercase-prefixed by area: `site:`, `ci:`,
  `publish timer:`. `data:` and `check:` are reserved for the publisher.

## Ideas not yet done

- Fix Nimbus throughput, or show lag per log so one slow log doesn't dominate.
- A registrar or actor watchlist for known bulk squatters.
- Notifications (e.g. Slack or email) for `new` verdicts.
- Split bursts into separate registration batches (they're currently chained
  by first-seen time, so overnight batches merge into one group).
