# ct2shell

Tails every active Certificate Transparency log and records **newly seen
domains whose registrable label ends in `4shell`, `2shell`, `2root` or `4root`**.
This is the naming pattern of branded vulnerability sites (log4shell, spring4shell,
text4shell, react2shell, …). The idea is to spot a site the moment it gets a TLS
cert, which is often the same day as, or slightly before, public disclosure.

## How it works

1. Fetches Chrome's log list (`log_list.json` v3) and tails every `usable`/`qualified`
   log whose temporal shard covers certs being issued now. Supports both the
   RFC 6962 JSON API and the static-ct-api (tiled: Let's Encrypt, Google, Geomys,
   IPng, …). The list is refreshed every 6h so new shards are picked up.
2. Prefilters each entry's raw TBS/cert bytes for the suffixes, which is cheap. Only
   hits are parsed as X.509. If a cert won't parse, hostnames are pulled from the
   raw DER with a regex, so a malformed cert can't hide a match.
3. Matches the **registrable label** (via the Public Suffix List, private section
   included). So `react2shell.com`, `react2shell.co.uk` and `react2shell.github.io`
   match, but `react2shell.example.com` does not.
4. Dedupes by registrable domain: one record per domain, the first time it is seen.
5. Enriches each new domain in the background, in two stages:
   - **Stage 1, on detection:** an **RDAP** lookup for the registration date and
     registrar (ICANN suffixes only; skipped for hosting platforms like
     `github.io` / `pages.dev`).
   - **Stage 2, after `-bulk-hold` (3m) has passed since first sighting, so a burst
     can assemble:**
     - **Bulk detection.** The domain is grouped with other matches first seen
       within ±`-bulk-window` (30m). Peers already known to be `existing`, or with
       a different known registrar, are excluded. With `-bulk-min` (3) or more in
       the group, a new-ish domain gets verdict `bulk`; `base_verdict` keeps what
       it would have been. This targets speculative squatting, e.g. one actor
       registering fortinet2root, flask2root, envoy2shell, fastapi2shell, … in
       under a minute.
     - **crt.sh** prior cert count and earliest `not_before`. Skipped when RDAP
       already shows a fresh registration (crt.sh lags CT by hours, so it would
       add nothing) and for bulk members, so a burst can't hold up a real site
       queued behind it.
   - **verdict**: `new` (registered ≤ `-new-days` ago), `bulk`, `dormant` (old
     registration, no cert history), `existing`, `likely_new` (no registration
     data, no history), `unknown`.
6. Appends one JSON line per domain to the output file. To see only the
   interesting ones: `jq -c 'select(.verdict=="new" or .verdict=="likely_new")' matches.jsonl`.

State (log positions and seen domains) is saved atomically every 10s. Restarts
resume where they left off, and domains seen but not yet enriched are retried.

## Usage

```
go build -o bin/ct2shell ./cmd/ct2shell
./bin/ct2shell -state state.json -out matches.jsonl -contact you@example.com
```

Useful flags:

| flag | default | |
|---|---|---|
| `-suffixes` | `4shell,2shell,2root,4root` | label suffixes to match |
| `-contact` | none | email/URL added to the User-Agent. **Strongly recommended**: Sunlight/Skylight logs (Geomys) rate-limit anonymous clients |
| `-backfill N` | 0 | on first sight of a log, start N entries before the tip |
| `-new-days` | 30 | registration age threshold for `new` |
| `-bulk-window` | 30m | time window for grouping matches |
| `-bulk-min` | 3 | group size that triggers `bulk` (0 disables) |
| `-bulk-hold` | 3m | delay before classifying, so a burst can assemble |
| `-no-enrich` | false | skip RDAP/crt.sh |
| `-include` / `-exclude` | | regexp on log name |
| `-concurrency` | 4 | max parallel fetches per log (adapts down on 429) |
| `-run-for` | 0 | exit after a duration (testing) |

To smoke-test the pipeline, use a common suffix:
`-suffixes shop -no-enrich -backfill 3000 -run-for 2m`.

## Running as a service

`deploy/ct2shell.service` is a systemd user unit (install steps in the file). The
contact address is read from `~/ct2shell/ct2shell.env` (`CT2SHELL_CONTACT=…`), so
it isn't in the repo. Watch it with `journalctl --user -u ct2shell -f`.

## Public site (GitHub Pages)

The results are published at **https://raesene.github.io/ct2shell/**. The page
uses the [Cathode](https://katagami.ai/language/en-01a100fa-7443-7490-b733-370fa661b031)
design language from Katagami.

- **Ingestion stays on the server.** GitHub Actions jobs are capped at 6h and full
  CT ingest is ~100–150 GB/day, so the monitor isn't run there.
- `deploy/publish.sh` (run by `ct2shell-publish.timer` every 15 min) converts the
  private `matches.jsonl` and `state.json` into the public `data/data.json` with
  `cmd/ct2export`, and pushes it to `main` using a repo deploy key. It commits on
  every run, as `data: …` when there are new domains and `check: …` when there
  aren't, so the page's "last checked" time stays current. Set
  `CT2SHELL_HEARTBEAT=1h` in the publish service's environment to cut check-only commits.
- `.github/workflows/pages.yml` runs on every push: it renders the site with
  `cmd/ct2site` and deploys it to Pages. The page reads fine without JavaScript.
  `site/app.js` moves the lamp, filters the table, reloads itself when newer data
  is published, and flags `[WARN]` after 45 min without a check-in and `[ERR]`
  after 2h. A check made while the monitor had stopped reading logs renders as `[ERR]`.

Preview locally: `go run ./cmd/ct2site -data data/data.json -out _site` and serve `_site/`.

## Output record

```json
{"domain":"react2shell.com","label":"react2shell","public_suffix":"com","icann":true,
 "matched_suffix":"2shell","first_seen":"…","names":["*.react2shell.com","react2shell.com"],
 "cert":{"log":"Let's Encrypt Sycamore2027h1","log_index":123,"log_timestamp":"…","precert":true,
         "issuer":"CN=R13,O=Let's Encrypt,C=US","serial":"…","not_before":"…","not_after":"…"},
 "detection_delay_sec":14.3,
 "enrichment":{"rdap_domain":"react2shell.com","registered_at":"…","registration_age_days":0.4,
               "registrar":"…","crtsh_cert_count":0},
 "bulk":{"is_bulk":false,"group_size":1,"window_sec":1800},
 "verdict":"new"}
```

## Limitations

- **The warning is short.** Historically the first cert lands on or after disclosure
  day (log4shell.com: +1 day, react2shell.com: same day). Expect minutes to hours of
  warning at best.
- **Wildcard certs hide subdomains.** `foo2shell.example.com` covered by `*.example.com`
  never appears by name. Out of scope by design (registrable label only).
- **Squatters.** Every named bug attracts look-alike registrations. Use `verdict`
  and the registration date to separate them.
- **Bandwidth.** Full CT ingest is ~2.5k entries/s, roughly 100–150 GB/day.
- Log signatures and inclusion proofs are not verified. This is a name monitor, not an auditor.
