//go:debug x509negativeserial=1

// Command ct2shell tails every active Certificate Transparency log and records
// newly seen registrable domains whose label ends in a target suffix
// (default: 4shell, 2shell, 2root, 4root) — the naming pattern used by
// branded vulnerability disclosure sites like log4shell / react2shell.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"ct2shell/internal/ctlog"
	"ct2shell/internal/enrich"
	"ct2shell/internal/loglist"
	"ct2shell/internal/match"
	"ct2shell/internal/monitor"
	"ct2shell/internal/state"
)

func main() {
	var (
		statePath    = flag.String("state", "ct2shell-state.json", "state file (log positions, seen domains)")
		outPath      = flag.String("out", "ct2shell-matches.jsonl", "JSONL output file (one record per new domain)")
		suffixes     = flag.String("suffixes", "4shell,2shell,2root,4root", "comma-separated label suffixes to match")
		logListURL   = flag.String("log-list", loglist.DefaultURL, "Chrome v3 log list URL")
		include      = flag.String("include", "", "only monitor logs whose name matches this regexp")
		exclude      = flag.String("exclude", "", "skip logs whose name matches this regexp")
		backfill     = flag.Uint64("backfill", 0, "on first sight of a log, start this many entries before the tip")
		concurrency  = flag.Int("concurrency", 4, "parallel fetches per log")
		batch        = flag.Uint64("batch", 1024, "RFC 6962 get-entries batch size (logs that serve fewer per request are looped)")
		poll         = flag.Duration("poll", 5*time.Second, "how often to check log size when caught up")
		partialDelay = flag.Duration("partial-delay", 30*time.Second, "fetch a partial tile if no full tile has appeared for this long")
		refresh      = flag.Duration("refresh", 6*time.Hour, "log list refresh interval")
		statsEvery   = flag.Duration("stats", time.Minute, "stats logging interval (0 to disable)")
		noEnrich     = flag.Bool("no-enrich", false, "disable RDAP / crt.sh enrichment")
		newDays      = flag.Int("new-days", 30, "registration age (days) at or below which a domain is 'new'")
		bulkWindow   = flag.Duration("bulk-window", 30*time.Minute, "matches first seen within ± this window are grouped for bulk detection")
		bulkMin      = flag.Int("bulk-min", 3, "group size (including the domain) at which it is flagged as bulk; 0 disables")
		bulkHold     = flag.Duration("bulk-hold", 3*time.Minute, "wait this long after first sighting before classifying, so a burst can assemble")
		runFor       = flag.Duration("run-for", 0, "exit after this long (0 = run forever)")
		contact      = flag.String("contact", "", "contact (email or URL) to put in the User-Agent; Sunlight/Skylight logs rate-limit anonymous clients")
		verbose      = flag.Bool("v", false, "debug logging")
	)
	flag.Parse()

	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	if *contact != "" {
		ctlog.UserAgent = fmt.Sprintf("ct2shell/0.1 (certificate transparency monitor; +%s)", *contact)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *runFor > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *runFor)
		defer cancel()
	}

	var incRe, excRe *regexp.Regexp
	if *include != "" {
		incRe = regexp.MustCompile(*include)
	}
	if *exclude != "" {
		excRe = regexp.MustCompile(*exclude)
	}

	st, err := state.Load(*statePath)
	if err != nil {
		fatal(log, "load state", err)
	}
	freshState := !st.HasLogs()

	client := ctlog.NewClient()
	matcher := match.New(strings.Split(*suffixes, ","))
	var enr *enrich.Enricher
	if !*noEnrich {
		enr = enrich.New(client, ctlog.UserAgent)
	}
	mon, err := monitor.New(matcher, st, enr, *outPath, *newDays,
		monitor.BulkConfig{Window: *bulkWindow, Min: *bulkMin, Hold: *bulkHold}, log)
	if err != nil {
		fatal(log, "open output", err)
	}
	defer mon.Close()

	var wg sync.WaitGroup
	wg.Go(func() { mon.RunEnricher(ctx) })
	mon.Requeue()

	// Periodic state saves.
	wg.Go(func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.Save(); err != nil {
					log.Error("save state", "err", err)
				}
			}
		}
	})

	// Stats.
	if *statsEvery > 0 {
		wg.Go(func() { statsLoop(ctx, log, mon, st, *statsEvery) })
	}

	// Log runners, with periodic log list refresh.
	running := map[string]context.CancelFunc{}
	sync1 := func(initial bool) {
		all, err := loglist.Fetch(ctx, client, *logListURL, ctlog.UserAgent)
		if err != nil {
			log.Error("fetch log list", "err", err)
			return
		}
		active := map[string]loglist.Log{}
		for _, l := range loglist.Active(all, time.Now()) {
			if incRe != nil && !incRe.MatchString(l.Name) || excRe != nil && excRe.MatchString(l.Name) {
				continue
			}
			active[l.ID] = l
		}
		for id, cancel := range running {
			if _, ok := active[id]; !ok {
				log.Info("log no longer active; stopping", "id", id)
				cancel()
				delete(running, id)
			}
		}
		for id, l := range active {
			if _, ok := running[id]; ok {
				continue
			}
			var src ctlog.Source
			if l.Tiled {
				src = ctlog.NewTiled(l.URL, client)
			} else {
				src = ctlog.NewRFC6962(l.URL, client, *batch)
			}
			pos, known := st.LogPos(id)
			if !known {
				size, err := src.Size(ctx)
				if err != nil {
					log.Warn("can't get size of new log; will retry at next refresh", "log", l.Name, "err", err)
					continue
				}
				// First run: start at the tip. A log that appears later (new
				// shard) starts at 0 if it's small, so we miss nothing.
				switch {
				case !freshState && !initial && size <= 5_000_000:
					pos = 0
				case size > *backfill:
					pos = size - *backfill
				default:
					pos = 0
				}
				st.SetLogPos(id, l.Name, l.URL, pos, size)
			}
			lctx, cancel := context.WithCancel(ctx)
			running[id] = cancel
			r := &ctlog.Runner{
				Name: l.Name, Src: src, Concurrency: *concurrency, Poll: *poll, PartialDelay: *partialDelay,
				Handle: mon.Handle, Log: log,
				SavePos: func(next, size uint64) { st.SetLogPos(id, l.Name, l.URL, next, size) },
			}
			kind := "rfc6962"
			if l.Tiled {
				kind = "tiled"
			}
			log.Info("monitoring log", "log", l.Name, "type", kind, "state", l.State, "start", pos)
			wg.Go(func() { r.Run(lctx, pos) })
		}
		log.Info("log list synced", "active", len(running))
	}
	sync1(true)

	t := time.NewTicker(*refresh)
	defer t.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-t.C:
			sync1(false)
		}
	}
	log.Info("shutting down")
	wg.Wait()
	if err := st.Save(); err != nil {
		log.Error("final save", "err", err)
	}
}

func statsLoop(ctx context.Context, log *slog.Logger, mon *monitor.Monitor, st *state.Store, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	var last uint64
	lastT := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			n := mon.Stats.Entries.Load()
			rate := float64(n-last) / now.Sub(lastT).Seconds()
			last, lastT = n, now
			lag := st.Lag()
			var total uint64
			type kv struct {
				k string
				v uint64
			}
			var worst []kv
			for k, v := range lag {
				total += v
				if v > 0 {
					worst = append(worst, kv{k, v})
				}
			}
			sort.Slice(worst, func(i, j int) bool { return worst[i].v > worst[j].v })
			var ws []string
			for i := 0; i < len(worst) && i < 3; i++ {
				ws = append(ws, fmt.Sprintf("%s=%d", worst[i].k, worst[i].v))
			}
			log.Info("stats",
				"entries_per_sec", int(rate), "entries_total", n,
				"candidates", mon.Stats.Candidates.Load(), "matches", mon.Stats.Matches.Load(),
				"new_domains", mon.Stats.NewDomains.Load(), "parse_fails", mon.Stats.ParseFails.Load(),
				"total_lag", total, "worst_lag", strings.Join(ws, " "))
		}
	}
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error(msg, "err", err)
	os.Exit(1)
}
