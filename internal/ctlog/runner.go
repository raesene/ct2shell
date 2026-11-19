package ctlog

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// ErrNotReady means the log advertised entries it can't serve yet. Expected
// near the tip of several logs; retried quietly.
var ErrNotReady = errors.New("entries not yet available")

// Range is a half-open interval of log indices [Start, End).
type Range struct{ Start, End uint64 }

// Source is a CT log that can be tailed.
type Source interface {
	Size(ctx context.Context) (uint64, error)
	Plan(pos, size uint64, allowPartial bool, k int) []Range
	Fetch(ctx context.Context, r Range) ([]Entry, error)
}

// Runner tails one log, fetching ranges concurrently but handing them to
// Handle strictly in order so the saved position is always consistent.
type Runner struct {
	Name         string
	Src          Source
	Concurrency  int // maximum; adapts down on rate limiting
	Poll         time.Duration
	PartialDelay time.Duration
	Handle       func(name string, es []Entry)
	SavePos      func(pos, size uint64)
	Log          *slog.Logger
}

type errClass int

const (
	errOther errClass = iota
	errRateLimited
	errNotReady
)

func classify(err error) errClass {
	var he *HTTPError
	switch {
	case errors.Is(err, ErrNotReady):
		return errNotReady
	case errors.As(err, &he) && (he.Status == http.StatusTooManyRequests || he.Status == http.StatusServiceUnavailable):
		return errRateLimited
	}
	return errOther
}

func (r *Runner) Run(ctx context.Context, pos uint64) {
	var (
		size        uint64
		sizeAt      time.Time
		lastAdvance = time.Now()
		failures    int // consecutive failed rounds
		okRounds    int // consecutive good rounds (for raising concurrency)
		conc        = max(r.Concurrency, 1)
	)
	sleep := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
			return true
		}
	}
	fail := func(err error) bool {
		failures++
		okRounds = 0
		var d time.Duration
		switch classify(err) {
		case errNotReady:
			d = min(r.Poll*time.Duration(failures), 30*time.Second)
		case errRateLimited:
			conc = max(1, conc/2)
			// get() already waits out Retry-After per host; just space retries.
			d = min(500*time.Millisecond*time.Duration(failures), 30*time.Second)
			var he *HTTPError
			if errors.As(err, &he) && he.RetryAfter > d {
				d = he.RetryAfter
			}
		default:
			d = min(2*time.Second<<min(failures-1, 8), 5*time.Minute)
		}
		if ctx.Err() != nil {
			return false
		}
		// Transient tip/rate-limit noise is debug-level unless it persists.
		lvl := slog.LevelDebug
		if classify(err) == errOther || time.Since(lastAdvance) > 10*time.Minute {
			lvl = slog.LevelWarn
		}
		r.Log.Log(ctx, lvl, "log fetch failed", "log", r.Name, "err", err, "retry_in", d, "concurrency", conc)
		return sleep(d)
	}

	for ctx.Err() == nil {
		if pos >= size || time.Since(sizeAt) > r.Poll {
			s, err := r.Src.Size(ctx)
			if err != nil {
				if !fail(err) {
					return
				}
				continue
			}
			size, sizeAt = s, time.Now()
			r.SavePos(pos, size)
		}
		ranges := r.Src.Plan(pos, size, time.Since(lastAdvance) > r.PartialDelay, conc)
		if len(ranges) == 0 {
			if !sleep(r.Poll) {
				return
			}
			continue
		}

		type result struct {
			es  []Entry
			err error
		}
		results := make([]result, len(ranges))
		var wg sync.WaitGroup
		for i, rg := range ranges {
			wg.Go(func() {
				es, err := r.Src.Fetch(ctx, rg)
				results[i] = result{es, err}
			})
		}
		wg.Wait()

		var ferr error
		for i, rg := range ranges {
			if results[i].err != nil {
				ferr = results[i].err
				break
			}
			r.Handle(r.Name, results[i].es)
			pos = rg.End
			lastAdvance = time.Now()
			r.SavePos(pos, size)
		}
		if ferr != nil {
			if !fail(ferr) {
				return
			}
			continue
		}
		failures = 0
		if okRounds++; okRounds >= 20 && conc < r.Concurrency {
			conc++
			okRounds = 0
		}
	}
}
