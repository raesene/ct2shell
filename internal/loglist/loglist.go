// Package loglist fetches and filters Chrome's CT log list (v3).
package loglist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const DefaultURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

type Log struct {
	ID       string // base64 log ID; stable key
	Name     string // description
	Operator string
	URL      string // RFC 6962 base URL or static-ct monitoring prefix
	Tiled    bool
	State    string
	Start    time.Time
	End      time.Time
}

type rawLog struct {
	Description   string                     `json:"description"`
	LogID         string                     `json:"log_id"`
	URL           string                     `json:"url"`
	MonitoringURL string                     `json:"monitoring_url"`
	State         map[string]json.RawMessage `json:"state"`
	Temporal      struct {
		Start time.Time `json:"start_inclusive"`
		End   time.Time `json:"end_exclusive"`
	} `json:"temporal_interval"`
}

func Fetch(ctx context.Context, c *http.Client, url, ua string) ([]Log, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("log list: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func Parse(b []byte) ([]Log, error) {
	var ll struct {
		Operators []struct {
			Name  string   `json:"name"`
			Logs  []rawLog `json:"logs"`
			Tiled []rawLog `json:"tiled_logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(b, &ll); err != nil {
		return nil, err
	}
	var out []Log
	for _, op := range ll.Operators {
		add := func(r rawLog, tiled bool) {
			l := Log{ID: r.LogID, Name: r.Description, Operator: op.Name, URL: r.URL, Tiled: tiled,
				Start: r.Temporal.Start, End: r.Temporal.End}
			if tiled {
				l.URL = r.MonitoringURL
			}
			for k := range r.State {
				l.State = k
			}
			out = append(out, l)
		}
		for _, r := range op.Logs {
			add(r, false)
		}
		for _, r := range op.Tiled {
			add(r, true)
		}
	}
	return out, nil
}

// Active returns logs that can currently receive new certificates: state
// usable or qualified, and a temporal shard that covers certificates being
// issued now (max cert lifetime is < 400 days).
func Active(logs []Log, now time.Time) []Log {
	var out []Log
	for _, l := range logs {
		if l.State != "usable" && l.State != "qualified" {
			continue
		}
		if !l.End.IsZero() && !l.End.After(now) {
			continue
		}
		if !l.Start.IsZero() && l.Start.After(now.Add(400*24*time.Hour)) {
			continue
		}
		out = append(out, l)
	}
	return out
}
