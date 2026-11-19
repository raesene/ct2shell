package ctlog

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// hostGate makes every request to a host wait out a 429's Retry-After, so
// several shards on one operator back off together.
var hostGate = struct {
	sync.Mutex
	until map[string]time.Time
}{until: map[string]time.Time{}}

func waitHost(ctx context.Context, host string) error {
	hostGate.Lock()
	t := hostGate.until[host]
	hostGate.Unlock()
	if d := time.Until(t); d > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	return nil
}

func blockHost(host string, d time.Duration) {
	hostGate.Lock()
	defer hostGate.Unlock()
	if t := time.Now().Add(d); t.After(hostGate.until[host]) {
		hostGate.until[host] = t
	}
}

// parseRetryAfter accepts delay-seconds or an HTTP-date (Skylight uses the latter).
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	for _, layout := range []string{http.TimeFormat, "Mon, 02 Jan 2006 15:04:05 MST", time.RFC1123Z} {
		if t, err := time.Parse(layout, v); err == nil {
			return max(time.Until(t), 0)
		}
	}
	return 0
}

// UserAgent is sent with every request. Deliberately generic.
var UserAgent = "ct2shell/0.1 (certificate transparency monitor)"

// HTTPError is a non-200 response.
type HTTPError struct {
	URL        string
	Status     int
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.Status) }

// NewClient returns an HTTP client tuned for many parallel log fetches.
func NewClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 256
	t.MaxIdleConnsPerHost = 16
	return &http.Client{Transport: t, Timeout: 90 * time.Second}
}

func get(ctx context.Context, c *http.Client, rawURL string, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if err := waitHost(ctx, u.Host); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		he := &HTTPError{URL: rawURL, Status: resp.StatusCode, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
		if resp.StatusCode == http.StatusTooManyRequests {
			blockHost(u.Host, max(he.RetryAfter, 500*time.Millisecond))
		}
		return nil, he
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	// Some static hosts serve pre-gzipped objects without Content-Encoding.
	// A TileLeaf starts with a big-endian ms timestamp (first byte 0x00), so
	// the gzip magic is unambiguous.
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(io.LimitReader(zr, limit))
	}
	return b, nil
}
