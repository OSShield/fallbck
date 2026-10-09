// Package m365 executes Microsoft 365 backup jobs on the agent: it talks to Microsoft
// Graph, keeps a per-unit index of what the previous snapshot held, presents each
// user, site or team as a virtual tree whose unchanged items are never fetched, and
// uploads one snapshot per unit through the shared backup engine.
package m365

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	spec "github.com/osshield/fallbck/pkg/m365"
	"golang.org/x/oauth2"
)

// Request limits
const (
	// maxAttempts bounds the retries of one request on throttling or 5xx
	maxAttempts = 8
	// maxRetryAfter caps a Retry-After wait
	maxRetryAfter = 5 * time.Minute
	// pageSize asks Graph for its largest pages
	pageSize = 999
)

// GraphError is a non-2xx answer from Graph
type GraphError struct {
	Status  int
	Code    string
	Message string
	URL     string
	// retryAfter is the server's Retry-After (0 = none given)
	retryAfter time.Duration
}

func (e *GraphError) Error() string {
	msg := fmt.Sprintf("Graph %d", e.Status)
	if e.Code != "" {
		msg += " " + e.Code
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

// IsStatus reports whether err is a GraphError with one of the statuses
func IsStatus(err error, statuses ...int) bool {
	var ge *GraphError
	if !errors.As(err, &ge) {
		return false
	}
	for _, s := range statuses {
		if ge.Status == s {
			return true
		}
	}
	return false
}

// IsResync reports a delta link Graph no longer honours (410 Gone, resyncRequired)
func IsResync(err error) bool { return IsStatus(err, http.StatusGone) }

// Client is a Graph HTTP client with bearer auth, paging and throttling retries
type Client struct {
	http *http.Client
	// base is GraphURL + "/v1.0" (tests substitute a server)
	base string
	// Stats counts what the client did (read after the run)
	Stats Stats
}

// Stats are the client's request counters
type Stats struct {
	Requests   int
	Retries    int
	Downloaded uint64
}

// NewClient builds a client from the tenant credentials. graphURL "" means GraphURL;
// authority "" means AuthorityURL.
func NewClient(ctx context.Context, creds spec.Credentials, authority, graphURL string) (*Client, error) {
	src, err := spec.TokenSource(ctx, creds, authority)
	if err != nil {
		return nil, err
	}
	if graphURL == "" {
		graphURL = spec.GraphURL
	}
	hc := oauth2.NewClient(ctx, src)
	hc.Timeout = 10 * time.Minute
	return &Client{http: hc, base: strings.TrimRight(graphURL, "/") + "/v1.0"}, nil
}

// URL joins a path onto the API base (absolute URLs pass through) and
// percent-encodes the query string (OData filters carry spaces and quotes)
func (c *Client) URL(path string) string {
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		path = c.base + "/" + strings.TrimLeft(path, "/")
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i] + "?" + encodeQuery(path[i+1:])
	}
	return path
}

// encodeQuery escapes every value of a raw query string once (values that are
// already escaped, as in Graph's own nextLink URLs, are left alone)
func encodeQuery(raw string) string {
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		if dec, err := url.QueryUnescape(v); err == nil && dec != v {
			continue // already escaped
		}
		// Graph wants %20 for spaces inside OData expressions, not '+'
		parts[i] = k + "=" + strings.ReplaceAll(url.QueryEscape(v), "+", "%20")
	}
	return strings.Join(parts, "&")
}

// do sends the request, retrying on 429 and 5xx with Retry-After, and returns the
// response for a 2xx (the caller closes it)
func (c *Client) do(ctx context.Context, method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rd)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		c.Stats.Requests++
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
		} else if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
			lastErr = readError(resp, url)
			resp.Body.Close()
		} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		} else {
			defer resp.Body.Close()
			return nil, readError(resp, url)
		}
		wait := retryAfter(lastErr, attempt)
		slog.Debug("Graph request retried", "url", redact(url), "attempt", attempt, "wait", wait, "error", lastErr)
		c.Stats.Retries++
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", maxAttempts, lastErr)
}

// retryAfter honours the server's Retry-After, otherwise backs off exponentially
func retryAfter(err error, attempt int) time.Duration {
	var ge *GraphError
	if errors.As(err, &ge) && ge.retryAfter > 0 {
		if ge.retryAfter > maxRetryAfter {
			return maxRetryAfter
		}
		return ge.retryAfter
	}
	d := time.Duration(1<<uint(attempt)) * time.Second
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d
}

func readError(resp *http.Response, url string) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	ge := &GraphError{Status: resp.StatusCode, URL: url}
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil {
		ge.Code, ge.Message = e.Error.Code, e.Error.Message
	} else if s := strings.TrimSpace(string(body)); s != "" {
		ge.Message = truncate(s, 200)
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil {
			ge.retryAfter = time.Duration(secs) * time.Second
		}
	}
	return ge
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// redact strips the query string (pre-authenticated download URLs carry their token there)
func redact(url string) string {
	if i := strings.IndexByte(url, '?'); i >= 0 {
		return url[:i] + "?…"
	}
	return url
}

// Get fetches one JSON document
func (c *Client) Get(ctx context.Context, path string, out any, headers map[string]string) error {
	resp, err := c.do(ctx, http.MethodGet, c.URL(path), nil, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Post sends a JSON body and decodes the JSON answer
func (c *Client) Post(ctx context.Context, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, c.URL(path), raw, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Page is one page of a collection
type Page struct {
	Value     []json.RawMessage `json:"value"`
	NextLink  string            `json:"@odata.nextLink"`
	DeltaLink string            `json:"@odata.deltaLink"`
}

// Each walks a collection page by page (nextLink) calling fn for every element;
// it returns the deltaLink of the last page (delta queries) or ""
func (c *Client) Each(ctx context.Context, path string, headers map[string]string, fn func(raw json.RawMessage) error) (deltaLink string, err error) {
	url := c.URL(path)
	for url != "" {
		var page Page
		if err := c.Get(ctx, url, &page, headers); err != nil {
			return "", err
		}
		for _, v := range page.Value {
			if err := fn(v); err != nil {
				return "", err
			}
		}
		url, deltaLink = page.NextLink, page.DeltaLink
	}
	return deltaLink, nil
}

// List decodes every element of a collection into a slice
func List[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var out []T
	_, err := c.Each(ctx, path, nil, func(raw json.RawMessage) error {
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		out = append(out, v)
		return nil
	})
	return out, err
}

// Download streams a content URL. Graph content endpoints answer with a redirect to a
// pre-authenticated URL on another host; the bearer header must not follow it there,
// which Go's client already guarantees for cross-host redirects. Returns the body and
// the Content-Length (-1 when unknown).
func (c *Client) Download(ctx context.Context, url string) (io.ReadCloser, int64, error) {
	resp, err := c.do(ctx, http.MethodGet, c.URL(url), nil, nil)
	if err != nil {
		return nil, 0, err
	}
	c.Stats.Downloaded += uint64(max(resp.ContentLength, 0))
	return resp.Body, resp.ContentLength, nil
}

// ReadAll downloads a content URL into memory (bounded)
func (c *Client) ReadAll(ctx context.Context, url string, limit int64) ([]byte, error) {
	body, _, err := c.Download(ctx, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("content larger than %d bytes", limit)
	}
	return data, nil
}

// odataQuote escapes a string literal for $filter
func odataQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
