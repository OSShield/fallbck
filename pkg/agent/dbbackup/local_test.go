package dbbackup

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestIsLocalHost(t *testing.T) {
	ctx := context.Background()
	hn, _ := os.Hostname()
	for _, h := range []string{"localhost", "LOCALHOST", "127.0.0.1", "::1", "[::1]", "/var/run/postgresql", ".", `.\SQLEXPRESS`, `localhost\inst`, hn, strings.ToUpper(hn)} {
		if h == "" {
			continue
		}
		if !isLocalHost(ctx, h) {
			t.Errorf("%q should be local", h)
		}
	}
	for _, h := range []string{"", "db01.example.invalid", "203.0.113.7", "2001:db8::1"} {
		if isLocalHost(ctx, h) {
			t.Errorf("%q should not be local", h)
		}
	}
}

func TestScanString(t *testing.T) {
	var s string
	var n int
	var n64 int64
	var b bool
	for _, c := range []struct {
		dest any
		val  string
		ok   bool
	}{
		{&s, "hello", true}, {&n, " 42", true}, {&n64, "4096", true}, {&b, "t", true}, {&b, "f", true},
		{&n, "x", false}, {&b, "maybe", false}, {new(float64), "1", false},
	} {
		if err := scanString(c.dest, c.val); (err == nil) != c.ok {
			t.Errorf("scan %q into %T: %v", c.val, c.dest, err)
		}
	}
	if s != "hello" || n != 42 || n64 != 4096 || b {
		t.Errorf("values: %q %d %d %v", s, n, n64, b)
	}
}
