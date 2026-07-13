package zerologadapter_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"labcatch/authz/zerologadapter"
)

func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	zl := zerolog.New(buf)
	return slog.New(zerologadapter.Handler(&zl))
}

func lastLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	var entry map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &entry); err != nil {
		t.Fatalf("cannot parse log line %q: %v", buf.String(), err)
	}
	return entry
}

func TestHandler_MessageLevelAndAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	logger.Warn("authorization denied",
		slog.String("resource", "document"),
		slog.Int("count", 3),
		slog.Bool("ok", false),
	)

	entry := lastLine(t, &buf)
	if entry["level"] != "warn" {
		t.Errorf("expected level warn, got %v", entry["level"])
	}
	if entry["message"] != "authorization denied" {
		t.Errorf("expected message, got %v", entry["message"])
	}
	if entry["resource"] != "document" {
		t.Errorf("expected resource=document, got %v", entry["resource"])
	}
	if entry["count"] != float64(3) {
		t.Errorf("expected count=3, got %v", entry["count"])
	}
	if entry["ok"] != false {
		t.Errorf("expected ok=false, got %v", entry["ok"])
	}
}

func TestHandler_LevelMapping(t *testing.T) {
	tests := []struct {
		log  func(*slog.Logger)
		want string
	}{
		{func(l *slog.Logger) { l.Debug("m") }, "debug"},
		{func(l *slog.Logger) { l.Info("m") }, "info"},
		{func(l *slog.Logger) { l.Warn("m") }, "warn"},
		{func(l *slog.Logger) { l.Error("m") }, "error"},
	}
	for _, tt := range tests {
		var buf bytes.Buffer
		tt.log(newTestLogger(&buf))
		if entry := lastLine(t, &buf); entry["level"] != tt.want {
			t.Errorf("expected level %s, got %v", tt.want, entry["level"])
		}
	}
}

func TestHandler_Enabled(t *testing.T) {
	var buf bytes.Buffer
	zl := zerolog.New(&buf).Level(zerolog.WarnLevel)
	logger := slog.New(zerologadapter.Handler(&zl))

	logger.Info("suppressed")
	if buf.Len() != 0 {
		t.Errorf("expected info below warn level to be suppressed, got %q", buf.String())
	}
	logger.Warn("emitted")
	if buf.Len() == 0 {
		t.Error("expected warn to be emitted")
	}
}

func TestHandler_AttrKinds(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	logger.Info("m",
		slog.Uint64("u", 7),
		slog.Float64("f", 1.5),
		slog.Duration("d", 2*time.Second),
		slog.Time("ts", time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)),
		slog.Any("xs", []int{1, 2}),
		slog.Group("", slog.String("inline", "yes")),
	)

	entry := lastLine(t, &buf)
	if entry["u"] != float64(7) {
		t.Errorf("expected u=7, got %v", entry["u"])
	}
	if entry["f"] != 1.5 {
		t.Errorf("expected f=1.5, got %v", entry["f"])
	}
	if entry["d"] != float64(2000) { // zerolog default duration unit is milliseconds
		t.Errorf("expected d=2000, got %v", entry["d"])
	}
	if ts, ok := entry["ts"].(string); !ok || !strings.HasPrefix(ts, "2026-07-07T12:00:00") {
		t.Errorf("expected ts to be the formatted time, got %v", entry["ts"])
	}
	if xs, ok := entry["xs"].([]any); !ok || len(xs) != 2 {
		t.Errorf("expected xs=[1 2], got %v", entry["xs"])
	}
	if entry["inline"] != "yes" { // empty group key inlines its attrs (slog convention)
		t.Errorf("expected inline=yes at top level, got %v", entry["inline"])
	}
}

func TestHandler_GroupsAndWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf).
		With(slog.String("component", "authz")).
		WithGroup("req")

	logger.Info("m", slog.String("id", "42"), slog.Group("sub", slog.String("k", "v")))

	entry := lastLine(t, &buf)
	if entry["component"] != "authz" {
		t.Errorf("expected component=authz, got %v", entry["component"])
	}
	if entry["req.id"] != "42" {
		t.Errorf("expected req.id=42, got %v", entry["req.id"])
	}
	if entry["req.sub.k"] != "v" {
		t.Errorf("expected req.sub.k=v, got %v", entry["req.sub.k"])
	}
}

func TestHandler_WithGroupEmptyName(t *testing.T) {
	// slog.Logger short-circuits WithGroup("") itself, so the handler's guard
	// is only reachable when the handler is used directly.
	var buf bytes.Buffer
	zl := zerolog.New(&buf)
	h := zerologadapter.Handler(&zl)
	if h.WithGroup("") != h {
		t.Error("expected WithGroup(\"\") to return the same handler")
	}
}
