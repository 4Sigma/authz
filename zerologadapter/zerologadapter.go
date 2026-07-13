// Package zerologadapter bridges zerolog into log/slog, so applications that
// log with zerolog can plug their logger into slog-based libraries (such as
// authz) without a second logging stack. It lives in its own package so that
// applications not using zerolog never link it.
package zerologadapter

import (
	"context"
	"log/slog"

	"github.com/rs/zerolog"
)

// Handler wraps logger as a slog.Handler. slog groups are flattened into
// dot-separated key prefixes (group "req" + key "id" → "req.id"). The
// record's timestamp and source location are not forwarded: timestamps come
// from the wrapped logger's own configuration (e.g. zerolog's Timestamp()).
func Handler(logger *zerolog.Logger) slog.Handler {
	return &handler{logger: logger}
}

type handler struct {
	logger *zerolog.Logger
	attrs  []slog.Attr // accumulated via WithAttrs, keys already prefixed
	prefix string      // dotted group prefix from WithGroup
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return zerologLevel(level) >= h.logger.GetLevel()
}

func (h *handler) Handle(_ context.Context, rec slog.Record) error {
	evt := h.logger.WithLevel(zerologLevel(rec.Level)) //nolint:zerologlint // dispatched by evt.Msg below; the linter loses track of evt when it is passed to addAttr
	for _, attr := range h.attrs {
		addAttr(evt, "", attr)
	}
	rec.Attrs(func(attr slog.Attr) bool {
		addAttr(evt, h.prefix, attr)
		return true
	})
	evt.Msg(rec.Message)
	return nil
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := *h
	nh.attrs = make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	nh.attrs = append(nh.attrs, h.attrs...)
	for _, attr := range attrs {
		attr.Key = h.prefix + attr.Key
		nh.attrs = append(nh.attrs, attr)
	}
	return &nh
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := *h
	nh.prefix = h.prefix + name + "."
	return &nh
}

func addAttr(evt *zerolog.Event, prefix string, attr slog.Attr) {
	val := attr.Value.Resolve()
	key := prefix + attr.Key
	switch val.Kind() {
	case slog.KindGroup:
		groupPrefix := key + "."
		if attr.Key == "" { // slog convention: empty group key inlines the attrs
			groupPrefix = prefix
		}
		for _, groupAttr := range val.Group() {
			addAttr(evt, groupPrefix, groupAttr)
		}
	case slog.KindString:
		evt.Str(key, val.String())
	case slog.KindInt64:
		evt.Int64(key, val.Int64())
	case slog.KindUint64:
		evt.Uint64(key, val.Uint64())
	case slog.KindFloat64:
		evt.Float64(key, val.Float64())
	case slog.KindBool:
		evt.Bool(key, val.Bool())
	case slog.KindDuration:
		evt.Dur(key, val.Duration())
	case slog.KindTime:
		evt.Time(key, val.Time())
	default:
		evt.Interface(key, val.Any())
	}
}

func zerologLevel(level slog.Level) zerolog.Level {
	switch {
	case level < slog.LevelInfo:
		return zerolog.DebugLevel
	case level < slog.LevelWarn:
		return zerolog.InfoLevel
	case level < slog.LevelError:
		return zerolog.WarnLevel
	default:
		return zerolog.ErrorLevel
	}
}
