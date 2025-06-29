package main

import (
	"context"
	"log/slog"
	"os"
)

// logHandler implements a slog.Handler wrapper to add attributes to each log
// record.
type logHandler struct {
	slog.Handler
	attrs []slog.Attr
}

// newLogger returns a new logHandler.
func newLogger(attrs ...slog.Attr) *slog.Logger {
	handler := &logHandler{
		Handler: slog.NewTextHandler(os.Stdout, nil),
		attrs:   attrs,
	}

	return slog.New(handler)
}

// Handle handles a slog.Record by adding the attributes and passing it to the
// underlying handler.
func (h *logHandler) Handle(ctx context.Context, record slog.Record) error {
	record.AddAttrs(h.attrs...)
	return h.Handler.Handle(ctx, record)
}
