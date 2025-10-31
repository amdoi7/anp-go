package anp_crawler

import "log/slog"

var logger = slog.Default()

// SetLogger allows callers to provide a custom slog.Logger. Passing nil resets to slog.Default().
func SetLogger(l *slog.Logger) {
	if l == nil {
		logger = slog.Default()
		return
	}
	logger = l
}

// Logger returns the logger used within the anp_crawler package.
func Logger() *slog.Logger {
	return logger
}
