package anp_auth

import "log/slog"

var logger = slog.Default()

// SetLogger allows callers to provide a custom slog.Logger for the anp_auth package.
// Passing nil resets to slog.Default().
func SetLogger(l *slog.Logger) {
	if l == nil {
		logger = slog.Default()
		return
	}
	logger = l
}

// Logger returns the logger used by the anp_auth package.
func Logger() *slog.Logger {
	return logger
}
