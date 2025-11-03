package anp_auth

// Logger is an interface for structured logging.
// This allows users to inject their own logger implementation.
type Logger interface {
	Debug(msg string, keysAndValues ...interface{})
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
}

// NoOpLogger is a logger that does nothing.
// Used as the default logger if none is provided.
type NoOpLogger struct{}

func (NoOpLogger) Debug(msg string, keysAndValues ...interface{}) {}
func (NoOpLogger) Info(msg string, keysAndValues ...interface{})  {}
func (NoOpLogger) Warn(msg string, keysAndValues ...interface{})  {}
func (NoOpLogger) Error(msg string, keysAndValues ...interface{}) {}

// defaultLogger is used when no logger is injected
var defaultLogger Logger = NoOpLogger{}
