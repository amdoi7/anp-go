# Logger Integration Guide

## Overview

anp-go v2.0 uses **dependency injection** for logging. Instead of relying on global state, each `Authenticator` instance can have its own logger.

## Logger Interface

Implement this simple interface to integrate your favorite logger:

```go
type Logger interface {
    Debug(msg string, keysAndValues ...interface{})
    Info(msg string, keysAndValues ...interface{})
    Warn(msg string, keysAndValues ...interface{})
    Error(msg string, keysAndValues ...interface{})
}
```

## Default Behavior

By default, if no logger is provided, a **no-op logger** is used (no output):

```go
auth, _ := anp_auth.NewAuthenticator(
    anp_auth.WithDIDCfgPaths("did.json", "key.pem"),
)
// No logging output
```

## Using slog (Go 1.21+)

### Simple Adapter

```go
package main

import (
    "log/slog"
    "os"
    "github.com/openanp/anp-go/anp_auth"
)

// SlogAdapter wraps slog.Logger to implement anp_auth.Logger
type SlogAdapter struct {
    logger *slog.Logger
}

func (s *SlogAdapter) Debug(msg string, keysAndValues ...interface{}) {
    s.logger.Debug(msg, keysAndValues...)
}

func (s *SlogAdapter) Info(msg string, keysAndValues ...interface{}) {
    s.logger.Info(msg, keysAndValues...)
}

func (s *SlogAdapter) Warn(msg string, keysAndValues ...interface{}) {
    s.logger.Warn(msg, keysAndValues...)
}

func (s *SlogAdapter) Error(msg string, keysAndValues ...interface{}) {
    s.logger.Error(msg, keysAndValues...)
}

func main() {
    // Create slog logger
    logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelDebug,
    }))

    // Inject into authenticator
    auth, err := anp_auth.NewAuthenticator(
        anp_auth.WithDIDCfgPaths("did.json", "key.pem"),
        anp_auth.WithLogger(&SlogAdapter{logger: logger}),
    )
    
    // Now auth will use your logger
}
```

## Using Zap (uber-go/zap)

```go
package main

import (
    "go.uber.org/zap"
    "github.com/openanp/anp-go/anp_auth"
)

// ZapAdapter wraps zap.SugaredLogger to implement anp_auth.Logger
type ZapAdapter struct {
    logger *zap.SugaredLogger
}

func (z *ZapAdapter) Debug(msg string, keysAndValues ...interface{}) {
    z.logger.Debugw(msg, keysAndValues...)
}

func (z *ZapAdapter) Info(msg string, keysAndValues ...interface{}) {
    z.logger.Infow(msg, keysAndValues...)
}

func (z *ZapAdapter) Warn(msg string, keysAndValues ...interface{}) {
    z.logger.Warnw(msg, keysAndValues...)
}

func (z *ZapAdapter) Error(msg string, keysAndValues ...interface{}) {
    z.logger.Errorw(msg, keysAndValues...)
}

func main() {
    // Create zap logger
    logger, _ := zap.NewProduction()
    defer logger.Sync()
    sugar := logger.Sugar()

    // Inject into authenticator
    auth, _ := anp_auth.NewAuthenticator(
        anp_auth.WithDIDCfgPaths("did.json", "key.pem"),
        anp_auth.WithLogger(&ZapAdapter{logger: sugar}),
    )
}
```

## Using Logrus

```go
package main

import (
    "github.com/sirupsen/logrus"
    "github.com/openanp/anp-go/anp_auth"
)

// LogrusAdapter wraps logrus.Logger to implement anp_auth.Logger
type LogrusAdapter struct {
    logger *logrus.Logger
}

func (l *LogrusAdapter) Debug(msg string, keysAndValues ...interface{}) {
    l.logger.WithFields(toFields(keysAndValues)).Debug(msg)
}

func (l *LogrusAdapter) Info(msg string, keysAndValues ...interface{}) {
    l.logger.WithFields(toFields(keysAndValues)).Info(msg)
}

func (l *LogrusAdapter) Warn(msg string, keysAndValues ...interface{}) {
    l.logger.WithFields(toFields(keysAndValues)).Warn(msg)
}

func (l *LogrusAdapter) Error(msg string, keysAndValues ...interface{}) {
    l.logger.WithFields(toFields(keysAndValues)).Error(msg)
}

func toFields(keysAndValues []interface{}) logrus.Fields {
    fields := logrus.Fields{}
    for i := 0; i < len(keysAndValues); i += 2 {
        if i+1 < len(keysAndValues) {
            key := keysAndValues[i].(string)
            fields[key] = keysAndValues[i+1]
        }
    }
    return fields
}

func main() {
    logger := logrus.New()
    logger.SetFormatter(&logrus.JSONFormatter{})
    logger.SetLevel(logrus.DebugLevel)

    auth, _ := anp_auth.NewAuthenticator(
        anp_auth.WithDIDCfgPaths("did.json", "key.pem"),
        anp_auth.WithLogger(&LogrusAdapter{logger: logger}),
    )
}
```

## Multi-Tenant Example

Each authenticator can have its own logger with context:

```go
// Tenant A
loggerA := slog.Default().With("tenant", "A")
authA, _ := anp_auth.NewAuthenticator(
    anp_auth.WithDIDMaterial(docA, keyA),
    anp_auth.WithLogger(&SlogAdapter{logger: loggerA}),
)

// Tenant B
loggerB := slog.Default().With("tenant", "B")
authB, _ := anp_auth.NewAuthenticator(
    anp_auth.WithDIDMaterial(docB, keyB),
    anp_auth.WithLogger(&SlogAdapter{logger: loggerB}),
)

// Each authenticator logs with its tenant context
```

## Testing with Mock Logger

```go
type MockLogger struct {
    DebugCalls []string
    InfoCalls  []string
    WarnCalls  []string
    ErrorCalls []string
}

func (m *MockLogger) Debug(msg string, keysAndValues ...interface{}) {
    m.DebugCalls = append(m.DebugCalls, msg)
}

func (m *MockLogger) Info(msg string, keysAndValues ...interface{}) {
    m.InfoCalls = append(m.InfoCalls, msg)
}

func (m *MockLogger) Warn(msg string, keysAndValues ...interface{}) {
    m.WarnCalls = append(m.WarnCalls, msg)
}

func (m *MockLogger) Error(msg string, keysAndValues ...interface{}) {
    m.ErrorCalls = append(m.ErrorCalls, msg)
}

func TestWithMockLogger(t *testing.T) {
    mockLogger := &MockLogger{}
    
    auth, _ := anp_auth.NewAuthenticator(
        anp_auth.WithDIDMaterial(testDoc, testKey),
        anp_auth.WithLogger(mockLogger),
    )
    
    // Use authenticator...
    
    // Verify logging behavior
    if len(mockLogger.DebugCalls) != 1 {
        t.Errorf("Expected 1 debug call, got %d", len(mockLogger.DebugCalls))
    }
}
```

## What Gets Logged

The authenticator logs the following events:

- **Debug**: Cache hits (JWT tokens and DID-WBA headers)
- **Warn**: Invalid domains, token clearing issues
- **Error**: (Currently unused, reserved for future critical errors)

Example debug output:

```
DEBUG using cached JWT domain=example.com
DEBUG using cached DIDWba header domain=api.example.com
WARN update token: invalid domain url=invalid://url error=...
```

## Migration from v1

### Old Way (Global Logger)

```go
// v1: Global logger affects all instances
anp_auth.SetLogger(slog.Default())

auth1 := anp_auth.NewAuthenticator(config1)
auth2 := anp_auth.NewAuthenticator(config2)
// Both use the same global logger
```

### New Way (Dependency Injection)

```go
// v2: Each instance has its own logger
auth1, _ := anp_auth.NewAuthenticator(
    anp_auth.WithDIDCfgPaths(...),
    anp_auth.WithLogger(logger1),
)

auth2, _ := anp_auth.NewAuthenticator(
    anp_auth.WithDIDCfgPaths(...),
    anp_auth.WithLogger(logger2),
)
// Complete isolation
```

## Best Practices

1. **Use structured logging**: The interface is designed for key-value pairs
2. **Inject per-instance**: Different authenticators can have different loggers
3. **Add context**: Use logger.With() to add tenant/service context
4. **Test with mocks**: Easy to verify logging behavior in tests
5. **Silent by default**: No logger = no output, perfect for libraries

## Benefits of Logger DI

✅ **No global state** - Better testability and isolation
✅ **Multi-tenant friendly** - Each tenant can have separate logging
✅ **Flexible** - Use any logger that implements the interface
✅ **Testable** - Easy to mock and verify logging
✅ **Optional** - No logger required for simple use cases
