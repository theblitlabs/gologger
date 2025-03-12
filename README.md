# GoLogger

A flexible, feature-rich logging package for Go applications built on top of [zerolog](https://github.com/rs/zerolog). This logger provides structured logging with multiple output formats, log levels, and convenient helper functions.

## Features

- Multiple logging modes (Debug, Pretty, Info, Production, Test, JSON)
- Structured logging with JSON output
- Pretty printing with colors for development
- Configurable log levels (Debug, Info, Warn, Error, Fatal, Disabled)
- Component-based logging
- Trace ID support for request tracking
- Thread-safe operations
- Customizable time formats
- Caller information (optional)
- Color output (can be disabled)
- **Log rotation with compression**
- **File-based logging with size limits**
- **Level-based log splitting**
- **Global fields support**
- **Automatic old log cleanup**

## Installation

```bash
go get github.com/art3mis/gologger
```

## Quick Start

### Console Logging

```go
package main

import (
    "github.com/art3mis/gologger"
)

func main() {
    // Initialize with pretty printing for development
    gologger.InitWithMode(gologger.LogModePretty)

    // Log some messages
    gologger.Info("main", "Application started")

    // Log with additional fields
    gologger.Info("main", "User logged in", map[string]interface{}{
        "user_id": "123",
        "ip": "192.168.1.1",
    })

    // Log an error
    err := someOperation()
    if err != nil {
        gologger.Error("main", err, "Operation failed")
    }
}
```

### File-Based Logging

```go
package main

import (
    "github.com/art3mis/gologger"
)

func main() {
    // Initialize logging to a file with default settings:
    // - 100MB max file size
    // - 7 days retention
    // - 5 backup files
    // - Compression enabled
    err := gologger.InitWithFile("/var/log/myapp/app.log")
    if err != nil {
        panic(err)
    }

    // Log as usual
    gologger.Info("main", "Application started")
}
```

## Advanced Configuration

### File Output with Rotation

```go
config := gologger.Config{
    Level:         gologger.LogLevelInfo,
    Pretty:        false,
    TimeFormat:    time.RFC3339,
    CallerEnabled: true,
    Output: &gologger.OutputConfig{
        File:       "/var/log/myapp/app.log",
        MaxSize:    100,    // 100MB
        MaxAge:     7 * 24 * time.Hour,  // 7 days
        MaxBackups: 5,      // Keep 5 old files
        Compress:   true,   // Compress old files
        SplitLevel: true,   // Split logs by level
    },
    Fields: map[string]interface{}{
        "app_name": "myapp",
        "version":  "1.0.0",
    },
}
gologger.Init(config)
```

### Level-Based Logging

When `SplitLevel` is enabled, logs will be written to separate files based on their level:

- `/var/log/myapp/app.log` (all logs)
- `/var/log/myapp/app.error.log` (error and fatal only)
- `/var/log/myapp/app.info.log` (info and above)
- `/var/log/myapp/app.debug.log` (debug and above)

### Global Fields

Add fields to all log entries:

```go
config := gologger.Config{
    // ... other config ...
    Fields: map[string]interface{}{
        "environment": "production",
        "service":     "auth-api",
    },
}
```

### Component-Based Logging

```go
logger := gologger.WithComponent("auth")
logger.Info().Str("user", "john").Msg("User authenticated")
```

### Field Management

```go
// Add multiple fields
logger := gologger.WithFields(map[string]interface{}{
    "request_id": "123",
    "user_id":    "456",
})

// Add a single field
logger := gologger.WithField("transaction_id", "789")
```

### Fatal Logging

```go
if err := criticalOperation(); err != nil {
    gologger.Fatal("main", err, "Critical error occurred", map[string]interface{}{
        "operation": "system_init",
    })
    // Program will exit after this
}
```

## Configuration

You can customize the logger using the `Config` struct:

```go
config := gologger.Config{
    Level:         gologger.LogLevelDebug,
    Pretty:        true,
    TimeFormat:    time.RFC3339,
    CallerEnabled: true,
    NoColor:      false,
}
gologger.Init(config)
```

## Predefined Modes

- `LogModeDebug`: Debug level with pretty printing
- `LogModePretty`: Info level with pretty printing
- `LogModeInfo`: Standard info level logging
- `LogModeProd`: Production mode (no colors, nano timestamps)
- `LogModeTest`: Test mode (error level only)

## Component-Based Logging

```go
logger := gologger.WithComponent("auth")
logger.Info().Str("user", "john").Msg("User authenticated")
```

## Trace ID Support

```go
logger := gologger.WithTraceID("request-123")
logger.Info().Msg("Processing request")
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
