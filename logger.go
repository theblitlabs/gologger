package gologger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/rs/zerolog"
)

var (
	log zerolog.Logger
	mu  sync.RWMutex
)

type LogLevel string

const (
	LogLevelDebug    LogLevel = "debug"
	LogLevelInfo     LogLevel = "info"
	LogLevelWarn     LogLevel = "warn"
	LogLevelError    LogLevel = "error"
	LogLevelFatal    LogLevel = "fatal"
	LogLevelDisabled LogLevel = "disabled"
)

type LogMode string

const (
	LogModeDebug  LogMode = "debug"
	LogModePretty LogMode = "pretty"
	LogModeInfo   LogMode = "info"
	LogModeProd   LogMode = "prod"
	LogModeTest   LogMode = "test"
	LogModeJSON   LogMode = "json"
)

type OutputConfig struct {
	File       string
	MaxSize    int64
	MaxAge     time.Duration
	MaxBackups int
	Compress   bool
	SplitLevel bool
}

type Config struct {
	Level         LogLevel
	Pretty        bool
	TimeFormat    string
	CallerEnabled bool
	NoColor       bool
	Output        *OutputConfig
	Fields        map[string]interface{}
}

func DefaultConfig() Config {
	return Config{
		Level:         LogLevelInfo,
		Pretty:        false,
		TimeFormat:    time.RFC3339,
		CallerEnabled: true,
		NoColor:       false,
		Fields:        make(map[string]interface{}),
	}
}

func ConfigForMode(mode LogMode) Config {
	switch mode {
	case LogModeDebug:
		return Config{
			Level:         LogLevelDebug,
			Pretty:        true,
			TimeFormat:    time.RFC3339,
			CallerEnabled: true,
			NoColor:       false,
		}
	case LogModePretty:
		return Config{
			Level:         LogLevelInfo,
			Pretty:        true,
			TimeFormat:    time.RFC3339,
			CallerEnabled: true,
			NoColor:       false,
		}
	case LogModeInfo:
		return Config{
			Level:         LogLevelInfo,
			Pretty:        false,
			TimeFormat:    time.RFC3339,
			CallerEnabled: true,
			NoColor:       false,
		}
	case LogModeProd:
		return Config{
			Level:         LogLevelInfo,
			Pretty:        false,
			TimeFormat:    time.RFC3339Nano,
			CallerEnabled: false,
			NoColor:       true,
		}
	case LogModeTest:
		return Config{
			Level:         LogLevelError,
			Pretty:        false,
			TimeFormat:    time.RFC3339,
			CallerEnabled: false,
			NoColor:       true,
		}
	case LogModeJSON:
		return Config{
			Level:         LogLevelInfo,
			Pretty:        false,
			TimeFormat:    time.RFC3339,
			CallerEnabled: false,
			NoColor:       true,
		}
	default:
		return DefaultConfig()
	}
}

func InitWithMode(mode LogMode) {
	Init(ConfigForMode(mode))
}

func Init(cfg Config) {
	mu.Lock()
	defer mu.Unlock()

	if cfg.Level == LogLevelDisabled {
		zerolog.SetGlobalLevel(zerolog.Disabled)
		log = zerolog.New(io.Discard).With().Logger()
		zerolog.DefaultContextLogger = &log
		return
	}

	var output io.Writer = os.Stdout

	if cfg.Output != nil && cfg.Output.File != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Output.File), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create log directory: %v\n", err)
			return
		}

		file, err := os.OpenFile(cfg.Output.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			return
		}

		if cfg.Output.MaxSize > 0 {
			output = newRotateWriter(file, cfg.Output)
		} else {
			output = file
		}
	}

	if cfg.Output != nil && cfg.Output.SplitLevel {
		output = newLevelWriter(output, cfg.Output)
	}

	if cfg.Pretty {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: cfg.TimeFormat,
			NoColor:    cfg.NoColor,
			FormatLevel: func(i interface{}) string {
				return colorizeLevel(i.(string))
			},
			FormatFieldName: func(i interface{}) string {
				name := fmt.Sprint(i)
				if name == "component" || name == "trace_id" {
					return ""
				}
				return colorize(fmt.Sprintf("%s=", name), dim+cyan)
			},
			FormatFieldValue: func(i interface{}) string {
				switch v := i.(type) {
				case string:
					if v == "" {
						return ""
					}
					return colorize(v, blue)
				case json.Number:
					return colorize(v.String(), magenta)
				case error:
					return colorize(v.Error(), red)
				case nil:
					return ""
				default:
					s := fmt.Sprint(v)
					if s == "" {
						return ""
					}
					return colorize(s, blue)
				}
			},
			FormatMessage: func(i interface{}) string {
				msg := fmt.Sprint(i)
				msg = strings.Replace(msg, "Request started", colorize("→", bold+green), 1)
				msg = strings.Replace(msg, "Request completed", colorize("←", bold+green), 1)
				return colorize(msg, bold)
			},
			FormatTimestamp: func(i interface{}) string {
				t := fmt.Sprint(i)
				return colorize(t, dim+gray)
			},
			PartsOrder: []string{
				zerolog.TimestampFieldName,
				zerolog.LevelFieldName,
				zerolog.CallerFieldName,
				zerolog.MessageFieldName,
				"device_id",
			},
			PartsExclude: []string{
				"query",
				"referer",
				"user_agent",
				"remote_addr",
				"duration_human",
				"component",
				"trace_id",
			},
		}
		output = consoleWriter
	}

	switch cfg.Level {
	case LogLevelDebug:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case LogLevelInfo:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case LogLevelWarn:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case LogLevelError:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case LogLevelFatal:
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	zerolog.TimeFieldFormat = cfg.TimeFormat

	logCtx := zerolog.New(output).With().Timestamp()
	if cfg.CallerEnabled {
		logCtx = logCtx.Caller()
	}

	if len(cfg.Fields) > 0 {
		logCtx = logCtx.Fields(cfg.Fields)
	}

	log = logCtx.Logger()
	zerolog.DefaultContextLogger = &log
}

const (
	gray    = "\x1b[37m"
	blue    = "\x1b[34m"
	cyan    = "\x1b[36m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	magenta = "\x1b[35m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	reset   = "\x1b[0m"
)

func colorize(s, color string) string {
	return color + s + reset
}

func colorizeLevel(level string) string {
	switch level {
	case "debug":
		return colorize("DBG", dim+magenta)
	case "info":
		return colorize("INF", bold+green)
	case "warn":
		return colorize("WRN", bold+yellow)
	case "error":
		return colorize("ERR", bold+red)
	case "fatal":
		return colorize("FTL", bold+red+"\x1b[7m")
	default:
		return colorize(level, blue)
	}
}

func Get() zerolog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return log
}

func WithComponent(component string) zerolog.Logger {
	return Get().With().Str("component", component).Logger()
}

func WithTraceID(traceID string) zerolog.Logger {
	return Get().With().Str("trace_id", traceID).Logger()
}

func Error(component string, err error, msg string, fields ...map[string]interface{}) {
	logger := WithComponent(component)
	if len(fields) > 0 {
		logger = logger.With().Fields(fields[0]).Logger()
	}
	logger.Error().Err(err).Msg(msg)
}

func Info(component string, msg string, fields ...map[string]interface{}) {
	logger := WithComponent(component)
	if len(fields) > 0 {
		logger = logger.With().Fields(fields[0]).Logger()
	}
	logger.Info().Msg(msg)
}

func Debug(component string, msg string, fields ...map[string]interface{}) {
	logger := WithComponent(component)
	if len(fields) > 0 {
		logger = logger.With().Fields(fields[0]).Logger()
	}
	logger.Debug().Msg(msg)
}

func Warn(component string, msg string, fields ...map[string]interface{}) {
	logger := WithComponent(component)
	if len(fields) > 0 {
		logger = logger.With().Fields(fields[0]).Logger()
	}
	logger.Warn().Msg(msg)
}

func Fatal(component string, err error, msg string, fields ...map[string]interface{}) {
	logger := WithComponent(component)
	if len(fields) > 0 {
		logger = logger.With().Fields(fields[0]).Logger()
	}
	logger.Fatal().Err(err).Msg(msg)
}

func WithFields(fields map[string]interface{}) zerolog.Logger {
	return Get().With().Fields(fields).Logger()
}

func WithField(key string, value interface{}) zerolog.Logger {
	return Get().With().Interface(key, value).Logger()
}

type rotateWriter struct {
	file   *os.File
	config *OutputConfig
}

func newRotateWriter(file *os.File, config *OutputConfig) *rotateWriter {
	return &rotateWriter{
		file:   file,
		config: config,
	}
}

func (w *rotateWriter) Write(p []byte) (n int, err error) {
	if w.config.MaxSize > 0 {
		if info, err := w.file.Stat(); err == nil {
			if info.Size() >= w.config.MaxSize*1024*1024 {
				w.rotate()
			}
		}
	}
	return w.file.Write(p)
}

func (w *rotateWriter) rotate() {
	if w.file != nil {
		w.file.Close()

		timestamp := time.Now().Format("2006-01-02-15-04-05")
		newPath := fmt.Sprintf("%s.%s", w.config.File, timestamp)
		os.Rename(w.config.File, newPath)

		if w.config.Compress {
			go compressLogFile(newPath)
		}

		if w.config.MaxAge > 0 || w.config.MaxBackups > 0 {
			go cleanupOldLogs(w.config)
		}

		file, err := os.OpenFile(w.config.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			w.file = file
		}
	}
}

type levelWriter struct {
	writers map[LogLevel]io.Writer
	base    io.Writer
}

func newLevelWriter(base io.Writer, config *OutputConfig) *levelWriter {
	lw := &levelWriter{
		writers: make(map[LogLevel]io.Writer),
		base:    base,
	}

	basePath := config.File
	ext := filepath.Ext(basePath)
	prefix := basePath[:len(basePath)-len(ext)]

	levels := []LogLevel{LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError, LogLevelFatal}
	for _, level := range levels {
		path := fmt.Sprintf("%s.%s%s", prefix, level, ext)
		if file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			lw.writers[level] = file
		}
	}

	return lw
}

func (w *levelWriter) Write(p []byte) (n int, err error) {
	n, err = w.base.Write(p)
	if err != nil {
		return n, err
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(p, &entry); err == nil {
		if level, ok := entry["level"].(string); ok {
			if writer, exists := w.writers[LogLevel(level)]; exists {
				if _, err := writer.Write(p); err != nil {
					return n, err
				}
			}
		}
	}

	return n, nil
}

func compressLogFile(filepath string) {
	input, err := os.Open(filepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file for compression: %v\n", err)
		return
	}
	defer input.Close()

	gzipPath := filepath + ".gz"
	output, err := os.Create(gzipPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create gzip file: %v\n", err)
		return
	}
	defer output.Close()

	gw := gzip.NewWriter(output)
	defer gw.Close()

	if _, err := io.Copy(gw, input); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to compress log file: %v\n", err)
		return
	}

	os.Remove(filepath)
}

func cleanupOldLogs(config *OutputConfig) {
	dir := filepath.Dir(config.File)
	pattern := filepath.Base(config.File) + ".*"

	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list old log files: %v\n", err)
		return
	}

	type logFile struct {
		path    string
		modTime time.Time
	}

	var files []logFile
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}
		files = append(files, logFile{path: match, modTime: info.ModTime()})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})

	if config.MaxBackups > 0 && len(files) > config.MaxBackups {
		for _, f := range files[config.MaxBackups:] {
			os.Remove(f.path)
		}
	}

	if config.MaxAge > 0 {
		cutoff := time.Now().Add(-config.MaxAge)
		for _, f := range files {
			if f.modTime.Before(cutoff) {
				os.Remove(f.path)
			}
		}
	}
}

func InitWithFile(filepath string) error {
	config := DefaultConfig()
	config.Output = &OutputConfig{
		File:       filepath,
		MaxSize:    100,
		MaxAge:     7 * 24 * time.Hour,
		MaxBackups: 5,
		Compress:   true,
	}
	Init(config)
	return nil
}
