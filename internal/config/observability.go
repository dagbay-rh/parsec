package config

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog"

	"github.com/project-kessel/parsec/internal/observer"
	"github.com/project-kessel/parsec/internal/probe/zlog"
)

// LoggerContext couples a zerolog logger with its destination writer so
// per-event formatting overrides can preserve the original sink.
type LoggerContext struct {
	Logger zerolog.Logger
	Writer io.Writer
}

// NewLogger creates a structured zerolog logger from the observability configuration.
func NewLogger(cfg *ObservabilityConfig) (zerolog.Logger, error) {
	logCtx, err := NewLoggerContext(cfg)
	if err != nil {
		return zerolog.Logger{}, err
	}
	return logCtx.Logger, nil
}

func newLoggingObserver(cfg *ObservabilityConfig, logCtx LoggerContext) (observer.Observer, error) {
	el := func(name string, ecfg *EventLoggingConfig) (zerolog.Logger, error) {
		return EventLogger(logCtx, name, ecfg)
	}

	tiLog, err := el("token_issuance", cfg.TokenIssuance)
	if err != nil {
		return nil, err
	}
	teLog, err := el("token_exchange", cfg.TokenExchange)
	if err != nil {
		return nil, err
	}
	acLog, err := el("authz_check", cfg.AuthzCheck)
	if err != nil {
		return nil, err
	}
	dcLog, err := el("datasource_cache", cfg.DataSourceCache)
	if err != nil {
		return nil, err
	}
	luaLog, err := el("lua_datasource", cfg.LuaDataSource)
	if err != nil {
		return nil, err
	}
	krLog, err := el("key_rotation", cfg.KeyRotation)
	if err != nil {
		return nil, err
	}
	kpLog, err := el("key_provider", cfg.KeyProvider)
	if err != nil {
		return nil, err
	}
	tvLog, err := el("trust_validation", cfg.TrustValidation)
	if err != nil {
		return nil, err
	}
	jcLog, err := el("jwks_cache", cfg.JWKSCache)
	if err != nil {
		return nil, err
	}
	slLog, err := el("server_lifecycle", cfg.ServerLifecycle)
	if err != nil {
		return nil, err
	}

	app := zlog.NewLoggingObserverWithConfig(zlog.LoggingObserverConfig{
		TokenIssuanceLogger: tiLog,
		TokenExchangeLogger: teLog,
		AuthzCheckLogger:    acLog,
	})

	return observer.Compose(
		app,
		zlog.NewLoggingDataSourceObserver(dcLog, luaLog),
		zlog.NewLoggingKeysObserver(krLog, kpLog),
		zlog.NewLoggingTrustObserver(tvLog),
		zlog.NewLoggingServerObserver(jcLog, slLog),
	), nil
}

// NewLoggerContext creates a structured zerolog logger and the writer used as
// its sink. Writer holds the raw destination (e.g. os.Stdout), never a
// format wrapper, so EventLogger can re-wrap it with a different format.
func NewLoggerContext(cfg *ObservabilityConfig) (LoggerContext, error) {
	if cfg == nil {
		return LoggerContext{
			Logger: zerolog.New(os.Stdout).With().Timestamp().Logger(),
			Writer: os.Stdout,
		}, nil
	}

	rawSink := os.Stdout
	defaultLevel, err := parseLogLevel(cfg.LogLevel)
	if err != nil {
		return LoggerContext{}, err
	}
	writer, err := createWriter(cfg.LogFormat, rawSink)
	if err != nil {
		return LoggerContext{}, err
	}
	return LoggerContext{
		Logger: zerolog.New(writer).With().Timestamp().Logger().Level(defaultLevel),
		Writer: rawSink,
	}, nil
}

// deriveLoggerContext builds a child LoggerContext that shares the parent's
// raw sink but applies the child config's LogLevel and/or LogFormat overrides.
// If the child specifies neither, the parent context is returned as-is.
func deriveLoggerContext(parent LoggerContext, cfg *ObservabilityConfig) (LoggerContext, error) {
	if cfg == nil || (cfg.LogLevel == "" && cfg.LogFormat == "") {
		return parent, nil
	}

	logger := parent.Logger

	if cfg.LogFormat != "" {
		w, err := createWriter(cfg.LogFormat, parent.Writer)
		if err != nil {
			return LoggerContext{}, err
		}
		logger = logger.Output(w)
	}
	if cfg.LogLevel != "" {
		lvl, err := parseLogLevel(cfg.LogLevel)
		if err != nil {
			return LoggerContext{}, err
		}
		logger = logger.Level(lvl)
	}

	return LoggerContext{
		Logger: logger,
		Writer: parent.Writer,
	}, nil
}

// EventLogger creates a pre-configured sub-logger for a specific event type.
// The returned logger has the "event" field baked in.
//
// Override precedence (applied in order):
//  1. LogFormat -- output format is always applied first
//  2. Enabled=false -- disables the event entirely (zerolog.Disabled), overrides LogLevel
//  3. LogLevel -- sets the minimum severity threshold
//
// If eventCfg is nil the logger inherits all base settings unchanged.
func EventLogger(logCtx LoggerContext, eventName string, eventCfg *EventLoggingConfig) (zerolog.Logger, error) {
	logger := logCtx.Logger.With().Str("event", eventName).Logger()
	if eventCfg == nil {
		return logger, nil
	}
	if eventCfg.LogFormat != "" {
		w, err := createWriter(eventCfg.LogFormat, logCtx.Writer)
		if err != nil {
			return zerolog.Logger{}, fmt.Errorf("%s: %w", eventName, err)
		}
		logger = logger.Output(w)
	}
	if eventCfg.Enabled != nil && !*eventCfg.Enabled {
		return logger.Level(zerolog.Disabled), nil
	}
	if eventCfg.LogLevel != "" {
		lvl, err := parseLogLevel(eventCfg.LogLevel)
		if err != nil {
			return zerolog.Logger{}, fmt.Errorf("%s: %w", eventName, err)
		}
		return logger.Level(lvl), nil
	}
	return logger, nil
}

func createWriter(format string, fallback io.Writer) (io.Writer, error) {
	if fallback == nil {
		fallback = os.Stdout
	}
	switch strings.ToLower(format) {
	case "text":
		return zerolog.ConsoleWriter{Out: fallback}, nil
	case "json", "":
		return fallback, nil
	default:
		return nil, fmt.Errorf("invalid log_format %q (valid: json, text)", format)
	}
}

func parseLogLevel(levelStr string) (zerolog.Level, error) {
	switch strings.ToLower(levelStr) {
	case "debug":
		return zerolog.DebugLevel, nil
	case "info", "":
		return zerolog.InfoLevel, nil
	case "warn", "warning":
		return zerolog.WarnLevel, nil
	case "error":
		return zerolog.ErrorLevel, nil
	default:
		return 0, fmt.Errorf("invalid log_level %q (valid: debug, info, warn, error)", levelStr)
	}
}
