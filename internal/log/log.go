package log

import (
	"os"

	"github.com/sirupsen/logrus"
)

// Logger is the global logger instance
var Logger = logrus.New()

// Init initializes the logger with the given configuration
func Init(level string) {
	// Set log level
	switch level {
	case "trace":
		Logger.SetLevel(logrus.TraceLevel)
	case "debug":
		Logger.SetLevel(logrus.DebugLevel)
	case "info":
		Logger.SetLevel(logrus.InfoLevel)
	case "warn":
		Logger.SetLevel(logrus.WarnLevel)
	case "error":
		Logger.SetLevel(logrus.ErrorLevel)
	default:
		Logger.SetLevel(logrus.InfoLevel)
	}

	// Set output format - JSON in production, text in development
	if os.Getenv("ENV") == "production" {
		Logger.SetFormatter(&logrus.JSONFormatter{})
	} else {
		Logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	// Output to stderr
	Logger.SetOutput(os.Stderr)
}

// WithFields wraps logrus WithFields
func WithFields(fields logrus.Fields) *logrus.Entry {
	return Logger.WithFields(fields)
}

// WithField wraps logrus WithField
func WithField(key string, value interface{}) *logrus.Entry {
	return Logger.WithField(key, value)
}

// Trace logs a message at level Trace
func Trace(args ...interface{}) {
	Logger.Trace(args...)
}

// Debug logs a message at level Debug
func Debug(args ...interface{}) {
	Logger.Debug(args...)
}

// Info logs a message at level Info
func Info(args ...interface{}) {
	Logger.Info(args...)
}

// Warn logs a message at level Warn
func Warn(args ...interface{}) {
	Logger.Warn(args...)
}

// Error logs a message at level Error
func Error(args ...interface{}) {
	Logger.Error(args...)
}

// Fatal logs a message at level Fatal then the process will exit with status set to 1
func Fatal(args ...interface{}) {
	Logger.Fatal(args...)
}

// Tracef logs a formatted message at level Trace
func Tracef(format string, args ...interface{}) {
	Logger.Tracef(format, args...)
}

// Debugf logs a formatted message at level Debug
func Debugf(format string, args ...interface{}) {
	Logger.Debugf(format, args...)
}

// Infof logs a formatted message at level Info
func Infof(format string, args ...interface{}) {
	Logger.Infof(format, args...)
}

// Warnf logs a formatted message at level Warn
func Warnf(format string, args ...interface{}) {
	Logger.Warnf(format, args...)
}

// Errorf logs a formatted message at level Error
func Errorf(format string, args ...interface{}) {
	Logger.Errorf(format, args...)
}

// Fatalf logs a formatted message at level Fatal then the process will exit with status set to 1
func Fatalf(format string, args ...interface{}) {
	Logger.Fatalf(format, args...)
}