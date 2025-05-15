package log

import (
	"bytes"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestInit(t *testing.T) {
	// Test each log level
	levels := []string{"trace", "debug", "info", "warn", "error"}
	expectedLevels := []logrus.Level{
		logrus.TraceLevel,
		logrus.DebugLevel,
		logrus.InfoLevel,
		logrus.WarnLevel,
		logrus.ErrorLevel,
	}

	for i, level := range levels {
		// Initialize logger with test level
		Init(level)
		
		// Check if the correct level was set
		if Logger.GetLevel() != expectedLevels[i] {
			t.Errorf("Expected log level %s, got %s", expectedLevels[i], Logger.GetLevel())
		}
	}

	// Test invalid log level
	// Should default to "info"
	Init("invalid")
	if Logger.GetLevel() != logrus.InfoLevel {
		t.Errorf("Expected log level %s for invalid input, got %s", logrus.InfoLevel, Logger.GetLevel())
	}
}

func TestLogFunctions(t *testing.T) {
	// Set up a buffer to capture log output
	var buf bytes.Buffer
	originalOutput := Logger.Out
	Logger.SetOutput(&buf)
	defer Logger.SetOutput(originalOutput)
	
	// Set log level to trace to ensure all logs are captured
	Logger.SetLevel(logrus.TraceLevel)
	
	// Test each log function with a simple message
	Debug("debug message")
	Debugf("debug %s", "formatted")
	
	Info("info message")
	Infof("info %s", "formatted")
	
	Warn("warn message")
	Warnf("warn %s", "formatted")
	
	// Check that log contains expected output (simplified check)
	output := buf.String()
	
	if len(output) == 0 {
		t.Error("Expected log output, got empty string")
	}
	
	expectedMessages := []string{
		"debug message",
		"debug formatted",
		"info message", 
		"info formatted",
		"warn message",
		"warn formatted",
	}
	
	for _, msg := range expectedMessages {
		if !bytes.Contains(buf.Bytes(), []byte(msg)) {
			t.Errorf("Log output does not contain expected message: %s", msg)
		}
	}
	
	// Skip testing Error/Fatal/Panic as they may have unwanted side effects in tests
}