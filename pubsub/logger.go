package pubsub

import (
	"sync"
)

// LogMessage struct represents a single log entry.
type LogMessage struct {
	Msg string // The actual log message.
}

// Logger provides functionality for logging and subscribing to logs.
type Logger struct {
	logChannel chan LogMessage // Channel used to communicate log messages.
	mu         sync.Mutex      // Mutex used to ensure thread-safety when writing logs.
}

// NewLogger initializes and returns a new instance of Logger.
func NewLogger() *Logger {
	return &Logger{
		logChannel: make(chan LogMessage, 100), // Initialize a buffered channel for log messages.
	}
}

// publish sends a log message to the log channel.
// It ensures that log writes are thread-safe using a mutex.
func (l *Logger) Publish(msg string) {
	l.mu.Lock()                 // Acquire the mutex lock to ensure exclusive access.
	defer l.mu.Unlock()         // Release the mutex once done. Using 'defer' guarantees the mutex is released even if there's a panic.
	l.logChannel <- LogMessage{ // Send the log message to the channel.
		Msg: msg,
	}
}

// Subscribe provides a read-only channel to receive log messages.
// This allows external components to "listen" for new logs.
func (l *Logger) Subscribe() <-chan LogMessage {
	return l.logChannel // Return the channel for external components to read from.
}
