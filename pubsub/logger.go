// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

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
	logChannel chan *string // Channel used to communicate log messages.
	mu         sync.Mutex   // Mutex used to ensure thread-safety when writing logs.
}

// NewLogger initializes and returns a new instance of Logger.
func NewLogger() *Logger {
	return &Logger{
		logChannel: make(chan *string, 100), // Initialize a buffered channel for log messages.
	}
}

// Publish sends a log message to the log channel.
// It ensures that log writes are thread-safe using a mutex.
func (l *Logger) Publish(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logChannel <- &msg
}

// Write allows the Logger to be used as a Writer and in structured logging.
func (l *Logger) Write(p []byte) (n int, err error) {
	go func() {
		l.Publish(string(p))
	}()
	return len(p), nil
}

// Subscribe provides a read-only channel to receive log messages.
// This allows external components to "listen" for new logs.
func (l *Logger) Subscribe() <-chan *string {
	return l.logChannel // Return the channel for external components to read from.
}
