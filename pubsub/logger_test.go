package pubsub_test

import (
	"testing"
	"time"

	"github.com/owasp-amass/engine/pubsub"
	"github.com/owasp-amass/engine/sessions"
)

func TestSessionSpecificLogs(t *testing.T) {
	// Create a new session storage
	manager := sessions.NewStorage()

	// Create two sessions
	session1 := &sessions.Session{
		PubSub: pubsub.NewLogger(),
	}
	session1ID := manager.Add(session1)

	session2 := &sessions.Session{
		PubSub: pubsub.NewLogger(),
	}
	session2ID := manager.Add(session2)

	// Subscribe to logs from both sessions
	sub1 := manager.Get(session1ID).PubSub.Subscribe()
	sub2 := manager.Get(session2ID).PubSub.Subscribe()

	// Send a log only to session1's logger
	manager.Get(session1ID).PubSub.Publish("Test message for session1")

	// Wait a little bit to ensure the message is received.
	// Note: In a real-world scenario, we'd probably avoid sleeps and use synchronization mechanisms.
	time.Sleep(50 * time.Millisecond)

	// Check logs for session1
	select {
	case logMsg := <-sub1:
		if logMsg.Msg != "Test message for session1" {
			t.Errorf("Expected 'Test message for session1', got: %s", logMsg.Msg)
		}
	default:
		t.Error("Expected a log message for session1 but didn't receive any")
	}

	// Ensure no logs for session2
	select {
	case logMsg := <-sub2:
		t.Errorf("Didn't expect a log message for session2, but got: %s", logMsg.Msg)
	default:
		// This is what we expect, no messages for session2
	}

	// Now, send a log only to session2's logger
	manager.Get(session2ID).PubSub.Publish("Test message for session2")

	// Again, wait a little to ensure the message is received
	time.Sleep(50 * time.Millisecond)

	// Check logs for session2
	select {
	case logMsg := <-sub2:
		if logMsg.Msg != "Test message for session2" {
			t.Errorf("Expected 'Test message for session2', got: %s", logMsg.Msg)
		}
	default:
		t.Error("Expected a log message for session2 but didn't receive any")
	}

	// Ensure no additional logs for session1
	select {
	case logMsg := <-sub1:
		t.Errorf("Didn't expect another log message for session1, but got: %s", logMsg.Msg)
	default:
		// This is what we expect, no additional messages for session1
	}
}
