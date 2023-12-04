package sessions

import (
	"io"
	"log"
	"testing"
)

func TestAddSession001(t *testing.T) {
	l := log.New(io.Discard, "T", log.Lmicroseconds)
	mgr := NewManager(l)
	defer mgr.Shutdown()

	s := &Session{}
	id, err := mgr.Add(s)
	if err != nil {
		t.Error(err)
	}

	if id == zeroSessionUUID {
		t.Error("Session ID is zero")
	}
}
