package server

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"github.com/owasp-amass/engine/events"
)

type Resolver struct {
	scheduler *events.Scheduler
}
