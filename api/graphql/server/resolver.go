package server

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"log"

	s "github.com/owasp-amass/engine/scheduler"
	"github.com/owasp-amass/engine/sessions"
)

type Resolver struct {
	Mgr   *sessions.Manager
	Log   *log.Logger
	Sched *s.Scheduler
}
