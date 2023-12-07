package server

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"log"

	"github.com/owasp-amass/engine/dispatcher"
	"github.com/owasp-amass/engine/sessions"
)

type Resolver struct {
	Log        *log.Logger
	Manager    *sessions.Manager
	Dispatcher *dispatcher.Dispatcher
}
