package server

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"log"

	et "github.com/owasp-amass/engine/types"
)

type Resolver struct {
	Log        *log.Logger
	Manager    et.SessionManager
	Dispatcher et.Dispatcher
}
