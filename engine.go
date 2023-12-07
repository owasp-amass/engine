package engine

import (
	"errors"
	"log"
	"os"

	"github.com/owasp-amass/engine/api/graphql/server"
	"github.com/owasp-amass/engine/dispatcher"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
)

type Engine struct {
	Log        *log.Logger
	Dispatcher *dispatcher.Dispatcher
	Registry   *registry.Registry
	Manager    *sessions.Manager
	Server     *server.Server
}

func NewEngine(l *log.Logger) (*Engine, error) {
	if l == nil {
		l = log.New(os.Stdout, "", log.Lmicroseconds)
	}

	reg := registry.NewRegistry(l)
	if reg == nil {
		return nil, errors.New("failed to create the handler registry")
	}

	mgr := sessions.NewManager(l)
	if mgr == nil {
		return nil, errors.New("failed to create the session manager")
	}

	dis := dispatcher.NewDispatcher(l, reg, mgr)
	if dis == nil {
		mgr.Shutdown()
		return nil, errors.New("failed to create the event scheduler")
	}

	srv := server.NewServer(l, dis, mgr)
	if srv == nil {
		dis.Shutdown()
		mgr.Shutdown()
		return nil, errors.New("failed to create the API server")
	}
	go func() { _ = srv.Start() }()

	return &Engine{
		Log:        l,
		Dispatcher: dis,
		Registry:   reg,
		Manager:    mgr,
		Server:     srv,
	}, nil
}

func (e *Engine) Shutdown() {
	_ = e.Server.Shutdown()
	e.Dispatcher.Shutdown()
	e.Manager.Shutdown()
}
