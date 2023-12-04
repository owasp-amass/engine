package engine

import (
	"errors"
	"log"
	"os"

	"github.com/owasp-amass/engine/api/graphql/server"
	"github.com/owasp-amass/engine/registry"
	s "github.com/owasp-amass/engine/scheduler"
	"github.com/owasp-amass/engine/sessions"
)

type Engine struct {
	Log   *log.Logger
	Sched *s.Scheduler
	Reg   *registry.Registry
	Mgr   *sessions.Manager
	Srv   *server.Server
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

	sched := s.NewScheduler(l, reg, mgr)
	if sched == nil {
		mgr.Shutdown()
		return nil, errors.New("failed to create the event scheduler")
	}

	srv := server.NewServer(l, sched, mgr)
	if srv == nil {
		sched.Shutdown()
		mgr.Shutdown()
		return nil, errors.New("failed to create the API server")
	}
	go func() { _ = srv.Start() }()

	return &Engine{
		Log:   l,
		Sched: sched,
		Reg:   reg,
		Mgr:   mgr,
		Srv:   srv,
	}, nil
}

func (e *Engine) Shutdown() {
	_ = e.Srv.Shutdown()
	e.Sched.Shutdown()
	e.Mgr.Shutdown()
}
