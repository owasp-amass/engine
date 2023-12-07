package server

import (
	"context"
	"log"
	"net"
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/owasp-amass/engine/dispatcher"
	"github.com/owasp-amass/engine/sessions"
)

const keyServerAddr key = "serverAddr"

type key string

type Server struct {
	ctx    context.Context
	cancel context.CancelFunc
	ch     chan struct{}
	srv    *http.Server
}

func NewServer(logger *log.Logger, d *dispatcher.Dispatcher, mgr *sessions.Manager) *Server {
	hdr := handler.NewDefaultServer(NewExecutableSchema(Config{
		Resolvers: &Resolver{
			Log:        logger,
			Manager:    mgr,
			Dispatcher: d,
		},
	}))
	// Needed for subscription
	// Connecting websocket clients need to support the proper subprotocols \
	// e.g. graphql-ws, graphql-transport-ws, subscriptions-transport-ws, etc
	hdr.AddTransport(&transport.Websocket{})

	mux := http.NewServeMux()
	mux.Handle("/graphql", hdr)

	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		ctx:    ctx,
		cancel: cancel,
		ch:     make(chan struct{}),
		srv: &http.Server{
			Addr:    ":4000",
			Handler: mux,
			BaseContext: func(l net.Listener) context.Context {
				ctx = context.WithValue(ctx, keyServerAddr, l.Addr().String())
				return ctx
			},
		},
	}
}

func (s *Server) Start() error {
	err := s.srv.ListenAndServe()

	s.cancel()
	close(s.ch)
	return err
}

func (s *Server) Shutdown() error {
	err := s.srv.Shutdown(s.ctx)

	<-s.ch
	return err
}
