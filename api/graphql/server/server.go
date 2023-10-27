package server

import (
	//"/graph"

	"fmt"
	"log"
	"net/http"
	"os"

	//	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/owasp-amass/engine/scheduler"
	"github.com/owasp-amass/engine/sessions"
)

type Server struct {
	port    string
	handler http.Handler
}

func NewServer(logger *log.Logger, sched *scheduler.Scheduler, sessionManager *sessions.Manager) *Server {

	//r = &Resolver{scheduler: s}
	srv := handler.NewDefaultServer(NewExecutableSchema(Config{Resolvers: &Resolver{logger: logger, sched: sched, sessionManager: sessionManager}}))

	// Needed for subscription
	srv.AddTransport(&transport.Websocket{})

	http.Handle("/", playground.Handler("GraphQL playground", "/graphql"))
	http.Handle("/graphql", srv)

	return &Server{
		port:    "4000",
		handler: srv,
	}
}

func (s *Server) Start() {

	err := http.ListenAndServe(":"+s.port, nil)
	if err != nil {
		fmt.Println("Error starting the server:", err)
		os.Exit(1)
	}
}

func (s *Server) Shutdown() {

}
