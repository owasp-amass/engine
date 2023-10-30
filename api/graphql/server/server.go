package server

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/owasp-amass/engine/scheduler"
	"github.com/owasp-amass/engine/sessions"
	// "github.com/99designs/gqlgen/graphql/playground"
)

type Server struct {
	port    string
	handler http.Handler
}

func NewServer(logger *log.Logger, sched *scheduler.Scheduler, sessionManager *sessions.Manager) *Server {

	srv := handler.NewDefaultServer(NewExecutableSchema(Config{Resolvers: &Resolver{logger: logger, sched: sched, sessionManager: sessionManager}}))

	// Needed for subscription
	// Connecting websocket clients need to support the proper subprotocols \
	// e.g. graphql-ws, graphql-transport-ws, subscriptions-transport-ws, etc
	srv.AddTransport(&transport.Websocket{})
	/*
		srv.AddTransport(transport.Websocket{
			KeepAlivePingInterval: 10 * time.Second,
			Upgrader: websocket.Upgrader{
				CheckOrigin: func(r *http.Request) bool {
					return true
				},
			},
		})
	*/
	// Uncomment to enable playground
	// http.Handle("/", playground.Handler("GraphQL playground", "/graphql"))
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
