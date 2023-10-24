package server

import (
	//"/graph"

	"fmt"
	"net/http"
	"os"

	//	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/owasp-amass/engine/events"
	// "github.com/99designs/gqlgen/graphql/playground"
)

type Server struct {
	port string
}

func NewServer(scheduler *events.Scheduler) *Server {

	//r = &Resolver{scheduler: s}
	srv := handler.NewDefaultServer(NewExecutableSchema(Config{Resolvers: &Resolver{scheduler: scheduler}}))
	http.Handle("/graphql", srv)

	return &Server{
		port: "4000",
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
